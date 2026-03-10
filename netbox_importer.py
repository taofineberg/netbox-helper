#!/usr/bin/env python3
"""
Netbox CSV Importer
Imports data from CSV files into Netbox using the API
"""

import os
import csv
import sys
import time
import json
import hmac
import base64
import hashlib
import logging
import argparse
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from dotenv import load_dotenv
import pynetbox
import urllib3

from api_handlers import NetboxAPIHandler
from glitchtip_utils import init_glitchtip, capture_exception
from netbox_branching import ensure_branch_exists, resolve_branch_header_value

# Load environment variables
load_dotenv()

# Setup logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', 'netbox_import.log')
try:
    DEFAULT_IMPORT_WORKERS = int(os.getenv('NBH_IMPORT_WORKERS_DEFAULT', '6'))
except Exception:
    DEFAULT_IMPORT_WORKERS = 6
DEFAULT_IMPORT_WORKERS = max(1, min(12, DEFAULT_IMPORT_WORKERS))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)
init_glitchtip(service='netbox-importer-cli', with_flask=False)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, str(default))).strip().lower()
    return raw in {'1', 'true', 'yes', 'on'}


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


TLS_VERIFY = _env_bool('NBH_TLS_VERIFY', True)
TLS_CA_BUNDLE = str(os.getenv('NBH_TLS_CA_BUNDLE', '') or '').strip()
if not TLS_VERIFY and not TLS_CA_BUNDLE:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _requests_verify():
    return TLS_CA_BUNDLE if TLS_CA_BUNDLE else TLS_VERIFY

INSTANCES_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'template-sync',
    'instances.json',
)


def _make_key() -> bytes:
    secret = os.getenv('SECRET_KEY', 'changeme_set_in_env')
    return hashlib.sha256(secret.encode('utf-8')).digest()


def _decrypt_token(stored: str) -> str:
    if not isinstance(stored, str) or not stored.startswith('enc:'):
        return stored
    try:
        key = _make_key()
        data = base64.urlsafe_b64decode(stored[4:])
        nonce, ct = data[:16], data[16:]
        blocks = (len(ct) + 31) // 32
        ks = b''.join(
            hmac.new(key, nonce + i.to_bytes(4, 'big'), hashlib.sha256).digest()
            for i in range(blocks)
        )
        return bytes(a ^ b for a, b in zip(ct, ks)).decode('utf-8')
    except Exception:
        return stored


def _load_instances() -> List[Dict]:
    if not os.path.exists(INSTANCES_FILE):
        return []
    with open(INSTANCES_FILE, 'r', encoding='utf-8') as f:
        instances = json.load(f).get('instances', [])
    for inst in instances:
        if 'token' in inst:
            inst['token'] = _decrypt_token(inst.get('token'))
        inst['skip_ssl_verify'] = _to_bool(inst.get('skip_ssl_verify', False))
    return instances


def resolve_instance(instance_id: Optional[str] = None, instance_name: Optional[str] = None) -> Dict:
    instances = _load_instances()
    if not instances:
        raise ValueError(
            f'No instances found in {INSTANCES_FILE}. Add a NetBox instance before running imports.'
        )

    if instance_id:
        inst = next((i for i in instances if i.get('id') == instance_id), None)
        if not inst:
            raise ValueError(f'Instance id "{instance_id}" not found in {INSTANCES_FILE}')
        return inst

    if instance_name:
        inst = next((i for i in instances if i.get('name') == instance_name), None)
        if not inst:
            raise ValueError(f'Instance name "{instance_name}" not found in {INSTANCES_FILE}')
        return inst

    return instances[0]

class ImportStopped(Exception):
    """Exception raised when the import is manually stopped"""
    pass

class NetboxImporter:
    """Main importer class"""
    
    # Import order - dependencies first
    IMPORT_ORDER = [
        'sites',
        'locations',
        'racks',
        'power-panels',
        'devices',
        'power-feeds',
        'modules',
        'cables',
        'power-cables',
        'vrf',
        'prefixroles',
        'prefix',
        'ip-addresses'
    ]
    FOUNDATIONAL_SECTIONS = {
        'sites',
        'locations',
        'racks',
        'power-panels',
        'devices',
    }
    # These sections are dependency-sensitive and should run serially by default
    # to avoid race conditions (for example, device components required by cables).
    SERIAL_SECTIONS = {
        'sites',
        'locations',
        'racks',
        'power-panels',
        'devices',
        'power-feeds',
        'modules',
        'cables',
        'power-cables',
    }
    
    def __init__(self, csv_file: str, dry_run: bool = False, replace: bool = False, interactive: bool = True,
                 netbox_url: str = None, netbox_token: str = None, connect: bool = True,
                 netbox_skip_ssl_verify: bool = False, netbox_branch: str = None):
        self.csv_file = csv_file
        self.dry_run = dry_run
        self.replace = replace
        self.interactive = interactive
        self.api = None
        self.handler = None
        self.fail_fast_foundation = _env_bool('NBH_FAIL_FAST_FOUNDATION', True)
        self.strict_import_order = _env_bool('NBH_IMPORT_STRICT_ORDER', True)
        
        # Statistics
        self.stats = defaultdict(lambda: {'created': 0, 'updated': 0, 'skipped': 0, 'errors': 0})
        self.failures = []
        self._result_lock = threading.Lock()  # protects stats and failures.csv writes

        if not connect:
            return

        if not netbox_url or not netbox_token:
            raise ValueError('netbox_url and netbox_token are required (resolved from instances.json)')

        logger.info(f'Connecting to Netbox at {netbox_url}')
        import requests
        from urllib3.util import Retry
        from requests.adapters import HTTPAdapter

        session = requests.Session()
        if bool(netbox_skip_ssl_verify):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            session.verify = False
        else:
            session.verify = _requests_verify()

        if str(netbox_branch or '').strip():
            # Optional destination branch targeting (e.g. NetBox Branching plugin).
            branch_ref = str(netbox_branch).strip()
            branch_instance = {
                'url': str(netbox_url or '').strip().rstrip('/'),
                'token': str(netbox_token or '').strip(),
                'verify': session.verify,
            }
            branch_phase_start = time.monotonic()
            logger.info(f'Ensuring destination branch "{branch_ref}" exists...')
            branch_created = False
            try:
                branch_info = ensure_branch_exists(branch_instance, branch_ref, timeout=20)
                branch_created = bool((branch_info or {}).get('created'))
                if branch_created:
                    logger.info(f'Branch "{branch_ref}" created. Waiting for readiness...')
                else:
                    logger.info(f'Branch "{branch_ref}" already exists. Checking readiness...')
            except Exception:
                # resolve_branch_header_value handles ensure/create path too; keep going.
                logger.debug('Pre-create branch check failed; falling back to resolver', exc_info=True)
                logger.info(
                    f'Branch pre-check for "{branch_ref}" was inconclusive; '
                    'continuing with branch header resolution.'
                )

            branch_header = resolve_branch_header_value(branch_instance, branch_ref)
            if not str(branch_header or '').strip():
                raise ValueError(f'Failed to resolve branch header for "{branch_ref}"')
            session.headers.update({'X-NetBox-Branch': branch_header})
            logger.info(f'Using branch header "{branch_header}" for "{branch_ref}"')

            # New branches can take a short moment before writes are accepted.
            # Probe and briefly wait so users don't need a second import run.
            try:
                default_attempts = 30 if branch_created else 5
                warm_attempts = max(1, int(os.getenv('NBH_BRANCH_WARMUP_ATTEMPTS', str(default_attempts))))
            except Exception:
                warm_attempts = 30 if branch_created else 5
            try:
                warm_backoff = float(os.getenv('NBH_BRANCH_WARMUP_BACKOFF', '0.6'))
            except Exception:
                warm_backoff = 0.6
            try:
                warm_max_sleep = float(os.getenv('NBH_BRANCH_WARMUP_MAX_SLEEP', '3.0'))
            except Exception:
                warm_max_sleep = 3.0
            try:
                probe_timeout = int(os.getenv('NBH_BRANCH_PROBE_TIMEOUT', '12'))
            except Exception:
                probe_timeout = 12

            final_verdict = None
            for attempt in range(1, warm_attempts + 1):
                # Re-resolve header in case schema_id appears shortly after creation.
                if attempt > 1:
                    try:
                        refreshed = resolve_branch_header_value(branch_instance, branch_ref, timeout=20)
                        if str(refreshed or '').strip() and refreshed != branch_header:
                            branch_header = refreshed
                            session.headers.update({'X-NetBox-Branch': branch_header})
                            logger.info(
                                f'Resolved refreshed branch header for "{branch_ref}" '
                                f'on warm-up attempt {attempt}'
                            )
                    except Exception:
                        logger.debug('Branch header re-resolve failed during warm-up', exc_info=True)

                logger.info(
                    f'Branch readiness check {attempt}/{warm_attempts} for "{branch_ref}" '
                    f'(header="{branch_header}")...'
                )
                verdict = self._probe_branch_header_ready(
                    branch_instance,
                    branch_header,
                    timeout=probe_timeout,
                )
                final_verdict = verdict
                if verdict is True:
                    elapsed_s = time.monotonic() - branch_phase_start
                    logger.info(
                        f'Branch "{branch_ref}" is ready for writes '
                        f'after {attempt} check(s) ({elapsed_s:.1f}s).'
                    )
                    break
                if attempt < warm_attempts:
                    wait_s = min(max(0.1, warm_backoff) * attempt, max(0.2, warm_max_sleep))
                    if verdict is False:
                        reason = 'branch not ready yet'
                    else:
                        reason = 'probe inconclusive'
                    logger.info(
                        f'Branch "{branch_ref}" not ready ({reason}) on check '
                        f'{attempt}/{warm_attempts}; retrying in {wait_s:.1f}s...'
                    )
                    time.sleep(wait_s)

            if final_verdict is not True:
                elapsed_s = time.monotonic() - branch_phase_start
                logger.warning(
                    f'Branch "{branch_ref}" header readiness could not be confirmed '
                    f'(header="{branch_header}") after {warm_attempts} check(s) '
                    f'over {elapsed_s:.1f}s; proceeding may hit transient branch errors.'
                )
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        self.api = pynetbox.api(netbox_url, token=netbox_token)
        self.api.http_session = session
        self.handler = NetboxAPIHandler(self.api)
        
    def parse_csv(self) -> Dict[str, List[Dict]]:
        """Parse CSV file and group data by import type"""
        logger.info(f'Parsing CSV file: {self.csv_file}')
        
        data = defaultdict(list)
        current_type = None
        current_headers = []
        current_prefix = None
        
        with open(self.csv_file, 'r', encoding='utf-8-sig') as f:
            for line_num, line in enumerate(f, 1):
                # Parse CSV line
                reader = csv.reader([line])
                row = next(reader)
                
                # Skip empty rows
                if not any(row):
                    continue
                
                # Get identifier from first column  
                identifier = row[0].strip() if row else ''
                
                # Check if this is a header row (ends with -h)
                if identifier.endswith('-h'):
                    # Extract import type and prefix
                    full_prefix = identifier[:-2]  # Remove -h suffix
                    # Extract the prefix (e.g., "STL1PAPB" from "STL1PAPBsites-h")
                    # Find where the lowercase name starts
                    for i, char in enumerate(full_prefix):
                        if char.islower():
                            current_prefix = full_prefix[:i]
                            current_type = full_prefix[i:]
                            break
                    else:
                        # If no lowercase found, use whole thing
                        current_type = full_prefix
                        current_prefix = full_prefix
                    
                    # Get headers from remaining columns (skip first 2 empty columns)
                    current_headers = [h.strip() for h in row[2:] if h.strip()]
                    
                    # Special case: "devices" section that is actually Power Feeds
                    if current_type == 'devices' and 'power_panel' in current_headers:
                        current_type = 'power-feeds'
                    
                    # Special case: "powercables" section
                    if current_type == 'powercables':
                        current_type = 'power-cables'
                        
                    logger.debug(f'Found header for {current_type}: {current_headers}')
                    continue
                
                # If we have a current type and this row starts with the prefix, it's a data row
                if current_type and current_headers and identifier and not identifier.endswith('-h'):
                    # Check if this identifier matches the current import type
                    # It should start with the prefix and match the type
                    if current_prefix and identifier.startswith(current_prefix):
                        # Extract the actual identifier (everything after prefix)
                        identifier_suffix = identifier[len(current_prefix):]
                        
                        # Check if it matches current type
                        # Special case for power-feeds and power-cables which might have different labels in CSV
                        is_match = (identifier_suffix.lower() == current_type.lower())
                        if not is_match and current_type == 'power-feeds' and identifier_suffix.lower() == 'devices':
                            is_match = True
                        if not is_match and current_type == 'power-cables' and identifier_suffix.lower() == 'powercables':
                            is_match = True
                            
                        if is_match:
                            # Create dict from headers and values (skip first 2 columns)
                            values = row[2:]
                            row_data = {}
                            for i, header in enumerate(current_headers):
                                if i < len(values):
                                    # Use the first occurrence of a header if duplicates exist
                                    if header not in row_data:
                                        row_data[header] = values[i].strip() if values[i] else ''
                            
                            if any(row_data.values()):  # Only add if not empty
                                data[current_type].append(row_data)
                                logger.debug(f'Added {current_type} record: {list(row_data.keys())}')
        
        # Log summary
        logger.info('CSV parsing complete:')
        for import_type in self.IMPORT_ORDER:
            if import_type in data:
                logger.info(f'  {import_type}: {len(data[import_type])} records')
        
        return data
    
    def _get_ident(self, row: Dict, import_type: str) -> str:
        """Extract a display identifier from a row."""
        ident = row.get('name') or row.get('label') or row.get('display_name')
        if not ident and import_type in ['cables', 'power-cables']:
            ident = f"{row.get('side_a_device')}:{row.get('side_a_name')} -> {row.get('side_b_device')}:{row.get('side_b_name')}"
        if not ident and import_type == 'modules':
            ident = f"{row.get('device')}/{row.get('module_bay')} ({row.get('module_type')})"
        if not ident:
            ident = row.get('address') or row.get('prefix') or row.get('id') or 'Record'
        return ident

    def _handle_result(self, import_type: str, result: Dict, ident: str, row: Dict):
        """Update stats and log failures for a processed record. Thread-safe."""
        import json
        if result['success']:
            with self._result_lock:
                if result['action'] == 'create':
                    self.stats[import_type]['created'] += 1
                elif result['action'] == 'update':
                    self.stats[import_type]['updated'] += 1
                elif result['action'] == 'skipped':
                    self.stats[import_type]['skipped'] += 1
        else:
            error_msg = result['message']
            logger.error(f'  Error [{import_type}:{ident}]: {error_msg}')
            with self._result_lock:
                self.stats[import_type]['errors'] += 1
                try:
                    csv_file = 'failures.csv'
                    file_exists = os.path.exists(csv_file)
                    with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        if not file_exists:
                            writer.writerow(['import_type', 'identifier', 'error', 'original_data'])
                        writer.writerow([import_type, ident, error_msg, json.dumps(row)])
                except Exception as e:
                    logger.error(f'Failed to log failure to CSV: {str(e)}')

    def _snapshot_section_stats(self, import_type: str) -> Dict[str, int]:
        """Read section counters in a thread-safe way."""
        with self._result_lock:
            stats = self.stats.get(import_type, {})
            return {
                'created': int(stats.get('created', 0) or 0),
                'updated': int(stats.get('updated', 0) or 0),
                'skipped': int(stats.get('skipped', 0) or 0),
                'errors': int(stats.get('errors', 0) or 0),
            }

    def _snapshot_totals(self) -> Dict[str, int]:
        """Read global counters in a thread-safe way."""
        with self._result_lock:
            totals = {'created': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
            for stats in self.stats.values():
                totals['created'] += int(stats.get('created', 0) or 0)
                totals['updated'] += int(stats.get('updated', 0) or 0)
                totals['skipped'] += int(stats.get('skipped', 0) or 0)
                totals['errors'] += int(stats.get('errors', 0) or 0)
            return totals

    def _emit_progress(self, progress_cb: Optional[Callable[[Dict], None]], payload: Dict):
        """Emit progress without breaking the import flow on callback errors."""
        if not callable(progress_cb):
            return
        try:
            progress_cb(payload)
        except Exception:
            logger.debug('Progress callback failed', exc_info=True)

    def _is_transient_error_message(self, message: str) -> bool:
        text = str(message or '')
        markers = (
            'HTTPSConnectionPool',
            'Max retries exceeded',
            'too many 500 error responses',
            "ResponseError('too many 500",
            'Read timed out',
            'ConnectTimeout',
            'ConnectionError',
            '504 Gateway Time-out',
            '502 Bad Gateway',
            '503 Service Unavailable',
        )
        return any(m in text for m in markers)

    def _probe_branch_header_ready(self, instance: Dict[str, Any], branch_header: str, timeout: int = 15) -> Optional[bool]:
        """Best-effort check whether the branch header is ready for API writes."""
        import requests

        base = str((instance or {}).get('url') or '').strip().rstrip('/')
        token = str((instance or {}).get('token') or '').strip()
        header = str(branch_header or '').strip()
        verify = (instance or {}).get('verify', True)
        if not base or not token or not header:
            return False

        try:
            resp = requests.get(
                f"{base}/api/dcim/sites/?limit=1",
                headers={
                    'Authorization': f'Token {token}',
                    'Accept': 'application/json',
                    'X-NetBox-Branch': header,
                },
                verify=verify,
                timeout=max(3, int(timeout or 15)),
            )
        except Exception:
            return None

        if resp.status_code == 200:
            return True
        if resp.status_code == 403:
            # Header is likely accepted; caller token may not list sites.
            return True
        if resp.status_code in {400, 404}:
            return False

        body_l = str(resp.text or '').lower()
        if resp.status_code >= 500 and (
            'schema_name' in body_l
            or ('x-netbox-branch' in body_l and 'invalid' in body_l)
            or ('invalid branch identifier' in body_l)
        ):
            return False
        return None

    def _run_handler_with_retry(
        self,
        handler_method: Callable[[Dict, bool, bool], Dict],
        row: Dict,
        import_type: str,
        ident: str,
        retry_attempts: int,
        retry_backoff: float,
        should_stop: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[Dict], None]] = None,
        section_index: int = 0,
        total_sections: int = 0,
        section_total: int = 0,
        section_processed: int = 0,
        processed_total: int = 0,
        total_records: int = 0,
        completed_sections: int = 0,
    ) -> Dict:
        max_attempts = max(1, int(retry_attempts or 0) + 1)
        backoff = max(0.0, float(retry_backoff or 0.0))
        attempt = 1
        while True:
            result = handler_method(row, dry_run=self.dry_run, replace=self.replace)
            if result.get('success'):
                return result
            if attempt >= max_attempts:
                return result
            if not self._is_transient_error_message(result.get('message', '')):
                return result
            if should_stop and should_stop():
                return result
            wait_s = backoff * (2 ** (attempt - 1))
            logger.warning(
                f'  Retry {attempt}/{max_attempts - 1} for [{import_type}:{ident}] '
                f'after transient error: {result.get("message", "")}'
            )
            self._emit_progress(progress_cb, {
                'event': 'record_retry',
                'section': import_type,
                'section_index': int(section_index),
                'total_sections': int(total_sections),
                'section_total': int(section_total),
                'section_processed': int(section_processed),
                'identifier': str(ident or ''),
                'attempt': int(attempt),
                'max_retries': int(max_attempts - 1),
                'wait_seconds': float(wait_s),
                'message': str(result.get('message') or ''),
                'processed_records': int(processed_total),
                'total_records': int(total_records),
                'completed_sections': int(completed_sections),
                'totals': self._snapshot_totals(),
                'section_stats': self._snapshot_section_stats(import_type),
            })
            if wait_s > 0:
                time.sleep(wait_s)
            attempt += 1

    def import_data(
        self,
        data: Dict[str, List[Dict]],
        sections: Optional[List[str]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
        delay: float = 0.0,
        workers: int = DEFAULT_IMPORT_WORKERS,
        retry_attempts: int = 0,
        retry_backoff: float = 1.0,
        progress_cb: Optional[Callable[[Dict], None]] = None,
    ):
        """Import data in the correct order, optionally filtered by sections and interruptible"""
        if self.handler is None:
            raise ValueError('NetBox connection not initialized. Use connect=True with instance credentials.')

        logger.info('='*80)
        if self.dry_run:
            logger.info('DRY RUN MODE - No changes will be made to Netbox')
        logger.info('='*80)

        active_sections = [
            import_type
            for import_type in self.IMPORT_ORDER
            if ((not sections or import_type in sections) and import_type in data)
        ]
        section_totals = {
            import_type: len(data.get(import_type, []) or [])
            for import_type in active_sections
        }
        total_records = sum(section_totals.values())
        processed_total = 0
        total_sections = len(active_sections)

        self._emit_progress(progress_cb, {
            'event': 'run_start',
            'sections': list(active_sections),
            'section_totals': dict(section_totals),
            'total_sections': int(total_sections),
            'total_records': int(total_records),
            'processed_records': 0,
            'completed_sections': 0,
            'totals': self._snapshot_totals(),
        })

        # Process in dependency order — each section completes before the next starts
        completed_sections = 0
        for import_type in self.IMPORT_ORDER:
            if should_stop and should_stop():
                logger.warning("!!! Import stop requested by user !!!")
                raise ImportStopped("Import stopped by user")

            if sections and import_type not in sections:
                continue
            if import_type not in data:
                continue

            records = data[import_type]
            handler_method = self._get_handler_method(import_type)
            section_total = len(records)
            section_index = completed_sections + 1
            section_processed = 0

            logger.info('')
            logger.info(f'Processing {import_type}: {len(records)} records')
            logger.info('-'*80)

            if not handler_method:
                logger.warning(f'No handler for import type: {import_type}')
                continue

            self._emit_progress(progress_cb, {
                'event': 'section_start',
                'section': import_type,
                'section_index': int(section_index),
                'total_sections': int(total_sections),
                'section_total': int(section_total),
                'section_processed': 0,
                'processed_records': int(processed_total),
                'total_records': int(total_records),
                'completed_sections': int(completed_sections),
                'totals': self._snapshot_totals(),
                'section_stats': self._snapshot_section_stats(import_type),
            })

            # Parallelism is section-aware; dependency-sensitive sections are
            # forced to serial mode when strict ordering is enabled.
            effective_workers = self._section_workers(
                import_type=import_type,
                requested_workers=workers,
                delay=delay,
            )

            if effective_workers > 1:
                logger.info(f'Using {effective_workers} parallel workers')
                stop_flag = threading.Event()

                def _run(args, _handler=handler_method, _type=import_type, _total=len(records)):
                    i, row = args
                    if stop_flag.is_set():
                        return None
                    ident = self._get_ident(row, _type)
                    self._emit_progress(progress_cb, {
                        'event': 'record_start',
                        'section': _type,
                        'section_index': int(section_index),
                        'total_sections': int(total_sections),
                        'section_total': int(section_total),
                        'section_processed': int(section_processed),
                        'identifier': str(ident or ''),
                        'processed_records': int(processed_total),
                        'total_records': int(total_records),
                        'completed_sections': int(completed_sections),
                        'totals': self._snapshot_totals(),
                        'section_stats': self._snapshot_section_stats(_type),
                    })
                    logger.info(f'[{i}/{_total}] Processing {_type}: {ident}...')
                    result = self._run_handler_with_retry(
                        _handler,
                        row,
                        import_type=_type,
                        ident=ident,
                        retry_attempts=retry_attempts,
                        retry_backoff=retry_backoff,
                        should_stop=should_stop,
                        progress_cb=progress_cb,
                        section_index=section_index,
                        total_sections=total_sections,
                        section_total=section_total,
                        section_processed=section_processed,
                        processed_total=processed_total,
                        total_records=total_records,
                        completed_sections=completed_sections,
                    )
                    return result, ident, row

                with ThreadPoolExecutor(max_workers=effective_workers) as executor:
                    futures = [executor.submit(_run, (i, row)) for i, row in enumerate(records, 1)]
                    for future in as_completed(futures):
                        if should_stop and should_stop():
                            stop_flag.set()
                        res = future.result()
                        if res is not None:
                            result, ident, row = res
                            self._handle_result(import_type, result, ident, row)
                            section_processed += 1
                            processed_total += 1
                            self._emit_progress(progress_cb, {
                                'event': 'record',
                                'section': import_type,
                                'section_index': int(section_index),
                                'total_sections': int(total_sections),
                                'section_total': int(section_total),
                                'section_processed': int(section_processed),
                                'identifier': str(ident or ''),
                                'success': bool(result.get('success')),
                                'action': str(result.get('action') or ''),
                                'message': str(result.get('message') or ''),
                                'processed_records': int(processed_total),
                                'total_records': int(total_records),
                                'completed_sections': int(completed_sections),
                                'totals': self._snapshot_totals(),
                                'section_stats': self._snapshot_section_stats(import_type),
                            })

                if stop_flag.is_set():
                    logger.warning("!!! Import stop requested by user !!!")
                    raise ImportStopped("Import stopped by user")
            else:
                if self.strict_import_order and import_type in self.SERIAL_SECTIONS and workers > 1 and delay <= 0:
                    logger.info(
                        f'Using serial worker for {import_type} '
                        f'(strict ordering; requested workers={workers})'
                    )
                for i, row in enumerate(records, 1):
                    if should_stop and should_stop():
                        logger.warning("!!! Import stop requested by user !!!")
                        raise ImportStopped("Import stopped by user")

                    ident = self._get_ident(row, import_type)
                    self._emit_progress(progress_cb, {
                        'event': 'record_start',
                        'section': import_type,
                        'section_index': int(section_index),
                        'total_sections': int(total_sections),
                        'section_total': int(section_total),
                        'section_processed': int(section_processed),
                        'identifier': str(ident or ''),
                        'processed_records': int(processed_total),
                        'total_records': int(total_records),
                        'completed_sections': int(completed_sections),
                        'totals': self._snapshot_totals(),
                        'section_stats': self._snapshot_section_stats(import_type),
                    })
                    logger.info(f'[{i}/{len(records)}] Processing {import_type}: {ident}...')
                    result = self._run_handler_with_retry(
                        handler_method,
                        row,
                        import_type=import_type,
                        ident=ident,
                        retry_attempts=retry_attempts,
                        retry_backoff=retry_backoff,
                        should_stop=should_stop,
                        progress_cb=progress_cb,
                        section_index=section_index,
                        total_sections=total_sections,
                        section_total=section_total,
                        section_processed=section_processed,
                        processed_total=processed_total,
                        total_records=total_records,
                        completed_sections=completed_sections,
                    )
                    self._handle_result(import_type, result, ident, row)
                    section_processed += 1
                    processed_total += 1
                    self._emit_progress(progress_cb, {
                        'event': 'record',
                        'section': import_type,
                        'section_index': int(section_index),
                        'total_sections': int(total_sections),
                        'section_total': int(section_total),
                        'section_processed': int(section_processed),
                        'identifier': str(ident or ''),
                        'success': bool(result.get('success')),
                        'action': str(result.get('action') or ''),
                        'message': str(result.get('message') or ''),
                        'processed_records': int(processed_total),
                        'total_records': int(total_records),
                        'completed_sections': int(completed_sections),
                        'totals': self._snapshot_totals(),
                        'section_stats': self._snapshot_section_stats(import_type),
                    })

                    if delay > 0:
                        time.sleep(delay)

            completed_sections += 1
            self._emit_progress(progress_cb, {
                'event': 'section_complete',
                'section': import_type,
                'section_index': int(section_index),
                'total_sections': int(total_sections),
                'section_total': int(section_total),
                'section_processed': int(section_processed),
                'processed_records': int(processed_total),
                'total_records': int(total_records),
                'completed_sections': int(completed_sections),
                'totals': self._snapshot_totals(),
                'section_stats': self._snapshot_section_stats(import_type),
            })
            if self._should_abort_after_section(import_type):
                failed_stats = self._snapshot_section_stats(import_type)
                downstream_sections = [
                    s for s in active_sections
                    if self.IMPORT_ORDER.index(s) > self.IMPORT_ORDER.index(import_type)
                ]
                err_count = int(failed_stats.get('errors', 0) or 0)
                logger.error(
                    f'Fail-fast abort: foundational section "{import_type}" finished with '
                    f'{err_count} error(s).'
                )
                if downstream_sections:
                    logger.error(f'Skipping downstream sections: {", ".join(downstream_sections)}')
                self._emit_progress(progress_cb, {
                    'event': 'run_aborted',
                    'reason': f'Foundational section "{import_type}" has errors',
                    'failed_section': import_type,
                    'failed_section_errors': err_count,
                    'skipped_sections': downstream_sections,
                    'processed_records': int(processed_total),
                    'total_records': int(total_records),
                    'completed_sections': int(completed_sections),
                    'total_sections': int(total_sections),
                    'totals': self._snapshot_totals(),
                })
                self._print_summary()
                raise RuntimeError(
                    f'Foundational section "{import_type}" has {err_count} error(s); '
                    f'aborting remaining sections.'
                )

        self._emit_progress(progress_cb, {
            'event': 'run_complete',
            'processed_records': int(processed_total),
            'total_records': int(total_records),
            'completed_sections': int(completed_sections),
            'total_sections': int(total_sections),
            'totals': self._snapshot_totals(),
        })

        # Print summary
        self._print_summary()
    
    def _get_handler_method(self, import_type: str):
        """Get the appropriate handler method for an import type"""
        handler_map = {
            'sites': self.handler.import_sites,
            'locations': self.handler.import_locations,
            'racks': self.handler.import_racks,
            'power-panels': self.handler.import_power_panels,
            'devices': self.handler.import_devices,
            'power-feeds': self.handler.import_power_feeds,
            'modules': self.handler.import_modules,
            'cables': self.handler.import_cables,
            'power-cables': self.handler.import_cables,
            'vrf': self.handler.import_vrfs,
            'prefixroles': self.handler.import_prefix_roles,
            'prefix': self.handler.import_prefixes,
            'ip-addresses': self.handler.import_ip_addresses,
        }
        return handler_map.get(import_type)

    def _should_abort_after_section(self, import_type: str) -> bool:
        """Return True when foundational section errors should halt downstream processing."""
        if not self.fail_fast_foundation:
            return False
        if import_type not in self.FOUNDATIONAL_SECTIONS:
            return False
        stats = self._snapshot_section_stats(import_type)
        return int(stats.get('errors', 0) or 0) > 0

    def _section_workers(self, import_type: str, requested_workers: int, delay: float) -> int:
        if delay > 0:
            return 1
        wanted = max(1, int(requested_workers or 1))
        if self.strict_import_order and import_type in self.SERIAL_SECTIONS:
            return 1
        return wanted
    
    def _print_summary(self):
        """Print import summary"""
        logger.info('')
        logger.info('='*80)
        logger.info('IMPORT SUMMARY')
        logger.info('='*80)
        
        total_created = 0
        total_updated = 0
        total_skipped = 0
        total_errors = 0
        
        for import_type in self.IMPORT_ORDER:
            if import_type in self.stats:
                stats = self.stats[import_type]
                logger.info(f'{import_type}:')
                logger.info(f'  Created: {stats["created"]}')
                logger.info(f'  Updated: {stats["updated"]}')
                logger.info(f'  Skipped: {stats["skipped"]}')
                logger.info(f'  Errors:  {stats["errors"]}')
                
                total_created += stats['created']
                total_updated += stats['updated']
                total_skipped += stats['skipped']
                total_errors += stats['errors']
        
        logger.info('-'*80)
        logger.info(f'TOTAL:')
        logger.info(f'  Created: {total_created}')
        logger.info(f'  Updated: {total_updated}')
        logger.info(f'  Skipped: {total_skipped}')
        logger.info(f'  Errors:  {total_errors}')
        logger.info('='*80)
        
        # Print detailed failures if any
        if self.failures:
            logger.info('')
            logger.info('DETAILED FAILURES')
            logger.info('-'*80)
            logger.info(f'{"TYPE":<15} | {"IDENTIFIER":<30} | {"ERROR MESSAGE"}')
            logger.info('-'*80)
            for failure in self.failures:
                logger.info(f'{failure["type"]:<15} | {str(failure["id"]):<30} | {failure["error"]}')
            logger.info('-'*80)
            logger.info('')
        
        if self.dry_run:
            logger.info('DRY RUN COMPLETE - No changes were made to Netbox')
        else:
            logger.info('IMPORT COMPLETE')
        
        logger.info(f'Log file: {LOG_FILE}')


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Import CSV data into Netbox',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Dry run to preview changes
  python netbox_importer.py SLA.csv --dry-run
  
  # Import and skip existing items (default)
  python netbox_importer.py SLA.csv
  
  # Import and replace existing items
  python netbox_importer.py SLA.csv --replace
        '''
    )
    
    parser.add_argument('csv_file', help='Path to CSV file to import')
    parser.add_argument('--dry-run', action='store_true', 
                        help='Preview changes without making any modifications')
    parser.add_argument('--replace', action='store_true',
                        help='Replace existing items instead of skipping them')
    parser.add_argument('--non-interactive', action='store_true',
                        help='Run without prompts (uses --replace setting for duplicates)')
    parser.add_argument('--instance-id',
                        help='Instance ID from template-sync/instances.json')
    parser.add_argument('--instance-name',
                        help='Instance name from template-sync/instances.json (used when --instance-id is not set)')
    parser.add_argument(
        '--workers',
        type=int,
        default=DEFAULT_IMPORT_WORKERS,
        help=f'Parallel worker threads per section (default: {DEFAULT_IMPORT_WORKERS})',
    )
    
    args = parser.parse_args()
    
    # Validate CSV file exists
    if not os.path.exists(args.csv_file):
        logger.error(f'CSV file not found: {args.csv_file}')
        sys.exit(1)
    
    try:
        instance = resolve_instance(args.instance_id, args.instance_name)
        netbox_url = (instance.get('url') or '').rstrip('/')
        netbox_token = instance.get('token') or ''
        if not netbox_url or not netbox_token:
            raise ValueError(f'Instance "{instance.get("name", "unknown")}" is missing URL or token')

        # Create importer
        importer = NetboxImporter(
            csv_file=args.csv_file,
            dry_run=args.dry_run,
            replace=args.replace,
            interactive=not args.non_interactive,
            netbox_url=netbox_url,
            netbox_token=netbox_token,
            netbox_skip_ssl_verify=_to_bool(instance.get('skip_ssl_verify', False)),
        )
        
        # Parse CSV
        data = importer.parse_csv()
        
        # Import data
        importer.import_data(data, workers=max(1, int(args.workers or DEFAULT_IMPORT_WORKERS)))
        
        # Exit with error code if there were errors
        total_errors = sum(stats['errors'] for stats in importer.stats.values())
        sys.exit(1 if total_errors > 0 else 0)
        
    except Exception as e:
        logger.error(f'Fatal error: {str(e)}', exc_info=True)
        capture_exception(
            e,
            script='netbox_importer.py',
            filename=args.csv_file,
            server_id=args.instance_id or '',
            branch='',
        )
        sys.exit(1)


if __name__ == '__main__':
    main()
