"""
netbox_helper.py — Unified Netbox Helper app
Combines CSV Import and Template Sync into one Flask app.

Start:  PORT=81 .venv/bin/python netbox_helper.py
"""

import os
import json
import uuid
import difflib
import traceback
import hmac
import hashlib
import base64
import secrets as _secrets
import requests
import threading
import time
import csv
import subprocess
import re
import ipaddress
import shutil
import contextvars
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for, send_file, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from netbox_importer import NetboxImporter, ImportStopped
import logging
from collections import defaultdict
from functools import wraps
from dotenv import load_dotenv
from urllib.parse import urlparse
import pynetbox
try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
except Exception:  # optional dependency
    sentry_sdk = None
    FlaskIntegration = None
from export_netbox_config import (
    XlsxReader,
    get_cell,
    _source_sheet_matrix,
    _source_sheet_layout,
    row_from_source_by_site,
    header_col_index,
    list_b2_options,
    list_d7_options,
    build_netbox_import_export,
    write_export_csv,
    safe_filename,
)
from netbox_site_to_csv import (
    parse_reference_template,
    fetch_site_export_data,
    render_csv as render_site_csv,
)
from netbox_server_compare import (
    compare_instances as server_compare_instances,
    list_compare_options as server_compare_list_options,
    resolve_site_facility as server_compare_resolve_site_facility,
    sync_many as server_compare_sync_many,
)
from netbox_site_sync import (
    SITE_GROUP_LABELS,
    build_site_sync_plan,
    sync_site_data,
)
from netbox_branching import (
    ensure_branch_exists,
    list_branches as netbox_list_branches,
    resolve_branch_header_value,
)

# Load .env from project directory
load_dotenv()

import urllib3


def _env_bool(name, default=False):
    raw = str(os.getenv(name, str(default))).strip().lower()
    return raw in ('1', 'true', 'yes', 'on')


TLS_VERIFY = _env_bool('NBH_TLS_VERIFY', True)
TLS_CA_BUNDLE = str(os.getenv('NBH_TLS_CA_BUNDLE', '') or '').strip()
DEV_MODE = _env_bool('DEV', False)
GLITCHTIP_DSN = str(os.getenv('GLITCHTIP_DSN', '') or '').strip()
GLITCHTIP_ENABLED = DEV_MODE and _env_bool('GLITCHTIP_ENABLED', True) and bool(GLITCHTIP_DSN)
GLITCHTIP_ENV = str(os.getenv('GLITCHTIP_ENV', os.getenv('ENVIRONMENT', 'dev')) or 'dev').strip()
GLITCHTIP_RELEASE = str(os.getenv('GLITCHTIP_RELEASE', '') or '').strip()
try:
    GLITCHTIP_TRACES_SAMPLE_RATE = float(os.getenv('GLITCHTIP_TRACES_SAMPLE_RATE', '0.0') or 0.0)
except Exception:
    GLITCHTIP_TRACES_SAMPLE_RATE = 0.0
GLITCHTIP_TRACES_SAMPLE_RATE = max(0.0, min(1.0, GLITCHTIP_TRACES_SAMPLE_RATE))
SESSION_COOKIE_SECURE = _env_bool('NBH_SESSION_COOKIE_SECURE', False)
SESSION_COOKIE_SAMESITE = str(os.getenv('NBH_SESSION_COOKIE_SAMESITE', 'Lax') or 'Lax').strip()
CSRF_ENFORCE_ORIGIN = _env_bool('NBH_CSRF_ENFORCE_ORIGIN', True)
CSRF_ALLOW_EMPTY_ORIGIN = _env_bool('NBH_CSRF_ALLOW_EMPTY_ORIGIN', False)
REQUIRE_STRONG_SECRET = _env_bool('NBH_REQUIRE_STRONG_SECRET', True)
LOGIN_MAX_ATTEMPTS = max(1, int(os.getenv('NBH_LOGIN_MAX_ATTEMPTS', '5')))
LOGIN_WINDOW_SECONDS = max(60, int(os.getenv('NBH_LOGIN_WINDOW_SECONDS', '300')))
LOGIN_LOCKOUT_SECONDS = max(60, int(os.getenv('NBH_LOGIN_LOCKOUT_SECONDS', '900')))
PASSWORD_MIN_LENGTH = max(10, int(os.getenv('NBH_PASSWORD_MIN_LENGTH', '12')))
DEFAULT_IMPORT_WORKERS = max(1, min(12, int(os.getenv('NBH_IMPORT_WORKERS_DEFAULT', '6'))))
QUIET_POLL_ACCESS_LOGS = _env_bool('NBH_QUIET_POLL_ACCESS_LOGS', True)
PROXY_FIX_ENABLED = _env_bool('NBH_PROXY_FIX_ENABLED', True)
PROXY_FIX_X_FOR = max(0, int(os.getenv('NBH_PROXY_FIX_X_FOR', '1') or '1'))
PROXY_FIX_X_PROTO = max(0, int(os.getenv('NBH_PROXY_FIX_X_PROTO', '1') or '1'))
PROXY_FIX_X_HOST = max(0, int(os.getenv('NBH_PROXY_FIX_X_HOST', '1') or '1'))
PROXY_FIX_X_PORT = max(0, int(os.getenv('NBH_PROXY_FIX_X_PORT', '1') or '1'))
INSTANCE_ALLOWED_HOSTS = {
    s.strip().lower()
    for s in str(os.getenv('NBH_ALLOWED_INSTANCE_HOSTS', '') or '').split(',')
    if s.strip()
}
ALLOW_LOOPBACK_INSTANCES = str(os.getenv('NBH_ALLOW_LOOPBACK_INSTANCES', '')).strip().lower() in {'1', 'true', 'yes', 'on'}

if not TLS_VERIFY and not TLS_CA_BUNDLE:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if SESSION_COOKIE_SAMESITE not in {'Lax', 'Strict', 'None'}:
    SESSION_COOKIE_SAMESITE = 'Lax'


def _requests_verify():
    return TLS_CA_BUNDLE if TLS_CA_BUNDLE else TLS_VERIFY


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(PROJECT_DIR, 'logs')
UPLOAD_DIR = os.path.join(PROJECT_DIR, 'uploads')
IMPORT_LOG_FILE = os.path.join(LOG_DIR, 'netbox_import.log')
FAILURES_FILE = os.path.join(LOG_DIR, 'failures.csv')


def _resolve_writable_data_dir():
    """Choose a writable directory for workbook/template data files."""
    configured = str(os.getenv('NBH_DATA_DIR', '') or '').strip()
    candidates = []
    if configured:
        candidates.append(os.path.abspath(configured))
    candidates.extend([
        os.path.join(PROJECT_DIR, 'data'),
        os.path.join(UPLOAD_DIR, 'data'),
    ])

    checked = []
    for candidate in candidates:
        checked.append(candidate)
        try:
            os.makedirs(candidate, exist_ok=True)
        except OSError:
            continue
        if os.path.isdir(candidate) and os.access(candidate, os.W_OK | os.X_OK):
            if candidate != checked[0]:
                logging.warning(
                    'Using fallback data directory %s because preferred locations were not writable.',
                    candidate,
                )
            return candidate

    raise OSError(
        'No writable data directory available. Checked: '
        + ', '.join(checked)
    )


def _is_instance_url_allowed(raw_url):
    try:
        p = urlparse(str(raw_url or '').strip())
    except Exception:
        return False, 'Invalid URL'
    if p.scheme not in ('http', 'https'):
        return False, 'URL must start with http:// or https://'
    host = str(p.hostname or '').strip().lower()
    if not host:
        return False, 'URL must include a hostname'
    if INSTANCE_ALLOWED_HOSTS and host not in INSTANCE_ALLOWED_HOSTS:
        return False, f'Hostname "{host}" is not in NBH_ALLOWED_INSTANCE_HOSTS'
    try:
        ip = ipaddress.ip_address(host)
    except Exception:
        ip = None
    if ip and (ip.is_multicast or ip.is_unspecified):
        return False, f'Unsafe instance IP "{host}" is not allowed'
    if not ALLOW_LOOPBACK_INSTANCES:
        if ip and ip.is_loopback:
            return False, f'Unsafe instance IP "{host}" is not allowed'
        if host in {'localhost', 'localhost.localdomain'}:
            return False, 'localhost is not allowed as an instance URL host'
    return True, ''

app = Flask(__name__)
if PROXY_FIX_ENABLED:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=PROXY_FIX_X_FOR,
        x_proto=PROXY_FIX_X_PROTO,
        x_host=PROXY_FIX_X_HOST,
        x_port=PROXY_FIX_X_PORT,
    )
app.secret_key = os.getenv('SECRET_KEY', 'netbox_helper_secret_key_change_me')
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = SESSION_COOKIE_SAMESITE
app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


class _AccessPathFilter(logging.Filter):
    def __init__(self, blocked_paths):
        super().__init__()
        self._blocked_paths = tuple(blocked_paths or [])

    def filter(self, record):
        try:
            msg = str(record.getMessage() or '')
        except Exception:
            return True
        return not any(path in msg for path in self._blocked_paths)


if QUIET_POLL_ACCESS_LOGS:
    try:
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.addFilter(
            _AccessPathFilter(
                (
                    'GET /sync/api/site-sync/progress',
                    'GET /sync/api/site-sync/log',
                    'GET /queue',
                    'GET /status',
                )
            )
        )
    except Exception:
        pass


def _init_glitchtip():
    if not GLITCHTIP_ENABLED:
        return
    if not GLITCHTIP_DSN:
        return
    if sentry_sdk is None or FlaskIntegration is None:
        logging.warning('GlitchTip enabled but sentry_sdk is not installed.')
        return
    try:
        init_kwargs = {
            'dsn': GLITCHTIP_DSN,
            'integrations': [FlaskIntegration()],
            'environment': GLITCHTIP_ENV,
            'send_default_pii': False,
            'traces_sample_rate': GLITCHTIP_TRACES_SAMPLE_RATE,
        }
        if GLITCHTIP_RELEASE:
            init_kwargs['release'] = GLITCHTIP_RELEASE
        sentry_sdk.init(**init_kwargs)
        sentry_sdk.set_tag('service', 'netbox-helper')
        logging.info('GlitchTip initialized (env=%s).', GLITCHTIP_ENV)
    except Exception as exc:
        logging.warning('Failed to initialize GlitchTip: %s', exc)


def _capture_exception(exc, **context):
    if not GLITCHTIP_ENABLED:
        return
    if sentry_sdk is None:
        return
    try:
        with sentry_sdk.push_scope() as scope:
            for key, value in (context or {}).items():
                if value is None:
                    continue
                text = str(value)
                if key in {'job_id', 'site_name', 'server_id', 'branch', 'section', 'route', 'filename'}:
                    scope.set_tag(key, text[:200])
                else:
                    scope.set_extra(key, text[:2000])
            sentry_sdk.capture_exception(exc)
    except Exception:
        pass


_init_glitchtip()

APP_USERNAME = os.getenv('APP_USERNAME', 'admin')
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin')  # kept for legacy; overridden by settings.json

DEFAULT_SECRET_VALUES = {
    '',
    'netbox_helper_secret_key_change_me',
    'default_secret_key_if_none',
    'template_sync_secret_key_change_me',
    'changeme_set_in_env',
    'changeme',
}
if REQUIRE_STRONG_SECRET and str(app.secret_key or '') in DEFAULT_SECRET_VALUES:
    raise RuntimeError(
        'Insecure SECRET_KEY detected. Set a strong SECRET_KEY in .env '
        'or disable strict check with NBH_REQUIRE_STRONG_SECRET=false.'
    )

# Keep instances.json in template-sync/ to preserve existing data
INSTANCES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template-sync', 'instances.json')
# User accounts with hashed passwords
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.json')
APP_ICON_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Icon.png')

# ---------------------------------------------------------------------------
# Job Queue State (CSV Import)
# ---------------------------------------------------------------------------

job_queue      = []
queue_lock     = threading.Lock()
stop_requested = False
worker_running = False
worker_thread = None
worker_state_lock = threading.Lock()
AUTO_BRANCH_SENTINEL = '__auto__'
REQUEST_BRANCH_HEADER = contextvars.ContextVar('request_branch_header', default='')
REQUEST_BRANCH_URL = contextvars.ContextVar('request_branch_url', default='')

import_status = {
    'running': False,
    'last_file': None,
    'last_server_id': None,
    'last_branch': None,
    'start_time': None,
    'stop_requested': False,
    'stopped': False,
}

login_attempts = {}
login_attempts_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Zabbix runner state
# ---------------------------------------------------------------------------

NBSYNC_SCRIPT = os.path.join(PROJECT_DIR, 'nbsync-helper.py')
NBSYNC_LOG_FILE = os.path.join(PROJECT_DIR, 'logs', 'nbsync_job.log')
NBSYNC_OPTIONS_FILE = os.path.join(PROJECT_DIR, 'template-sync', 'nbsync_options.json')
NETBOX_DATA_DIR = _resolve_writable_data_dir()
NETBOX_XLSX_FILE = os.path.join(NETBOX_DATA_DIR, 'data.xlsx')
NETBOX_IMPORT_TEMPLATE_CSV = os.path.join(NETBOX_DATA_DIR, 'Netbox-import.csv')
NETBOX_SITE_REFERENCE_CSV = os.path.join(NETBOX_DATA_DIR, 'Reference-template.csv')
NETBOX_UPLOAD_DIR = os.path.join(PROJECT_DIR, 'uploads')
NETBOX_BUNDLED_TEMPLATE_CSV = os.path.join(PROJECT_DIR, 'SLA.csv')
NETBOX_LEGACY_PROJECT_DIR = '/opt/PBI-Netbox-CSV-Import'
NBSYNC_INTERFACE_EXAMPLES_FILE = os.path.join(
    PROJECT_DIR, 'template-sync', 'nbxsync-interface-config-context-examples.json'
)
nbsync_lock = threading.Lock()
nbsync_state = {
    'running': False,
    'process': None,
    'start_time': None,
    'end_time': None,
    'instance_id': None,
    'instance_name': None,
    'cmd': [],
    'last_exit_code': None,
    'log_file': NBSYNC_LOG_FILE,
}
nbsync_pull_progress_lock = threading.Lock()
nbsync_pull_progress = {}
site_sync_jobs_lock = threading.Lock()
site_sync_jobs = {}


def _resolve_netbox_import_template_csv() -> Path:
    """Resolve the template CSV path used by Netbox-import export/preview.

    Primary location is data/Netbox-import.csv. If missing, fall back to known
    legacy/reference filenames in data/ or uploads/.
    """
    env_override = str(os.getenv('NBH_NETBOX_IMPORT_TEMPLATE_CSV', '') or '').strip()
    candidates = []
    if env_override:
        candidates.append(env_override)
    candidates.extend([
        NETBOX_IMPORT_TEMPLATE_CSV,
        NETBOX_SITE_REFERENCE_CSV,
        os.path.join(NETBOX_DATA_DIR, 'SLA.csv'),
        os.path.join(NETBOX_DATA_DIR, 'Reference-template.csv'),
        os.path.join(NETBOX_DATA_DIR, 'MDT1PAPB.csv'),
        os.path.join(NETBOX_UPLOAD_DIR, 'Netbox-import.csv'),
        os.path.join(NETBOX_UPLOAD_DIR, 'Reference-template.csv'),
        os.path.join(NETBOX_UPLOAD_DIR, 'MDT1PAPB.csv'),
        os.path.join(NETBOX_UPLOAD_DIR, 'data', 'Netbox-import.csv'),
        os.path.join(NETBOX_UPLOAD_DIR, 'data', 'Reference-template.csv'),
        os.path.join(NETBOX_UPLOAD_DIR, 'data', 'MDT1PAPB.csv'),
        NETBOX_BUNDLED_TEMPLATE_CSV,
    ])

    seen = set()
    ordered = []
    for raw in candidates:
        p = os.path.abspath(str(raw))
        if p in seen:
            continue
        seen.add(p)
        ordered.append(Path(p))

    for p in ordered:
        if p.exists() and p.is_file():
            return p

    searched = "\n".join(f"- {str(p)}" for p in ordered)
    raise ValueError(
        "Template CSV not found. Checked:\n"
        f"{searched}\n"
        "Place a template CSV at data/Netbox-import.csv "
        "or set NBH_NETBOX_IMPORT_TEMPLATE_CSV in the service environment. "
        f"Bundled fallback expected at {NETBOX_BUNDLED_TEMPLATE_CSV}."
    )


def _resolve_target_facility_code(xlsx_path: Path, b2_value: str, d7_value: str) -> str:
    reader = XlsxReader(xlsx_path)
    try:
        cfg_cells = reader.parse_sheet_cells("Netbox-Config")
        match_key = get_cell(cfg_cells, "F7").strip() or "Facility-Code"
        source_matrix = _source_sheet_matrix(reader, b2_value)
        source_headers, site_col = _source_sheet_layout(source_matrix)
        key_col = header_col_index(source_headers, match_key)
        if key_col is None:
            raise ValueError(f'Could not find header "{match_key}" in source sheet "{b2_value}".')
        row = row_from_source_by_site(source_matrix, d7_value, site_col)
        if row is None:
            raise ValueError(f'Site "{d7_value}" was not found in source sheet "{b2_value}".')
        facility = (row[key_col] if key_col < len(row) else "").strip()
        if not facility:
            raise ValueError(f'Could not resolve Netbox-Config!G7 value from source row for "{d7_value}".')
        return facility
    finally:
        reader.close()


def _template_csv_site_name(template_path: Path) -> str:
    try:
        with template_path.open(newline='', encoding='utf-8') as f:
            rows = list(csv.reader(f))
    except Exception:
        return ''
    if len(rows) < 2:
        return ''
    sample = rows[1]
    return (sample[2] if len(sample) > 2 else '').strip()


def _resolve_netbox_import_template_csv_for_target(xlsx_path: Path, b2_value: str, d7_value: str) -> Path:
    facility = ''
    try:
        facility = _resolve_target_facility_code(xlsx_path, b2_value, d7_value)
    except Exception:
        facility = ''

    candidates = []
    if facility:
        candidates.extend([
            os.path.join(NETBOX_DATA_DIR, f'{facility}.csv'),
            os.path.join(NETBOX_DATA_DIR, f'nbimp_{facility}.csv'),
            os.path.join(NETBOX_UPLOAD_DIR, f'{facility}.csv'),
            os.path.join(NETBOX_UPLOAD_DIR, f'nbimp_{facility}.csv'),
            os.path.join(NETBOX_UPLOAD_DIR, 'data', f'{facility}.csv'),
            os.path.join(NETBOX_UPLOAD_DIR, 'data', f'nbimp_{facility}.csv'),
            os.path.join(NETBOX_LEGACY_PROJECT_DIR, 'data', f'{facility}.csv'),
            os.path.join(NETBOX_LEGACY_PROJECT_DIR, 'uploads', f'{facility}.csv'),
            os.path.join(NETBOX_LEGACY_PROJECT_DIR, 'uploads', f'nbimp_{facility}.csv'),
        ])

    for raw in candidates:
        p = Path(os.path.abspath(raw))
        if p.exists() and p.is_file():
            return p

    site_target = str(d7_value or '').strip()
    search_roots = [
        NETBOX_DATA_DIR,
        NETBOX_UPLOAD_DIR,
        os.path.join(NETBOX_UPLOAD_DIR, 'data'),
        os.path.join(NETBOX_LEGACY_PROJECT_DIR, 'data'),
        os.path.join(NETBOX_LEGACY_PROJECT_DIR, 'uploads'),
    ]
    for root in search_roots:
        root_path = Path(root)
        if not root_path.exists() or not root_path.is_dir():
            continue
        for p in sorted(root_path.glob('*.csv')):
            if _template_csv_site_name(p) == site_target:
                return p
    return _resolve_netbox_import_template_csv()


def _nbsync_pull_progress_cleanup_locked(now_ts=None):
    now_ts = now_ts or time.time()
    ttl_s = 15 * 60
    expired = []
    for pid, state in nbsync_pull_progress.items():
        updated = float(state.get('updated_at') or 0)
        if updated and (now_ts - updated) > ttl_s:
            expired.append(pid)
    for pid in expired:
        nbsync_pull_progress.pop(pid, None)


def _nbsync_pull_progress_update(
    pull_id,
    owner=None,
    status=None,
    stage=None,
    message=None,
    fetched=None,
    total_estimate=None,
    scanned=None,
    matched=None,
    result_count=None,
    error=None,
):
    pid = str(pull_id or '').strip()
    if not pid:
        return
    with nbsync_pull_progress_lock:
        _nbsync_pull_progress_cleanup_locked()
        cur = nbsync_pull_progress.get(pid) or {
            'owner': str(owner or ''),
            'status': 'running',
            'stage': 'init',
            'message': 'Starting pull...',
            'fetched': 0,
            'total_estimate': 0,
            'scanned': 0,
            'matched': 0,
            'result_count': 0,
            'error': '',
            'updated_at': time.time(),
        }
        if owner is not None:
            cur['owner'] = str(owner or '')
        if status is not None:
            cur['status'] = str(status or '')
        if stage is not None:
            cur['stage'] = str(stage or '')
        if message is not None:
            cur['message'] = str(message or '')
        if fetched is not None:
            cur['fetched'] = int(max(0, int(fetched)))
        if total_estimate is not None:
            cur['total_estimate'] = int(max(0, int(total_estimate)))
        if scanned is not None:
            cur['scanned'] = int(max(0, int(scanned)))
        if matched is not None:
            cur['matched'] = int(max(0, int(matched)))
        if result_count is not None:
            cur['result_count'] = int(max(0, int(result_count)))
        if error is not None:
            cur['error'] = str(error or '')
        cur['updated_at'] = time.time()
        nbsync_pull_progress[pid] = cur


def _site_sync_jobs_cleanup_locked(now_ts=None):
    now_ts = now_ts or time.time()
    ttl_finished = 30 * 60
    ttl_running = 2 * 60 * 60
    expired = []
    for job_id, state in site_sync_jobs.items():
        updated = float(state.get('updated_at') or 0)
        status = str(state.get('status') or '')
        if not updated:
            continue
        age = now_ts - updated
        if status in {'done', 'failed'} and age > ttl_finished:
            expired.append(job_id)
        elif status in {'queued', 'running'} and age > ttl_running:
            expired.append(job_id)
    for job_id in expired:
        site_sync_jobs.pop(job_id, None)


def _site_sync_zero_stats():
    return {'created': 0, 'updated': 0, 'skipped': 0, 'errors': 0}


def _site_sync_zero_fallback():
    return {'devices': 0, 'rebuild_seconds_total': 0.0, 'rebuild_seconds_max': 0.0}


def _site_sync_norm_stats(raw):
    raw = raw or {}
    return {
        'created': int(raw.get('created', 0) or 0),
        'updated': int(raw.get('updated', 0) or 0),
        'skipped': int(raw.get('skipped', 0) or 0),
        'errors': int(raw.get('errors', 0) or 0),
    }


def _site_sync_norm_fallback(raw):
    raw = raw or {}
    total = float(raw.get('rebuild_seconds_total', 0.0) or 0.0)
    max_v = float(raw.get('rebuild_seconds_max', 0.0) or 0.0)
    return {
        'devices': int(raw.get('devices', 0) or 0),
        'rebuild_seconds_total': round(max(0.0, total), 3),
        'rebuild_seconds_max': round(max(0.0, max_v), 3),
    }


def _site_sync_job_snapshot(state):
    result = state.get('result')
    return {
        'job_id': str(state.get('job_id') or ''),
        'status': str(state.get('status') or 'queued'),
        'stage': str(state.get('stage') or ''),
        'message': str(state.get('message') or ''),
        'error': str(state.get('error') or ''),
        'site_name': str(state.get('site_name') or ''),
        'dry_run': bool(state.get('dry_run')),
        'workers': int(state.get('workers') or 1),
        'created_at': float(state.get('created_at') or 0.0),
        'started_at': float(state.get('started_at') or 0.0),
        'finished_at': float(state.get('finished_at') or 0.0),
        'updated_at': float(state.get('updated_at') or 0.0),
        'total_items': int(state.get('total_items') or 0),
        'processed_items': int(state.get('processed_items') or 0),
        'total_sections': int(state.get('total_sections') or 0),
        'completed_sections': int(state.get('completed_sections') or 0),
        'current_section': str(state.get('current_section') or ''),
        'current_item': str(state.get('current_item') or ''),
        'sections': list(state.get('sections') or []),
        'dependency_sections': list(state.get('dependency_sections') or []),
        'section_totals': {str(k): int(v or 0) for k, v in (state.get('section_totals') or {}).items()},
        'section_done': {str(k): int(v or 0) for k, v in (state.get('section_done') or {}).items()},
        'section_stats': {str(k): _site_sync_norm_stats(v) for k, v in (state.get('section_stats') or {}).items()},
        'totals': _site_sync_norm_stats(state.get('totals') or {}),
        'fallback': _site_sync_norm_fallback(state.get('fallback') or {}),
        'result': result if isinstance(result, dict) else None,
    }


def _site_sync_log_write(state, message):
    log_path = str((state or {}).get('log_file') or '').strip()
    if not log_path:
        return
    try:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        return


def _site_sync_apply_progress_locked(state, payload):
    event = str((payload or {}).get('event') or '').strip().lower()
    now_ts = time.time()
    if not event:
        state['updated_at'] = now_ts
        return

    if event == 'planned':
        state['workers'] = int((payload or {}).get('workers') or state.get('workers') or 1)
        sections = list((payload or {}).get('sections') or [])
        totals = {str(k): int(v or 0) for k, v in ((payload or {}).get('section_totals') or {}).items()}
        if not totals:
            totals = {s: 0 for s in sections}
        state['sections'] = sections
        state['dependency_sections'] = list((payload or {}).get('dependency_sections') or [])
        state['section_totals'] = totals
        state['section_done'] = {s: 0 for s in sections}
        state['section_stats'] = {s: _site_sync_zero_stats() for s in sections}
        state['total_sections'] = int((payload or {}).get('total_sections') or len(sections))
        state['total_items'] = int((payload or {}).get('total_items') or sum(totals.values()))
        state['processed_items'] = 0
        state['completed_sections'] = 0
        state['current_section'] = ''
        state['current_item'] = ''
        state['fallback'] = _site_sync_zero_fallback()
        state['stage'] = 'planned'
        state['message'] = (
            f"Prepared {state['total_items']} item(s) across {state['total_sections']} section(s)."
        )
    elif event == 'run_start':
        sections = list((payload or {}).get('sections') or state.get('sections') or [])
        totals = {str(k): int(v or 0) for k, v in ((payload or {}).get('section_totals') or {}).items()}
        if sections:
            state['sections'] = sections
        if totals:
            state['section_totals'] = totals
            state['section_done'] = {s: int((state.get('section_done') or {}).get(s, 0) or 0) for s in totals.keys()}
        state['total_sections'] = int((payload or {}).get('total_sections') or len(state.get('sections') or []))
        state['total_items'] = int((payload or {}).get('total_records') or state.get('total_items') or 0)
        state['processed_items'] = int((payload or {}).get('processed_records') or state.get('processed_items') or 0)
        state['completed_sections'] = int((payload or {}).get('completed_sections') or state.get('completed_sections') or 0)
        state['totals'] = _site_sync_norm_stats((payload or {}).get('totals') or state.get('totals') or {})
        state['stage'] = 'syncing'
        state['message'] = 'Sync started.'
    elif event == 'section_start':
        section = str((payload or {}).get('section') or '').strip()
        section_total = int((payload or {}).get('section_total') or 0)
        if section:
            state['current_section'] = section
            section_totals = dict(state.get('section_totals') or {})
            section_totals[section] = section_total
            state['section_totals'] = section_totals
            section_done = dict(state.get('section_done') or {})
            section_done.setdefault(section, 0)
            state['section_done'] = section_done
            section_stats = dict(state.get('section_stats') or {})
            section_stats.setdefault(section, _site_sync_zero_stats())
            state['section_stats'] = section_stats
            state['message'] = (
                f"Syncing {SITE_GROUP_LABELS.get(section, section)} "
                f"({section_done.get(section, 0)}/{section_total})..."
            )
        state['stage'] = 'syncing'
        state['processed_items'] = int((payload or {}).get('processed_records') or state.get('processed_items') or 0)
        state['completed_sections'] = int((payload or {}).get('completed_sections') or state.get('completed_sections') or 0)
    elif event == 'record':
        section = str((payload or {}).get('section') or '').strip()
        section_processed = int((payload or {}).get('section_processed') or 0)
        state['stage'] = 'syncing'
        state['processed_items'] = int((payload or {}).get('processed_records') or state.get('processed_items') or 0)
        state['completed_sections'] = int((payload or {}).get('completed_sections') or state.get('completed_sections') or 0)
        state['totals'] = _site_sync_norm_stats((payload or {}).get('totals') or state.get('totals') or {})
        if section:
            state['current_section'] = section
            section_done = dict(state.get('section_done') or {})
            section_done[section] = section_processed
            state['section_done'] = section_done
            section_stats = dict(state.get('section_stats') or {})
            section_stats[section] = _site_sync_norm_stats((payload or {}).get('section_stats') or section_stats.get(section) or {})
            state['section_stats'] = section_stats
        ident = str((payload or {}).get('identifier') or '').strip()
        if ident:
            state['current_item'] = ident
        action = str((payload or {}).get('action') or '').strip()
        message = str((payload or {}).get('message') or '')
        msg_lower = message.lower()
        if 'surrogate create fallback' in msg_lower:
            fb = _site_sync_norm_fallback(state.get('fallback') or {})
            fb['devices'] = int(fb.get('devices', 0) or 0) + 1
            m = re.search(r'component rebuild\\s+([0-9]+(?:\\.[0-9]+)?)s', message, flags=re.IGNORECASE)
            if m:
                sec = float(m.group(1))
                fb['rebuild_seconds_total'] = round(float(fb.get('rebuild_seconds_total', 0.0) or 0.0) + sec, 3)
                fb['rebuild_seconds_max'] = round(max(float(fb.get('rebuild_seconds_max', 0.0) or 0.0), sec), 3)
            state['fallback'] = fb
        if action and ident:
            state['message'] = f"{action.capitalize()}: {ident}"
    elif event == 'record_start':
        section = str((payload or {}).get('section') or '').strip()
        ident = str((payload or {}).get('identifier') or '').strip()
        state['stage'] = 'syncing'
        if section:
            state['current_section'] = section
        if ident:
            state['current_item'] = ident
            state['message'] = f"Processing: {ident}"
    elif event == 'record_retry':
        section = str((payload or {}).get('section') or '').strip()
        ident = str((payload or {}).get('identifier') or '').strip()
        attempt = int((payload or {}).get('attempt') or 0)
        max_retries = int((payload or {}).get('max_retries') or 0)
        wait_s = float((payload or {}).get('wait_seconds') or 0.0)
        state['stage'] = 'syncing'
        if section:
            state['current_section'] = section
        if ident:
            state['current_item'] = ident
        if ident:
            state['message'] = (
                f"Retry {attempt}/{max_retries} in {wait_s:.1f}s: {ident}"
            )
        else:
            state['message'] = f"Retry {attempt}/{max_retries} in {wait_s:.1f}s..."
    elif event == 'section_complete':
        section = str((payload or {}).get('section') or '').strip()
        section_total = int((payload or {}).get('section_total') or 0)
        section_processed = int((payload or {}).get('section_processed') or section_total)
        state['stage'] = 'syncing'
        state['processed_items'] = int((payload or {}).get('processed_records') or state.get('processed_items') or 0)
        state['completed_sections'] = int((payload or {}).get('completed_sections') or state.get('completed_sections') or 0)
        state['totals'] = _site_sync_norm_stats((payload or {}).get('totals') or state.get('totals') or {})
        if section:
            section_done = dict(state.get('section_done') or {})
            section_done[section] = section_processed
            state['section_done'] = section_done
            section_stats = dict(state.get('section_stats') or {})
            section_stats[section] = _site_sync_norm_stats((payload or {}).get('section_stats') or section_stats.get(section) or {})
            state['section_stats'] = section_stats
            state['message'] = (
                f"Completed {SITE_GROUP_LABELS.get(section, section)} "
                f"({section_processed}/{section_total})."
            )
        state['current_item'] = ''
    elif event == 'run_complete':
        state['processed_items'] = int((payload or {}).get('processed_records') or state.get('processed_items') or 0)
        state['total_items'] = int((payload or {}).get('total_records') or state.get('total_items') or 0)
        state['completed_sections'] = int((payload or {}).get('completed_sections') or state.get('completed_sections') or 0)
        state['total_sections'] = int((payload or {}).get('total_sections') or state.get('total_sections') or 0)
        state['totals'] = _site_sync_norm_stats((payload or {}).get('totals') or state.get('totals') or {})
        state['stage'] = 'finalizing'
        state['current_item'] = ''
        state['message'] = 'Finalizing results...'
    elif event == 'complete':
        result = (payload or {}).get('result')
        if isinstance(result, dict):
            state['result'] = result
    state['updated_at'] = now_ts


def _site_sync_worker_run(
    job_id,
    source_instance,
    dest_instance,
    site_name,
    selected_groups,
    selected_item_ids,
    dry_run,
    workers,
):
    root_logger = None
    job_handler = None
    with site_sync_jobs_lock:
        state = site_sync_jobs.get(job_id)
        if not state:
            return
        state['status'] = 'running'
        state['stage'] = 'preparing'
        state['message'] = 'Preparing site sync...'
        state['started_at'] = time.time()
        state['updated_at'] = state['started_at']
        _site_sync_log_write(
            state,
            (
                f"--- Site Sync Job {job_id} started: site={site_name}, "
                f"dry_run={bool(dry_run)}, workers={int(workers or 1)} ---"
            ),
        )
        _site_sync_log_write(
            state,
            (
                f"Sections selected={len(selected_groups or [])}, "
                f"item overrides={len(selected_item_ids or [])}, "
                f"workers={int(workers or 1)}"
            ),
        )

        log_path = str(state.get('log_file') or '').strip()
        if log_path:
            job_handler = logging.FileHandler(log_path, encoding='utf-8')
            job_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            root_logger = logging.getLogger()
            root_logger.addHandler(job_handler)

    def progress_cb(payload):
        with site_sync_jobs_lock:
            cur = site_sync_jobs.get(job_id)
            if not cur:
                return
            _site_sync_apply_progress_locked(cur, payload)

    try:
        result = sync_site_data(
            source_instance,
            dest_instance,
            site_name=site_name,
            selected_groups=selected_groups,
            selected_item_ids=selected_item_ids,
            dry_run=dry_run,
            workers=workers,
            progress_cb=progress_cb,
        )
        with site_sync_jobs_lock:
            cur = site_sync_jobs.get(job_id)
            if cur:
                cur['status'] = 'done'
                cur['stage'] = 'done'
                cur['message'] = 'Dry run complete.' if bool(dry_run) else 'Site sync complete.'
                cur['error'] = ''
                cur['result'] = result
                cur['finished_at'] = time.time()
                cur['updated_at'] = cur['finished_at']
                cur['totals'] = _site_sync_norm_stats((result or {}).get('totals') or cur.get('totals') or {})
                cur['section_stats'] = {
                    str(k): _site_sync_norm_stats(v)
                    for k, v in ((result or {}).get('section_stats') or {}).items()
                }
                cur['fallback'] = _site_sync_norm_fallback(cur.get('fallback') or {})
                if isinstance(cur.get('result'), dict):
                    cur['result']['fallback'] = dict(cur['fallback'])
                _site_sync_log_write(cur, '--- Site sync complete ---')
    except Exception as exc:
        logging.exception("Site sync worker failed for job %s", job_id)
        _capture_exception(
            exc,
            route='site_sync_worker',
            job_id=job_id,
            site_name=site_name,
            branch=str((dest_instance or {}).get('branch') or ''),
            workers=workers,
            dry_run=dry_run,
        )
        with site_sync_jobs_lock:
            cur = site_sync_jobs.get(job_id)
            if cur:
                cur['status'] = 'failed'
                cur['stage'] = 'failed'
                cur['error'] = str(exc)
                cur['message'] = f"Site sync failed: {exc}"
                cur['finished_at'] = time.time()
                cur['updated_at'] = cur['finished_at']
                _site_sync_log_write(cur, f"--- Site sync failed: {exc} ---")
                _site_sync_log_write(cur, traceback.format_exc())
    finally:
        if root_logger and job_handler:
            try:
                root_logger.removeHandler(job_handler)
            except Exception:
                pass
            try:
                job_handler.close()
            except Exception:
                pass

DEFAULT_NBSYNC_OPTIONS = {
    'defaults': {
        'config_group_id': 2,
        'only_primary_ipv4': True,
    },
    # True => apply tag/hostgroup/macro assignments on Zabbix Configuration Group
    # and let Zabbix propagate to member devices.
    'use_configuration_group_inheritance': True,
    # Baseline behavior from current hardcoded flow.
    'include_device_tags_as_tags': False,
    'include_device_tags_as_hostgroups': False,
    # None => all source tags are selected (legacy behavior).
    'selected_source_tags': None,
    # Optional explicit Zabbix server selection. None => derive from config group.
    'selected_zabbix_server_id': None,
    # GUI-editable persistent lists.
    'static_hostgroups': [
        '{{ device.device_type.model }}',
        '{{ site.facility }}',
        '{{ site.region.name }}',
        '{{ device.role.name }}',
        '{{ site.name }}',
        '{{ device.tenant.name }}',
    ],
    # Host inventory options (plugins/nbxsync/zabbixhostinventory).
    'use_host_inventory': True,
    'host_inventory_mode': 0,  # Manual
    'host_inventory_fields': [
        {'field': 'location_lat', 'template': '{{ object.site.latitude }}', 'enabled': True},
        {'field': 'location_lon', 'template': '{{ object.site.longitude }}', 'enabled': True},
        {'field': 'name', 'template': '{{ object.name }}', 'enabled': True},
        {'field': 'alias', 'template': '{{ object.name }}', 'enabled': True},
        {'field': 'asset_tag', 'template': '{{ object.asset_tag }}', 'enabled': True},
        {'field': 'serialno_a', 'template': '{{ object.serial }}', 'enabled': True},
        {'field': 'vendor', 'template': '{{ object.device_type.manufacturer.name }}', 'enabled': True},
        {'field': 'model_field', 'template': '{{ object.device_type.model }}', 'enabled': True},
        {'field': 'type', 'template': '{{ object.device_type.model }}', 'enabled': True},
        {'field': 'site_address_a', 'template': '{{ object.site.name }}', 'enabled': True},
        {'field': 'site_notes', 'template': '{{ object.site.description }}', 'enabled': False},
    ],
    # Host interface options (plugins/nbxsync/zabbixhostinterface).
    'use_host_interface': True,
    # Config-context key that contains interface config.
    'host_interface_context_key': 'interface',
    # Macro used for SNMPv3 security name when a plain value is provided.
    'host_interface_security_name_macro': '{$SNMP_SECURITYNAME}',
    'macros': [],  # [{"macro":"{$NAME}", "value":"template", "description":"..."}]
}

# ---------------------------------------------------------------------------
# Template type definitions (Template Sync)
# ---------------------------------------------------------------------------

TEMPLATE_TYPES = {
    'tags': {
        'label': 'Tags',
        'endpoint': 'extras/tags',
        'match_key': 'slug',
        'compare_fields': ['name', 'slug', 'color', 'description'],
        'sync_fields':    ['name', 'slug', 'color', 'description'],
    },
    'config-templates': {
        'label': 'Config Templates',
        'endpoint': 'extras/config-templates',
        'compare_fields': ['template_code', 'description', 'environment_params'],
        'sync_fields': ['name', 'description', 'template_code', 'environment_params'],
    },
    'export-templates': {
        'label': 'Export Templates',
        'endpoint': 'extras/export-templates',
        'compare_fields': [
            'content_types', 'template_code', 'description',
            'file_extension', 'as_attachment', 'mime_type',
        ],
        'sync_fields': [
            'name', 'content_types', 'template_code', 'description',
            'file_extension', 'as_attachment', 'mime_type',
        ],
    },
    'config-contexts': {
        'label': 'Config Contexts',
        'endpoint': 'extras/config-contexts',
        'compare_fields': ['weight', 'description', 'is_active', 'data'],
        'sync_fields': ['name', 'weight', 'description', 'is_active', 'data'],
    },
    'manufacturers': {
        'label': 'Manufacturers',
        'endpoint': 'dcim/manufacturers',
        'match_key': 'slug',
        'compare_fields': ['name', 'slug', 'description', 'comments'],
        'sync_fields':    ['name', 'slug', 'description', 'comments'],
    },
    'module-type-profiles': {
        'label': 'Module Type Profiles',
        'endpoint': 'dcim/module-type-profiles',
        'compare_fields': ['name', 'description', 'schema', 'comments'],
        'sync_fields':    ['name', 'description', 'schema', 'comments'],
    },
    'device-types': {
        'label': 'Device Types',
        'endpoint': 'dcim/device-types',
        'match_key': 'slug',
        'handler': 'device-types',
    },
    'module-types': {
        'label': 'Module Types',
        'endpoint': 'dcim/module-types',
        'match_key': 'model',
        'handler': 'module-types',
    },
}

COMPONENT_TYPES = [
    {
        'endpoint': 'dcim/rear-port-templates',
        'label': 'Rear Ports',
        'compare_fields': ['name', 'label', 'type', 'color', 'positions', 'description'],
        'payload_fields': ['name', 'label', 'type', 'color', 'positions', 'description'],
    },
    {
        'endpoint': 'dcim/front-port-templates',
        'label': 'Front Ports',
        'compare_fields': ['name', 'label', 'type', 'color', 'rear_port_name', 'rear_port_position', 'description'],
        'payload_fields': ['name', 'label', 'type', 'color', 'rear_port_position', 'description'],
        'resolve_rear_port': True,
    },
    {
        'endpoint': 'dcim/console-port-templates',
        'label': 'Console Ports',
        'compare_fields': ['name', 'label', 'type', 'description'],
        'payload_fields': ['name', 'label', 'type', 'description'],
    },
    {
        'endpoint': 'dcim/console-server-port-templates',
        'label': 'Console Server Ports',
        'compare_fields': ['name', 'label', 'type', 'description'],
        'payload_fields': ['name', 'label', 'type', 'description'],
    },
    {
        'endpoint': 'dcim/power-port-templates',
        'label': 'Power Ports',
        'compare_fields': ['name', 'label', 'type', 'maximum_draw', 'allocated_draw', 'description'],
        'payload_fields': ['name', 'label', 'type', 'maximum_draw', 'allocated_draw', 'description'],
    },
    {
        'endpoint': 'dcim/power-outlet-templates',
        'label': 'Power Outlets',
        'compare_fields': ['name', 'label', 'type', 'feed_leg', 'power_port_name', 'description'],
        'payload_fields': ['name', 'label', 'type', 'feed_leg', 'description'],
        'resolve_power_port': True,
    },
    {
        'endpoint': 'dcim/interface-templates',
        'label': 'Interfaces',
        'compare_fields': ['name', 'label', 'type', 'enabled', 'mgmt_only', 'description'],
        'payload_fields': ['name', 'label', 'type', 'enabled', 'mgmt_only', 'description'],
    },
    {
        'endpoint': 'dcim/device-bay-templates',
        'label': 'Device Bays',
        'compare_fields': ['name', 'label', 'description'],
        'payload_fields': ['name', 'label', 'description'],
    },
    {
        'endpoint': 'dcim/module-bay-templates',
        'label': 'Module Bays',
        'compare_fields': ['name', 'label', 'position', 'description'],
        'payload_fields': ['name', 'label', 'position', 'description'],
    },
    {
        'endpoint': 'dcim/inventory-item-templates',
        'label': 'Inventory Items',
        'compare_fields': ['name', 'label', 'description'],
        'payload_fields': ['name', 'label', 'description'],
    },
]

# ---------------------------------------------------------------------------
# Token encryption (Template Sync)
# ---------------------------------------------------------------------------

def _make_key():
    secret = os.getenv('SECRET_KEY', 'changeme_set_in_env')
    return hashlib.sha256(secret.encode('utf-8')).digest()


def encrypt_token(token):
    if not token:
        return token
    key   = _make_key()
    nonce = _secrets.token_bytes(16)
    tb    = token.encode('utf-8')
    blocks = (len(tb) + 31) // 32
    ks = b''.join(
        hmac.new(key, nonce + i.to_bytes(4, 'big'), hashlib.sha256).digest()
        for i in range(blocks)
    )
    ct = bytes(a ^ b for a, b in zip(tb, ks))
    return 'enc:' + base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_token(stored):
    if not isinstance(stored, str) or not stored.startswith('enc:'):
        return stored
    try:
        key  = _make_key()
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

# ---------------------------------------------------------------------------
# Instance persistence (Template Sync)
# ---------------------------------------------------------------------------

_instance_ssl_cache = {'mtime': None, 'by_url': {}}
_instance_ssl_cache_lock = threading.Lock()


def _to_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v or '').strip().lower()
    return s in {'1', 'true', 'yes', 'on'}


def _instance_url_key(raw_url):
    try:
        p = urlparse(str(raw_url or '').strip())
    except Exception:
        return str(raw_url or '').strip().rstrip('/').lower()
    if p.scheme and p.netloc:
        path = str(p.path or '')
        low = path.lower()
        if '/api/' in low:
            path = path[:low.find('/api/')]
        elif low.endswith('/api'):
            path = path[:-4]
        path = path.rstrip('/')
        return f'{p.scheme.lower()}://{p.netloc.lower()}{path}'
    return str(raw_url or '').strip().rstrip('/').lower()


def _invalidate_instance_ssl_cache():
    with _instance_ssl_cache_lock:
        _instance_ssl_cache['mtime'] = None
        _instance_ssl_cache['by_url'] = {}


def _reload_instance_ssl_cache_if_needed():
    try:
        mtime = os.path.getmtime(INSTANCES_FILE)
    except Exception:
        mtime = None
    with _instance_ssl_cache_lock:
        if _instance_ssl_cache['mtime'] == mtime:
            return
        by_url = {}
        if os.path.exists(INSTANCES_FILE):
            try:
                with open(INSTANCES_FILE, 'r', encoding='utf-8') as f:
                    rows = json.load(f).get('instances', [])
                for row in rows:
                    k = _instance_url_key(row.get('url'))
                    if k:
                        by_url[k] = _to_bool(row.get('skip_ssl_verify', False))
            except Exception:
                by_url = {}
        _instance_ssl_cache['mtime'] = mtime
        _instance_ssl_cache['by_url'] = by_url


def _requests_verify_for_url(url):
    _reload_instance_ssl_cache_if_needed()
    k = _instance_url_key(url)
    if k:
        with _instance_ssl_cache_lock:
            if _instance_ssl_cache['by_url'].get(k, False):
                return False
    return _requests_verify()


def load_instances():
    if os.path.exists(INSTANCES_FILE):
        with open(INSTANCES_FILE, 'r') as f:
            instances = json.load(f).get('instances', [])
        for inst in instances:
            if 'token' in inst:
                inst['token'] = decrypt_token(inst['token'])
            inst['skip_ssl_verify'] = _to_bool(inst.get('skip_ssl_verify', False))
        return instances
    return []


def resolve_instance_by_id(inst_id):
    if not inst_id:
        raise ValueError('server_id is required')

    inst = next((i for i in load_instances() if i.get('id') == inst_id), None)
    if not inst:
        raise ValueError(f'Instance "{inst_id}" not found')

    url = (inst.get('url') or '').strip().rstrip('/')
    token = (inst.get('token') or '').strip()
    if not url or not token:
        raise ValueError(f'Instance "{inst.get("name", inst_id)}" is missing URL or token')
    allowed, reason = _is_instance_url_allowed(url)
    if not allowed:
        raise ValueError(f'Instance "{inst.get("name", inst_id)}" URL rejected: {reason}')

    inst['url'] = url
    inst['token'] = token
    inst['skip_ssl_verify'] = _to_bool(inst.get('skip_ssl_verify', False))
    return inst


def save_instances(instances):
    to_save = []
    for inst in instances:
        s = dict(inst)
        if 'token' in s and s['token'] and not s['token'].startswith('enc:'):
            s['token'] = encrypt_token(s['token'])
        s['skip_ssl_verify'] = _to_bool(s.get('skip_ssl_verify', False))
        to_save.append(s)
    with open(INSTANCES_FILE, 'w') as f:
        json.dump({'instances': to_save}, f, indent=2)
    _invalidate_instance_ssl_cache()


def _migrate_tokens():
    if not os.path.exists(INSTANCES_FILE):
        return
    try:
        with open(INSTANCES_FILE, 'r') as f:
            raw = json.load(f).get('instances', [])
        if any(not (i.get('token', '') or '').startswith('enc:') for i in raw):
            save_instances(load_instances())
    except Exception:
        pass


def _nbsync_python_bin():
    venv_py = os.path.join(PROJECT_DIR, '.venv', 'bin', 'python')
    if os.path.exists(venv_py):
        return venv_py
    return 'python3'


def _unique_str_list(values):
    seen, out = set(), []
    for v in values or []:
        s = str(v).strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _sanitize_nbsync_hostgroup_name(value):
    raw = str(value or '').strip()
    if not raw:
        return ''
    # Align with Zabbix/Zabbix-safe pattern used for host identifiers.
    sanitized = re.sub(r'[^0-9a-zA-Z_. \-]', '_', raw)
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    sanitized = re.sub(r'_+', '_', sanitized)
    if len(sanitized) > 512:
        sanitized = sanitized[:512].rstrip()
    return sanitized


def _normalize_macro_name(value):
    s = str(value or '').strip()
    if not s:
        return ''
    inner = s
    if inner.startswith('{'):
        inner = inner[1:]
    if inner.endswith('}'):
        inner = inner[:-1]
    inner = inner.strip()
    if inner.startswith('$'):
        inner = inner[1:]
    inner = inner.strip().upper()
    if not inner:
        return ''
    return '{$' + inner + '}'


def _normalize_macro_list(values):
    out = []
    for row in values or []:
        if not isinstance(row, dict):
            continue
        macro = _normalize_macro_name(row.get('macro', ''))
        value = str(row.get('value', '')).strip()
        description = str(row.get('description', row.get('discription', ''))).strip()
        is_regex = _parse_boolish(row.get('is_regex', False), default=False)
        enabled = _parse_boolish(row.get('enabled', True), default=True)
        if not macro:
            continue
        out.append({
            'macro': macro,
            'value': value,
            'description': description,
            'is_regex': bool(is_regex),
            'enabled': bool(enabled),
        })
    return out


def _normalize_inventory_mode(value):
    try:
        mode = int(value)
    except Exception:
        return 0
    if mode < -1:
        return -1
    if mode > 1:
        return 1
    return mode


def _normalize_inventory_field_list(values):
    out = []
    if not isinstance(values, list):
        return out
    for row in values:
        if not isinstance(row, dict):
            continue
        field = str(row.get('field', '')).strip()
        template = str(row.get('template', '')).strip()
        if not field:
            continue
        out.append({
            'field': field,
            'template': template,
            'enabled': bool(row.get('enabled', True)),
        })
    return out


def _normalize_positive_int(value):
    try:
        n = int(value)
        if n > 0:
            return n
    except Exception:
        pass
    return None


def normalize_nbsync_options(raw):
    opts = json.loads(json.dumps(DEFAULT_NBSYNC_OPTIONS))
    if isinstance(raw, dict):
        d = raw.get('defaults', {})
        if isinstance(d, dict):
            try:
                cg = int(d.get('config_group_id', opts['defaults']['config_group_id']))
                if cg > 0:
                    opts['defaults']['config_group_id'] = cg
            except Exception:
                pass
            opts['defaults']['only_primary_ipv4'] = bool(d.get('only_primary_ipv4', True))

        opts['use_configuration_group_inheritance'] = bool(
            raw.get('use_configuration_group_inheritance', True)
        )
        opts['include_device_tags_as_tags'] = bool(
            raw.get('include_device_tags_as_tags', opts['include_device_tags_as_tags'])
        )
        opts['include_device_tags_as_hostgroups'] = bool(
            raw.get('include_device_tags_as_hostgroups', opts['include_device_tags_as_hostgroups'])
        )
        opts['use_host_inventory'] = bool(raw.get('use_host_inventory', True))
        opts['host_inventory_mode'] = _normalize_inventory_mode(raw.get('host_inventory_mode', 0))
        opts['use_host_interface'] = bool(raw.get('use_host_interface', True))
        ctx_key = str(raw.get('host_interface_context_key', opts.get('host_interface_context_key', 'interface')) or '').strip()
        opts['host_interface_context_key'] = ctx_key or 'interface'
        sec_macro = str(raw.get('host_interface_security_name_macro', opts.get('host_interface_security_name_macro', '{$SNMP_SECURITYNAME}')) or '').strip()
        if sec_macro.startswith('{$') and sec_macro.endswith('}'):
            opts['host_interface_security_name_macro'] = sec_macro
        else:
            opts['host_interface_security_name_macro'] = '{$SNMP_SECURITYNAME}'
        if 'selected_source_tags' in raw:
            if isinstance(raw.get('selected_source_tags'), list):
                opts['selected_source_tags'] = _unique_str_list(raw.get('selected_source_tags', []))
            elif raw.get('selected_source_tags') is None:
                opts['selected_source_tags'] = None
        if 'selected_zabbix_server_id' in raw:
            opts['selected_zabbix_server_id'] = _normalize_positive_int(
                raw.get('selected_zabbix_server_id')
            )
        if 'static_hostgroups' in raw:
            opts['static_hostgroups'] = _unique_str_list(raw.get('static_hostgroups', []))
        if 'host_inventory_fields' in raw:
            opts['host_inventory_fields'] = _normalize_inventory_field_list(
                raw.get('host_inventory_fields')
            )
        # Macro sync is disabled; keep the options key for backwards compatibility.
        opts['macros'] = []
    return opts


def load_nbsync_options():
    if not os.path.exists(NBSYNC_OPTIONS_FILE):
        return normalize_nbsync_options({})
    try:
        with open(NBSYNC_OPTIONS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return normalize_nbsync_options(data)
    except Exception:
        return normalize_nbsync_options({})


def save_nbsync_options(options):
    normalized = normalize_nbsync_options(options)
    with open(NBSYNC_OPTIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(normalized, f, indent=2)
    return normalized

# ---------------------------------------------------------------------------
# User / Settings management
# ---------------------------------------------------------------------------

def load_users():
    """Load users from settings.json and normalize required fields."""
    users = []
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            users = json.load(f).get('users', [])

    changed = False
    out = []
    for u in users:
        if not isinstance(u, dict):
            continue
        row = dict(u)
        role = str(row.get('role') or '').strip().lower()
        if role not in ('admin', 'operator'):
            row['role'] = 'admin'
            changed = True
        mcp = _to_bool(row.get('must_change_password', False))
        if row.get('must_change_password') != mcp:
            changed = True
        row['must_change_password'] = mcp
        out.append(row)
    if changed:
        save_users(out)
    return out


def save_users(users):
    """Persist users list into settings.json, preserving other keys."""
    data = {}
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            try:
                data = json.load(f)
            except Exception:
                data = {}
    data['users'] = users
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def load_ssl_config():
    """Load SSL configuration from settings.json or environment variables.
    
    Environment variables take priority over settings.json:
    - NBH_SSL_ENABLED: Enable HTTPS (true/false)
    - NBH_SSL_CERTFILE: Path to SSL certificate file
    - NBH_SSL_KEYFILE: Path to SSL key file
    """
    ssl_config = {
        'enabled': False,
        'certfile': '',
        'keyfile': ''
    }
    
    # Load from settings.json if it exists
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                data = json.load(f)
                settings_ssl = data.get('ssl', {})
                if isinstance(settings_ssl, dict):
                    ssl_config['enabled'] = _to_bool(settings_ssl.get('enabled', False))
                    ssl_config['certfile'] = str(settings_ssl.get('certfile', '') or '').strip()
                    ssl_config['keyfile'] = str(settings_ssl.get('keyfile', '') or '').strip()
        except Exception as e:
            app.logger.warning('Error loading SSL config from settings.json: %s', e)
    
    # Environment variables override settings.json
    env_enabled = str(os.getenv('NBH_SSL_ENABLED', '') or '').strip()
    if env_enabled.lower() in ('1', 'true', 'yes', 'on'):
        ssl_config['enabled'] = True
    elif env_enabled.lower() in ('0', 'false', 'no', 'off'):
        ssl_config['enabled'] = False
    
    env_certfile = str(os.getenv('NBH_SSL_CERTFILE', '') or '').strip()
    if env_certfile:
        ssl_config['certfile'] = env_certfile
    
    env_keyfile = str(os.getenv('NBH_SSL_KEYFILE', '') or '').strip()
    if env_keyfile:
        ssl_config['keyfile'] = env_keyfile
    
    return ssl_config


def verify_ssl_config(ssl_config):
    """Verify that SSL certificate files exist and are readable.
    
    Returns: (valid: bool, error_message: str)
    """
    if not ssl_config.get('enabled'):
        return True, ''
    
    certfile = ssl_config.get('certfile', '').strip()
    keyfile = ssl_config.get('keyfile', '').strip()
    
    if not certfile or not keyfile:
        return False, 'SSL enabled but certfile or keyfile is not configured'
    
    if not os.path.exists(certfile):
        return False, f'SSL certificate file not found: {certfile}'
    
    if not os.path.isfile(certfile):
        return False, f'SSL certificate path is not a file: {certfile}'
    
    if not os.path.exists(keyfile):
        return False, f'SSL key file not found: {keyfile}'
    
    if not os.path.isfile(keyfile):
        return False, f'SSL key path is not a file: {keyfile}'
    
    # Verify files are readable
    try:
        with open(certfile, 'r') as f:
            f.read(1)
    except Exception as e:
        return False, f'Cannot read SSL certificate file: {e}'
    
    try:
        with open(keyfile, 'r') as f:
            f.read(1)
    except Exception as e:
        return False, f'Cannot read SSL key file: {e}'
    
    return True, ''


def save_ssl_config(ssl_config):
    """Persist SSL configuration into settings.json, preserving other keys."""
    data = {}
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            try:
                data = json.load(f)
            except Exception:
                data = {}
    data['ssl'] = ssl_config
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def _init_default_user():
    """Create initial admin from env vars when settings.json has no users yet."""
    if not load_users():
        username = str(os.getenv('APP_USERNAME', 'admin') or 'admin').strip() or 'admin'
        password = str(os.getenv('APP_PASSWORD', 'admin') or 'admin')
        pw_error = _validate_password_strength(password)
        if pw_error:
            app.logger.warning(
                'APP_PASSWORD for first-run bootstrap user "%s" is weak: %s',
                username,
                pw_error,
            )
        save_users([{
            'id': uuid.uuid4().hex[:8],
            'username': username,
            'password_hash': generate_password_hash(password),
            'role': 'admin',
            'must_change_password': True,
            'created': datetime.utcnow().isoformat(),
        }])


def _mark_bootstrap_admin_for_password_change():
    users = load_users()
    if not users:
        return
    username = str(APP_USERNAME or 'admin').strip() or 'admin'
    password = str(APP_PASSWORD or 'admin')
    changed = False
    for user in users:
        if str(user.get('username') or '') != username:
            continue
        if not _is_admin_user(user):
            continue
        try:
            matches_env_pw = check_password_hash(str(user.get('password_hash') or ''), password)
        except Exception:
            matches_env_pw = False
        if matches_env_pw and not _to_bool(user.get('must_change_password', False)):
            user['must_change_password'] = True
            changed = True
    if changed:
        save_users(users)


def _get_user_by_id(user_id):
    if not user_id:
        return None
    users = load_users()
    return next((u for u in users if u.get('id') == user_id), None)


def _get_current_user():
    return _get_user_by_id(session.get('user_id'))


def _is_admin_user(user):
    return isinstance(user, dict) and str(user.get('role') or '').lower() == 'admin'


def _login_client_ip():
    fwd = str(request.headers.get('X-Forwarded-For') or '').strip()
    if fwd:
        return fwd.split(',')[0].strip() or 'unknown'
    return str(request.remote_addr or 'unknown')


def _login_rate_limit_key(username):
    return f"{_login_client_ip()}::{str(username or '').strip().lower()}"


def _cleanup_login_attempts(now_ts):
    stale = []
    for key, state in login_attempts.items():
        last_failed = float(state.get('last_failed', 0.0))
        locked_until = float(state.get('locked_until', 0.0))
        if max(last_failed, locked_until) + LOGIN_LOCKOUT_SECONDS + LOGIN_WINDOW_SECONDS < now_ts:
            stale.append(key)
    for key in stale:
        login_attempts.pop(key, None)


def _is_login_locked(username):
    now_ts = time.time()
    key = _login_rate_limit_key(username)
    with login_attempts_lock:
        _cleanup_login_attempts(now_ts)
        state = login_attempts.get(key) or {}
        locked_until = float(state.get('locked_until', 0.0))
        if locked_until > now_ts:
            return True, int(locked_until - now_ts)
    return False, 0


def _register_login_failure(username):
    now_ts = time.time()
    key = _login_rate_limit_key(username)
    with login_attempts_lock:
        _cleanup_login_attempts(now_ts)
        state = login_attempts.get(key) or {'failures': [], 'locked_until': 0.0, 'last_failed': 0.0}
        failures = [
            float(ts) for ts in (state.get('failures') or [])
            if now_ts - float(ts) <= LOGIN_WINDOW_SECONDS
        ]
        failures.append(now_ts)
        state['failures'] = failures
        state['last_failed'] = now_ts
        if len(failures) >= LOGIN_MAX_ATTEMPTS:
            state['locked_until'] = now_ts + LOGIN_LOCKOUT_SECONDS
        login_attempts[key] = state


def _clear_login_failures(username):
    key = _login_rate_limit_key(username)
    with login_attempts_lock:
        login_attempts.pop(key, None)


def _is_allowed_upload_path(file_path):
    if not file_path:
        return False
    try:
        upload_root = os.path.realpath(app.config['UPLOAD_FOLDER'])
        candidate = os.path.realpath(str(file_path))
    except Exception:
        return False
    return os.path.commonpath([upload_root, candidate]) == upload_root


def _clean_branch_name(raw_value):
    text = str(raw_value or '').replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').strip()
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:120] if text else ''


def _normalize_requested_branch(raw_value):
    text = _clean_branch_name(raw_value)
    if not text:
        return ''
    if text.lower() in {'auto', AUTO_BRANCH_SENTINEL}:
        return AUTO_BRANCH_SENTINEL
    return text


def _extract_requested_branch(data, key='branch'):
    payload = data if isinstance(data, dict) else {}
    if key not in payload:
        return AUTO_BRANCH_SENTINEL
    return _normalize_requested_branch(payload.get(key))


def _derive_auto_branch_from_parsed_rows(parsed_data):
    data = parsed_data if isinstance(parsed_data, dict) else {}

    def _pick_from_row(row):
        if not isinstance(row, dict):
            return ''
        normalized = {str(k or '').strip().lower(): _clean_branch_name(v) for k, v in row.items()}
        for field in ('facility', 'site_facility', 'facility_id'):
            val = normalized.get(field, '')
            if val:
                return val
        for field in ('site', 'name', 'slug'):
            val = normalized.get(field, '')
            if val:
                return val
        return ''

    for row in (data.get('sites') or []):
        branch = _pick_from_row(row)
        if branch:
            return branch

    for section in NetboxImporter.IMPORT_ORDER:
        if section == 'sites':
            continue
        for row in (data.get(section) or []):
            branch = _pick_from_row(row)
            if branch:
                return branch
    return ''


def _derive_auto_branch_name(file_path='', filename=''):
    path = str(file_path or '').strip()
    if path and os.path.exists(path):
        try:
            importer = NetboxImporter(path, connect=False)
            parsed = importer.parse_csv()
            branch = _derive_auto_branch_from_parsed_rows(parsed)
            if branch:
                return _clean_branch_name(branch)
        except Exception:
            pass

    fallback = str(filename or '').strip() or os.path.basename(path or '')
    stem = Path(fallback).stem
    for prefix in ('nbsrc_', 'nbimp_'):
        if stem.lower().startswith(prefix):
            stem = stem[len(prefix):]
            break
    stem = _clean_branch_name(stem.strip('._- '))
    return stem


def _resolve_job_branch_name(requested_branch, file_path='', filename=''):
    req = _normalize_requested_branch(requested_branch)
    if req != AUTO_BRANCH_SENTINEL:
        return req, False
    auto_branch = _derive_auto_branch_name(file_path=file_path, filename=filename)
    if not auto_branch:
        return '', True
    return auto_branch, True


def _derive_auto_branch_from_sync_items(items):
    rows = items if isinstance(items, list) else []
    if not rows:
        return ''
    seen = set()
    ordered_types = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ttype = _clean_branch_name(row.get('template_type', '')).lower()
        if not ttype:
            continue
        if ttype in seen:
            continue
        seen.add(ttype)
        ordered_types.append(ttype)
    if not ordered_types:
        return 'Tempalte-Sync'
    type_part = '-'.join(ordered_types[:4])
    candidate = f"Tempalte-Sync-{type_part}"
    candidate = candidate.replace('/', '-').replace('\\', '-').replace(':', '-')
    candidate = re.sub(r'[^A-Za-z0-9._ -]+', '-', candidate)
    candidate = _clean_branch_name(candidate.strip('._- '))
    return candidate or 'Tempalte-Sync'


def _friendly_legacy_sync_error(template_type, error_text, branch_name):
    text = str(error_text or '')
    low = text.lower()
    if (
        str(template_type or '').strip() == 'config-contexts'
        and 'schema_name' in low
        and 'httpresponsebadrequest' in low
    ):
        return (
            f'Config Context sync to branch "{branch_name}" is blocked by destination NetBox '
            f'branching bug (schema_name AttributeError on branch header). '
            f'Main-write fallback is disabled by policy.'
        )
    return text


def _probe_branch_endpoint(url, token, branch_header_value, endpoint='extras/config-contexts'):
    base = str(url or '').strip().rstrip('/')
    ep = str(endpoint or '').strip().strip('/')
    if not base or not ep:
        return False, 'invalid probe target'
    try:
        resp = requests.get(
            f"{base}/api/{ep}/?limit=1",
            headers={
                **nb_headers(token, base, allow_branch=False),
                'X-NetBox-Branch': str(branch_header_value or '').strip(),
            },
            verify=_requests_verify_for_url(base),
            timeout=20,
        )
    except Exception as exc:
        return False, str(exc)
    if resp.ok:
        return True, ''
    return False, str(resp.text or '')[:400]


def _validate_password_strength(password):
    pw = str(password or '')
    if len(pw) < PASSWORD_MIN_LENGTH:
        return f'Password must be at least {PASSWORD_MIN_LENGTH} characters'
    if not re.search(r'[a-z]', pw):
        return 'Password must include at least one lowercase letter'
    if not re.search(r'[A-Z]', pw):
        return 'Password must include at least one uppercase letter'
    if not re.search(r'[0-9]', pw):
        return 'Password must include at least one number'
    return None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _is_api_route(path):
    """Check if a route should return JSON responses instead of HTML redirects."""
    # Any path with /api/ in it
    if '/api/' in path:
        return True
    # CSV Import routes
    api_routes = [
        '/upload', '/get-sections', '/queue', '/status',
        '/stop-import', '/retry-failures', '/clear-failures',
    ]
    return any(path == route or path.startswith(route + '/') for route in api_routes)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if _is_api_route(request.path):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        user = _get_current_user()
        if not _is_admin_user(user):
            if _is_api_route(request.path):
                return jsonify({'error': 'Admin access required'}), 403
            abort(403)
        return f(*args, **kwargs)
    return decorated


def _same_origin(candidate):
    if not candidate:
        return False
    try:
        c = urlparse(str(candidate).strip())
        b = urlparse(str(request.host_url or '').strip())
    except Exception:
        return False
    return (c.scheme, c.netloc) == (b.scheme, b.netloc)


@app.before_request
def _enforce_session_and_csrf():
    user = _get_current_user() if session.get('logged_in') else None
    if session.get('logged_in') and not user:
        session.clear()
        return redirect(url_for('login'))

    if user and _to_bool(user.get('must_change_password', False)):
        session['force_password_change'] = True
        allowed_endpoints = {
            'first_password_change',
            'logout',
            'app_icon',
            'favicon',
            'static',
        }
        if request.endpoint not in allowed_endpoints:
            return redirect(url_for('first_password_change'))
    else:
        session.pop('force_password_change', None)

    if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        return None
    if not session.get('logged_in'):
        return None
    if request.endpoint in {'login', 'first_password_change'}:
        return None
    if not CSRF_ENFORCE_ORIGIN:
        return None

    origin = str(request.headers.get('Origin') or '').strip()
    referer = str(request.headers.get('Referer') or '').strip()
    if origin:
        if not _same_origin(origin):
            return jsonify({'error': 'CSRF origin check failed'}), 403
        return None
    if referer:
        if not _same_origin(referer):
            return jsonify({'error': 'CSRF referer check failed'}), 403
        return None
    if not CSRF_ALLOW_EMPTY_ORIGIN:
        return jsonify({'error': 'CSRF origin header required'}), 403
    return None


@app.after_request
def _add_security_headers(resp):
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    resp.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    return resp

# ---------------------------------------------------------------------------
# Netbox API helpers (Template Sync)
# ---------------------------------------------------------------------------

def nb_headers(token, url='', allow_branch=True):
    headers = {'Authorization': f'Token {token}', 'Accept': 'application/json'}
    branch = str(REQUEST_BRANCH_HEADER.get('') or '').strip()
    target_base = str(url or '').strip().rstrip('/')
    branch_base = str(REQUEST_BRANCH_URL.get('') or '').strip().rstrip('/')
    if allow_branch and branch and (not branch_base or (target_base and target_base == branch_base)):
        headers['X-NetBox-Branch'] = branch
    return headers


def _looks_like_branch_schema_name_error(status_code, body_text):
    if int(status_code or 0) < 500:
        return False
    text = str(body_text or '').lower()
    if 'schema_name' not in text:
        return False
    return ('attributerror' in text) or ('httpresponsebadrequest' in text) or ('branch' in text)


def fetch_all(url, token, endpoint, params=None, progress_cb=None):
    base = url.rstrip('/')
    qp = dict(params or {})
    if 'limit' not in qp:
        qp['limit'] = 1000
    qs = '&'.join(f'{k}={v}' for k, v in qp.items())
    api_url = f"{base}/api/{endpoint}/?{qs}" if qs else f"{base}/api/{endpoint}/"
    results = []
    while api_url:
        attempts = 0
        while True:
            attempts += 1
            try:
                resp = requests.get(api_url, headers=nb_headers(token, url), verify=_requests_verify_for_url(url), timeout=30)
            except requests.exceptions.ConnectionError as e:
                if attempts < 3:
                    time.sleep(0.4 * attempts)
                    continue
                raise ValueError(f"Cannot connect to {base} — {e}")
            except requests.exceptions.Timeout:
                if attempts < 3:
                    time.sleep(0.5 * attempts)
                    continue
                raise ValueError(f"Connection timed out for {base}")
            if _looks_like_branch_schema_name_error(resp.status_code, resp.text):
                try:
                    resp_unbranched = requests.get(
                        api_url,
                        headers=nb_headers(token, url, allow_branch=False),
                        verify=_requests_verify_for_url(url),
                        timeout=30,
                    )
                    if resp_unbranched.ok:
                        resp = resp_unbranched
                except Exception:
                    pass
            if resp.status_code in {500, 502, 503, 504} and attempts < 3:
                time.sleep(0.5 * attempts)
                continue
            break

        if resp.status_code == 401:
            raise ValueError(f"Authentication failed for {base} — check the API token")

        if resp.status_code == 404:
            ct = resp.headers.get('Content-Type', '')
            if 'application/json' not in ct:
                hint = " (URL uses http:// — try https:// instead)" if base.startswith('http://') else ""
                raise ValueError(
                    f"Got a non-Netbox 404 from {base}{hint}. "
                    f"Check the instance URL and scheme."
                )
            raise ValueError(
                f"Endpoint '{endpoint}' not found at {base} — "
                f"may not be supported by this Netbox version"
            )

        if not resp.ok:
            raise ValueError(f"GET {endpoint}: {resp.status_code} {resp.text[:250]}")
        data = resp.json()
        page_rows = data.get('results', [])
        results.extend(page_rows)
        if callable(progress_cb):
            try:
                progress_cb(
                    fetched=len(results),
                    total_estimate=int(data.get('count') or 0),
                    page_size=len(page_rows),
                )
            except Exception:
                pass
        api_url = data.get('next')
    return results


def nb_post(url, token, endpoint, payload):
    h = {**nb_headers(token, url), 'Content-Type': 'application/json'}
    resp = requests.post(
        f"{url.rstrip('/')}/api/{endpoint}/",
        headers=h, json=payload, verify=_requests_verify_for_url(url), timeout=30,
    )
    if not resp.ok:
        raise ValueError(f"POST {endpoint}: {resp.status_code} {resp.text[:250]}")
    return resp.json()


def nb_patch(url, token, endpoint, obj_id, payload):
    h = {**nb_headers(token, url), 'Content-Type': 'application/json'}
    resp = requests.patch(
        f"{url.rstrip('/')}/api/{endpoint}/{obj_id}/",
        headers=h, json=payload, verify=_requests_verify_for_url(url), timeout=30,
    )
    if not resp.ok:
        raise ValueError(f"PATCH {endpoint}/{obj_id}: {resp.status_code} {resp.text[:250]}")
    return resp.json()

# ---------------------------------------------------------------------------
# Normalisation helpers (Template Sync)
# ---------------------------------------------------------------------------

def _enum(obj, field):
    val = (obj or {}).get(field)
    if isinstance(val, dict):
        return val.get('value')
    return val


def _slug(obj, field):
    val = (obj or {}).get(field)
    if isinstance(val, dict):
        return val.get('slug')
    return val


def _name(obj, field):
    val = (obj or {}).get(field)
    if isinstance(val, dict):
        return val.get('name')
    return val


def normalize_value(val):
    if isinstance(val, list):
        try:
            return sorted(val)
        except TypeError:
            return val
    return val


def extract_fields(obj, fields):
    return {f: normalize_value(obj.get(f)) for f in fields}


def build_diff(src_norm, dst_norm):
    src_json = json.dumps(src_norm, indent=2, sort_keys=True)
    dst_json = json.dumps(dst_norm, indent=2, sort_keys=True)
    return list(difflib.unified_diff(
        dst_json.splitlines(),
        src_json.splitlines(),
        fromfile='destination (current)',
        tofile='source (new)',
        lineterm='',
    ))


def normalize_component(tmpl, ctype_cfg):
    result = {}
    for field in ctype_cfg['compare_fields']:
        if field == 'type':
            result[field] = _enum(tmpl, 'type')
        elif field == 'feed_leg':
            result[field] = _enum(tmpl, 'feed_leg')
        elif field == 'rear_port_name':
            result[field] = _name(tmpl, 'rear_port')
        elif field == 'power_port_name':
            result[field] = _name(tmpl, 'power_port')
        else:
            result[field] = tmpl.get(field)
    return result


def build_component_payload(tmpl, ctype_cfg, parent_id, parent_field,
                            rear_port_map=None, power_port_map=None):
    payload = {parent_field: parent_id}
    for field in ctype_cfg['payload_fields']:
        if field == 'type':
            payload[field] = _enum(tmpl, 'type')
        elif field == 'feed_leg':
            v = _enum(tmpl, 'feed_leg')
            if v is not None:
                payload[field] = v
        else:
            payload[field] = tmpl.get(field)

    if ctype_cfg.get('resolve_rear_port') and rear_port_map:
        rp_name = _name(tmpl, 'rear_port')
        if rp_name and rp_name in rear_port_map:
            payload['rear_port'] = rear_port_map[rp_name]
            payload['rear_port_position'] = tmpl.get('rear_port_position', 1)

    if ctype_cfg.get('resolve_power_port') and power_port_map:
        pp_name = _name(tmpl, 'power_port')
        if pp_name and pp_name in power_port_map:
            payload['power_port'] = power_port_map[pp_name]

    return payload


def normalize_device_type_core(dt):
    return {
        'model':                    dt.get('model'),
        'slug':                     dt.get('slug'),
        'manufacturer':             _slug(dt, 'manufacturer'),
        'part_number':              dt.get('part_number', ''),
        'u_height':                 dt.get('u_height'),
        'exclude_from_utilization': dt.get('exclude_from_utilization', False),
        'is_full_depth':            dt.get('is_full_depth', True),
        'subdevice_role':           _enum(dt, 'subdevice_role'),
        'airflow':                  _enum(dt, 'airflow'),
        'weight':                   dt.get('weight'),
        'weight_unit':              _enum(dt, 'weight_unit'),
        'description':              dt.get('description', ''),
        'comments':                 dt.get('comments', ''),
    }


def normalize_module_type_core(mt):
    return {
        'model':        mt.get('model'),
        'manufacturer': _slug(mt, 'manufacturer'),
        'profile':      _name(mt, 'profile'),
        'part_number':  mt.get('part_number', ''),
        'airflow':      _enum(mt, 'airflow'),
        'weight':       mt.get('weight'),
        'weight_unit':  _enum(mt, 'weight_unit'),
        'description':  mt.get('description', ''),
        'comments':     mt.get('comments', ''),
        'attributes':   mt.get('attributes'),
    }


def fetch_components_bulk(url, token, parent_field):
    result = {}
    for ctype in COMPONENT_TYPES:
        endpoint = ctype['endpoint']
        all_tmps = fetch_all(url, token, endpoint)
        for tmpl in all_tmps:
            parent_obj = tmpl.get(parent_field)
            if not parent_obj:
                continue
            pid = parent_obj['id']
            if pid not in result:
                result[pid] = {}
            if endpoint not in result[pid]:
                result[pid][endpoint] = []
            result[pid][endpoint].append(normalize_component(tmpl, ctype))

    for comps_by_ep in result.values():
        for lst in comps_by_ep.values():
            lst.sort(key=lambda t: t.get('name', ''))

    return result


def enrich_with_components(norm_core, parent_id, components_bulk):
    comps = components_bulk.get(parent_id, {})
    for ctype in COMPONENT_TYPES:
        ep = ctype['endpoint']
        norm_core[ep] = comps.get(ep, [])
    return norm_core

# ---------------------------------------------------------------------------
# Compare & Sync logic (Template Sync)
# ---------------------------------------------------------------------------

def compare_type(source_url, source_token, dest_url, dest_token, template_type):
    cfg = TEMPLATE_TYPES[template_type]
    handler = cfg.get('handler')
    if handler == 'device-types':
        return compare_device_types(source_url, source_token, dest_url, dest_token)
    if handler == 'module-types':
        return compare_module_types(source_url, source_token, dest_url, dest_token)

    endpoint      = cfg['endpoint']
    compare_fields = cfg['compare_fields']
    match_key     = cfg.get('match_key', 'name')

    try:
        src_items = fetch_all(source_url, source_token, endpoint)
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Source ({source_url}): {e}") from e

    try:
        dst_items = fetch_all(dest_url, dest_token, endpoint)
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Destination ({dest_url}): {e}") from e

    src_map = {item[match_key]: item for item in src_items}
    dst_map = {item[match_key]: item for item in dst_items}
    all_keys = sorted(set(list(src_map.keys()) + list(dst_map.keys())))

    results = []
    for key in all_keys:
        in_src = key in src_map
        in_dst = key in dst_map
        if in_src and not in_dst:
            results.append({'name': key, 'status': 'source_only', 'diff': None})
        elif in_dst and not in_src:
            results.append({'name': key, 'status': 'dest_only', 'diff': None})
        else:
            src_norm = extract_fields(src_map[key], compare_fields)
            dst_norm = extract_fields(dst_map[key], compare_fields)
            if src_norm == dst_norm:
                results.append({'name': key, 'status': 'in_sync', 'diff': None})
            else:
                results.append({'name': key, 'status': 'different',
                                'diff': build_diff(src_norm, dst_norm)})
    return results


def sync_one_template(source_url, source_token, dest_url, dest_token, template_type, name):
    cfg = TEMPLATE_TYPES[template_type]
    handler = cfg.get('handler')
    if handler == 'device-types':
        return sync_device_type(source_url, source_token, dest_url, dest_token, name)
    if handler == 'module-types':
        return sync_module_type(source_url, source_token, dest_url, dest_token, name)

    endpoint   = cfg['endpoint']
    sync_fields = cfg['sync_fields']
    match_key  = cfg.get('match_key', 'name')

    src_items = fetch_all(source_url, source_token, endpoint, params={match_key: name, 'limit': 100})
    src = next((i for i in src_items if str(i.get(match_key, '')) == str(name)), None)
    if not src:
        src_items = fetch_all(source_url, source_token, endpoint, params={'q': name, 'limit': 100})
        src = next((i for i in src_items if str(i.get(match_key, '')) == str(name)), None)
    if not src:
        raise ValueError(f"'{name}' not found in source")

    dst_items = fetch_all(dest_url, dest_token, endpoint, params={match_key: name, 'limit': 100})
    dst = next((i for i in dst_items if str(i.get(match_key, '')) == str(name)), None)
    if not dst:
        dst_items = fetch_all(dest_url, dest_token, endpoint, params={'q': name, 'limit': 100})
        dst = next((i for i in dst_items if str(i.get(match_key, '')) == str(name)), None)

    payload = {f: src[f] for f in sync_fields if f in src}

    if dst:
        return nb_patch(dest_url, dest_token, endpoint, dst['id'], payload)
    else:
        return nb_post(dest_url, dest_token, endpoint, payload)


def compare_device_types(src_url, src_token, dst_url, dst_token):
    try:
        src_dts = fetch_all(src_url, src_token, 'dcim/device-types')
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Source ({src_url}): {e}") from e
    try:
        dst_dts = fetch_all(dst_url, dst_token, 'dcim/device-types')
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Destination ({dst_url}): {e}") from e

    src_comps = fetch_components_bulk(src_url, src_token, 'device_type')
    dst_comps = fetch_components_bulk(dst_url, dst_token, 'device_type')

    src_map = {dt['slug']: dt for dt in src_dts}
    dst_map = {dt['slug']: dt for dt in dst_dts}
    all_slugs = sorted(set(list(src_map.keys()) + list(dst_map.keys())))

    results = []
    for slug in all_slugs:
        in_src = slug in src_map
        in_dst = slug in dst_map
        if in_src and not in_dst:
            results.append({'name': slug, 'status': 'source_only', 'diff': None})
        elif in_dst and not in_src:
            results.append({'name': slug, 'status': 'dest_only', 'diff': None})
        else:
            src_norm = enrich_with_components(normalize_device_type_core(src_map[slug]),
                                              src_map[slug]['id'], src_comps)
            dst_norm = enrich_with_components(normalize_device_type_core(dst_map[slug]),
                                              dst_map[slug]['id'], dst_comps)
            if src_norm == dst_norm:
                results.append({'name': slug, 'status': 'in_sync', 'diff': None})
            else:
                results.append({'name': slug, 'status': 'different',
                                'diff': build_diff(src_norm, dst_norm)})
    return results


def _ensure_manufacturer(src_url, src_token, dst_url, dst_token, mfr_slug):
    dst_mfrs = {m['slug']: m for m in fetch_all(dst_url, dst_token, 'dcim/manufacturers')}
    if mfr_slug in dst_mfrs:
        return dst_mfrs[mfr_slug]['id']

    src_mfr = next(
        (m for m in fetch_all(src_url, src_token, 'dcim/manufacturers') if m['slug'] == mfr_slug),
        None,
    )
    if not src_mfr:
        raise ValueError(f"Manufacturer '{mfr_slug}' not found in source")

    created = nb_post(dst_url, dst_token, 'dcim/manufacturers', {
        'name': src_mfr['name'], 'slug': src_mfr['slug'],
        'description': src_mfr.get('description', ''),
        'comments': src_mfr.get('comments', ''),
    })
    return created['id']


def _ensure_module_type_profile(src_url, src_token, dst_url, dst_token, profile_name):
    dst_mtps = {m['name']: m for m in fetch_all(dst_url, dst_token, 'dcim/module-type-profiles')}
    if profile_name in dst_mtps:
        return dst_mtps[profile_name]['id']

    src_mtp = next(
        (m for m in fetch_all(src_url, src_token, 'dcim/module-type-profiles')
         if m['name'] == profile_name),
        None,
    )
    if not src_mtp:
        raise ValueError(f"Module type profile '{profile_name}' not found in source")

    created = nb_post(dst_url, dst_token, 'dcim/module-type-profiles', {
        'name': src_mtp['name'],
        'description': src_mtp.get('description', ''),
        'schema': src_mtp.get('schema'),
        'comments': src_mtp.get('comments', ''),
    })
    return created['id']


def sync_components(src_url, src_token, dst_url, dst_token,
                    src_parent_id, dst_parent_id, parent_field):
    errors = []
    rear_port_map  = {}
    power_port_map = {}

    for ctype in COMPONENT_TYPES:
        endpoint = ctype['endpoint']

        src_tmps = fetch_all(src_url, src_token, endpoint,
                             {f'{parent_field}_id': src_parent_id})
        dst_tmps = fetch_all(dst_url, dst_token, endpoint,
                             {f'{parent_field}_id': dst_parent_id})

        dst_name_map = {t['name']: t for t in dst_tmps}

        if endpoint == 'dcim/rear-port-templates':
            rear_port_map.update({t['name']: t['id'] for t in dst_tmps})
        if endpoint == 'dcim/power-port-templates':
            power_port_map.update({t['name']: t['id'] for t in dst_tmps})

        for src_tmpl in src_tmps:
            name = src_tmpl['name']
            try:
                payload = build_component_payload(
                    src_tmpl, ctype, dst_parent_id, parent_field,
                    rear_port_map=rear_port_map, power_port_map=power_port_map,
                )
                if name in dst_name_map:
                    result = nb_patch(dst_url, dst_token, endpoint,
                                      dst_name_map[name]['id'], payload)
                else:
                    result = nb_post(dst_url, dst_token, endpoint, payload)

                if endpoint == 'dcim/rear-port-templates':
                    rear_port_map[name] = result['id']
                elif endpoint == 'dcim/power-port-templates':
                    power_port_map[name] = result['id']

            except Exception as e:
                errors.append(f"{endpoint}/{name}: {e}")

    return errors


def sync_device_type(src_url, src_token, dst_url, dst_token, slug):
    src_dts = {dt['slug']: dt for dt in fetch_all(src_url, src_token, 'dcim/device-types')}
    src_dt = src_dts.get(slug)
    if not src_dt:
        raise ValueError(f"Device type '{slug}' not found in source")

    mfr_slug   = _slug(src_dt, 'manufacturer')
    dst_mfr_id = _ensure_manufacturer(src_url, src_token, dst_url, dst_token, mfr_slug)

    payload = {
        'manufacturer':              dst_mfr_id,
        'model':                     src_dt.get('model'),
        'slug':                      src_dt.get('slug'),
        'part_number':               src_dt.get('part_number', ''),
        'u_height':                  src_dt.get('u_height', 1.0),
        'exclude_from_utilization':  src_dt.get('exclude_from_utilization', False),
        'is_full_depth':             src_dt.get('is_full_depth', True),
        'description':               src_dt.get('description', ''),
        'comments':                  src_dt.get('comments', ''),
    }
    for f in ('subdevice_role', 'airflow', 'weight_unit'):
        v = _enum(src_dt, f)
        if v is not None:
            payload[f] = v
    if src_dt.get('weight') is not None:
        payload['weight'] = src_dt['weight']

    dst_dts = {dt['slug']: dt for dt in fetch_all(dst_url, dst_token, 'dcim/device-types')}
    if slug in dst_dts:
        result = nb_patch(dst_url, dst_token, 'dcim/device-types', dst_dts[slug]['id'], payload)
    else:
        result = nb_post(dst_url, dst_token, 'dcim/device-types', payload)

    dst_dt_id = result['id']

    comp_errors = sync_components(
        src_url, src_token, dst_url, dst_token,
        src_dt['id'], dst_dt_id, 'device_type',
    )
    if comp_errors:
        raise ValueError(
            f"Device type synced but {len(comp_errors)} component error(s): "
            + "; ".join(comp_errors[:5])
        )
    return result


def compare_module_types(src_url, src_token, dst_url, dst_token):
    try:
        src_mts = fetch_all(src_url, src_token, 'dcim/module-types')
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Source ({src_url}): {e}") from e
    try:
        dst_mts = fetch_all(dst_url, dst_token, 'dcim/module-types')
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Destination ({dst_url}): {e}") from e

    src_comps = fetch_components_bulk(src_url, src_token, 'module_type')
    dst_comps = fetch_components_bulk(dst_url, dst_token, 'module_type')

    src_map = {mt['model']: mt for mt in src_mts}
    dst_map = {mt['model']: mt for mt in dst_mts}
    all_models = sorted(set(list(src_map.keys()) + list(dst_map.keys())))

    results = []
    for model in all_models:
        in_src = model in src_map
        in_dst = model in dst_map
        if in_src and not in_dst:
            results.append({'name': model, 'status': 'source_only', 'diff': None})
        elif in_dst and not in_src:
            results.append({'name': model, 'status': 'dest_only', 'diff': None})
        else:
            src_norm = enrich_with_components(normalize_module_type_core(src_map[model]),
                                              src_map[model]['id'], src_comps)
            dst_norm = enrich_with_components(normalize_module_type_core(dst_map[model]),
                                              dst_map[model]['id'], dst_comps)
            if src_norm == dst_norm:
                results.append({'name': model, 'status': 'in_sync', 'diff': None})
            else:
                results.append({'name': model, 'status': 'different',
                                'diff': build_diff(src_norm, dst_norm)})
    return results


def sync_module_type(src_url, src_token, dst_url, dst_token, model):
    src_mts = {mt['model']: mt for mt in fetch_all(src_url, src_token, 'dcim/module-types')}
    src_mt = src_mts.get(model)
    if not src_mt:
        raise ValueError(f"Module type '{model}' not found in source")

    mfr_slug   = _slug(src_mt, 'manufacturer')
    dst_mfr_id = _ensure_manufacturer(src_url, src_token, dst_url, dst_token, mfr_slug)

    payload = {
        'manufacturer': dst_mfr_id,
        'model':        src_mt.get('model'),
        'part_number':  src_mt.get('part_number', ''),
        'description':  src_mt.get('description', ''),
        'comments':     src_mt.get('comments', ''),
        'attributes':   src_mt.get('attributes') or {},
    }
    for f in ('airflow', 'weight_unit'):
        v = _enum(src_mt, f)
        if v is not None:
            payload[f] = v
    if src_mt.get('weight') is not None:
        payload['weight'] = src_mt['weight']

    profile_obj = src_mt.get('profile')
    if profile_obj:
        profile_name = profile_obj.get('name')
        if profile_name:
            payload['profile'] = _ensure_module_type_profile(
                src_url, src_token, dst_url, dst_token, profile_name
            )

    dst_mts = {mt['model']: mt for mt in fetch_all(dst_url, dst_token, 'dcim/module-types')}
    if model in dst_mts:
        result = nb_patch(dst_url, dst_token, 'dcim/module-types', dst_mts[model]['id'], payload)
    else:
        result = nb_post(dst_url, dst_token, 'dcim/module-types', payload)

    dst_mt_id = result['id']

    comp_errors = sync_components(
        src_url, src_token, dst_url, dst_token,
        src_mt['id'], dst_mt_id, 'module_type',
    )
    if comp_errors:
        raise ValueError(
            f"Module type synced but {len(comp_errors)} component error(s): "
            + "; ".join(comp_errors[:5])
        )
    return result

# ---------------------------------------------------------------------------
# CSV Import — Worker helpers
# ---------------------------------------------------------------------------

def _log_to_job(job, message):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(job['log_file'], 'a', encoding='utf-8') as f:
        f.write(f"[{ts}] {message}\n")


def _first_missing_site_name(importer, parsed_data, sections=None):
    active_sections = set(sections or [])
    check_all = not active_sections

    planned_sites = set()
    for row in parsed_data.get('sites', []):
        name = str((row or {}).get('name', '')).strip()
        if name:
            planned_sites.add(name)

    referenced_sites = set()
    for import_type, rows in parsed_data.items():
        if not check_all and import_type not in active_sections:
            continue
        if import_type == 'sites':
            continue
        for row in rows:
            site_name = str((row or {}).get('site', '')).strip()
            if site_name:
                referenced_sites.add(site_name)

    for site_name in sorted(referenced_sites):
        if site_name in planned_sites:
            continue
        try:
            result = importer.api.dcim.sites.filter(name=site_name)
            if next(iter(result), None) is None:
                return site_name
        except Exception:
            return site_name
    return None


def _run_single_job(job):
    global stop_requested, import_status

    log_path  = job['log_file']
    file_path = job['file_path']
    diff_mode = bool(job.get('diff_mode', False))
    dry_run   = True if diff_mode else job['dry_run']
    replace   = False if diff_mode else job['replace']
    sections  = job['sections']
    delay     = job['delay']
    workers   = job.get('workers', DEFAULT_IMPORT_WORKERS)
    requested_branch = _normalize_requested_branch(job.get('branch'))
    branch, branch_auto = _resolve_job_branch_name(
        requested_branch,
        file_path=file_path,
        filename=job.get('filename') or os.path.basename(file_path or ''),
    )
    branch_resolution_error = ''
    if requested_branch == AUTO_BRANCH_SENTINEL and not branch:
        branch_resolution_error = 'Auto branch requested but no branch name could be derived from the import data'
    if branch:
        job['resolved_branch'] = branch

    run_label = 'Diff' if diff_mode else ('Dry Run' if dry_run else 'Live')
    header_parts = [f"--- Job {job['id']}: {job['filename']} ({run_label}) ---"]
    if delay > 0:
        header_parts.append(f"Slow Mode: {delay}s delay")
    elif workers > 1:
        header_parts.append(f"Workers: {workers}")
    if sections:
        header_parts.append(f"Sections: {', '.join(sections)}")
    if branch:
        branch_tag = 'auto' if branch_auto else 'selected'
        header_parts.append(f"Branch: {branch} ({branch_tag})")
    header = '\n'.join(header_parts)

    _log_to_job(job, header)
    with open(IMPORT_LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(header + '\n')

    job_handler = logging.FileHandler(log_path, encoding='utf-8')
    job_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root_logger = logging.getLogger()
    original_root_level = root_logger.level
    if original_root_level > logging.INFO:
        # Gunicorn can leave root at WARNING; force INFO so GUI counters stay live.
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(job_handler)

    import_status['running'] = True
    import_status['stop_requested'] = False
    import_status['stopped'] = False
    import_status['start_time'] = job['start_time']
    import_status['last_file'] = file_path
    stop_requested = False

    def check_stop():
        return stop_requested

    try:
        if branch_resolution_error:
            raise ValueError(branch_resolution_error)
        srv = resolve_instance_by_id(job.get('server_id'))
        import_status['last_server_id'] = srv['id']
        import_status['last_branch'] = branch or None
        _log_to_job(job, f"Target server: {srv['name']} ({srv['url']})")
        if branch:
            _log_to_job(
                job,
                (
                    f'Branch "{branch}" selected. Waiting for branch readiness '
                    'before import starts (first-time branch create can take ~15s).'
                ),
            )

        importer = NetboxImporter(file_path, dry_run=dry_run, replace=replace, interactive=False,
                                  netbox_url=srv['url'], netbox_token=srv['token'],
                                  netbox_skip_ssl_verify=_to_bool(srv.get('skip_ssl_verify', False)),
                                  netbox_branch=branch)
        data = importer.parse_csv()
        if diff_mode:
            missing_site = _first_missing_site_name(importer, data, sections=sections)
            if missing_site:
                raise ImportStopped(f'No site named {missing_site}')
        importer.import_data(data, sections=sections, should_stop=check_stop, delay=delay, workers=workers)
        job['status'] = 'done'
    except ImportStopped as e:
        reason = str(e or '').strip()
        if reason and reason != 'Import stopped by user':
            msg = f"--- IMPORT STOPPED: {reason} ---"
        else:
            msg = "--- IMPORT STOPPED BY USER ---"
        with open(IMPORT_LOG_FILE, 'a') as f:
            f.write(msg + '\n')
        _log_to_job(job, msg)
        job['status'] = 'stopped'
        import_status['stopped'] = True
    except Exception as e:
        msg = f"FATAL ERROR: {str(e)}"
        with open(IMPORT_LOG_FILE, 'a') as f:
            f.write(msg + '\n')
        _log_to_job(job, msg)
        _capture_exception(
            e,
            route='csv_import_worker',
            job_id=job.get('id'),
            filename=job.get('filename'),
            server_id=job.get('server_id'),
            branch=branch,
            diff_mode=diff_mode,
        )
        job['status'] = 'failed'
        job['error'] = str(e)
    finally:
        root_logger.removeHandler(job_handler)
        job_handler.close()
        if root_logger.level != original_root_level:
            root_logger.setLevel(original_root_level)
        job['end_time'] = time.time()
        import_status['running'] = False


def _worker_loop():
    global worker_running, worker_thread
    try:
        while True:
            job = None
            with queue_lock:
                for j in job_queue:
                    if j['status'] == 'pending':
                        j['status'] = 'running'
                        j['start_time'] = time.time()
                        job = j
                        break

            if job is None:
                break

            _run_single_job(job)

            if job['status'] == 'stopped':
                break
    finally:
        with worker_state_lock:
            worker_running = False
            worker_thread = None


def _ensure_worker():
    global worker_running, worker_thread
    with worker_state_lock:
        if worker_thread is not None and worker_thread.is_alive():
            worker_running = True
            return
        t = threading.Thread(target=_worker_loop, daemon=True)
        worker_thread = t
        worker_running = True
        t.start()


def run_retry_thread(file_path, dry_run, replace, delay=0.0, server_id=None, branch=None):
    global import_status, stop_requested
    resolved_branch = ''

    import_status['running'] = True
    import_status['stop_requested'] = False
    import_status['stopped'] = False
    import_status['start_time'] = time.time()
    stop_requested = False

    def check_stop():
        return stop_requested

    try:
        failed_records = []
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'original_data' in row:
                        try:
                            original_row = json.loads(row['original_data'])
                            failed_records.append((row['import_type'], original_row))
                        except json.JSONDecodeError:
                            continue

        if os.path.exists(file_path):
            os.remove(file_path)

        data = defaultdict(list)
        for import_type, row in failed_records:
            data[import_type].append(row)

        srv = resolve_instance_by_id(server_id)
        requested_branch = _normalize_requested_branch(branch)
        resolved_branch, branch_auto = _resolve_job_branch_name(
            requested_branch,
            file_path=file_path,
            filename=os.path.basename(file_path or ''),
        )
        if requested_branch == AUTO_BRANCH_SENTINEL and not resolved_branch:
            resolved_branch = _clean_branch_name(import_status.get('last_branch') or '')
        if requested_branch == AUTO_BRANCH_SENTINEL and not resolved_branch:
            raise ValueError('Auto branch requested for retry but no branch could be derived')
        import_status['last_branch'] = resolved_branch or None
        if branch_auto and resolved_branch:
            with open(IMPORT_LOG_FILE, 'a') as f:
                f.write(f"\n[AUTO-BRANCH] Retry resolved branch: {resolved_branch}\n")

        importer = NetboxImporter(
            FAILURES_FILE,
            dry_run=dry_run,
            replace=replace,
            interactive=False,
            netbox_url=srv['url'],
            netbox_token=srv['token'],
            netbox_skip_ssl_verify=_to_bool(srv.get('skip_ssl_verify', False)),
            netbox_branch=resolved_branch or None,
        )
        importer.import_data(data, should_stop=check_stop, delay=delay)

    except ImportStopped:
        with open(IMPORT_LOG_FILE, 'a') as f:
            f.write("\n--- RETRY STOPPED BY USER ---\n")
        import_status['stopped'] = True
    except Exception as e:
        with open(IMPORT_LOG_FILE, 'a') as f:
            f.write(f"\nFATAL ERROR IN RETRY THREAD: {str(e)}\n")
        _capture_exception(
            e,
            route='retry_failures_worker',
            server_id=server_id,
            branch=resolved_branch or branch,
            file_path=file_path,
        )
    finally:
        import_status['running'] = False


def _watch_nbsync_process(proc, log_handle):
    """Wait for Zabbix subprocess, then finalize state."""
    exit_code = proc.wait()
    try:
        log_handle.flush()
    except Exception:
        pass
    try:
        log_handle.close()
    except Exception:
        pass

    with nbsync_lock:
        nbsync_state['running'] = False
        nbsync_state['end_time'] = time.time()
        nbsync_state['last_exit_code'] = exit_code
        nbsync_state['process'] = None


def _nbsync_headers(token):
    return {'Authorization': f'Token {token}', 'Accept': 'application/json'}


def _extract_field_id(value):
    if isinstance(value, dict):
        return value.get('id')
    return value


def _extract_primary_ipv4(device):
    p = device.get('primary_ip4')
    if isinstance(p, dict):
        return p.get('address') or p.get('display') or ''
    return str(p or '')


def _extract_device_tags(device):
    out = []
    for t in device.get('tags', []) or []:
        if isinstance(t, dict):
            name = (t.get('name') or t.get('slug') or '').strip()
        else:
            name = str(t).strip()
        if name:
            out.append(name)
    return _unique_str_list(out)


def _nbsync_template_map(device, site_details=None):
    site = device.get('site') or {}
    role = device.get('role') or {}
    dtype = device.get('device_type') or {}
    tenant = device.get('tenant') or {}
    sd = site_details or {}
    site_name = str(sd.get('name') or site.get('name') or '')
    site_slug = str(sd.get('slug') or site.get('slug') or '')
    site_facility = str(sd.get('facility') or site.get('facility') or '')
    site_region = sd.get('region')
    if site_region is None:
        site_region = site.get('region')
    if isinstance(site_region, dict):
        site_region_name = str(site_region.get('name') or '')
    else:
        site_region_name = ''
    role_name = str(role.get('name') or '')
    role_slug = str(role.get('slug') or '')
    dtype_model = str(dtype.get('model') or '')
    tenant_name = str(tenant.get('name') or '')
    manufacturer = dtype.get('manufacturer') or {}
    manufacturer_name = str(manufacturer.get('name') or '')
    site_lat = str(sd.get('latitude') or site.get('latitude') or '')
    site_lon = str(sd.get('longitude') or site.get('longitude') or '')
    site_desc = str(sd.get('description') or site.get('description') or '')
    site_addr = str(sd.get('physical_address') or site.get('physical_address') or '')
    site_tz = str(sd.get('time_zone') or site.get('time_zone') or '')
    primary_ipv4 = _extract_primary_ipv4(device)
    device_name = str(device.get('name') or '')
    device_id = str(device.get('id') or '')
    serial = str(device.get('serial') or '')
    asset_tag = str(device.get('asset_tag') or '')
    return {
        'device_name': device_name,
        'device_id': device_id,
        'primary_ipv4': primary_ipv4,
        'site': site_name,
        'site_slug': site_slug,
        'role': role_name,
        'role_slug': role_slug,
        'serial': serial,
        'asset_tag': asset_tag,
        'device_type': dtype_model,
        'tenant': tenant_name,
        'manufacturer': manufacturer_name,
        'site.latitude': site_lat,
        'site.longitude': site_lon,
        'site.description': site_desc,
        'site.physical_address': site_addr,
        'site.time_zone': site_tz,
        # Jinja-like hostgroup variable aliases.
        'device.device_type.model': dtype_model,
        'device.device_type.manufacturer.name': manufacturer_name,
        'site.facility': site_facility,
        'site.region.name': site_region_name,
        'device.role.name': role_name,
        'site.name': site_name,
        'device.tenant.name': tenant_name,
        # Zabbix host inventory template aliases requested by UI.
        'object.name': device_name,
        'object.id': device_id,
        'object.serial': serial,
        'object.asset_tag': asset_tag,
        'object.primary_ip4.address': primary_ipv4,
        'object.device_type.model': dtype_model,
        'object.device_type.manufacturer.name': manufacturer_name,
        'object.site.name': site_name,
        'object.site.slug': site_slug,
        'object.site.facility': site_facility,
        'object.site.region.name': site_region_name,
        'object.site.latitude': site_lat,
        'object.site.longitude': site_lon,
        'object.site.description': site_desc,
        'object.site.physical_address': site_addr,
        'object.site.time_zone': site_tz,
    }


def _render_template_value(template, values):
    out = str(template or '')
    for k, v in values.items():
        out = out.replace('{' + k + '}', str(v))
    return out


def _render_nbsync_value_template(template, values):
    out = str(template or '')
    if not out:
        return ''

    def repl(match):
        key = str(match.group(1) or '').strip()
        return str(values.get(key, ''))

    out = re.sub(r'\{\{\s*([^}]+?)\s*\}\}', repl, out)
    # Backward compatibility with old {key} formatting.
    out = _render_template_value(out, values)
    return out.strip()


def _render_nbsync_hostgroup_template(template, values):
    return _render_nbsync_value_template(template, values)


def _nbsync_get_site_details(url, token, site_ref, cache):
    site_id = _extract_field_id(site_ref)
    try:
        site_id = int(site_id)
    except Exception:
        return {}
    if site_id <= 0:
        return {}
    if site_id in cache:
        return cache[site_id]
    try:
        resp = requests.get(
            f"{url.rstrip('/')}/api/dcim/sites/{site_id}/",
            headers=_nbsync_headers(token),
            verify=_requests_verify_for_url(url),
            timeout=30,
        )
        if resp.status_code >= 400:
            cache[site_id] = {}
            return {}
        cache[site_id] = resp.json()
        return cache[site_id]
    except Exception:
        cache[site_id] = {}
        return {}


def _build_nbsync_targets(
    device, options, apply_tags=True, apply_hostgroups=True, apply_macros=True,
    template_values=None,
):
    device_tags = _extract_device_tags(device)
    selected_source_tags = options.get('selected_source_tags')
    selected_set = None
    if isinstance(selected_source_tags, list):
        selected_set = {str(t).strip().lower() for t in selected_source_tags if str(t).strip()}
    device_tags_for_zabbix_tags = [
        t for t in device_tags
        if selected_set is None or t.lower() in selected_set
    ]
    values = template_values if isinstance(template_values, dict) else _nbsync_template_map(device)
    tags, hostgroups, macros = [], [], []

    if apply_tags:
        if options.get('include_device_tags_as_tags', True):
            tags.extend(device_tags_for_zabbix_tags)

    if apply_hostgroups:
        if options.get('include_device_tags_as_hostgroups', True):
            for tag in device_tags:
                safe = _sanitize_nbsync_hostgroup_name(tag)
                if safe:
                    hostgroups.append(safe)
        for h in options.get('static_hostgroups', []):
            rendered = _render_nbsync_hostgroup_template(h, values)
            safe = _sanitize_nbsync_hostgroup_name(rendered)
            if safe:
                hostgroups.append(safe)

    if apply_macros:
        for m in options.get('macros', []):
            if not _parse_boolish(m.get('enabled', True), default=True):
                continue
            macro = _normalize_macro_name(m.get('macro', ''))
            if not macro:
                continue
            value = _render_template_value(m.get('value', ''), values)
            description = str(m.get('description', '')).strip()
            is_regex = _parse_boolish(m.get('is_regex', False), default=False)
            macros.append({
                'macro': macro,
                'value': value,
                'description': description,
                'is_regex': bool(is_regex),
            })

    return {
        'tags': _unique_str_list(tags),
        'hostgroups': _unique_str_list(hostgroups),
        'macros': macros,
    }


def _build_nbsync_inventory_targets(options, template_values):
    mode = _normalize_inventory_mode(options.get('host_inventory_mode', 0))
    fields = {}
    for row in options.get('host_inventory_fields', []) or []:
        if not isinstance(row, dict):
            continue
        if not bool(row.get('enabled', True)):
            continue
        field = str(row.get('field') or '').strip()
        if not field:
            continue
        if field in ('id', 'url', 'display', 'assigned_object_type', 'assigned_object_id'):
            continue
        rendered = _render_nbsync_value_template(row.get('template', ''), template_values or {})
        if rendered == '':
            continue
        fields[field] = rendered
    return {'inventory_mode': mode, 'fields': fields}


def _parse_boolish(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    if isinstance(value, (int, float)):
        return int(value) != 0
    s = str(value or '').strip().lower()
    if s in ('1', 'true', 'yes', 'y', 'on'):
        return True
    if s in ('0', 'false', 'no', 'n', 'off'):
        return False
    return bool(default)


def _int_or_default(value, default=0):
    try:
        return int(value)
    except Exception:
        return int(default)


def _normalize_choice_key(value):
    return re.sub(r'[^a-z0-9]+', '', str(value or '').strip().lower())


def _normalize_nbsync_host_interface_type(value, default=1):
    direct = _normalize_positive_int(value)
    if direct in (1, 2, 3, 4):
        return int(direct)
    s = _normalize_choice_key(value)
    mapping = {
        'agent': 1,
        'snmp': 2,
        'snmpv1': 2,
        'snmpv2': 2,
        'snmpv2c': 2,
        'snmpv3': 2,
        'ipmi': 3,
        'jmx': 4,
    }
    return mapping.get(s, int(default))


def _normalize_nbsync_interface_main(value, default=1):
    if value is None:
        return int(default)
    direct = str(value).strip()
    if direct in ('0', '1'):
        return int(direct)
    return 1 if _parse_boolish(value, default=bool(default)) else 0


def _normalize_nbsync_useip(value, default=1):
    if value is None:
        return int(default)
    direct = str(value).strip()
    if direct in ('0', '1'):
        return int(direct)
    if _normalize_choice_key(value) == 'dns':
        return 0
    if _normalize_choice_key(value) == 'ip':
        return 1
    return 1 if _parse_boolish(value, default=bool(default)) else 0


def _normalize_nbsync_snmp_version(value, default=2):
    direct = _normalize_positive_int(value)
    if direct in (1, 2, 3):
        return int(direct)
    s = _normalize_choice_key(value)
    mapping = {
        '1': 1,
        'v1': 1,
        'snmpv1': 1,
        '2': 2,
        '2c': 2,
        'v2': 2,
        'v2c': 2,
        'snmpv2': 2,
        'snmpv2c': 2,
        '3': 3,
        'v3': 3,
        'snmpv3': 3,
    }
    return mapping.get(s, int(default))


def _normalize_nbsync_snmp_security_level(value, default=0):
    direct = str(value or '').strip()
    if direct in ('0', '1', '2'):
        return int(direct)
    s = _normalize_choice_key(value)
    mapping = {
        'noauthnopriv': 0,
        'authnopriv': 1,
        'authpriv': 2,
    }
    return mapping.get(s, int(default))


def _normalize_nbsync_snmp_auth_protocol(value, default=0):
    direct = str(value or '').strip()
    if direct in ('0', '1', '2', '3', '4', '5'):
        return int(direct)
    s = _normalize_choice_key(value)
    mapping = {
        'md5': 0,
        'sha1': 1,
        'sha224': 2,
        'sha256': 3,
        'sha384': 4,
        'sha512': 5,
    }
    return mapping.get(s, int(default))


def _normalize_nbsync_snmp_priv_protocol(value, default=0):
    direct = str(value or '').strip()
    if direct in ('0', '1', '2', '3', '4', '5'):
        return int(direct)
    s = _normalize_choice_key(value)
    mapping = {
        'des': 0,
        'aes128': 1,
        'aes192': 2,
        'aes256': 3,
        'aes192c': 4,
        'aes256c': 5,
    }
    return mapping.get(s, int(default))


def _normalize_nbsync_tls_accept(value):
    if value is None:
        return [1]
    out = []
    if isinstance(value, (list, tuple)):
        candidates = list(value)
    elif isinstance(value, (int, float)):
        # Support bitmask-style integer values.
        n = int(value)
        candidates = [x for x in (1, 2, 4) if n & x]
    else:
        s = str(value or '').strip()
        if not s:
            candidates = []
        else:
            candidates = [x.strip() for x in s.split(',')]
    for c in candidates:
        try:
            n = int(c)
        except Exception:
            continue
        if n in (1, 2, 4) and n not in out:
            out.append(n)
    return out or [1]


def _extract_primary_ipv4_id(device):
    p = device.get('primary_ip4')
    if p is None:
        p = device.get('primary_ip')
    if isinstance(p, dict):
        return _normalize_positive_int(p.get('id'))
    return None


def _is_macro_syntax(value):
    s = str(value or '').strip()
    return bool(s) and s.startswith('{$') and s.endswith('}')


def _nbsync_is_sensitive_macro_name(name):
    macro_name = str(name or '').strip().upper()
    if not macro_name:
        return False
    sensitive_terms = (
        'COMMUNITY',
        'PASSPHRASE',
        'PASSWORD',
        'SECRET',
        'TOKEN',
        'PSK',
    )
    return any(term in macro_name for term in sensitive_terms)


def _nbsync_format_macro_for_diff(macro_name, macro_value):
    m = str(macro_name or '').strip()
    v = str(macro_value or '').strip()
    if _nbsync_is_sensitive_macro_name(m):
        return f"{m}=<set>" if v else f"{m}=<empty>"
    return f"{m}={v}"


def _nbsync_merged_config_context(device):
    merged = {}
    cc = device.get('config_context')
    if isinstance(cc, str):
        try:
            cc = json.loads(cc)
        except Exception:
            cc = {}
    if isinstance(cc, dict):
        merged.update(cc)
    local = device.get('local_context_data')
    if isinstance(local, str):
        try:
            local = json.loads(local)
        except Exception:
            local = {}
    if isinstance(local, dict):
        merged.update(local)
    return merged


def _build_nbsync_host_interface_targets(device, options, zabbix_server_id=None):
    if not bool(options.get('use_host_interface', True)):
        return {'enabled': False, 'reason': 'disabled'}

    ctx_key = str(options.get('host_interface_context_key') or 'interface').strip() or 'interface'
    ctx = _nbsync_merged_config_context(device)
    raw = ctx.get(ctx_key)
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = None
    if not isinstance(raw, dict):
        return {'enabled': False, 'reason': 'no_context'}

    raw_type = raw.get('type')
    if raw_type is None:
        raw_type = raw.get('interface_type')
    host_type = _normalize_nbsync_host_interface_type(raw_type, default=1)

    useip = _normalize_nbsync_useip(raw.get('useip', raw.get('use_ip', 1)), default=1)
    dns = str(raw.get('dns') or '').strip()
    ip_id = _extract_primary_ipv4_id(device)
    if useip == 1 and ip_id is None and dns:
        useip = 0
    if useip == 0 and not dns and ip_id is not None:
        useip = 1

    port = _normalize_positive_int(raw.get('port'))
    if port is None:
        if host_type == 1:
            port = 10050
        elif host_type == 2:
            port = 161
        elif host_type == 3:
            port = 623
        elif host_type == 4:
            port = 12345
        else:
            port = 10050

    interface_main = _normalize_nbsync_interface_main(
        raw.get('main', raw.get('default', raw.get('is_default', 1))),
        default=1,
    )

    snmp_version = _normalize_nbsync_snmp_version(raw.get('snmp_version', 2), default=2)
    snmp_usebulk = _parse_boolish(raw.get('snmp_usebulk', True), default=True)
    snmp_pushcommunity = _parse_boolish(raw.get('snmp_pushcommunity', True), default=True)
    snmp_security_level = _normalize_nbsync_snmp_security_level(raw.get('snmpv3_security_level', 0), default=0)
    snmp_auth_proto = _normalize_nbsync_snmp_auth_protocol(raw.get('snmpv3_authentication_protocol', 0), default=0)
    snmp_priv_proto = _normalize_nbsync_snmp_priv_protocol(raw.get('snmpv3_privacy_protocol', 0), default=0)

    snmp_community = str(raw.get('snmp_community', raw.get('community', '')) or '').strip()
    snmpv3_context_name = str(raw.get('snmpv3_context_name', raw.get('contextname', '')) or '').strip()
    snmpv3_security_name = str(raw.get('snmpv3_security_name', raw.get('securityname', '')) or '').strip()
    snmpv3_auth_pass = str(raw.get('snmpv3_authentication_passphrase', raw.get('authpassphrase', '')) or '').strip()
    snmpv3_priv_pass = str(raw.get('snmpv3_privacy_passphrase', raw.get('privpassphrase', '')) or '').strip()
    if not snmpv3_security_name and snmp_version == 3:
        # Keep empty when not provided; don't auto-inject a macro without a value.
        snmpv3_security_name = ''

    # For auth/privacy passphrases, Zabbix host interface handling already maps these to
    # SNMP macros during host sync when snmp_pushcommunity is enabled.
    if snmpv3_auth_pass and _is_macro_syntax(snmpv3_auth_pass):
        snmpv3_auth_pass = ''
    if snmpv3_priv_pass and _is_macro_syntax(snmpv3_priv_pass):
        snmpv3_priv_pass = ''

    target = {
        'enabled': True,
        'zabbix_server_id': _normalize_positive_int(zabbix_server_id),
        'type': host_type,
        'interface_type': interface_main,
        'useip': useip,
        'dns': dns,
        'ip_id': ip_id,
        'port': int(port),
        'tls_connect': _normalize_positive_int(raw.get('tls_connect')) or 1,
        'tls_accept': _normalize_nbsync_tls_accept(raw.get('tls_accept')),
        'tls_issuer': str(raw.get('tls_issuer') or '').strip(),
        'tls_subject': str(raw.get('tls_subject') or '').strip(),
        'tls_psk_identity': str(raw.get('tls_psk_identity') or '').strip(),
        'tls_psk': str(raw.get('tls_psk') or '').strip(),
        'snmp_version': snmp_version,
        'snmp_usebulk': bool(snmp_usebulk),
        'snmp_pushcommunity': bool(snmp_pushcommunity),
        'snmp_community': snmp_community,
        'snmpv3_context_name': snmpv3_context_name,
        'snmpv3_security_name': snmpv3_security_name,
        'snmpv3_security_level': snmp_security_level,
        'snmpv3_authentication_passphrase': snmpv3_auth_pass,
        'snmpv3_authentication_protocol': snmp_auth_proto,
        'snmpv3_privacy_passphrase': snmpv3_priv_pass,
        'snmpv3_privacy_protocol': snmp_priv_proto,
        'ipmi_authtype': _int_or_default(raw.get('ipmi_authtype'), -1),
        'ipmi_password': str(raw.get('ipmi_password') or '').strip(),
        'ipmi_privilege': _int_or_default(raw.get('ipmi_privilege'), 2),
        'ipmi_username': str(raw.get('ipmi_username') or '').strip(),
        'explicit_macros': [],
    }

    if target['useip'] == 1 and target['ip_id'] is None:
        if target['dns']:
            target['useip'] = 0
        else:
            target['enabled'] = False
            target['reason'] = 'missing_primary_ip'
    if target['enabled'] and target['useip'] == 0 and not target['dns']:
        if target['ip_id'] is not None:
            target['useip'] = 1
        else:
            target['enabled'] = False
            target['reason'] = 'missing_primary_ip'

    return target


def _nbsync_host_interface_payload_from_target(device_id, zabbix_server_id, target):
    payload = {
        'assigned_object_type': 'dcim.device',
        'assigned_object_id': device_id,
        'zabbixserver': zabbix_server_id,
        'zabbixserver_id': zabbix_server_id,
        'type': int(target.get('type', 1)),
        'interface_type': int(target.get('interface_type', 1)),
        'useip': int(target.get('useip', 1)),
        'dns': str(target.get('dns') or '').strip(),
        'port': int(target.get('port', 10050)),
        'tls_connect': int(target.get('tls_connect', 1)),
        'tls_accept': list(target.get('tls_accept') or [1]),
        'tls_issuer': str(target.get('tls_issuer') or '').strip(),
        'tls_subject': str(target.get('tls_subject') or '').strip(),
        'tls_psk_identity': str(target.get('tls_psk_identity') or '').strip(),
        'tls_psk': str(target.get('tls_psk') or '').strip(),
        'snmp_version': int(target.get('snmp_version', 2)),
        'snmp_usebulk': bool(target.get('snmp_usebulk', True)),
        'snmp_pushcommunity': bool(target.get('snmp_pushcommunity', True)),
        'snmp_community': str(target.get('snmp_community') or '').strip(),
        'snmpv3_context_name': str(target.get('snmpv3_context_name') or '').strip(),
        'snmpv3_security_name': str(target.get('snmpv3_security_name') or '').strip(),
        'snmpv3_security_level': int(target.get('snmpv3_security_level', 0)),
        'snmpv3_authentication_passphrase': str(target.get('snmpv3_authentication_passphrase') or '').strip(),
        'snmpv3_authentication_protocol': int(target.get('snmpv3_authentication_protocol', 0)),
        'snmpv3_privacy_passphrase': str(target.get('snmpv3_privacy_passphrase') or '').strip(),
        'snmpv3_privacy_protocol': int(target.get('snmpv3_privacy_protocol', 0)),
        'ipmi_authtype': _int_or_default(target.get('ipmi_authtype'), -1),
        'ipmi_password': str(target.get('ipmi_password') or '').strip(),
        'ipmi_privilege': _int_or_default(target.get('ipmi_privilege'), 2),
        'ipmi_username': str(target.get('ipmi_username') or '').strip(),
    }
    ip_id = _normalize_positive_int(target.get('ip_id'))
    if ip_id is not None:
        payload['ip'] = ip_id
    else:
        payload['ip'] = None
    return payload


def _nbsync_host_interface_signature(row):
    if not isinstance(row, dict):
        return {}
    return {
        'zabbix_server_id': _normalize_positive_int(_extract_field_id(row.get('zabbixserver'))),
        'type': _normalize_positive_int(row.get('type')) or 1,
        'interface_type': _normalize_nbsync_interface_main(row.get('interface_type', 1), default=1),
        'useip': _normalize_nbsync_useip(row.get('useip', 1), default=1),
        'dns': str(row.get('dns') or '').strip(),
        'ip_id': _normalize_positive_int(_extract_field_id(row.get('ip'))),
        'port': _normalize_positive_int(row.get('port')) or 0,
        'snmp_version': _normalize_nbsync_snmp_version(row.get('snmp_version', 2), default=2),
        'snmp_usebulk': _parse_boolish(row.get('snmp_usebulk', True), default=True),
        'snmp_pushcommunity': _parse_boolish(row.get('snmp_pushcommunity', True), default=True),
        'snmp_community': str(row.get('snmp_community') or '').strip(),
        'snmpv3_context_name': str(row.get('snmpv3_context_name') or '').strip(),
        'snmpv3_security_name': str(row.get('snmpv3_security_name') or '').strip(),
        'snmpv3_security_level': _normalize_nbsync_snmp_security_level(row.get('snmpv3_security_level', 0), default=0),
        'snmpv3_authentication_passphrase': str(row.get('snmpv3_authentication_passphrase') or '').strip(),
        'snmpv3_authentication_protocol': _normalize_nbsync_snmp_auth_protocol(row.get('snmpv3_authentication_protocol', 0), default=0),
        'snmpv3_privacy_passphrase': str(row.get('snmpv3_privacy_passphrase') or '').strip(),
        'snmpv3_privacy_protocol': _normalize_nbsync_snmp_priv_protocol(row.get('snmpv3_privacy_protocol', 0), default=0),
        'ipmi_authtype': _int_or_default(row.get('ipmi_authtype'), -1),
        'ipmi_password': str(row.get('ipmi_password') or '').strip(),
        'ipmi_privilege': _int_or_default(row.get('ipmi_privilege'), 2),
        'ipmi_username': str(row.get('ipmi_username') or '').strip(),
    }


def _nbsync_upsert_host_interface(
    url, token, device_id, zabbix_server_id, interface_target, dry_run=False,
):
    if not interface_target or not isinstance(interface_target, dict):
        return 'none'
    if not bool(interface_target.get('enabled', False)):
        return interface_target.get('reason', 'disabled')

    zbx_id = _normalize_positive_int(zabbix_server_id or interface_target.get('zabbix_server_id'))
    if zbx_id is None:
        raise ValueError('Host interface requires a zabbix_server_id')

    desired_payload = _nbsync_host_interface_payload_from_target(device_id, zbx_id, interface_target)
    desired_sig = _nbsync_host_interface_signature(desired_payload)

    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixhostinterface',
        params={'assigned_object_id': device_id},
    )
    candidates = [r for r in rows if _nbsync_assignment_type_matches(r, 'dcim.device')]
    candidates.sort(
        key=lambda r: (
            0 if _normalize_positive_int(_extract_field_id(r.get('zabbixserver'))) == zbx_id else 1,
            0 if _normalize_nbsync_host_interface_type(r.get('type'), default=1) == desired_sig['type'] else 1,
            0 if _normalize_nbsync_interface_main(r.get('interface_type', 1), default=1) == desired_sig['interface_type'] else 1,
            _normalize_positive_int(r.get('id')) or 999999999,
        )
    )
    existing = candidates[0] if candidates else None

    if existing:
        cur_sig = _nbsync_host_interface_signature(existing)
        patch_payload = {}
        for key, desired in desired_sig.items():
            if key == 'zabbix_server_id':
                current = cur_sig.get('zabbix_server_id')
                if current != desired:
                    patch_payload['zabbixserver'] = desired
                    patch_payload['zabbixserver_id'] = desired
                continue
            current = cur_sig.get(key)
            if current != desired:
                payload_key = 'ip' if key == 'ip_id' else key
                patch_payload[payload_key] = desired

        if not patch_payload:
            return 'already'
        if dry_run:
            return 'would_update'

        row_id = existing.get('id')
        if not row_id:
            raise ValueError('Existing host interface row has no id')
        resp = requests.patch(
            f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixhostinterface/{row_id}/",
            headers=_nbsync_headers(token),
            json=patch_payload,
            verify=_requests_verify_for_url(url),
            timeout=30,
        )
        if resp.status_code >= 400:
            raise ValueError(f'Host interface update failed ({resp.status_code}): {resp.text[:200]}')
        return 'updated'

    if dry_run:
        return 'would_create'
    nb_post(url, token, 'plugins/nbxsync/zabbixhostinterface', desired_payload)
    return 'created'

def _build_nbsync_config_group_targets(rows_with_devices, options, include_hostgroups=True):
    """
    Build one merged target set for config-group inheritance mode.
    Macro names with multiple values across selected devices are skipped,
    because one config group cannot safely represent per-device values.
    """
    tags, hostgroups = [], []
    macro_name_case = {}
    macro_descriptions = {}
    macro_regex_flags = {}
    macro_values = {}  # lower(macro) -> set(values)

    for row in rows_with_devices:
        device = row.get('device') or {}
        targets = _build_nbsync_targets(
            device,
            options,
            apply_tags=bool(row.get('apply_tags', True)),
            apply_hostgroups=(include_hostgroups and bool(row.get('apply_hostgroups', True))),
            apply_macros=bool(row.get('apply_macros', False)),
            template_values=row.get('template_values'),
        )
        tags.extend(targets['tags'])
        hostgroups.extend(targets['hostgroups'])
        for m in targets['macros']:
            macro = _normalize_macro_name(m.get('macro') or '')
            value = str(m.get('value') or '').strip()
            description = str(m.get('description') or '').strip()
            is_regex = _parse_boolish(m.get('is_regex', False), default=False)
            if not macro:
                continue
            key = macro.lower()
            if key not in macro_name_case:
                macro_name_case[key] = macro
            if key not in macro_descriptions and description:
                macro_descriptions[key] = description
            if key not in macro_regex_flags:
                macro_regex_flags[key] = bool(is_regex)
            if key not in macro_values:
                macro_values[key] = set()
            macro_values[key].add(value)

    macros = []
    warnings = []
    for key in sorted(macro_values.keys()):
        values = macro_values[key]
        macro_name = macro_name_case[key]
        if len(values) > 1:
            warnings.append(
                f"Macro {macro_name} has multiple values across selected devices; "
                f"skipped in configuration-group mode."
            )
            continue
        macros.append({
            'macro': macro_name,
            'value': next(iter(values)),
            'description': macro_descriptions.get(key, ''),
            'is_regex': bool(macro_regex_flags.get(key, False)),
        })

    return {
        'tags': _unique_str_list(tags),
        'hostgroups': _unique_str_list(hostgroups),
        'macros': macros,
    }, warnings


def _nbsync_get_zabbix_server_from_config_group(url, token, config_group_id):
    assignments = fetch_all(
        url, token, 'plugins/nbxsync/zabbixhostgroupassignment',
        params={'zabbixconfigurationgroup_id': config_group_id},
    )
    if not assignments:
        return None
    hostgroup_id = _extract_field_id(assignments[0].get('zabbixhostgroup'))
    if not hostgroup_id:
        return None

    resp = requests.get(
        f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixhostgroup/{hostgroup_id}/",
        headers=_nbsync_headers(token),
        verify=_requests_verify_for_url(url),
        timeout=30,
    )
    if resp.status_code >= 400:
        return None
    hostgroup = resp.json()
    server = hostgroup.get('zabbixserver')
    return _extract_field_id(server)


def _nbsync_has_config_assignment(url, token, device_id, config_group_id):
    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixconfigurationgroupassignment',
        params={'assigned_object_id': device_id, 'zabbixconfigurationgroup_id': config_group_id},
    )
    return bool(rows)


def _nbsync_attach_config_group(url, token, device_id, config_group_id, dry_run=False):
    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixconfigurationgroupassignment',
        params={'assigned_object_id': device_id},
    )
    device_rows = [
        r for r in rows
        if _nbsync_assignment_type_matches(r, 'dcim.device')
    ]
    target_rows = [
        r for r in device_rows
        if _extract_field_id(r.get('zabbixconfigurationgroup')) == config_group_id
    ]
    other_rows = [
        r for r in device_rows
        if _extract_field_id(r.get('zabbixconfigurationgroup')) != config_group_id
    ]

    if target_rows:
        if not other_rows:
            return 'already_assigned'
        if dry_run:
            return 'would_cleanup_existing'
        removed = 0
        for row in other_rows:
            row_id = row.get('id')
            if not row_id:
                continue
            resp = requests.delete(
                f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixconfigurationgroupassignment/{row_id}/",
                headers=_nbsync_headers(token),
                verify=_requests_verify_for_url(url),
                timeout=30,
            )
            if resp.status_code in (200, 202, 204):
                removed += 1
        return 'already_assigned' if removed == 0 else 'cleaned_and_assigned'

    if other_rows:
        if dry_run:
            return 'would_reassign'

        primary = other_rows[0]
        primary_id = primary.get('id')
        if not primary_id:
            raise ValueError('Existing config assignment row has no id')
        patch_resp = requests.patch(
            f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixconfigurationgroupassignment/{primary_id}/",
            headers=_nbsync_headers(token),
            json={
                'zabbixconfigurationgroup': config_group_id,
                'zabbixconfigurationgroup_id': config_group_id,
            },
            verify=_requests_verify_for_url(url),
            timeout=30,
        )
        if patch_resp.status_code >= 400:
            raise ValueError(
                f"Failed to reassign config group ({patch_resp.status_code}): {patch_resp.text[:200]}"
            )

        # Defensive cleanup if duplicate assignments exist.
        for row in other_rows[1:]:
            row_id = row.get('id')
            if not row_id:
                continue
            requests.delete(
                f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixconfigurationgroupassignment/{row_id}/",
                headers=_nbsync_headers(token),
                verify=_requests_verify_for_url(url),
                timeout=30,
            )
        return 'reassigned'

    if dry_run:
        return 'would_assign'
    nb_post(url, token, 'plugins/nbxsync/zabbixconfigurationgroupassignment', {
        'assigned_object_type': 'dcim.device',
        'assigned_object_id': device_id,
        'zabbixconfigurationgroup': config_group_id,
    })
    return 'assigned'


def _nbsync_remove_server_assignments(url, token, device_id, dry_run=False):
    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixserverassignment',
        params={'assigned_object_id': device_id},
    )
    if not rows:
        return {'removed': 0, 'status': 'none'}
    if dry_run:
        return {'removed': len(rows), 'status': 'would_remove'}

    removed = 0
    for row in rows:
        row_id = row.get('id')
        if not row_id:
            continue
        resp = requests.delete(
            f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixserverassignment/{row_id}/",
            headers=_nbsync_headers(token),
            verify=_requests_verify_for_url(url),
            timeout=30,
        )
        if resp.status_code in (200, 202, 204):
            removed += 1
    return {'removed': removed, 'status': 'removed'}


def _nbsync_get_device_server_map(url, token):
    rows = fetch_all(url, token, 'plugins/nbxsync/zabbixserverassignment')
    out = {}
    for row in rows:
        if not _nbsync_assignment_type_matches(row, 'dcim.device'):
            continue
        did = _normalize_positive_int(_extract_field_id(row.get('assigned_object_id')))
        sid = _normalize_positive_int(_extract_field_id(row.get('zabbixserver')))
        if did is None or sid is None:
            continue
        out[did] = sid
    return out


def _nbsync_upsert_server_assignment(url, token, device_id, zabbix_server_id, dry_run=False):
    sid = _normalize_positive_int(zabbix_server_id)
    if sid is None:
        return 'no_server'

    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixserverassignment',
        params={'assigned_object_id': device_id},
    )
    target_rows = [r for r in rows if _nbsync_assignment_type_matches(r, 'dcim.device')]
    if not target_rows:
        if dry_run:
            return 'would_assign'
        nb_post(url, token, 'plugins/nbxsync/zabbixserverassignment', {
            'assigned_object_type': 'dcim.device',
            'assigned_object_id': device_id,
            'zabbixserver': sid,
            'zabbixserver_id': sid,
        })
        return 'assigned'

    same_rows = []
    diff_rows = []
    for row in target_rows:
        row_sid = _normalize_positive_int(_extract_field_id(row.get('zabbixserver')))
        if row_sid == sid:
            same_rows.append(row)
        else:
            diff_rows.append(row)

    if same_rows and not diff_rows and len(same_rows) == 1:
        return 'already'

    if dry_run:
        if diff_rows:
            return 'would_reassign'
        return 'would_cleanup'

    if same_rows:
        keep = same_rows[0]
    else:
        keep = diff_rows[0]
        keep_id = _normalize_positive_int(keep.get('id'))
        if keep_id is None:
            raise ValueError('Server assignment row has no id')
        patch_resp = requests.patch(
            f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixserverassignment/{keep_id}/",
            headers=_nbsync_headers(token),
            json={
                'zabbixserver': sid,
                'zabbixserver_id': sid,
            },
            verify=_requests_verify_for_url(url),
            timeout=30,
        )
        if patch_resp.status_code >= 400:
            raise ValueError(
                f"Failed to reassign zabbix server ({patch_resp.status_code}): {patch_resp.text[:200]}"
            )

    keep_id = _normalize_positive_int(keep.get('id'))
    for row in target_rows:
        row_id = _normalize_positive_int(row.get('id'))
        if row_id is None or (keep_id is not None and row_id == keep_id):
            continue
        requests.delete(
            f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixserverassignment/{row_id}/",
            headers=_nbsync_headers(token),
            verify=_requests_verify_for_url(url),
            timeout=30,
        )

    if diff_rows:
        return 'reassigned'
    return 'cleaned'


def _nbsync_clear_config_group_hostgroup_assignments(url, token, config_group_id, dry_run=False):
    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixhostgroupassignment',
        params={'zabbixconfigurationgroup_id': config_group_id},
    )
    # Only clear assignments that are attached to the config-group object itself.
    target_rows = [
        r for r in rows
        if _nbsync_assignment_type_matches(r, 'nbxsync.zabbixconfigurationgroup')
        and _extract_field_id(r.get('assigned_object_id')) == config_group_id
    ]
    if not target_rows:
        return {'removed': 0, 'status': 'none'}
    if dry_run:
        return {'removed': len(target_rows), 'status': 'would_remove'}

    removed = 0
    for row in target_rows:
        row_id = row.get('id')
        if not row_id:
            continue
        resp = requests.delete(
            f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixhostgroupassignment/{row_id}/",
            headers=_nbsync_headers(token),
            verify=_requests_verify_for_url(url),
            timeout=30,
        )
        if resp.status_code in (200, 202, 204):
            removed += 1
    return {'removed': removed, 'status': 'removed'}


def _nbsync_assignment_type_matches(row, assigned_object_type):
    target = str(assigned_object_type or '').strip().lower()
    if not target:
        return True
    row_type = row.get('assigned_object_type')
    if isinstance(row_type, dict):
        app_label = str(row_type.get('app_label') or '').strip().lower()
        model = str(row_type.get('model') or '').strip().lower()
        if app_label and model:
            return f'{app_label}.{model}' == target
        row_type = (
            row_type.get('value')
            or row_type.get('label')
            or row_type.get('name')
            or ''
        )
    row_type_s = str(row_type or '').strip().lower()
    if row_type_s:
        return row_type_s == target
    return True


def _nbsync_assign_relation(
    url, token, endpoint, relation_field, relation_id, assigned_object_id,
    dry_run=False, assigned_object_type='dcim.device', config_group_id=None,
    extra_payload=None,
):
    if relation_id is None:
        if dry_run:
            return 'would_assign'
        raise ValueError(f'{relation_field} id is required')

    params = {'assigned_object_id': assigned_object_id}
    if config_group_id is not None:
        params['zabbixconfigurationgroup_id'] = config_group_id
    rows = fetch_all(url, token, endpoint, params=params)
    for r in rows:
        if not _nbsync_assignment_type_matches(r, assigned_object_type):
            continue
        if _extract_field_id(r.get(relation_field)) == relation_id:
            return 'already'

    if dry_run:
        return 'would_assign'

    payload = {
        'assigned_object_type': assigned_object_type,
        'assigned_object_id': assigned_object_id,
        relation_field: relation_id,
    }
    if isinstance(extra_payload, dict):
        payload.update(extra_payload)
    if config_group_id is not None:
        payload['zabbixconfigurationgroup'] = config_group_id
        payload['zabbixconfigurationgroup_id'] = config_group_id
    nb_post(url, token, endpoint, payload)
    return 'assigned'


def _nbsync_get_or_create_tag(url, token, tag_name, zabbix_server_id, dry_run, cache):
    key = tag_name.lower()
    if key in cache['tags']:
        return cache['tags'][key], 'cached'

    existing = fetch_all(url, token, 'plugins/nbxsync/zabbixtag', params={'tag': tag_name})
    for row in existing:
        if str(row.get('tag', '')).strip() == tag_name:
            cache['tags'][key] = row['id']
            return row['id'], 'existing'

    if dry_run:
        return None, 'would_create'

    payload = {
        'name': f'NetBox Tag: {tag_name}',
        'tag': tag_name,
        'value': tag_name,
        'description': f'Auto-synced from NetBox tag: {tag_name}',
    }
    if zabbix_server_id:
        payload['zabbixserver'] = zabbix_server_id
        payload['zabbixserver_id'] = zabbix_server_id
    created = nb_post(url, token, 'plugins/nbxsync/zabbixtag', payload)
    cache['tags'][key] = created['id']
    return created['id'], 'created'


def _nbsync_assign_tag(
    url, token, assigned_object_id, tag_id, dry_run=False,
    assigned_object_type='dcim.device', config_group_id=None,
):
    return _nbsync_assign_relation(
        url=url,
        token=token,
        endpoint='plugins/nbxsync/zabbixtagassignment',
        relation_field='zabbixtag',
        relation_id=tag_id,
        assigned_object_id=assigned_object_id,
        assigned_object_type=assigned_object_type,
        config_group_id=config_group_id,
        dry_run=dry_run,
    )


def _nbsync_get_or_create_hostgroup(url, token, name, zabbix_server_id, dry_run, cache):
    name = _sanitize_nbsync_hostgroup_name(name)
    if not name:
        raise ValueError('Hostgroup name is empty after sanitization')

    cache_key = f"{name.lower()}::{zabbix_server_id or ''}"
    if cache_key in cache['hostgroups']:
        return cache['hostgroups'][cache_key], 'cached'

    params = {'name': name}
    if zabbix_server_id:
        params['zabbixserver_id'] = zabbix_server_id
    existing = fetch_all(url, token, 'plugins/nbxsync/zabbixhostgroup', params=params)
    for row in existing:
        if str(row.get('name', '')).strip() == name:
            row_server = _extract_field_id(row.get('zabbixserver'))
            if zabbix_server_id and row_server and int(row_server) != int(zabbix_server_id):
                continue
            cache['hostgroups'][cache_key] = row['id']
            return row['id'], 'existing'

    if dry_run:
        return None, 'would_create'

    payload = {'name': name, 'value': name}
    if zabbix_server_id:
        payload['zabbixserver'] = zabbix_server_id
        payload['zabbixserver_id'] = zabbix_server_id
    created = nb_post(url, token, 'plugins/nbxsync/zabbixhostgroup', payload)
    cache['hostgroups'][cache_key] = created['id']
    return created['id'], 'created'


def _nbsync_assign_hostgroup(
    url, token, assigned_object_id, hostgroup_id, dry_run=False,
    assigned_object_type='dcim.device', config_group_id=None,
):
    return _nbsync_assign_relation(
        url=url,
        token=token,
        endpoint='plugins/nbxsync/zabbixhostgroupassignment',
        relation_field='zabbixhostgroup',
        relation_id=hostgroup_id,
        assigned_object_id=assigned_object_id,
        assigned_object_type=assigned_object_type,
        config_group_id=config_group_id,
        dry_run=dry_run,
    )


def _nbsync_get_or_create_macro(url, token, macro_name, macro_value, zabbix_server_id, dry_run, cache, macro_description=''):
    macro_name = _normalize_macro_name(macro_name)
    macro_value = str(macro_value or '').strip()
    macro_description = str(macro_description or '').strip()
    zabbix_server_id = _normalize_positive_int(zabbix_server_id)
    key = f"{macro_name.lower()}::{macro_value}::{zabbix_server_id or ''}"
    if key in cache['macros']:
        return cache['macros'][key], 'cached'

    # Zabbix macros are scoped to an assigned object (typically zabbix server or template).
    params = {'macro': macro_name}
    if zabbix_server_id is not None:
        params['assigned_object_type'] = 'nbxsync.zabbixserver'
        params['assigned_object_id'] = zabbix_server_id
    existing = fetch_all(url, token, 'plugins/nbxsync/zabbixmacro', params=params)
    for row in existing:
        row_macro = str(row.get('macro', '')).strip()
        row_value = str(row.get('value', '')).strip()
        if row_macro != macro_name or row_value != macro_value:
            continue
        if zabbix_server_id is not None:
            row_assigned_id = _normalize_positive_int(row.get('assigned_object_id'))
            if row_assigned_id is None and isinstance(row.get('assigned_object'), dict):
                row_assigned_id = _normalize_positive_int(row.get('assigned_object').get('id'))
            if row_assigned_id != zabbix_server_id:
                continue
            if not _nbsync_assignment_type_matches(row, 'nbxsync.zabbixserver'):
                continue
        cache['macros'][key] = row['id']
        return row['id'], 'existing'

    if dry_run:
        return None, 'would_create'

    macro_type = '1' if _nbsync_is_sensitive_macro_name(macro_name) else '0'
    payload = {
        'macro': macro_name,
        'value': macro_value,
        'description': macro_description or f'Auto-managed by Netbox Helper ({macro_name})',
        'type': macro_type,
    }
    if zabbix_server_id is not None:
        payload['assigned_object_type'] = 'nbxsync.zabbixserver'
        payload['assigned_object_id'] = zabbix_server_id
    else:
        raise ValueError(f"Cannot create macro {macro_name}: missing zabbix server assignment")
    created = nb_post(url, token, 'plugins/nbxsync/zabbixmacro', payload)
    cache['macros'][key] = created['id']
    return created['id'], 'created'


def _nbsync_assign_macro(
    url, token, assigned_object_id, macro_id, macro_value='', is_regex=False, dry_run=False,
    assigned_object_type='dcim.device', config_group_id=None,
):
    return _nbsync_assign_relation(
        url=url,
        token=token,
        endpoint='plugins/nbxsync/zabbixmacroassignment',
        relation_field='zabbixmacro',
        relation_id=macro_id,
        assigned_object_id=assigned_object_id,
        assigned_object_type=assigned_object_type,
        config_group_id=config_group_id,
        extra_payload={
            'value': str(macro_value or '').strip(),
            'is_regex': bool(is_regex),
        },
        dry_run=dry_run,
    )


def _nbsync_apply_explicit_macros(
    url, token, assigned_object_id, zabbix_server_id, macro_rows, dry_run=False, cache=None,
):
    if cache is None:
        cache = {'tags': {}, 'hostgroups': {}, 'macros': {}}
    messages = []
    errors = []
    for row in (macro_rows or []):
        if not isinstance(row, dict):
            continue
        macro_name = _normalize_macro_name(row.get('macro') or '')
        macro_value = str(row.get('value') or '').strip()
        macro_description = str(row.get('description') or '').strip()
        macro_is_regex = _parse_boolish(row.get('is_regex', False), default=False)
        if not macro_name:
            continue
        try:
            macro_id, macro_state = _nbsync_get_or_create_macro(
                url, token, macro_name, macro_value, zabbix_server_id, dry_run, cache, macro_description=macro_description
            )
            if dry_run:
                messages.append(f"Macro {macro_name}: {macro_state}")
                continue
            if macro_id is None:
                continue
            asn = _nbsync_assign_macro(
                url, token, assigned_object_id, macro_id,
                macro_value=macro_value,
                is_regex=macro_is_regex,
                dry_run=False,
            )
            messages.append(f"Macro {macro_name}: {asn}")
        except Exception as e:
            errors.append(f"Macro {macro_name} failed: {e}")
    return messages, errors


def _nbsync_upsert_host_inventory(
    url, token, assigned_object_id, inventory_mode, inventory_fields, dry_run=False,
    assigned_object_type='dcim.device',
):
    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixhostinventory',
        params={'assigned_object_id': assigned_object_id},
    )
    existing = None
    for row in rows:
        if _nbsync_assignment_type_matches(row, assigned_object_type):
            existing = row
            break

    desired_mode = _normalize_inventory_mode(inventory_mode)
    desired_fields = {}
    for key, value in (inventory_fields or {}).items():
        field_name = str(key or '').strip()
        if not field_name:
            continue
        desired_fields[field_name] = str(value or '').strip()

    if existing:
        patch_payload = {}
        try:
            current_mode = int(existing.get('inventory_mode', 0))
        except Exception:
            current_mode = 0
        if current_mode != desired_mode:
            patch_payload['inventory_mode'] = desired_mode
        for field, val in desired_fields.items():
            cur = str(existing.get(field) or '').strip()
            if cur != val:
                patch_payload[field] = val

        if not patch_payload:
            return 'already'
        if dry_run:
            return 'would_update'

        row_id = existing.get('id')
        if not row_id:
            raise ValueError('Found existing host inventory row without id')
        resp = requests.patch(
            f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixhostinventory/{row_id}/",
            headers=_nbsync_headers(token),
            json=patch_payload,
            verify=_requests_verify_for_url(url),
            timeout=30,
        )
        if resp.status_code >= 400:
            raise ValueError(f'Host inventory update failed ({resp.status_code}): {resp.text[:200]}')
        return 'updated'

    if dry_run:
        return 'would_create'

    payload = {
        'assigned_object_type': assigned_object_type,
        'assigned_object_id': assigned_object_id,
        'inventory_mode': desired_mode,
    }
    payload.update(desired_fields)
    nb_post(url, token, 'plugins/nbxsync/zabbixhostinventory', payload)
    return 'created'


def _nbsync_list_tags(url, token):
    rows = fetch_all(url, token, 'plugins/nbxsync/zabbixtag', params={'limit': 2000})
    seen = set()
    out = []
    for r in rows:
        tag = str(r.get('tag') or '').strip()
        if not tag:
            continue
        key = tag.lower()
        if key in seen:
            continue
        seen.add(key)
        name = str(r.get('name') or '').strip() or f'NetBox Tag: {tag}'
        value = str(r.get('value') or '').strip() or tag
        out.append({
            'id': r.get('id'),
            'name': name,
            'tag': tag,
            'value': value,
        })
    out.sort(key=lambda x: (x['tag'].lower(), x['name'].lower()))
    return out


def _nbsync_list_config_group_tags(url, token, config_group_id):
    rows = fetch_all(
        url, token, 'plugins/nbxsync/zabbixtagassignment',
        params={'zabbixconfigurationgroup_id': config_group_id},
    )

    tag_ids = set()
    for r in rows:
        if not _nbsync_assignment_type_matches(r, 'nbxsync.zabbixconfigurationgroup'):
            continue
        rid = r.get('assigned_object_id')
        if rid is None and isinstance(r.get('assigned_object'), dict):
            rid = r['assigned_object'].get('id')
        try:
            rid_i = int(rid)
        except Exception:
            continue
        if rid_i != int(config_group_id):
            continue
        tid = _extract_field_id(r.get('zabbixtag'))
        try:
            tid_i = int(tid)
        except Exception:
            continue
        if tid_i > 0:
            tag_ids.add(tid_i)

    if not tag_ids:
        return []

    all_tags = _nbsync_list_tags(url, token)
    by_id = {}
    for t in all_tags:
        try:
            tid = int(t.get('id'))
        except Exception:
            continue
        by_id[tid] = t

    out = []
    for tid in sorted(tag_ids):
        tag_row = by_id.get(tid)
        if tag_row:
            out.append(tag_row)
            continue
        try:
            resp = requests.get(
                f"{url.rstrip('/')}/api/plugins/nbxsync/zabbixtag/{tid}/",
                headers=_nbsync_headers(token),
                verify=_requests_verify_for_url(url),
                timeout=30,
            )
            if resp.status_code >= 400:
                continue
            row = resp.json()
            tag = str(row.get('tag') or '').strip()
            if not tag:
                continue
            out.append({
                'id': tid,
                'name': str(row.get('name') or f'NetBox Tag: {tag}').strip(),
                'tag': tag,
                'value': str(row.get('value') or tag).strip(),
            })
        except Exception:
            continue
    out.sort(key=lambda x: (str(x.get('tag') or '').lower(), str(x.get('name') or '').lower()))
    return out


def _nbsync_list_hostgroup_names(url, token):
    rows = fetch_all(url, token, 'plugins/nbxsync/zabbixhostgroup', params={'limit': 2000})
    out = []
    seen = set()
    for r in rows:
        name = str(r.get('name') or '').strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    out.sort(key=lambda x: x.lower())
    return out


def _nbsync_list_hostgroups_by_id(url, token):
    rows = fetch_all(url, token, 'plugins/nbxsync/zabbixhostgroup', params={'limit': 2000})
    out = {}
    for r in rows:
        rid = _normalize_positive_int(r.get('id'))
        if rid is None:
            continue
        name = str(r.get('name') or r.get('value') or '').strip()
        if not name:
            continue
        out[rid] = name
    return out


def _nbsync_list_macros_by_id(url, token):
    rows = fetch_all(url, token, 'plugins/nbxsync/zabbixmacro', params={'limit': 2000})
    out = {}
    for r in rows:
        rid = _normalize_positive_int(r.get('id'))
        if rid is None:
            continue
        macro = str(r.get('macro') or r.get('name') or '').strip()
        if not macro:
            continue
        out[rid] = {
            'macro': macro,
            'value': str(r.get('value') or '').strip(),
        }
    return out


def _nbsync_collect_device_current_state(url, token, device_ids, inventory_field_names=None):
    state = {}
    ids = set()
    for rid in device_ids or []:
        try:
            n = int(rid)
        except Exception:
            continue
        if n > 0:
            ids.add(n)
            state[n] = {
                'config_groups': set(),
                'tags': set(),
                'hostgroups': set(),
                'macros': set(),  # (macro, value)
                'inventory_mode': None,
                'inventory_fields': {},
                'host_interface': None,
            }
    if not ids:
        return state

    sorted_ids = sorted(ids)
    if len(sorted_ids) == 1:
        scoped_params = {'assigned_object_id': sorted_ids[0]}
    else:
        scoped_params = {'assigned_object_id__in': ','.join(str(x) for x in sorted_ids)}

    def _fetch_rows_scoped(endpoint):
        try:
            return fetch_all(url, token, endpoint, params=scoped_params)
        except Exception:
            # Fallback for Zabbix versions that do not support these filters.
            return fetch_all(url, token, endpoint)

    field_names = _unique_str_list(inventory_field_names or [])

    # Config group assignments
    try:
        rows = _fetch_rows_scoped('plugins/nbxsync/zabbixconfigurationgroupassignment')
        for r in rows:
            if not _nbsync_assignment_type_matches(r, 'dcim.device'):
                continue
            rid = _extract_field_id(r.get('assigned_object_id'))
            try:
                rid = int(rid)
            except Exception:
                continue
            if rid not in ids:
                continue
            gid = _normalize_positive_int(_extract_field_id(r.get('zabbixconfigurationgroup')))
            if gid is not None:
                state[rid]['config_groups'].add(gid)
    except Exception:
        pass

    # Tags
    tag_by_id = {}
    try:
        for t in _nbsync_list_tags(url, token):
            tid = _normalize_positive_int(t.get('id'))
            if tid is None:
                continue
            tag_value = str(t.get('tag') or t.get('value') or t.get('name') or '').strip()
            if tag_value:
                tag_by_id[tid] = tag_value
    except Exception:
        tag_by_id = {}

    try:
        rows = _fetch_rows_scoped('plugins/nbxsync/zabbixtagassignment')
        for r in rows:
            if not _nbsync_assignment_type_matches(r, 'dcim.device'):
                continue
            rid = _extract_field_id(r.get('assigned_object_id'))
            try:
                rid = int(rid)
            except Exception:
                continue
            if rid not in ids:
                continue

            tag_name = ''
            tag_ref = r.get('zabbixtag')
            tid = _normalize_positive_int(_extract_field_id(tag_ref))
            if isinstance(tag_ref, dict):
                tag_name = str(
                    tag_ref.get('tag') or tag_ref.get('value') or tag_ref.get('name') or ''
                ).strip()
            if not tag_name and tid is not None:
                tag_name = str(tag_by_id.get(tid) or '').strip()
            if tag_name:
                state[rid]['tags'].add(tag_name)
    except Exception:
        pass

    # Hostgroups
    hostgroup_by_id = {}
    try:
        hostgroup_by_id = _nbsync_list_hostgroups_by_id(url, token)
    except Exception:
        hostgroup_by_id = {}

    try:
        rows = _fetch_rows_scoped('plugins/nbxsync/zabbixhostgroupassignment')
        for r in rows:
            if not _nbsync_assignment_type_matches(r, 'dcim.device'):
                continue
            rid = _extract_field_id(r.get('assigned_object_id'))
            try:
                rid = int(rid)
            except Exception:
                continue
            if rid not in ids:
                continue

            hg_name = ''
            hg_ref = r.get('zabbixhostgroup')
            hid = _normalize_positive_int(_extract_field_id(hg_ref))
            if isinstance(hg_ref, dict):
                hg_name = str(hg_ref.get('name') or hg_ref.get('value') or '').strip()
            if not hg_name and hid is not None:
                hg_name = str(hostgroup_by_id.get(hid) or '').strip()
            if hg_name:
                state[rid]['hostgroups'].add(hg_name)
    except Exception:
        pass

    # Macros
    macro_by_id = {}
    try:
        macro_by_id = _nbsync_list_macros_by_id(url, token)
    except Exception:
        macro_by_id = {}

    try:
        rows = _fetch_rows_scoped('plugins/nbxsync/zabbixmacroassignment')
        for r in rows:
            if not _nbsync_assignment_type_matches(r, 'dcim.device'):
                continue
            rid = _extract_field_id(r.get('assigned_object_id'))
            try:
                rid = int(rid)
            except Exception:
                continue
            if rid not in ids:
                continue

            macro_name = ''
            macro_value = ''
            macro_ref = r.get('zabbixmacro')
            mid = _normalize_positive_int(_extract_field_id(macro_ref))
            if isinstance(macro_ref, dict):
                macro_name = str(macro_ref.get('macro') or macro_ref.get('name') or '').strip()
                macro_value = str(macro_ref.get('value') or '').strip()
            if not macro_name and mid is not None:
                mrow = macro_by_id.get(mid) or {}
                macro_name = str(mrow.get('macro') or '').strip()
                macro_value = str(mrow.get('value') or '').strip()
            if macro_name:
                state[rid]['macros'].add((macro_name, macro_value))
    except Exception:
        pass

    # Inventory
    try:
        rows = _fetch_rows_scoped('plugins/nbxsync/zabbixhostinventory')
        for r in rows:
            if not _nbsync_assignment_type_matches(r, 'dcim.device'):
                continue
            rid = _extract_field_id(r.get('assigned_object_id'))
            try:
                rid = int(rid)
            except Exception:
                continue
            if rid not in ids:
                continue
            if state[rid].get('inventory_mode') is not None:
                continue
            try:
                state[rid]['inventory_mode'] = int(r.get('inventory_mode', 0))
            except Exception:
                state[rid]['inventory_mode'] = 0
            fields = {}
            for fname in field_names:
                fields[fname] = str(r.get(fname) or '').strip()
            state[rid]['inventory_fields'] = fields
    except Exception:
        pass

    # Host interface (default/preferred per device)
    try:
        rows = _fetch_rows_scoped('plugins/nbxsync/zabbixhostinterface')
        by_device = {}
        for r in rows:
            if not _nbsync_assignment_type_matches(r, 'dcim.device'):
                continue
            rid = _normalize_positive_int(_extract_field_id(r.get('assigned_object_id')))
            if rid is None or rid not in ids:
                continue
            by_device.setdefault(rid, []).append(r)

        for rid, rlist in by_device.items():
            rlist.sort(
                key=lambda r: (
                    0 if _normalize_nbsync_interface_main(r.get('interface_type', 1), default=1) == 1 else 1,
                    _normalize_positive_int(r.get('id')) or 999999999,
                )
            )
            state[rid]['host_interface'] = _nbsync_host_interface_signature(rlist[0])
    except Exception:
        pass

    return state


def _nbsync_build_pull_diff_lines(row, current_state, options, config_group_id):
    current = current_state or {}
    device_id = _normalize_positive_int(row.get('device_id')) or 0
    device_name = str(row.get('name') or f'id:{device_id}')
    has_changes = False
    lines = [
        f"diff --nbxsync device/{device_id} ({device_name})",
        "--- current",
        "+++ planned",
    ]

    max_items = 10

    current_groups = sorted(
        int(x) for x in (current.get('config_groups') or set()) if _normalize_positive_int(x) is not None
    )
    lines.append("@@ config-group @@")
    if not current_groups:
        has_changes = True
        lines.append("- none")
        lines.append(f"+ {config_group_id}")
    elif config_group_id in current_groups and len(current_groups) == 1:
        lines.append(f"  {config_group_id} (no change)")
    elif config_group_id in current_groups:
        has_changes = True
        extras = [g for g in current_groups if g != config_group_id]
        for g in extras[:max_items]:
            lines.append(f"- {g}")
        if len(extras) > max_items:
            lines.append(f"- ... {len(extras) - max_items} more")
        lines.append(f"  {config_group_id} (kept)")
    else:
        has_changes = True
        for g in current_groups[:max_items]:
            lines.append(f"- {g}")
        if len(current_groups) > max_items:
            lines.append(f"- ... {len(current_groups) - max_items} more")
        lines.append(f"+ {config_group_id}")

    targets = row.get('targets') or {}
    use_cfg_inheritance = bool(options.get('use_configuration_group_inheritance', True))

    lines.append("@@ tags @@")
    if use_cfg_inheritance:
        lines.append("~ managed via configuration-group inheritance")
    else:
        target_tags = sorted(set(targets.get('tags') or []))
        current_tags = set(current.get('tags') or set())
        add_tags = [t for t in target_tags if t not in current_tags]
        if not add_tags:
            lines.append("  no direct additions")
        else:
            has_changes = True
            for t in add_tags[:max_items]:
                lines.append(f"+ {t}")
            if len(add_tags) > max_items:
                lines.append(f"+ ... {len(add_tags) - max_items} more")

    lines.append("@@ hostgroups @@")
    target_hostgroups = sorted(set(targets.get('hostgroups') or []))
    current_hostgroups = set(current.get('hostgroups') or set())
    add_hostgroups = [h for h in target_hostgroups if h not in current_hostgroups]
    if not add_hostgroups:
        lines.append("  no direct additions")
    else:
        has_changes = True
        for h in add_hostgroups[:max_items]:
            lines.append(f"+ {h}")
        if len(add_hostgroups) > max_items:
            lines.append(f"+ ... {len(add_hostgroups) - max_items} more")

    lines.append("@@ macros @@")
    interface_targets = row.get('interface_targets') if isinstance(row.get('interface_targets'), dict) else {}
    explicit_interface_macros = [
        {'macro': str(m.get('macro') or '').strip(), 'value': str(m.get('value') or '').strip()}
        for m in (interface_targets.get('explicit_macros') or [])
        if isinstance(m, dict) and str(m.get('macro') or '').strip()
    ]
    base_macro_targets = list(targets.get('macros') or [])
    target_macros = sorted(
        {
            (str(m.get('macro') or '').strip(), str(m.get('value') or '').strip())
            for m in (base_macro_targets + explicit_interface_macros)
            if str(m.get('macro') or '').strip()
        }
    )
    current_macros = set(current.get('macros') or set())
    add_macros = [
        _nbsync_format_macro_for_diff(m, v)
        for (m, v) in target_macros
        if (m, v) not in current_macros
    ]
    if use_cfg_inheritance:
        lines.append("~ managed via configuration-group inheritance")
        if not add_macros:
            lines.append("  no direct additions")
        else:
            has_changes = True
            for mv in add_macros[:max_items]:
                lines.append(f"+ {mv}")
            if len(add_macros) > max_items:
                lines.append(f"+ ... {len(add_macros) - max_items} more")
    else:
        if not add_macros:
            lines.append("  no direct additions")
        else:
            has_changes = True
            for mv in add_macros[:max_items]:
                lines.append(f"+ {mv}")
            if len(add_macros) > max_items:
                lines.append(f"+ ... {len(add_macros) - max_items} more")

    if bool(options.get('use_host_inventory', True)):
        lines.append("@@ inventory @@")
        inv_targets = row.get('inventory_targets') or {}
        to_mode = _normalize_inventory_mode(inv_targets.get('inventory_mode', 0))
        from_mode = current.get('inventory_mode')
        if from_mode is None:
            has_changes = True
            lines.append("- mode: none")
            lines.append(f"+ mode: {to_mode}")
        elif int(from_mode) != int(to_mode):
            has_changes = True
            lines.append(f"- mode: {from_mode}")
            lines.append(f"+ mode: {to_mode}")
        else:
            lines.append(f"  mode: {to_mode} (no change)")

        target_fields = inv_targets.get('fields') or {}
        current_fields = current.get('inventory_fields') or {}
        changed_keys = [
            k for k in sorted(target_fields.keys())
            if str(current_fields.get(k) or '').strip() != str(target_fields.get(k) or '').strip()
        ]
        if not changed_keys:
            lines.append("  fields: no direct updates")
        else:
            has_changes = True
            for k in changed_keys[:max_items]:
                old_v = str(current_fields.get(k) or '').strip()
                new_v = str(target_fields.get(k) or '').strip()
                lines.append(f"- {k}: {old_v or '<empty>'}")
                lines.append(f"+ {k}: {new_v or '<empty>'}")
            if len(changed_keys) > max_items:
                lines.append(f"~ ... {len(changed_keys) - max_items} more field changes")

    if bool(options.get('use_host_interface', True)):
        lines.append("@@ host-interface @@")
        iface_target = row.get('interface_targets') or {}
        if not isinstance(iface_target, dict) or not bool(iface_target.get('enabled', False)):
            lines.append("  no context interface")
        else:
            desired_server = (
                _normalize_positive_int(row.get('zabbix_server_id'))
                or _normalize_positive_int(iface_target.get('zabbix_server_id'))
                or _normalize_positive_int(options.get('selected_zabbix_server_id'))
                or _normalize_positive_int((current.get('host_interface') or {}).get('zabbix_server_id'))
            )
            if desired_server is None:
                has_changes = True
                lines.append("- unresolved zabbix server for host interface")
            else:
                desired_payload = _nbsync_host_interface_payload_from_target(
                    device_id, desired_server, iface_target
                )
                desired_sig = _nbsync_host_interface_signature(desired_payload)
                current_sig = current.get('host_interface') or {}
                if not current_sig:
                    has_changes = True
                    lines.append("- none")
                    lines.append(
                        f"+ create type={desired_sig.get('type')} port={desired_sig.get('port')} "
                        f"useip={desired_sig.get('useip')}"
                    )
                else:
                    cmp_keys = [
                        'zabbix_server_id', 'type', 'interface_type', 'useip', 'dns', 'ip_id', 'port',
                        'snmp_version', 'snmp_community', 'snmpv3_security_level', 'snmpv3_security_name',
                        'snmpv3_authentication_passphrase', 'snmpv3_privacy_passphrase',
                        'ipmi_authtype', 'ipmi_privilege',
                    ]
                    changed = []
                    for key in cmp_keys:
                        if current_sig.get(key) != desired_sig.get(key):
                            changed.append(key)
                    if not changed:
                        lines.append("  no direct updates")
                    else:
                        has_changes = True
                        for key in changed[:max_items]:
                            old_v = current_sig.get(key)
                            new_v = desired_sig.get(key)
                            if key in ('snmp_community', 'snmpv3_authentication_passphrase', 'snmpv3_privacy_passphrase'):
                                old_v = '<set>' if str(old_v or '').strip() else '<empty>'
                                new_v = '<set>' if str(new_v or '').strip() else '<empty>'
                            lines.append(f"- {key}: {old_v if old_v not in (None, '') else '<empty>'}")
                            lines.append(f"+ {key}: {new_v if new_v not in (None, '') else '<empty>'}")
                        if len(changed) > max_items:
                            lines.append(f"~ ... {len(changed) - max_items} more interface field changes")

    if not has_changes:
        return ['IN SYNC']
    return lines


def _nbsync_list_config_groups(url, token):
    rows = fetch_all(url, token, 'plugins/nbxsync/zabbixconfigurationgroup', params={'limit': 2000})
    out = []
    for r in rows:
        gid = r.get('id')
        if not gid:
            continue
        name = str(r.get('name') or '').strip()
        value = str(r.get('value') or '').strip()
        description = str(r.get('description') or '').strip()
        display = name or value or f'Config Group {gid}'
        zserver = r.get('zabbixserver')
        out.append({
            'id': int(gid),
            'name': display,
            'value': value,
            'description': description,
            'zabbix_server_id': _extract_field_id(zserver),
            'zabbix_server_name': (
                str((zserver or {}).get('name') or '').strip()
                if isinstance(zserver, dict) else ''
            ),
        })
    out.sort(key=lambda x: (x['name'].lower(), x['id']))
    return out


def _nbsync_list_servers(url, token):
    rows = fetch_all(url, token, 'plugins/nbxsync/zabbixserver', params={'limit': 2000})
    out = []
    for r in rows:
        sid = r.get('id')
        if not sid:
            continue
        name = str(r.get('name') or '').strip()
        value = str(r.get('value') or '').strip()
        host = str(r.get('host') or '').strip()
        display = name or value or host or f'Server {sid}'
        out.append({
            'id': int(sid),
            'name': display,
            'value': value,
            'host': host,
            'description': str(r.get('description') or '').strip(),
        })
    out.sort(key=lambda x: (x['name'].lower(), x['id']))
    return out


def _nbsync_default_interface_example_contexts():
    return [
        {
            'name': 'Example_AGENT',
            'description': 'Zabbix interface example (agent)',
            'data': {
                'interface': {
                    'type': 'Agent',
                    'interface_type': 1,
                    'use_ip': True,
                    'dns': '',
                    'port': 10050,
                    'main': 1,
                    'tls_connect': 1,
                    'tls_accept': [1],
                },
            },
        },
        {
            'name': 'Example_SNMP_V2C',
            'description': 'Zabbix interface example (snmp_v2c)',
            'data': {
                'interface': {
                    'type': 'SNMP',
                    'interface_type': 1,
                    'use_ip': True,
                    'dns': '',
                    'port': 161,
                    'main': 1,
                    'snmp_version': 2,
                    'snmp_usebulk': True,
                    'snmp_pushcommunity': True,
                    'snmp_community': '{$SNMP_COMMUNITY}',
                },
            },
        },
        {
            'name': 'Example_SNMP_V3_AUTH_NO_PRIV',
            'description': 'Zabbix interface example (snmp_v3_auth_no_priv)',
            'data': {
                'interface': {
                    'type': 2,
                    'interface_type': 1,
                    'use_ip': True,
                    'dns': '',
                    'port': 161,
                    'main': 1,
                    'snmp_version': 3,
                    'snmp_usebulk': True,
                    'snmp_pushcommunity': True,
                    'snmp_community': '',
                    'snmpv3_context_name': '',
                    'snmpv3_security_name': '{$SNMP_SECURITYNAME}',
                    'snmpv3_security_level': 1,
                    'snmpv3_authentication_protocol': 1,
                    'snmpv3_authentication_passphrase': '{$SNMP_AUTH_PASSPHRASE}',
                    'snmpv3_privacy_protocol': 0,
                    'snmpv3_privacy_passphrase': '',
                },
            },
        },
        {
            'name': 'Example_SNMP_V3_AUTH_PRIV',
            'description': 'Zabbix interface example (snmp_v3_auth_priv)',
            'data': {
                'interface': {
                    'type': 'SNMP',
                    'interface_type': 1,
                    'use_ip': True,
                    'dns': '',
                    'port': 161,
                    'main': 1,
                    'snmp_version': 3,
                    'snmp_usebulk': True,
                    'snmp_pushcommunity': True,
                    'snmp_community': '',
                    'snmpv3_context_name': '',
                    'snmpv3_security_name': '{$SNMP_SECURITYNAME}',
                    'snmpv3_security_level': 2,
                    'snmpv3_authentication_protocol': 3,
                    'snmpv3_authentication_passphrase': '{$SNMP_AUTH_PASSPHRASE}',
                    'snmpv3_privacy_protocol': 3,
                    'snmpv3_privacy_passphrase': '{$SNMP_PRIV_PASSPHRASE}',
                },
            },
        },
        {
            'name': 'Example_IPMI',
            'description': 'Zabbix interface example (ipmi)',
            'data': {
                'interface': {
                    'type': 'IPMI',
                    'interface_type': 1,
                    'use_ip': True,
                    'dns': '',
                    'port': 623,
                    'main': 1,
                    'ipmi_authtype': -1,
                    'ipmi_privilege': 2,
                    'ipmi_username': 'admin',
                    'ipmi_password': 'changeme',
                },
            },
        },
        {
            'name': 'Example_JMX',
            'description': 'Zabbix interface example (jmx)',
            'data': {
                'interface': {
                    'type': 'JMX',
                    'interface_type': 1,
                    'use_ip': True,
                    'dns': '',
                    'port': 12345,
                    'main': 1,
                },
            },
        },
    ]


def _nbsync_load_interface_example_contexts():
    examples = []
    if os.path.exists(NBSYNC_INTERFACE_EXAMPLES_FILE):
        try:
            with open(NBSYNC_INTERFACE_EXAMPLES_FILE, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            src = raw.get('examples') if isinstance(raw, dict) else None
            if isinstance(src, dict):
                for key, row in src.items():
                    if not isinstance(row, dict):
                        continue
                    data = json.loads(json.dumps(row))
                    if not isinstance(data, dict) or not data:
                        continue
                    key_s = str(key or '').strip()
                    if not key_s:
                        continue
                    examples.append({
                        'name': f'Example_{key_s.upper()}',
                        'description': f'Zabbix interface example ({key_s})',
                        'data': data,
                    })
        except Exception:
            examples = []

    if not examples:
        examples = _nbsync_default_interface_example_contexts()

    seen = set()
    out = []
    for row in examples:
        name = str(row.get('name') or '').strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({
            'name': name,
            'description': str(row.get('description') or '').strip(),
            'data': row.get('data') if isinstance(row.get('data'), dict) else {},
        })
    out.sort(key=lambda x: x['name'].lower())
    return out


def _nbsync_build_interface_example_diff(name, existing_row, desired_row):
    lines = [
        f"diff --nbxsync config-context/{name}",
        "--- current",
        "+++ planned",
    ]
    has_changes = False
    if not isinstance(existing_row, dict):
        has_changes = True
        lines.append("@@ state @@")
        lines.append("- missing")
        lines.append("+ create disabled example context")
        lines.append("@@ data @@")
        lines.append("+ apply interface example payload")
        return lines

    current_active = bool(existing_row.get('is_active', True))
    desired_active = bool(desired_row.get('is_active', False))
    lines.append("@@ state @@")
    if current_active != desired_active:
        has_changes = True
        lines.append(f"- is_active: {str(current_active).lower()}")
        lines.append(f"+ is_active: {str(desired_active).lower()}")
    else:
        lines.append(f"  is_active: {str(desired_active).lower()} (no change)")

    current_data = existing_row.get('data')
    if not isinstance(current_data, dict):
        current_data = {}
    desired_data = desired_row.get('data')
    if not isinstance(desired_data, dict):
        desired_data = {}

    lines.append("@@ data @@")
    if current_data == desired_data:
        lines.append("  no data changes")
    else:
        has_changes = True
        lines.append("~ interface payload differs")
        lines.append("+ apply interface example payload")

    if not has_changes:
        return ['IN SYNC']
    return lines


def _nbsync_sync_interface_example_contexts(url, token, dry_run=False):
    targets = _nbsync_load_interface_example_contexts()
    results = []
    totals = {'in_sync': 0, 'created': 0, 'updated': 0, 'dry_run': 0, 'error': 0}

    for target in targets:
        name = target['name']
        description = target.get('description') or f'Zabbix interface example ({name})'
        data_payload = target.get('data') if isinstance(target.get('data'), dict) else {}
        desired = {
            'name': name,
            'description': description,
            'is_active': False,
            'weight': 1000,
            'data': data_payload,
        }
        try:
            rows = fetch_all(url, token, 'extras/config-contexts', params={'name': name})
            existing = next(
                (r for r in rows if str(r.get('name') or '').strip() == name),
                None,
            )
            diff_lines = _nbsync_build_interface_example_diff(name, existing, desired)
            if diff_lines == ['IN SYNC']:
                totals['in_sync'] += 1
                results.append({'name': name, 'status': 'in_sync', 'diff_lines': diff_lines})
                continue

            if dry_run:
                totals['dry_run'] += 1
                results.append({'name': name, 'status': 'dry_run', 'diff_lines': diff_lines})
                continue

            if not isinstance(existing, dict):
                nb_post(url, token, 'extras/config-contexts', desired)
                totals['created'] += 1
                results.append({'name': name, 'status': 'created', 'diff_lines': diff_lines})
                continue

            patch_payload = {}
            if bool(existing.get('is_active', True)) != False:
                patch_payload['is_active'] = False
            if str(existing.get('description') or '').strip() != str(description).strip():
                patch_payload['description'] = str(description).strip()
            current_data = existing.get('data')
            if not isinstance(current_data, dict):
                current_data = {}
            if current_data != data_payload:
                patch_payload['data'] = data_payload

            if patch_payload:
                existing_id = _normalize_positive_int(existing.get('id'))
                if existing_id is None:
                    raise ValueError(f'Config context {name} has no id')
                nb_patch(url, token, 'extras/config-contexts', existing_id, patch_payload)
                totals['updated'] += 1
                results.append({'name': name, 'status': 'updated', 'diff_lines': diff_lines})
            else:
                totals['in_sync'] += 1
                results.append({'name': name, 'status': 'in_sync', 'diff_lines': ['IN SYNC']})
        except Exception as e:
            totals['error'] += 1
            results.append({
                'name': name,
                'status': 'error',
                'error': str(e),
                'diff_lines': [],
            })

    return results, totals


def _nbsync_list_device_type_catalog(url, token):
    rows = fetch_all(url, token, 'dcim/device-types', params={'limit': 2000})
    out = []
    seen = set()
    for r in rows:
        did = _normalize_positive_int(r.get('id'))
        if did is None or did in seen:
            continue
        seen.add(did)
        model = str(r.get('model') or '').strip()
        mref = r.get('manufacturer')
        manufacturer = str((mref or {}).get('name') or '').strip() if isinstance(mref, dict) else ''
        if manufacturer and model:
            label = f'{model} ({manufacturer})'
        else:
            label = model or manufacturer or f'Device Type {did}'
        out.append({
            'id': did,
            'model': model,
            'manufacturer': manufacturer,
            'label': label,
        })
    out.sort(key=lambda x: (x['label'].lower(), x['id']))
    return out


def _nbsync_list_site_catalog(url, token):
    rows = fetch_all(url, token, 'dcim/sites', params={'limit': 2000})
    out = []
    seen = set()
    for r in rows:
        sid = _normalize_positive_int(r.get('id'))
        if sid is None or sid in seen:
            continue
        seen.add(sid)
        name = str(r.get('name') or '').strip()
        slug = str(r.get('slug') or '').strip()
        out.append({
            'id': sid,
            'name': name,
            'slug': slug,
            'label': name or slug or f'Site {sid}',
        })
    out.sort(key=lambda x: (x['label'].lower(), x['id']))
    return out

# ===========================================================================
# Routes — Auth
# ===========================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        locked, wait_s = _is_login_locked(username)
        if locked:
            error = f'Too many failed login attempts. Try again in {wait_s} seconds.'
            return render_template('login.html', error=error), 429
        users = load_users()
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['username']  = username
            session['user_id']   = user['id']
            _clear_login_failures(username)
            if _to_bool(user.get('must_change_password', False)):
                session['force_password_change'] = True
                return redirect(url_for('first_password_change'))
            return redirect(url_for('index'))
        _register_login_failure(username)
        error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/first-password-change', methods=['GET', 'POST'])
@login_required
def first_password_change():
    users = load_users()
    user_id = session.get('user_id')
    user = next((u for u in users if u.get('id') == user_id), None)
    if not user:
        session.clear()
        return redirect(url_for('login'))
    if not _to_bool(user.get('must_change_password', False)):
        session.pop('force_password_change', None)
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if not current_pw or not new_pw or not confirm_pw:
            error = 'All fields are required.'
        elif new_pw != confirm_pw:
            error = 'New password and confirmation do not match.'
        else:
            pw_error = _validate_password_strength(new_pw)
            if pw_error:
                error = pw_error
            elif not check_password_hash(user.get('password_hash', ''), current_pw):
                error = 'Current password is incorrect.'
            else:
                user['password_hash'] = generate_password_hash(new_pw)
                user['must_change_password'] = False
                save_users(users)
                session.pop('force_password_change', None)
                return redirect(url_for('index'))

    return render_template('first_password_change.html', username=user.get('username', ''), error=error)


@app.route('/app-icon.png')
def app_icon():
    if os.path.exists(APP_ICON_FILE):
        return send_file(APP_ICON_FILE, mimetype='image/png')
    return '', 404


@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('app_icon'))


@app.route('/')
@login_required
def index():
    return render_template('helper_index.html')


@app.route('/netbox-import/api/options', methods=['GET'])
@login_required
def netbox_import_options():
    try:
        b2_options = list_b2_options(Path(NETBOX_XLSX_FILE))
        template_csv = _resolve_netbox_import_template_csv()
        return jsonify({
            'b2_options': b2_options,
            'default_b2': b2_options[0] if b2_options else '',
            'template_csv': str(template_csv),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-import/api/upload-xlsx', methods=['POST'])
@login_required
def netbox_import_upload_xlsx():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    filename = secure_filename(str(file.filename or ''))
    if not filename:
        return jsonify({'error': 'No selected file'}), 400

    ext = os.path.splitext(filename)[1].lower()
    if ext not in {'.xlsx', '.xlsm'}:
        return jsonify({'error': 'Invalid file type. Please upload an .xlsx or .xlsm file.'}), 400

    try:
        os.makedirs(NETBOX_DATA_DIR, exist_ok=True)
        file.save(NETBOX_XLSX_FILE)
        b2_options = list_b2_options(Path(NETBOX_XLSX_FILE))
        return jsonify({
            'message': f'Workbook {filename} uploaded successfully',
            'filename': filename,
            'workbook': os.path.basename(NETBOX_XLSX_FILE),
            'b2_options': b2_options,
            'default_b2': b2_options[0] if b2_options else '',
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _generate_site_csv_from_instance(source_server_id, site_name):
    inst = resolve_instance_by_id(source_server_id)
    site_name = str(site_name or '').strip()
    if not site_name:
        raise ValueError('site_name is required')

    api = pynetbox.api(inst['url'], token=inst['token'])
    session = requests.Session()
    session.verify = not _to_bool(inst.get('skip_ssl_verify', False))
    api.http_session = session

    ref = _resolve_netbox_import_template_csv()

    sections, max_cols = parse_reference_template(ref)
    prefix, data = fetch_site_export_data(api, site_name)
    rows = render_site_csv(sections, max_cols, prefix, data)

    out_dir = Path(NETBOX_DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f'{prefix}.csv'
    with out_path.open('w', newline='', encoding='utf-8') as f:
        csv.writer(f).writerows(rows)

    return {
        'instance': inst,
        'prefix': prefix,
        'file_path': str(out_path),
        'filename': out_path.name,
        'rows': len(rows),
        'cols': max_cols,
    }


@app.route('/netbox-site-export/api/generate', methods=['POST'])
@login_required
def netbox_site_export_generate():
    data = request.json or {}
    source_server_id = data.get('source_server_id')
    site_name = data.get('site_name')
    if not source_server_id:
        return jsonify({'error': 'source_server_id is required'}), 400
    if not site_name:
        return jsonify({'error': 'site_name is required'}), 400
    try:
        result = _generate_site_csv_from_instance(source_server_id, site_name)
        return jsonify({
            'message': 'CSV generated from NetBox site',
            'source_server_id': source_server_id,
            'source_server_name': result['instance'].get('name', ''),
            'site_name': str(site_name).strip(),
            'prefix': result['prefix'],
            'filename': result['filename'],
            'rows': result['rows'],
            'cols': result['cols'],
            'download_url': url_for('netbox_import_download', filename=result['filename']),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-site-export/api/sites', methods=['GET'])
@login_required
def netbox_site_export_sites():
    source_server_id = str(request.args.get('source_server_id', '') or '').strip()
    if not source_server_id:
        return jsonify({'error': 'source_server_id is required'}), 400
    try:
        inst = resolve_instance_by_id(source_server_id)
        api = pynetbox.api(inst['url'], token=inst['token'])
        session = requests.Session()
        session.verify = not _to_bool(inst.get('skip_ssl_verify', False))
        api.http_session = session

        names = []
        for site in api.dcim.sites.filter(limit=0):
            name = str(getattr(site, 'name', '') or '').strip()
            if name:
                names.append(name)
        names = sorted(set(names), key=lambda s: s.lower())
        return jsonify({
            'source_server_id': source_server_id,
            'source_server_name': inst.get('name', ''),
            'sites': names,
            'count': len(names),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-site-export/api/generate-queue', methods=['POST'])
@login_required
def netbox_site_export_generate_queue():
    data = request.json or {}
    source_server_id = data.get('source_server_id')
    target_server_id = data.get('target_server_id')
    site_name = data.get('site_name')
    target_branch = _extract_requested_branch(data, key='target_branch')
    if not source_server_id:
        return jsonify({'error': 'source_server_id is required'}), 400
    if not target_server_id:
        return jsonify({'error': 'target_server_id is required'}), 400
    if not site_name:
        return jsonify({'error': 'site_name is required'}), 400
    try:
        resolve_instance_by_id(target_server_id)
        result = _generate_site_csv_from_instance(source_server_id, site_name)
        queued_name = secure_filename(f"nbsrc_{result['filename']}")
        queued_path = os.path.join(app.config['UPLOAD_FOLDER'], queued_name)
        shutil.copy2(result['file_path'], queued_path)

        job_id = uuid.uuid4().hex[:8]
        log_file = os.path.join(LOG_DIR, f'job_{job_id}.log')
        job = {
            'id': job_id,
            'file_path': queued_path,
            'filename': queued_name,
            'dry_run': False,
            'replace': False,
            'sections': None,
            'delay': 0.0,
            'workers': DEFAULT_IMPORT_WORKERS,
            'branch': target_branch,
            'server_id': target_server_id,
            'status': 'pending',
            'log_file': log_file,
            'start_time': None,
            'end_time': None,
            'error': None,
        }
        with queue_lock:
            job_queue.append(job)
        import_status['last_file'] = queued_path
        import_status['stopped'] = False

        return jsonify({
            'message': 'Generated from NetBox and queued',
            'job_id': job_id,
            'queued_file': queued_name,
            'source_file': result['filename'],
            'source_server_id': source_server_id,
            'target_server_id': target_server_id,
            'site_name': str(site_name).strip(),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-import/api/d7-options', methods=['GET'])
@login_required
def netbox_import_d7_options():
    b2_value = str(request.args.get('b2', '') or '').strip()
    if not b2_value:
        return jsonify({'error': 'Missing b2 value'}), 400
    try:
        d7_options = list_d7_options(Path(NETBOX_XLSX_FILE), b2_value)
        return jsonify({
            'b2': b2_value,
            'd7_options': d7_options,
            'default_d7': d7_options[0] if d7_options else '',
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-import/api/preview', methods=['POST'])
@login_required
def netbox_import_preview():
    data = request.json or {}
    b2_value = str(data.get('b2', '') or '').strip()
    d7_value = str(data.get('d7', '') or '').strip()
    if not b2_value or not d7_value:
        return jsonify({'error': 'Both b2 and d7 are required'}), 400
    try:
        limit = int(data.get('limit', 25))
    except Exception:
        limit = 25
    limit = max(1, min(200, limit))

    try:
        xlsx_path = Path(NETBOX_XLSX_FILE)
        template_csv = _resolve_netbox_import_template_csv_for_target(xlsx_path, b2_value, d7_value)
        g7_value, rows = build_netbox_import_export(
            xlsx_path=xlsx_path,
            template_csv_path=template_csv,
            b2_value=b2_value,
            d7_value=d7_value,
        )
        header = rows[0] if rows else []
        data_rows = rows[1:] if len(rows) > 1 else []
        return jsonify({
            'b2': b2_value,
            'd7': d7_value,
            'g7': g7_value,
            'filename': f'{safe_filename(g7_value)}.csv',
            'columns': len(header),
            'total_rows': len(data_rows),
            'header': header,
            'rows': data_rows[:limit],
            'preview_limit': limit,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-import/api/export', methods=['POST'])
@login_required
def netbox_import_export():
    data = request.json or {}
    b2_value = str(data.get('b2', '') or '').strip()
    d7_value = str(data.get('d7', '') or '').strip()
    if not b2_value or not d7_value:
        return jsonify({'error': 'Both b2 and d7 are required'}), 400
    try:
        xlsx_path = Path(NETBOX_XLSX_FILE)
        template_csv = _resolve_netbox_import_template_csv_for_target(xlsx_path, b2_value, d7_value)
        g7_value, output_path = write_export_csv(
            xlsx_path=xlsx_path,
            template_csv_path=template_csv,
            output_dir=Path(NETBOX_DATA_DIR),
            b2_value=b2_value,
            d7_value=d7_value,
        )
        return jsonify({
            'message': 'Export complete',
            'b2': b2_value,
            'd7': d7_value,
            'g7': g7_value,
            'filename': output_path.name,
            'download_url': url_for('netbox_import_download', filename=output_path.name),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-import/api/export-queue', methods=['POST'])
@login_required
def netbox_import_export_queue():
    data = request.json or {}
    b2_value = str(data.get('b2', '') or '').strip()
    d7_value = str(data.get('d7', '') or '').strip()
    if not b2_value or not d7_value:
        return jsonify({'error': 'Both b2 and d7 are required'}), 400

    server_id = data.get('server_id')
    branch = _extract_requested_branch(data, key='branch')
    try:
        resolve_instance_by_id(server_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    dry_run = bool(data.get('dry_run', False))
    replace = bool(data.get('replace', False))
    delay = float(data.get('delay', 0.0))
    workers = int(data.get('workers', DEFAULT_IMPORT_WORKERS))

    try:
        xlsx_path = Path(NETBOX_XLSX_FILE)
        template_csv = _resolve_netbox_import_template_csv_for_target(xlsx_path, b2_value, d7_value)
        _g7_value, output_path = write_export_csv(
            xlsx_path=xlsx_path,
            template_csv_path=template_csv,
            output_dir=Path(NETBOX_DATA_DIR),
            b2_value=b2_value,
            d7_value=d7_value,
        )

        export_name = os.path.basename(str(output_path))
        queued_name = secure_filename(f"nbimp_{export_name}")
        queued_path = os.path.join(app.config['UPLOAD_FOLDER'], queued_name)
        shutil.copy2(str(output_path), queued_path)

        job_id = uuid.uuid4().hex[:8]
        log_file = os.path.join(LOG_DIR, f'job_{job_id}.log')
        job = {
            'id': job_id,
            'file_path': queued_path,
            'filename': queued_name,
            'dry_run': dry_run,
            'replace': replace,
            'sections': None,
            'delay': delay,
            'workers': workers,
            'branch': branch,
            'server_id': server_id,
            'status': 'pending',
            'log_file': log_file,
            'start_time': None,
            'end_time': None,
            'error': None,
        }
        with queue_lock:
            job_queue.append(job)
        import_status['last_file'] = queued_path
        import_status['stopped'] = False

        return jsonify({
            'message': 'Exported and queued',
            'job_id': job_id,
            'queued_file': queued_name,
            'source_file': output_path.name,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/netbox-import/api/download/<path:filename>', methods=['GET'])
@login_required
def netbox_import_download(filename):
    safe_name = os.path.basename(str(filename or ''))
    if not safe_name or safe_name != filename:
        return jsonify({'error': 'Invalid filename'}), 400
    file_path = os.path.join(NETBOX_DATA_DIR, safe_name)
    if not os.path.isfile(file_path):
        return jsonify({'error': 'File not found'}), 404
    return send_file(file_path, as_attachment=True, download_name=safe_name, mimetype='text/csv')

# ===========================================================================
# Routes — CSV Import
# ===========================================================================

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        import_status['last_file'] = path
        import_status['stopped'] = False
        return jsonify({'message': f'File {filename} uploaded successfully', 'path': path, 'filename': filename})
    return jsonify({'error': 'Invalid file type. Please upload a CSV.'}), 400


@app.route('/queue', methods=['GET'])
@login_required
def get_queue():
    with queue_lock:
        result = []
        for j in job_queue:
            result.append({
                'id': j['id'],
                'filename': j['filename'],
                'dry_run': j['dry_run'],
                'diff_mode': bool(j.get('diff_mode', False)),
                'replace': j['replace'],
                'sections': j['sections'],
                'delay': j['delay'],
                'workers': j.get('workers', DEFAULT_IMPORT_WORKERS),
                'branch': j.get('branch') or None,
                'resolved_branch': j.get('resolved_branch') or None,
                'server_id': j.get('server_id'),
                'status': j['status'],
                'start_time': j['start_time'],
                'end_time': j['end_time'],
                'error': j['error'],
            })
    return jsonify({'queue': result, 'worker_running': worker_running})


@app.route('/queue', methods=['POST'])
@login_required
def enqueue_job():
    data = request.json or {}
    file_path = data.get('file_path')
    filename = data.get('filename') or os.path.basename(file_path or '')

    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 400
    if not _is_allowed_upload_path(file_path):
        return jsonify({'error': 'Invalid file path'}), 400

    server_id = data.get('server_id')
    branch = _extract_requested_branch(data, key='branch')
    try:
        resolve_instance_by_id(server_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    job_id   = uuid.uuid4().hex[:8]
    log_file = os.path.join(LOG_DIR, f'job_{job_id}.log')

    job = {
        'id': job_id,
        'file_path': file_path,
        'filename': filename,
        'dry_run': bool(data.get('dry_run', False)),
        'replace': bool(data.get('replace', False)),
        'sections': data.get('sections') or None,
        'delay': float(data.get('delay', 0.0)),
        'workers': int(data.get('workers', DEFAULT_IMPORT_WORKERS)),
        'branch': branch,
        'server_id': server_id,
        'status': 'pending',
        'log_file': log_file,
        'start_time': None,
        'end_time': None,
        'error': None,
    }

    with queue_lock:
        job_queue.append(job)

    return jsonify({'message': 'Job added to queue', 'job_id': job_id})


@app.route('/queue/start', methods=['POST'])
@login_required
def start_queue():
    if import_status['running']:
        return jsonify({'error': 'An import is already running'}), 400

    with queue_lock:
        pending = [j for j in job_queue if j['status'] == 'pending']
        if not pending:
            return jsonify({'error': 'No pending jobs in the queue'}), 400
        for j in pending:
            j['diff_mode'] = False

    _ensure_worker()
    return jsonify({'message': 'Queue started'})


@app.route('/queue/start-diff', methods=['POST'])
@login_required
def start_queue_diff():
    if import_status['running']:
        return jsonify({'error': 'An import is already running'}), 400

    with queue_lock:
        pending = [j for j in job_queue if j['status'] == 'pending']
        if not pending:
            return jsonify({'error': 'No pending jobs in the queue'}), 400
        for j in pending:
            j['diff_mode'] = True

    _ensure_worker()
    return jsonify({'message': f'Diff started for {len(pending)} queued job(s)'})


@app.route('/queue/<job_id>/remove', methods=['POST'])
@login_required
def remove_job(job_id):
    with queue_lock:
        for i, j in enumerate(job_queue):
            if j['id'] == job_id:
                if j['status'] == 'running':
                    return jsonify({'error': 'Cannot remove a running job'}), 400
                job_queue.pop(i)
                return jsonify({'message': 'Job removed'})
    return jsonify({'error': 'Job not found'}), 404


@app.route('/queue/<job_id>/log', methods=['GET'])
@login_required
def get_job_log(job_id):
    with queue_lock:
        job = next((j for j in job_queue if j['id'] == job_id), None)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    log_path = job['log_file']
    if not os.path.exists(log_path):
        return jsonify({'log': ''})
    with open(log_path, 'r', encoding='utf-8') as f:
        return jsonify({'log': f.read()})


@app.route('/queue/clear', methods=['POST'])
@login_required
def clear_queue():
    with queue_lock:
        finished = {'done', 'failed', 'stopped'}
        before = len(job_queue)
        job_queue[:] = [j for j in job_queue if j['status'] not in finished]
        removed = before - len(job_queue)
    return jsonify({'message': f'Cleared {removed} finished jobs'})


@app.route('/start-import', methods=['POST'])
@login_required
def start_import():
    if import_status['running']:
        return jsonify({'error': 'An import is already in progress'}), 400

    data = request.json or {}
    dry_run   = data.get('dry_run', False)
    replace   = data.get('replace', False)
    sections  = data.get('sections')
    server_id = data.get('server_id')
    file_path = data.get('file_path') or import_status['last_file']
    delay     = float(data.get('delay', 0.0))
    branch    = _extract_requested_branch(data, key='branch')

    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'No file available for import'}), 400
    if not _is_allowed_upload_path(file_path):
        return jsonify({'error': 'Invalid file path'}), 400
    try:
        resolve_instance_by_id(server_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    job_id   = uuid.uuid4().hex[:8]
    log_file = os.path.join(LOG_DIR, f'job_{job_id}.log')
    job = {
        'id': job_id,
        'file_path': file_path,
        'filename': os.path.basename(file_path),
        'dry_run': dry_run,
        'replace': replace,
        'sections': sections,
        'server_id': server_id,
        'delay': delay,
        'branch': branch,
        'status': 'pending',
        'log_file': log_file,
        'start_time': None,
        'end_time': None,
        'error': None,
    }

    with open(IMPORT_LOG_FILE, 'w') as f:
        f.write(f"--- Starting Import ({'Dry Run' if dry_run else 'Live Run'}) ---\n")

    with queue_lock:
        job_queue.append(job)

    _ensure_worker()
    return jsonify({'message': 'Import started'})


@app.route('/stop-import', methods=['POST'])
@login_required
def stop_import():
    global stop_requested
    if not import_status['running']:
        return jsonify({'error': 'No import running'}), 400
    stop_requested = True
    import_status['stop_requested'] = True
    return jsonify({'message': 'Stop signal sent'})


@app.route('/get-sections', methods=['POST'])
@login_required
def get_sections():
    data = request.json or {}
    file_path = data.get('file_path') or import_status['last_file']

    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'No file available'}), 400
    if not _is_allowed_upload_path(file_path):
        return jsonify({'error': 'Invalid file path'}), 400

    try:
        importer = NetboxImporter(file_path, connect=False)
        parsed_data = importer.parse_csv()
        available = [s for s in importer.IMPORT_ORDER if s in parsed_data]
        return jsonify({'sections': available})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/retry-failures', methods=['POST'])
@login_required
def retry_failures():
    if import_status['running']:
        return jsonify({'error': 'An import is already in progress'}), 400

    file_path = FAILURES_FILE
    if not os.path.exists(file_path):
        return jsonify({'error': 'No failures to retry'}), 400

    data    = request.json or {}
    dry_run = data.get('dry_run', False)
    replace = data.get('replace', False)
    delay   = float(data.get('delay', 0.0))
    server_id = data.get('server_id') or import_status.get('last_server_id')
    branch = _extract_requested_branch(data, key='branch')
    if not server_id:
        return jsonify({'error': 'No target NetBox server selected for retry'}), 400
    try:
        resolve_instance_by_id(server_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    with open(IMPORT_LOG_FILE, 'w') as f:
        f.write(f"--- Starting Retry of Failures ({'Dry Run' if dry_run else 'Live Run'}) ---\n")

    thread = threading.Thread(target=run_retry_thread, args=(file_path, dry_run, replace, delay, server_id, branch))
    thread.start()
    return jsonify({'message': 'Retry started'})


@app.route('/clear-failures', methods=['POST'])
@login_required
def clear_failures():
    file_path = FAILURES_FILE
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return jsonify({'message': 'Failures cleared'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'message': 'No failures to clear'})


@app.route('/status')
@login_required
def get_status():
    status = import_status.copy()
    status['has_failures'] = os.path.exists(FAILURES_FILE)
    return jsonify(status)


@app.route('/stream-logs')
@login_required
def stream_logs():
    requested_job_id = str(request.args.get('job_id') or '').strip()
    start_pos = str(request.args.get('position') or '').strip().lower()
    start_at_end = start_pos in {'end', 'tail'}

    def _resolve_log_target():
        with queue_lock:
            if requested_job_id:
                requested = next((j for j in job_queue if j.get('id') == requested_job_id), None)
                if requested:
                    return str(requested.get('log_file') or IMPORT_LOG_FILE)
            running = next((j for j in job_queue if j.get('status') == 'running'), None)
            if running:
                return str(running.get('log_file') or IMPORT_LOG_FILE)
        return IMPORT_LOG_FILE

    def _open_stream_file(path, seek_end=False):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(path):
            with open(path, 'a', encoding='utf-8'):
                pass
        handle = open(path, 'r', encoding='utf-8', errors='replace')
        if seek_end:
            handle.seek(0, os.SEEK_END)
        return handle

    def generate():
        log_path = _resolve_log_target()
        f = _open_stream_file(log_path, seek_end=start_at_end)
        last_keepalive = time.time()
        try:
            while True:
                next_path = _resolve_log_target()
                if next_path != log_path:
                    try:
                        f.close()
                    except Exception:
                        pass
                    log_path = next_path
                    f = _open_stream_file(log_path, seek_end=False)
                    yield "data: [STREAM-SWITCH]\n\n"

                line = f.readline()
                if line:
                    last_keepalive = time.time()
                    yield f"data: {line.rstrip()}\n\n"
                    continue

                if not import_status['running']:
                    time.sleep(0.25)
                    line = f.readline()
                    if line:
                        last_keepalive = time.time()
                        yield f"data: {line.rstrip()}\n\n"
                        continue
                    if import_status['stopped']:
                        yield "data: [STOPPED]\n\n"
                    else:
                        yield "data: [DONE]\n\n"
                    break

                now = time.time()
                if (now - last_keepalive) >= 10.0:
                    # SSE comment frame keeps intermediaries from closing idle streams.
                    yield ": keepalive\n\n"
                    last_keepalive = now
                time.sleep(0.15)
        finally:
            try:
                f.close()
            except Exception:
                pass

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        },
    )


# ===========================================================================
# Routes — Zabbix Runner
# ===========================================================================

@app.route('/nbsync/api/options', methods=['GET'])
@login_required
def nbsync_get_options():
    return jsonify({'options': load_nbsync_options()})


@app.route('/nbsync/api/options', methods=['PUT'])
@login_required
def nbsync_put_options():
    data = request.json or {}
    options = save_nbsync_options(data.get('options', data))
    return jsonify({'options': options})


@app.route('/nbsync/api/interface-example-contexts/sync', methods=['POST'])
@login_required
def nbsync_sync_interface_example_contexts():
    data = request.json or {}
    instance_id = data.get('instance_id')
    dry_run = bool(data.get('dry_run', False))
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    try:
        results, totals = _nbsync_sync_interface_example_contexts(
            inst['url'], inst['token'], dry_run=dry_run
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({
        'results': results,
        'totals': totals,
        'dry_run': dry_run,
        'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']},
    })


@app.route('/nbsync/api/config-groups', methods=['GET'])
@login_required
def nbsync_get_config_groups():
    instance_id = request.args.get('instance_id')
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    try:
        groups = _nbsync_list_config_groups(inst['url'], inst['token'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({
        'config_groups': groups,
        'count': len(groups),
        'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']},
    })


@app.route('/nbsync/api/servers', methods=['GET'])
@login_required
def nbsync_get_servers():
    instance_id = request.args.get('instance_id')
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    try:
        servers = _nbsync_list_servers(inst['url'], inst['token'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({
        'servers': servers,
        'count': len(servers),
        'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']},
    })


@app.route('/nbsync/api/filter-catalog', methods=['GET'])
@login_required
def nbsync_get_filter_catalog():
    instance_id = request.args.get('instance_id')
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    try:
        device_types = _nbsync_list_device_type_catalog(inst['url'], inst['token'])
        sites = _nbsync_list_site_catalog(inst['url'], inst['token'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({
        'device_types': device_types,
        'sites': sites,
        'counts': {
            'device_types': len(device_types),
            'sites': len(sites),
        },
        'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']},
    })


@app.route('/nbsync/api/pull-progress', methods=['GET'])
@login_required
def nbsync_pull_progress_get():
    pull_id = str(request.args.get('pull_id') or '').strip()
    if not pull_id:
        return jsonify({'error': 'pull_id is required'}), 400
    owner = str(session.get('username') or '')
    with nbsync_pull_progress_lock:
        _nbsync_pull_progress_cleanup_locked()
        state = nbsync_pull_progress.get(pull_id)
    if not state:
        return jsonify({'error': 'pull progress not found'}), 404
    if owner and str(state.get('owner') or '') not in ('', owner):
        return jsonify({'error': 'pull progress not found'}), 404
    return jsonify({
        'pull_id': pull_id,
        'status': state.get('status') or 'running',
        'stage': state.get('stage') or '',
        'message': state.get('message') or '',
        'fetched': int(state.get('fetched') or 0),
        'total_estimate': int(state.get('total_estimate') or 0),
        'scanned': int(state.get('scanned') or 0),
        'matched': int(state.get('matched') or 0),
        'result_count': int(state.get('result_count') or 0),
        'error': state.get('error') or '',
        'updated_at': float(state.get('updated_at') or time.time()),
    })


@app.route('/nbsync/api/pull', methods=['POST'])
@login_required
def nbsync_pull_devices():
    data = request.json or {}
    pull_id = str(data.get('pull_id') or '').strip()
    pull_owner = str(session.get('username') or '')
    if pull_id:
        _nbsync_pull_progress_update(
            pull_id,
            owner=pull_owner,
            status='running',
            stage='init',
            message='Initializing pull...',
            fetched=0,
            total_estimate=0,
            scanned=0,
            matched=0,
            result_count=0,
            error='',
        )
    instance_id = data.get('instance_id')
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        if pull_id:
            _nbsync_pull_progress_update(
                pull_id, owner=pull_owner, status='error', stage='error', message='Pull failed', error=str(e)
            )
        return jsonify({'error': str(e)}), 400

    options = normalize_nbsync_options(data.get('options') or load_nbsync_options())

    try:
        config_group_id = int(data.get('config_group_id', options['defaults']['config_group_id']))
        if config_group_id <= 0:
            raise ValueError
    except Exception:
        return jsonify({'error': 'config_group_id must be a positive integer'}), 400

    only_primary_ipv4 = bool(data.get('only_primary_ipv4', options['defaults']['only_primary_ipv4']))
    include_diff = bool(data.get('include_diff', False))
    search = str(data.get('search', '')).strip().lower()
    raw_device_type_id = data.get('device_type_id')
    raw_site_id = data.get('site_id')
    if raw_device_type_id in (None, ''):
        device_type_id_filter = None
    else:
        device_type_id_filter = _normalize_positive_int(raw_device_type_id)
        if device_type_id_filter is None:
            return jsonify({'error': 'device_type_id must be a positive integer'}), 400
    if raw_site_id in (None, ''):
        site_id_filter = None
    else:
        site_id_filter = _normalize_positive_int(raw_site_id)
        if site_id_filter is None:
            return jsonify({'error': 'site_id must be a positive integer'}), 400
    limit = data.get('limit')
    if limit in (None, ''):
        limit = None
    else:
        try:
            limit = max(1, min(int(limit), 5000))
        except Exception:
            return jsonify({'error': 'limit must be a positive integer'}), 400

    try:
        if pull_id:
            _nbsync_pull_progress_update(
                pull_id, owner=pull_owner, stage='fetch_devices', message='Loading devices from NetBox...'
            )
        devices = fetch_all(
            inst['url'],
            inst['token'],
            'dcim/devices',
            progress_cb=(
                (lambda fetched=0, total_estimate=0, page_size=0: _nbsync_pull_progress_update(
                    pull_id,
                    owner=pull_owner,
                    stage='fetch_devices',
                    message=f"Loading devices from NetBox... {fetched}/{max(total_estimate, fetched)}",
                    fetched=fetched,
                    total_estimate=max(total_estimate, fetched),
                ))
                if pull_id else None
            ),
        )
        if pull_id:
            _nbsync_pull_progress_update(
                pull_id,
                owner=pull_owner,
                stage='fetch_assignments',
                message='Loading configuration group assignments...',
                fetched=len(devices),
                total_estimate=len(devices),
            )
        assignments = fetch_all(
            inst['url'], inst['token'], 'plugins/nbxsync/zabbixconfigurationgroupassignment',
            params={'zabbixconfigurationgroup_id': config_group_id},
        )
    except Exception as e:
        if pull_id:
            _nbsync_pull_progress_update(
                pull_id, owner=pull_owner, status='error', stage='error', message='Pull failed', error=str(e)
            )
        return jsonify({'error': str(e)}), 500

    try:
        device_server_map = _nbsync_get_device_server_map(inst['url'], inst['token'])
    except Exception:
        device_server_map = {}

    selected_server_id = _normalize_positive_int(options.get('selected_zabbix_server_id'))
    try:
        config_group_server_id = _normalize_positive_int(
            _nbsync_get_zabbix_server_from_config_group(inst['url'], inst['token'], config_group_id)
        )
    except Exception:
        config_group_server_id = None

    try:
        catalog_tags = _nbsync_list_config_group_tags(
            inst['url'], inst['token'], config_group_id
        )
    except Exception:
        catalog_tags = []
    try:
        catalog_hostgroups = _nbsync_list_hostgroup_names(inst['url'], inst['token'])
    except Exception:
        catalog_hostgroups = []

    assigned_ids = set()
    for row in assignments:
        rid = row.get('assigned_object_id')
        if rid is None and isinstance(row.get('assigned_object'), dict):
            rid = row['assigned_object'].get('id')
        if rid is not None:
            try:
                assigned_ids.add(int(rid))
            except Exception:
                pass

    rows = []
    site_cache = {}
    if pull_id:
        _nbsync_pull_progress_update(
            pull_id,
            owner=pull_owner,
            stage='build_rows',
            message=f'Filtering/building device rows... 0/{len(devices)}',
            fetched=len(devices),
            total_estimate=len(devices),
            scanned=0,
            matched=0,
        )
    scanned_count = 0
    matched_count = 0
    for d in devices:
        scanned_count += 1
        dtype_ref = d.get('device_type')
        site_ref = d.get('site')
        dtype_id = _normalize_positive_int(_extract_field_id(dtype_ref))
        site_id = _normalize_positive_int(_extract_field_id(site_ref))
        if device_type_id_filter is not None and dtype_id != device_type_id_filter:
            if pull_id and (scanned_count == 1 or scanned_count % 10 == 0 or scanned_count == len(devices)):
                _nbsync_pull_progress_update(
                    pull_id,
                    owner=pull_owner,
                    stage='build_rows',
                    message=f'Filtering/building device rows... {scanned_count}/{len(devices)}',
                    scanned=scanned_count,
                    matched=matched_count,
                )
            continue
        if site_id_filter is not None and site_id != site_id_filter:
            if pull_id and (scanned_count == 1 or scanned_count % 10 == 0 or scanned_count == len(devices)):
                _nbsync_pull_progress_update(
                    pull_id,
                    owner=pull_owner,
                    stage='build_rows',
                    message=f'Filtering/building device rows... {scanned_count}/{len(devices)}',
                    scanned=scanned_count,
                    matched=matched_count,
                )
            continue

        device_name = str(d.get('name') or '')
        if search and search not in device_name.lower():
            if pull_id and (scanned_count == 1 or scanned_count % 10 == 0 or scanned_count == len(devices)):
                _nbsync_pull_progress_update(
                    pull_id,
                    owner=pull_owner,
                    stage='build_rows',
                    message=f'Filtering/building device rows... {scanned_count}/{len(devices)}',
                    scanned=scanned_count,
                    matched=matched_count,
                )
            continue
        primary_ipv4 = _extract_primary_ipv4(d)
        if only_primary_ipv4 and not primary_ipv4:
            if pull_id and (scanned_count == 1 or scanned_count % 10 == 0 or scanned_count == len(devices)):
                _nbsync_pull_progress_update(
                    pull_id,
                    owner=pull_owner,
                    stage='build_rows',
                    message=f'Filtering/building device rows... {scanned_count}/{len(devices)}',
                    scanned=scanned_count,
                    matched=matched_count,
                )
            continue

        site_details = _nbsync_get_site_details(inst['url'], inst['token'], site_ref, site_cache)
        values = _nbsync_template_map(d, site_details=site_details)
        device_id = int(d['id'])
        row_zabbix_server_id = (
            _normalize_positive_int(device_server_map.get(device_id))
            or selected_server_id
            or config_group_server_id
        )
        already_assigned = device_id in assigned_ids
        targets = _build_nbsync_targets(
            d, options, True, True, False, template_values=values
        )
        inventory_targets = _build_nbsync_inventory_targets(options, values)
        interface_targets = _build_nbsync_host_interface_targets(
            d, options, zabbix_server_id=row_zabbix_server_id
        )

        preview = []
        if already_assigned:
            preview.append(f'Already in config group {config_group_id} (attach will be skipped)')
        else:
            preview.append(f'Attach to config group {config_group_id}')
        if targets['tags']:
            preview.append(f"Apply {len(targets['tags'])} tag(s)")
        if targets['hostgroups']:
            preview.append(f"Apply {len(targets['hostgroups'])} hostgroup(s)")
        if options.get('use_host_inventory', True):
            preview.append(
                f"Apply host inventory: mode={inventory_targets['inventory_mode']} fields={len(inventory_targets['fields'])}"
            )
        if options.get('use_host_interface', True):
            if interface_targets.get('enabled'):
                preview.append(
                    f"Apply host interface: type={interface_targets.get('type')} "
                    f"port={interface_targets.get('port')} useip={interface_targets.get('useip')}"
                )
            elif interface_targets.get('reason') == 'no_context':
                preview.append("Host interface: no config-context interface (skipped)")
            elif interface_targets.get('reason') == 'missing_primary_ip':
                preview.append("Host interface: context found but no usable primary IPv4/DNS (skipped)")

        site = site_ref if isinstance(site_ref, dict) else {}
        role = d.get('role') or {}
        dtype = dtype_ref if isinstance(dtype_ref, dict) else {}
        status = d.get('status') or {}
        rows.append({
            'device_id': device_id,
            'name': device_name,
            'site_id': site_id,
            'site': site.get('name', ''),
            'site_slug': site.get('slug', ''),
            'site_facility': values.get('site.facility', ''),
            'site_region': values.get('site.region.name', ''),
            'site_latitude': values.get('site.latitude', ''),
            'site_longitude': values.get('site.longitude', ''),
            'site_description': values.get('site.description', ''),
            'site_physical_address': values.get('site.physical_address', ''),
            'site_time_zone': values.get('site.time_zone', ''),
            'role': role.get('name', ''),
            'role_slug': role.get('slug', ''),
            'tenant': values.get('device.tenant.name', ''),
            'manufacturer': values.get('device.device_type.manufacturer.name', ''),
            'status': status.get('label') or status.get('value') or '',
            'primary_ipv4': primary_ipv4,
            'serial': str(d.get('serial') or ''),
            'asset_tag': str(d.get('asset_tag') or ''),
            'device_type_id': dtype_id,
            'device_type': str(dtype.get('model') or ''),
            'tags': _extract_device_tags(d),
            'zabbix_server_id': row_zabbix_server_id,
            'already_assigned': already_assigned,
            'action': 'attach',
            'apply_tags': True,
            'apply_hostgroups': True,
            'apply_macros': False,
            'apply_inventory': bool(options.get('use_host_inventory', True)),
            'apply_interface': bool(options.get('use_host_interface', True)),
            'preview': preview,
            'targets': targets,
            'inventory_targets': inventory_targets,
            'interface_targets': interface_targets,
        })
        matched_count += 1
        if pull_id and (scanned_count == 1 or scanned_count % 10 == 0 or scanned_count == len(devices)):
            _nbsync_pull_progress_update(
                pull_id,
                owner=pull_owner,
                stage='build_rows',
                message=f'Filtering/building device rows... {scanned_count}/{len(devices)} (matched {matched_count})',
                scanned=scanned_count,
                matched=matched_count,
            )

    rows.sort(key=lambda x: x['name'].lower())
    if limit:
        rows = rows[:limit]

    diff_error = None
    if include_diff and rows:
        device_ids = [r['device_id'] for r in rows]
        inventory_fields = [
            str(f.get('field') or '').strip()
            for f in (options.get('host_inventory_fields') or [])
            if isinstance(f, dict) and str(f.get('field') or '').strip()
        ]
        try:
            current_state_map = _nbsync_collect_device_current_state(
                inst['url'], inst['token'], device_ids, inventory_field_names=inventory_fields
            )
            for r in rows:
                r['diff_lines'] = _nbsync_build_pull_diff_lines(
                    r,
                    current_state_map.get(r['device_id']) or {},
                    options,
                    config_group_id,
                )
        except Exception as e:
            diff_error = str(e)
    if pull_id:
        _nbsync_pull_progress_update(
            pull_id,
            owner=pull_owner,
            status='done',
            stage='complete',
            message=f'Pull complete: {len(rows)} device(s) ready',
            fetched=len(devices),
            total_estimate=len(devices),
            scanned=len(devices),
            matched=len(rows),
            result_count=len(rows),
            error='',
        )

    return jsonify({
        'devices': rows,
        'count': len(rows),
        'include_diff': include_diff,
        'diff_error': diff_error,
        'options': options,
        'catalog_tags': catalog_tags,
        'catalog_hostgroups': catalog_hostgroups,
        'config_group_id': config_group_id,
        'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']},
    })


@app.route('/nbsync/api/pull-diff-chunk', methods=['POST'])
@login_required
def nbsync_pull_diff_chunk():
    data = request.json or {}
    instance_id = data.get('instance_id')
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    options = normalize_nbsync_options(data.get('options') or load_nbsync_options())

    try:
        config_group_id = int(data.get('config_group_id', options['defaults']['config_group_id']))
        if config_group_id <= 0:
            raise ValueError
    except Exception:
        return jsonify({'error': 'config_group_id must be a positive integer'}), 400

    incoming_rows = data.get('rows') or []
    if not isinstance(incoming_rows, list):
        return jsonify({'error': 'rows must be a list'}), 400

    rows = []
    for row in incoming_rows:
        if not isinstance(row, dict):
            continue
        device_id = _normalize_positive_int(row.get('device_id'))
        if device_id is None:
            continue
        targets = row.get('targets') if isinstance(row.get('targets'), dict) else {}
        inventory_targets = (
            row.get('inventory_targets')
            if isinstance(row.get('inventory_targets'), dict)
            else {}
        )
        interface_targets = (
            row.get('interface_targets')
            if isinstance(row.get('interface_targets'), dict)
            else {}
        )
        rows.append({
            'device_id': device_id,
            'name': str(row.get('name') or f'id:{device_id}'),
            'zabbix_server_id': _normalize_positive_int(row.get('zabbix_server_id')),
            'targets': targets,
            'inventory_targets': inventory_targets,
            'interface_targets': interface_targets,
        })

    if not rows:
        return jsonify({
            'diffs': [],
            'count': 0,
            'config_group_id': config_group_id,
            'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']},
        })

    inventory_fields = [
        str(f.get('field') or '').strip()
        for f in (options.get('host_inventory_fields') or [])
        if isinstance(f, dict) and str(f.get('field') or '').strip()
    ]

    try:
        current_state_map = _nbsync_collect_device_current_state(
            inst['url'],
            inst['token'],
            [r['device_id'] for r in rows],
            inventory_field_names=inventory_fields,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    diffs = []
    for row in rows:
        diff_lines = _nbsync_build_pull_diff_lines(
            row,
            current_state_map.get(row['device_id']) or {},
            options,
            config_group_id,
        )
        diffs.append({
            'device_id': row['device_id'],
            'diff_lines': diff_lines,
        })

    return jsonify({
        'diffs': diffs,
        'count': len(diffs),
        'config_group_id': config_group_id,
        'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']},
    })


@app.route('/nbsync/api/tag', methods=['POST'])
@login_required
def nbsync_create_tag():
    data = request.json or {}
    instance_id = data.get('instance_id')
    tag_name = str(data.get('tag') or '').strip()
    name = str(data.get('name') or '').strip()
    value = str(data.get('value') or '').strip()
    if not tag_name:
        return jsonify({'error': 'tag is required'}), 400
    if not name:
        name = f'NetBox Tag: {tag_name}'
    if not value:
        value = tag_name

    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    zabbix_server_id = _normalize_positive_int(data.get('zabbix_server_id'))
    if zabbix_server_id is None:
        try:
            config_group_id = int(data.get('config_group_id', 2))
            if config_group_id <= 0:
                raise ValueError
        except Exception:
            return jsonify({'error': 'config_group_id must be a positive integer'}), 400
        try:
            zabbix_server_id = _nbsync_get_zabbix_server_from_config_group(
                inst['url'], inst['token'], config_group_id
            )
        except Exception:
            zabbix_server_id = None

    try:
        existing = fetch_all(inst['url'], inst['token'], 'plugins/nbxsync/zabbixtag', params={'tag': tag_name})
        exact = next((r for r in existing if str(r.get('tag') or '').strip().lower() == tag_name.lower()), None)
        if exact:
            tag_id = exact.get('id')
            state = 'existing'
            cur_name = str(exact.get('name') or '').strip()
            cur_value = str(exact.get('value') or '').strip()
            if tag_id and (cur_name != name or cur_value != value):
                patch_payload = {'name': name, 'value': value}
                patch_resp = requests.patch(
                    f"{inst['url'].rstrip('/')}/api/plugins/nbxsync/zabbixtag/{tag_id}/",
                    headers=_nbsync_headers(inst['token']),
                    json=patch_payload,
                    verify=_requests_verify_for_url(inst['url']),
                    timeout=30,
                )
                if patch_resp.status_code in (200, 202):
                    state = 'updated'
        else:
            payload = {
                'name': name,
                'tag': tag_name,
                'value': value,
                'description': f'Auto-managed by Netbox Helper ({tag_name})',
            }
            if zabbix_server_id:
                payload['zabbixserver'] = zabbix_server_id
                payload['zabbixserver_id'] = zabbix_server_id
            created = nb_post(inst['url'], inst['token'], 'plugins/nbxsync/zabbixtag', payload)
            tag_id = created.get('id')
            state = 'created'

        catalog_tags = _nbsync_list_tags(inst['url'], inst['token'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({
        'name': name,
        'tag': tag_name,
        'value': value,
        'tag_id': tag_id,
        'state': state,
        'catalog_tags': catalog_tags,
    })


def _nbsync_prepare_execute_row_ctx(
    inst, row, options, selected_zabbix_server_id=None, config_group_server_id=None
):
    device_id = row.get('device_id')
    try:
        device_id = int(device_id)
    except Exception:
        return {
            'ok': False,
            'error': {
                'device_id': device_id,
                'name': str(row.get('name') or ''),
                'status': 'error',
                'messages': [],
                'errors': ['Invalid device_id'],
            },
        }

    resp = requests.get(
        f"{inst['url'].rstrip('/')}/api/dcim/devices/{device_id}/",
        headers=_nbsync_headers(inst['token']),
        verify=_requests_verify_for_url(inst['url']),
        timeout=30,
    )
    if resp.status_code >= 400:
        return {
            'ok': False,
            'error': {
                'device_id': device_id,
                'name': str(row.get('name') or f'id:{device_id}'),
                'status': 'error',
                'messages': [],
                'errors': [f'Failed to fetch device ({resp.status_code}): {resp.text[:200]}'],
            },
        }

    device = resp.json()
    site_details = _nbsync_get_site_details(
        inst['url'], inst['token'], device.get('site'), {}
    )
    values = _nbsync_template_map(device, site_details=site_details)
    row_zabbix_server_id = (
        _normalize_positive_int(row.get('zabbix_server_id'))
        or selected_zabbix_server_id
        or _normalize_positive_int(config_group_server_id)
    )
    interface_targets = row.get('interface_targets')
    if not isinstance(interface_targets, dict):
        interface_targets = _build_nbsync_host_interface_targets(
            device, options, zabbix_server_id=row_zabbix_server_id
        )
    return {
        'ok': True,
        'ctx': {
            'row': row,
            'device': device,
            'template_values': values,
            'device_id': device_id,
            'name': device.get('name') or str(row.get('name') or f'id:{device_id}'),
            'zabbix_server_id': row_zabbix_server_id,
            'action': row.get('action', 'attach'),
            'apply_tags': bool(row.get('apply_tags', True)),
            'apply_hostgroups': bool(row.get('apply_hostgroups', True)),
            'apply_macros': False,
            'apply_inventory': (
                bool(options.get('use_host_inventory', True))
                and bool(row.get('apply_inventory', True))
            ),
            'apply_interface': (
                bool(options.get('use_host_interface', True))
                and bool(row.get('apply_interface', True))
            ),
            'interface_targets': interface_targets,
        },
    }


@app.route('/nbsync/api/execute', methods=['POST'])
@login_required
def nbsync_execute():
    data = request.json or {}
    instance_id = data.get('instance_id')
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    options = normalize_nbsync_options(data.get('options') or load_nbsync_options())
    dry_run = bool(data.get('dry_run', False))
    fast_mode = bool(data.get('fast_mode', False))

    try:
        config_group_id = int(data.get('config_group_id', options['defaults']['config_group_id']))
        if config_group_id <= 0:
            raise ValueError
    except Exception:
        return jsonify({'error': 'config_group_id must be a positive integer'}), 400

    rows = data.get('rows') or []
    if not isinstance(rows, list) or not rows:
        return jsonify({'error': 'rows must be a non-empty list'}), 400

    selected_rows = [r for r in rows if bool(r.get('selected', True))]
    if not selected_rows:
        return jsonify({'error': 'No devices selected'}), 400

    use_config_group_inheritance = bool(options.get('use_configuration_group_inheritance', True))
    needs_attach = any((r.get('action', 'attach') == 'attach') for r in selected_rows)
    selected_zabbix_server_id = _normalize_positive_int(options.get('selected_zabbix_server_id'))
    config_group_server_id = None
    if needs_attach:
        try:
            config_group_server_id = _nbsync_get_zabbix_server_from_config_group(
                inst['url'], inst['token'], config_group_id
            )
        except Exception:
            config_group_server_id = None
    group_zabbix_server_id = selected_zabbix_server_id or _normalize_positive_int(config_group_server_id)

    cache = {'tags': {}, 'hostgroups': {}, 'macros': {}}
    results = []
    totals = {'ok': 0, 'error': 0, 'dry_run': 0, 'skipped': 0}
    rows_with_devices = []
    group_messages = []
    group_errors = []

    # Always read latest device details at execution time.
    if fast_mode and len(selected_rows) > 1:
        prep_workers = max(2, min(12, len(selected_rows)))
        futures = {}
        with ThreadPoolExecutor(max_workers=prep_workers) as ex:
            for idx, row in enumerate(selected_rows):
                fut = ex.submit(
                    _nbsync_prepare_execute_row_ctx,
                    inst,
                    row,
                    options,
                    selected_zabbix_server_id,
                    config_group_server_id,
                )
                futures[fut] = idx
            prepared = []
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    prepared.append((idx, fut.result()))
                except Exception as e:
                    prepared.append((idx, {
                        'ok': False,
                        'error': {
                            'device_id': selected_rows[idx].get('device_id'),
                            'name': str(selected_rows[idx].get('name') or ''),
                            'status': 'error',
                            'messages': [],
                            'errors': [str(e)],
                        },
                    }))
        prepared.sort(key=lambda x: x[0])
        for _, item in prepared:
            if not item.get('ok'):
                results.append(item.get('error') or {
                    'device_id': None,
                    'name': '',
                    'status': 'error',
                    'messages': [],
                    'errors': ['Failed to prepare device context'],
                })
                totals['error'] += 1
                continue
            rows_with_devices.append(item['ctx'])
        group_messages.append(f'Fast mode: parallel device prefetch workers={prep_workers}')
    else:
        for row in selected_rows:
            prep = _nbsync_prepare_execute_row_ctx(
                inst, row, options, selected_zabbix_server_id, config_group_server_id
            )
            if not prep.get('ok'):
                results.append(prep.get('error') or {
                    'device_id': row.get('device_id'),
                    'name': str(row.get('name') or ''),
                    'status': 'error',
                    'messages': [],
                    'errors': ['Failed to prepare device context'],
                })
                totals['error'] += 1
                continue
            rows_with_devices.append(prep['ctx'])

    if use_config_group_inheritance and needs_attach:
        try:
            cleanup_res = _nbsync_clear_config_group_hostgroup_assignments(
                inst['url'], inst['token'], config_group_id, dry_run=dry_run
            )
            if cleanup_res['status'] == 'would_remove':
                group_messages.append(
                    f"Would clear {cleanup_res['removed']} existing config-group hostgroup assignment(s) before apply"
                )
            elif cleanup_res['status'] == 'removed':
                group_messages.append(
                    f"Cleared {cleanup_res['removed']} existing config-group hostgroup assignment(s) before apply"
                )
            else:
                group_messages.append('No existing config-group hostgroup assignments to clear')

            attach_rows = [r for r in rows_with_devices if r['action'] == 'attach']
            if attach_rows:
                # Hostgroups remain per-device to avoid polluting all members of the config group.
                group_targets, macro_warnings = _build_nbsync_config_group_targets(
                    attach_rows, options, include_hostgroups=False
                )
                group_messages.append(
                    f'Configuration-group inheritance: shared targets for group {config_group_id} '
                    f"(tags={len(group_targets['tags'])}); "
                    f"hostgroups are assigned per-device"
                )
                group_messages.extend(macro_warnings)

                for t in group_targets['tags']:
                    try:
                        tag_id, tag_state = _nbsync_get_or_create_tag(
                            inst['url'], inst['token'], t, group_zabbix_server_id, dry_run, cache
                        )
                        if dry_run:
                            if tag_id is None:
                                group_messages.append(f"Config group tag '{t}': {tag_state}, would_assign")
                            else:
                                asn = _nbsync_assign_tag(
                                    inst['url'], inst['token'], config_group_id, tag_id,
                                    dry_run=True,
                                    assigned_object_type='nbxsync.zabbixconfigurationgroup',
                                    config_group_id=config_group_id,
                                )
                                group_messages.append(f"Config group tag '{t}': {tag_state}, {asn}")
                            continue
                        if tag_id is None:
                            continue
                        asn = _nbsync_assign_tag(
                            inst['url'], inst['token'], config_group_id, tag_id, dry_run=False,
                            assigned_object_type='nbxsync.zabbixconfigurationgroup',
                            config_group_id=config_group_id,
                        )
                        group_messages.append(f"Config group tag '{t}': {tag_state}, {asn}")
                    except Exception as e:
                        group_errors.append(f"Config group tag '{t}' failed: {e}")

                for h in group_targets['hostgroups']:
                    try:
                        hg_id, hg_state = _nbsync_get_or_create_hostgroup(
                            inst['url'], inst['token'], h, group_zabbix_server_id, dry_run, cache
                        )
                        if dry_run:
                            if hg_id is None:
                                group_messages.append(f"Config group hostgroup '{h}': {hg_state}, would_assign")
                            else:
                                asn = _nbsync_assign_hostgroup(
                                    inst['url'], inst['token'], config_group_id, hg_id,
                                    dry_run=True,
                                    assigned_object_type='nbxsync.zabbixconfigurationgroup',
                                    config_group_id=config_group_id,
                                )
                                group_messages.append(f"Config group hostgroup '{h}': {hg_state}, {asn}")
                            continue
                        if hg_id is None:
                            continue
                        asn = _nbsync_assign_hostgroup(
                            inst['url'], inst['token'], config_group_id, hg_id, dry_run=False,
                            assigned_object_type='nbxsync.zabbixconfigurationgroup',
                            config_group_id=config_group_id,
                        )
                        group_messages.append(f"Config group hostgroup '{h}': {hg_state}, {asn}")
                    except Exception as e:
                        group_errors.append(f"Config group hostgroup '{h}' failed: {e}")

        except Exception as e:
            group_errors.append(str(e))

    for row_ctx in rows_with_devices:
        device = row_ctx['device']
        device_id = row_ctx['device_id']
        name = row_ctx['name']
        action = row_ctx['action']
        apply_tags = row_ctx['apply_tags']
        apply_hostgroups = row_ctx['apply_hostgroups']
        apply_inventory = row_ctx['apply_inventory']
        apply_interface = row_ctx.get('apply_interface', False)
        row_zabbix_server_id = (
            _normalize_positive_int(row_ctx.get('zabbix_server_id'))
            or selected_zabbix_server_id
            or _normalize_positive_int(config_group_server_id)
        )
        messages, errors = [], []
        cfg_status = None
        inventory_changed = False
        interface_changed = False

        try:
            if action == 'remove_server':
                remove_res = _nbsync_remove_server_assignments(
                    inst['url'], inst['token'], device_id, dry_run=dry_run
                )
                if remove_res['status'] == 'none':
                    messages.append('No server assignments found')
                elif remove_res['status'] == 'would_remove':
                    messages.append(f"Would remove {remove_res['removed']} server assignment(s)")
                else:
                    messages.append(f"Removed {remove_res['removed']} server assignment(s)")
            else:
                cfg_status = _nbsync_attach_config_group(
                    inst['url'], inst['token'], device_id, config_group_id, dry_run=dry_run
                )
                if cfg_status == 'already_assigned':
                    messages.append(f'Config group {config_group_id} already assigned')
                elif cfg_status == 'would_cleanup_existing':
                    messages.append(f'Would remove duplicate non-target config assignments and keep group {config_group_id}')
                elif cfg_status == 'cleaned_and_assigned':
                    messages.append(f'Removed duplicate non-target config assignments; kept group {config_group_id}')
                elif cfg_status == 'would_reassign':
                    messages.append(f'Would reassign config group to {config_group_id}')
                elif cfg_status == 'reassigned':
                    messages.append(f'Reassigned config group to {config_group_id}')
                elif cfg_status == 'would_assign':
                    messages.append(f'Would assign config group {config_group_id}')
                else:
                    messages.append(f'Assigned config group {config_group_id}')

                if row_zabbix_server_id is None:
                    messages.append('No Zabbix server resolved for device assignment')
                else:
                    server_state = _nbsync_upsert_server_assignment(
                        inst['url'],
                        inst['token'],
                        device_id,
                        row_zabbix_server_id,
                        dry_run=dry_run,
                    )
                    if server_state == 'already':
                        messages.append(f'Zabbix server {row_zabbix_server_id} already assigned')
                    elif server_state == 'would_assign':
                        messages.append(f'Would assign Zabbix server {row_zabbix_server_id}')
                    elif server_state == 'assigned':
                        messages.append(f'Assigned Zabbix server {row_zabbix_server_id}')
                    elif server_state == 'would_reassign':
                        messages.append(f'Would reassign Zabbix server to {row_zabbix_server_id}')
                    elif server_state == 'reassigned':
                        messages.append(f'Reassigned Zabbix server to {row_zabbix_server_id}')
                    elif server_state == 'would_cleanup':
                        messages.append(f'Would clean duplicate Zabbix server assignments for {row_zabbix_server_id}')
                    elif server_state == 'cleaned':
                        messages.append(f'Cleaned duplicate Zabbix server assignments for {row_zabbix_server_id}')

                if use_config_group_inheritance:
                    messages.append(
                        'Tags are managed via configuration-group inheritance; hostgroups are assigned per-device'
                    )
                    # Keep hostgroups per-device even when inheritance mode is enabled.
                    if apply_hostgroups:
                        hostgroup_targets = _build_nbsync_targets(
                            device, options,
                            apply_tags=False,
                            apply_hostgroups=True,
                            apply_macros=False,
                            template_values=row_ctx.get('template_values'),
                        )
                        for h in hostgroup_targets['hostgroups']:
                            try:
                                hg_id, hg_state = _nbsync_get_or_create_hostgroup(
                                    inst['url'], inst['token'], h, row_zabbix_server_id, dry_run, cache
                                )
                                if dry_run:
                                    messages.append(f"Hostgroup '{h}': {hg_state}")
                                    continue
                                if hg_id is None:
                                    continue
                                asn = _nbsync_assign_hostgroup(
                                    inst['url'], inst['token'], device_id, hg_id, dry_run=False
                                )
                                messages.append(f"Hostgroup '{h}': {asn}")
                            except Exception as e:
                                errors.append(f"Hostgroup '{h}' failed: {e}")
                else:
                    targets = _build_nbsync_targets(
                        device, options,
                        apply_tags=apply_tags,
                        apply_hostgroups=apply_hostgroups,
                        apply_macros=False,
                        template_values=row_ctx.get('template_values'),
                    )

                    for t in targets['tags']:
                        try:
                            tag_id, tag_state = _nbsync_get_or_create_tag(
                                inst['url'], inst['token'], t, row_zabbix_server_id, dry_run, cache
                            )
                            if dry_run:
                                messages.append(f"Tag '{t}': {tag_state}")
                                continue
                            if tag_id is None:
                                continue
                            asn = _nbsync_assign_tag(inst['url'], inst['token'], device_id, tag_id, dry_run=False)
                            messages.append(f"Tag '{t}': {asn}")
                        except Exception as e:
                            errors.append(f"Tag '{t}' failed: {e}")

                    for h in targets['hostgroups']:
                        try:
                            hg_id, hg_state = _nbsync_get_or_create_hostgroup(
                                inst['url'], inst['token'], h, row_zabbix_server_id, dry_run, cache
                            )
                            if dry_run:
                                messages.append(f"Hostgroup '{h}': {hg_state}")
                                continue
                            if hg_id is None:
                                continue
                            asn = _nbsync_assign_hostgroup(inst['url'], inst['token'], device_id, hg_id, dry_run=False)
                            messages.append(f"Hostgroup '{h}': {asn}")
                        except Exception as e:
                            errors.append(f"Hostgroup '{h}' failed: {e}")

                if apply_inventory:
                    try:
                        inventory_targets = _build_nbsync_inventory_targets(
                            options, row_ctx.get('template_values') or {}
                        )
                        inv_mode = inventory_targets.get('inventory_mode', 0)
                        inv_fields = inventory_targets.get('fields', {})
                        inv_state = _nbsync_upsert_host_inventory(
                            inst['url'],
                            inst['token'],
                            device_id,
                            inv_mode,
                            inv_fields,
                            dry_run=dry_run,
                            assigned_object_type='dcim.device',
                        )
                        if inv_state in ('created', 'updated', 'would_create', 'would_update'):
                            inventory_changed = True
                        messages.append(
                            f"Host inventory: {inv_state} (mode={inv_mode}, fields={len(inv_fields)})"
                        )
                    except Exception as e:
                        errors.append(f'Host inventory failed: {e}')

                if apply_interface:
                    try:
                        interface_targets = row_ctx.get('interface_targets')
                        if not isinstance(interface_targets, dict):
                            interface_targets = _build_nbsync_host_interface_targets(
                                device, options, zabbix_server_id=row_zabbix_server_id
                            )
                        if not bool(interface_targets.get('enabled', False)):
                            reason = str(interface_targets.get('reason') or 'disabled')
                            if reason == 'no_context':
                                messages.append('Host interface: no config-context interface (skipped)')
                            elif reason == 'missing_primary_ip':
                                messages.append('Host interface: no usable primary IPv4/DNS (skipped)')
                            else:
                                messages.append(f'Host interface: {reason} (skipped)')
                        else:
                            iface_state = _nbsync_upsert_host_interface(
                                inst['url'],
                                inst['token'],
                                device_id,
                                row_zabbix_server_id,
                                interface_targets,
                                dry_run=dry_run,
                            )
                            if iface_state in ('created', 'updated', 'would_create', 'would_update'):
                                interface_changed = True
                            messages.append(
                                f"Host interface: {iface_state} "
                                f"(type={interface_targets.get('type')}, port={interface_targets.get('port')})"
                            )
                    except Exception as e:
                        errors.append(f'Host interface failed: {e}')
        except Exception as e:
            errors.append(str(e))

        if errors:
            status = 'error'
            totals['error'] += 1
        elif dry_run:
            status = 'dry_run'
            totals['dry_run'] += 1
        elif action == 'attach' and cfg_status == 'already_assigned' and not inventory_changed and not interface_changed:
            status = 'skipped'
            totals['skipped'] += 1
        else:
            status = 'ok'
            totals['ok'] += 1

        results.append({
            'device_id': device_id,
            'name': name,
            'status': status,
            'messages': messages,
            'errors': errors,
        })

    return jsonify({
        'results': results,
        'totals': totals,
        'dry_run': dry_run,
        'fast_mode': fast_mode,
        'config_group_id': config_group_id,
        'use_configuration_group_inheritance': use_config_group_inheritance,
        'group_messages': group_messages,
        'group_errors': group_errors,
    })


@app.route('/nbsync/api/start', methods=['POST'])
@login_required
def nbsync_start():
    data = request.json or {}
    instance_id = data.get('instance_id')
    try:
        inst = resolve_instance_by_id(instance_id)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    try:
        config_group_id = int(data.get('config_group_id', 2))
        if config_group_id <= 0:
            raise ValueError
    except Exception:
        return jsonify({'error': 'config_group_id must be a positive integer'}), 400

    dry_run = bool(data.get('dry_run', False))
    remove_server = bool(data.get('removeserver', False))

    try:
        parallel = int(data.get('parallel', 1))
    except Exception:
        return jsonify({'error': 'parallel must be an integer'}), 400
    parallel = max(1, min(parallel, 16))

    try:
        delay = float(data.get('delay', 0.5))
    except Exception:
        return jsonify({'error': 'delay must be a number'}), 400
    delay = max(0.0, min(delay, 30.0))

    limit = data.get('limit')
    if limit in ('', None):
        limit = None
    else:
        try:
            limit = int(limit)
            if limit <= 0:
                raise ValueError
        except Exception:
            return jsonify({'error': 'limit must be a positive integer'}), 400

    device_id = data.get('device_id')
    if device_id in ('', None):
        device_id = None
    else:
        try:
            device_id = int(device_id)
            if device_id <= 0:
                raise ValueError
        except Exception:
            return jsonify({'error': 'device_id must be a positive integer'}), 400

    device_name = (data.get('device_name') or '').strip()

    if not os.path.exists(NBSYNC_SCRIPT):
        return jsonify({'error': f'Zabbix script not found: {NBSYNC_SCRIPT}'}), 500

    cmd = [
        _nbsync_python_bin(),
        NBSYNC_SCRIPT,
        '--instance-id', inst['id'],
        '--config-group-id', str(config_group_id),
        '--parallel', str(parallel),
        '--delay', str(delay),
    ]
    if dry_run:
        cmd.append('--dry-run')
    if remove_server:
        cmd.append('--removeserver')
    if limit is not None:
        cmd.extend(['--limit', str(limit)])
    if device_id is not None:
        cmd.extend(['--device-id', str(device_id)])
    elif device_name:
        cmd.extend(['--device-name', device_name])

    with nbsync_lock:
        if nbsync_state['running']:
            return jsonify({'error': 'Zabbix is already running'}), 400

        with open(NBSYNC_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(f"[{datetime.now().isoformat()}] Zabbix job started\n")
            f.write(f"Instance: {inst['name']} ({inst['id']})\n")
            f.write(f"Command: {' '.join(cmd)}\n")
            f.write('-' * 80 + '\n')

        log_handle = None
        try:
            log_handle = open(NBSYNC_LOG_FILE, 'a', encoding='utf-8')
            proc = subprocess.Popen(
                cmd,
                cwd=PROJECT_DIR,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
        except Exception as e:
            try:
                if log_handle:
                    log_handle.close()
            except Exception:
                pass
            return jsonify({'error': f'Failed to start Zabbix: {e}'}), 500

        nbsync_state['running'] = True
        nbsync_state['process'] = proc
        nbsync_state['start_time'] = time.time()
        nbsync_state['end_time'] = None
        nbsync_state['instance_id'] = inst['id']
        nbsync_state['instance_name'] = inst['name']
        nbsync_state['cmd'] = cmd
        nbsync_state['last_exit_code'] = None

        watcher = threading.Thread(target=_watch_nbsync_process, args=(proc, log_handle), daemon=True)
        watcher.start()

    return jsonify({'message': 'Zabbix started'})


@app.route('/nbsync/api/stop', methods=['POST'])
@login_required
def nbsync_stop():
    with nbsync_lock:
        if not nbsync_state['running'] or not nbsync_state['process']:
            return jsonify({'error': 'Zabbix is not running'}), 400
        proc = nbsync_state['process']

    try:
        proc.terminate()
    except Exception as e:
        return jsonify({'error': f'Failed to stop Zabbix: {e}'}), 500

    return jsonify({'message': 'Stop signal sent to Zabbix'})


@app.route('/nbsync/api/status', methods=['GET'])
@login_required
def nbsync_status():
    with nbsync_lock:
        proc = nbsync_state['process']
        running = bool(nbsync_state['running'] and proc and proc.poll() is None)
        payload = {
            'running': running,
            'start_time': nbsync_state['start_time'],
            'end_time': nbsync_state['end_time'],
            'instance_id': nbsync_state['instance_id'],
            'instance_name': nbsync_state['instance_name'],
            'last_exit_code': nbsync_state['last_exit_code'],
            'pid': proc.pid if proc and running else None,
        }
    return jsonify(payload)


@app.route('/nbsync/api/log', methods=['GET'])
@login_required
def nbsync_log():
    try:
        offset = int(request.args.get('offset', '0'))
    except Exception:
        offset = 0
    if offset < 0:
        offset = 0

    if not os.path.exists(NBSYNC_LOG_FILE):
        return jsonify({'text': '', 'next_offset': 0})

    file_size = os.path.getsize(NBSYNC_LOG_FILE)
    if offset > file_size:
        offset = 0

    with open(NBSYNC_LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
        f.seek(offset)
        text = f.read()
        next_offset = f.tell()

    return jsonify({'text': text, 'next_offset': next_offset})

# ===========================================================================
# Routes — Template Sync (prefixed /sync)
# ===========================================================================

@app.route('/sync/api/instances', methods=['GET'])
@login_required
def sync_get_instances():
    instances = load_instances()
    safe = [{
        'id': i['id'],
        'name': i['name'],
        'url': i['url'],
        'skip_ssl_verify': _to_bool(i.get('skip_ssl_verify', False)),
    } for i in instances]
    return jsonify({'instances': safe})


@app.route('/sync/api/instances', methods=['POST'])
@login_required
@admin_required
def sync_add_instance():
    data  = request.json or {}
    name  = data.get('name', '').strip()
    url   = data.get('url', '').strip().rstrip('/')
    token = data.get('token', '').strip()
    skip_ssl_verify = _to_bool(data.get('skip_ssl_verify', False))

    if not name or not url or not token:
        return jsonify({'error': 'name, url, and token are required'}), 400
    allowed, reason = _is_instance_url_allowed(url)
    if not allowed:
        return jsonify({'error': reason}), 400

    instances = load_instances()
    if any(i['name'] == name for i in instances):
        return jsonify({'error': f"An instance named '{name}' already exists"}), 400

    new_inst = {
        'id': uuid.uuid4().hex[:8], 'name': name, 'url': url, 'token': token,
        'skip_ssl_verify': skip_ssl_verify,
        'created': datetime.utcnow().isoformat(),
    }
    instances.append(new_inst)
    save_instances(instances)
    return jsonify({'instance': {
        'id': new_inst['id'],
        'name': new_inst['name'],
        'url': new_inst['url'],
        'skip_ssl_verify': _to_bool(new_inst.get('skip_ssl_verify', False)),
    }})


@app.route('/sync/api/instances/<inst_id>', methods=['PATCH'])
@login_required
@admin_required
def sync_update_instance(inst_id):
    data = request.json or {}
    instances = load_instances()
    inst = next((i for i in instances if i['id'] == inst_id), None)
    if not inst:
        return jsonify({'error': 'Instance not found'}), 404

    if 'name' in data:
        new_name = data['name'].strip()
        if new_name != inst['name'] and any(i['name'] == new_name for i in instances):
            return jsonify({'error': f"An instance named '{new_name}' already exists"}), 400
        inst['name'] = new_name
    if 'url' in data:
        new_url = data['url'].strip().rstrip('/')
        allowed, reason = _is_instance_url_allowed(new_url)
        if not allowed:
            return jsonify({'error': reason}), 400
        inst['url'] = new_url
    if 'token' in data and data['token'].strip():
        inst['token'] = data['token'].strip()
    if 'skip_ssl_verify' in data:
        inst['skip_ssl_verify'] = _to_bool(data.get('skip_ssl_verify'))

    save_instances(instances)
    return jsonify({'instance': {
        'id': inst['id'],
        'name': inst['name'],
        'url': inst['url'],
        'skip_ssl_verify': _to_bool(inst.get('skip_ssl_verify', False)),
    }})


@app.route('/sync/api/instances/<inst_id>', methods=['DELETE'])
@login_required
@admin_required
def sync_delete_instance(inst_id):
    instances = load_instances()
    before = len(instances)
    instances = [i for i in instances if i['id'] != inst_id]
    if len(instances) == before:
        return jsonify({'error': 'Instance not found'}), 404
    save_instances(instances)
    return jsonify({'message': 'Instance deleted'})


@app.route('/sync/api/instances/<inst_id>/test', methods=['POST'])
@login_required
@admin_required
def sync_test_instance(inst_id):
    instances = load_instances()
    inst = next((i for i in instances if i['id'] == inst_id), None)
    if not inst:
        return jsonify({'error': 'Instance not found'}), 404
    try:
        resp = requests.get(
            f"{inst['url']}/api/",
            headers=nb_headers(inst['token']),
            verify=_requests_verify_for_url(inst['url']), timeout=10,
        )
        resp.raise_for_status()
        info = resp.json()
        return jsonify({'ok': True, 'netbox_version': info.get('netbox-version', 'unknown')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/sync/api/instances/<inst_id>/branches', methods=['GET'])
@login_required
def sync_list_instance_branches(inst_id):
    instances = load_instances()
    inst = next((i for i in instances if i['id'] == inst_id), None)
    if not inst:
        return jsonify({'error': 'Instance not found'}), 404
    try:
        data = netbox_list_branches(_build_server_compare_instance(inst), timeout=15, limit=500)
        return jsonify({
            'instance_id': inst_id,
            'instance_name': inst.get('name'),
            'endpoint': data.get('endpoint'),
            'branches': data.get('branches') or [],
        })
    except Exception as e:
        return jsonify({'error': str(e), 'branches': []}), 400


@app.route('/sync/api/template-types', methods=['GET'])
@login_required
def sync_get_template_types():
    return jsonify({k: {'label': v['label']} for k, v in TEMPLATE_TYPES.items()})


def _build_server_compare_instance(raw_inst, branch=None):
    if not raw_inst:
        raise ValueError('Instance not found')
    url = str(raw_inst.get('url') or '').strip().rstrip('/')
    token = str(raw_inst.get('token') or '').strip()
    if not url or not token:
        raise ValueError(f'Instance "{raw_inst.get("name", "unknown")}" is missing URL or token')
    return {
        'id': raw_inst.get('id'),
        'name': raw_inst.get('name'),
        'url': url,
        'token': token,
        'branch': str(branch or '').strip(),
        'skip_ssl_verify': _to_bool(raw_inst.get('skip_ssl_verify', False)),
        'verify': _requests_verify_for_url(url),
    }


def _derive_branch_from_source_site(raw_source_inst, selected_key='', site_name=''):
    try:
        source_instance = _build_server_compare_instance(raw_source_inst)
        facility = server_compare_resolve_site_facility(
            source_instance,
            selected_key=str(selected_key or '').strip(),
            site_name=str(site_name or '').strip(),
        )
    except Exception:
        return ''
    return str(facility or '').strip()


def _ensure_destination_branch(raw_dest_inst, branch_name):
    name = str(branch_name or '').strip()
    if not name:
        return None
    dest_instance = _build_server_compare_instance(raw_dest_inst, branch=name)
    return ensure_branch_exists(dest_instance, name)


@app.route('/sync/api/server-compare/options', methods=['GET'])
@login_required
def server_compare_options():
    source_id = str(request.args.get('source_id') or '').strip()
    if not source_id:
        return jsonify({'error': 'source_id is required'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    if not src:
        return jsonify({'error': 'Source instance not found'}), 404

    try:
        options = server_compare_list_options(_build_server_compare_instance(src))
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'options': options})


@app.route('/sync/api/server-compare', methods=['POST'])
@login_required
def server_compare_run():
    data = request.json or {}
    source_id = str(data.get('source_id') or '').strip()
    dest_id = str(data.get('dest_id') or '').strip()
    dest_branch = str(data.get('dest_branch') or '').strip()
    scope = str(data.get('scope') or 'all').strip().lower()
    selected_key = str(data.get('selected_key') or '').strip()

    if not source_id or not dest_id:
        return jsonify({'error': 'source_id and dest_id are required'}), 400
    if source_id == dest_id:
        return jsonify({'error': 'Source and destination must be different instances'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    dst = inst_map.get(dest_id)
    if not src or not dst:
        return jsonify({'error': 'One or both instances not found'}), 400

    if not dest_branch and scope == 'site' and selected_key:
        dest_branch = _derive_branch_from_source_site(src, selected_key=selected_key)

    if dest_branch:
        try:
            _ensure_destination_branch(dst, dest_branch)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    try:
        results = server_compare_instances(
            _build_server_compare_instance(src),
            _build_server_compare_instance(dst, branch=dest_branch),
            scope=scope,
            selected_key=selected_key,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'results': results})


@app.route('/sync/api/server-sync', methods=['POST'])
@login_required
def server_compare_sync():
    data = request.json or {}
    source_id = str(data.get('source_id') or '').strip()
    dest_id = str(data.get('dest_id') or '').strip()
    dest_branch = str(data.get('dest_branch') or '').strip()
    items = data.get('items') or []

    if not source_id or not dest_id:
        return jsonify({'error': 'source_id and dest_id are required'}), 400
    if source_id == dest_id:
        return jsonify({'error': 'Source and destination must be different instances'}), 400
    if not isinstance(items, list) or not items:
        return jsonify({'error': 'items is required and must be a non-empty list'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    dst = inst_map.get(dest_id)
    if not src or not dst:
        return jsonify({'error': 'One or both instances not found'}), 400

    if not dest_branch:
        site_item = next(
            (
                it for it in items
                if str((it or {}).get('object_type') or '').strip().lower() == 'site'
                and str((it or {}).get('key') or '').strip()
            ),
            None,
        )
        if site_item:
            dest_branch = _derive_branch_from_source_site(
                src,
                selected_key=str((site_item or {}).get('key') or '').strip(),
            )

    if dest_branch:
        try:
            _ensure_destination_branch(dst, dest_branch)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    try:
        results = server_compare_sync_many(
            _build_server_compare_instance(src),
            _build_server_compare_instance(dst, branch=dest_branch),
            items,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'results': results})


@app.route('/sync/api/site-sync/plan', methods=['POST'])
@login_required
def site_sync_plan():
    data = request.json or {}
    source_id = str(data.get('source_id') or '').strip()
    site_name = str(data.get('site_name') or '').strip()

    if not source_id:
        return jsonify({'error': 'source_id is required'}), 400
    if not site_name:
        return jsonify({'error': 'site_name is required'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    if not src:
        return jsonify({'error': 'Source instance not found'}), 404

    try:
        plan = build_site_sync_plan(_build_server_compare_instance(src), site_name=site_name)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'plan': plan})


@app.route('/sync/api/site-sync/start', methods=['POST'])
@login_required
def site_sync_start():
    data = request.json or {}
    source_id = str(data.get('source_id') or '').strip()
    dest_id = str(data.get('dest_id') or '').strip()
    dest_branch = str(data.get('dest_branch') or '').strip()
    site_name = str(data.get('site_name') or '').strip()
    selected_groups = data.get('selected_groups') or []
    selected_item_ids = data.get('selected_item_ids') or []
    dry_run = _to_bool(data.get('dry_run', False))
    try:
        workers = int(data.get('workers', 2) or 2)
    except Exception:
        return jsonify({'error': 'workers must be an integer'}), 400
    workers = max(1, min(8, workers))
    owner = str(session.get('username') or '')

    if not source_id or not dest_id:
        return jsonify({'error': 'source_id and dest_id are required'}), 400
    if source_id == dest_id:
        return jsonify({'error': 'Source and destination must be different instances'}), 400
    if not site_name:
        return jsonify({'error': 'site_name is required'}), 400
    if not isinstance(selected_groups, list):
        return jsonify({'error': 'selected_groups must be a list'}), 400
    if not isinstance(selected_item_ids, list):
        return jsonify({'error': 'selected_item_ids must be a list'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    dst = inst_map.get(dest_id)
    if not src or not dst:
        return jsonify({'error': 'One or both instances not found'}), 400

    if not dest_branch:
        dest_branch = _derive_branch_from_source_site(src, site_name=site_name)

    if dest_branch:
        try:
            _ensure_destination_branch(dst, dest_branch)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    with site_sync_jobs_lock:
        _site_sync_jobs_cleanup_locked()
        for state in site_sync_jobs.values():
            if str(state.get('owner') or '') == owner and str(state.get('status') or '') in {'queued', 'running'}:
                return jsonify({
                    'error': 'A site sync is already running for this user',
                    'job_id': str(state.get('job_id') or ''),
                }), 409

        job_id = uuid.uuid4().hex[:12]
        now_ts = time.time()
        log_file = os.path.join(LOG_DIR, f'site_sync_{job_id}.log')
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"[{datetime.now().isoformat()}] Site sync job queued\n")
        except Exception:
            pass
        site_sync_jobs[job_id] = {
            'job_id': job_id,
            'owner': owner,
            'status': 'queued',
            'stage': 'queued',
            'message': 'Queued site sync job.',
            'error': '',
            'site_name': site_name,
            'dest_branch': dest_branch,
            'dry_run': bool(dry_run),
            'workers': int(workers),
            'created_at': now_ts,
            'started_at': 0.0,
            'finished_at': 0.0,
            'updated_at': now_ts,
            'log_file': log_file,
            'total_items': 0,
            'processed_items': 0,
            'total_sections': 0,
            'completed_sections': 0,
            'current_section': '',
            'current_item': '',
            'sections': [],
            'dependency_sections': [],
            'section_totals': {},
            'section_done': {},
            'section_stats': {},
            'totals': _site_sync_zero_stats(),
            'fallback': _site_sync_zero_fallback(),
            'result': None,
        }

    source_instance = _build_server_compare_instance(src)
    dest_instance = _build_server_compare_instance(dst, branch=dest_branch)
    t = threading.Thread(
        target=_site_sync_worker_run,
        args=(
            job_id,
            source_instance,
            dest_instance,
            site_name,
            selected_groups,
            selected_item_ids,
            dry_run,
            workers,
        ),
        daemon=True,
    )
    t.start()

    return jsonify({'job_id': job_id, 'status': 'running', 'dest_branch': dest_branch, 'workers': int(workers)})


@app.route('/sync/api/site-sync/progress', methods=['GET'])
@login_required
def site_sync_progress():
    job_id = str(request.args.get('job_id') or '').strip()
    if not job_id:
        return jsonify({'error': 'job_id is required'}), 400
    owner = str(session.get('username') or '')
    with site_sync_jobs_lock:
        _site_sync_jobs_cleanup_locked()
        state = site_sync_jobs.get(job_id)
        if not state:
            return jsonify({'error': 'site sync job not found'}), 404
        if owner and str(state.get('owner') or '') not in {'', owner}:
            return jsonify({'error': 'site sync job not found'}), 404
        payload = _site_sync_job_snapshot(state)
    return jsonify(payload)


@app.route('/sync/api/site-sync/log', methods=['GET'])
@login_required
def site_sync_log():
    job_id = str(request.args.get('job_id') or '').strip()
    if not job_id:
        return jsonify({'error': 'job_id is required'}), 400
    try:
        offset = int(request.args.get('offset', '0'))
    except Exception:
        offset = 0
    if offset < 0:
        offset = 0

    owner = str(session.get('username') or '')
    with site_sync_jobs_lock:
        _site_sync_jobs_cleanup_locked()
        state = site_sync_jobs.get(job_id)
        if not state:
            return jsonify({'error': 'site sync job not found'}), 404
        if owner and str(state.get('owner') or '') not in {'', owner}:
            return jsonify({'error': 'site sync job not found'}), 404
        log_path = str(state.get('log_file') or '').strip()
    if not log_path:
        return jsonify({'text': '', 'next_offset': 0})
    if not os.path.exists(log_path):
        return jsonify({'text': '', 'next_offset': 0})

    file_size = os.path.getsize(log_path)
    if offset > file_size:
        offset = 0

    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        f.seek(offset)
        text = f.read()
        next_offset = f.tell()
    return jsonify({'text': text, 'next_offset': next_offset})


@app.route('/sync/api/site-sync/run', methods=['POST'])
@login_required
def site_sync_run():
    data = request.json or {}
    source_id = str(data.get('source_id') or '').strip()
    dest_id = str(data.get('dest_id') or '').strip()
    dest_branch = str(data.get('dest_branch') or '').strip()
    site_name = str(data.get('site_name') or '').strip()
    selected_groups = data.get('selected_groups') or []
    selected_item_ids = data.get('selected_item_ids') or []
    dry_run = _to_bool(data.get('dry_run', False))
    try:
        workers = int(data.get('workers', 2) or 2)
    except Exception:
        return jsonify({'error': 'workers must be an integer'}), 400
    workers = max(1, min(8, workers))

    if not source_id or not dest_id:
        return jsonify({'error': 'source_id and dest_id are required'}), 400
    if source_id == dest_id:
        return jsonify({'error': 'Source and destination must be different instances'}), 400
    if not site_name:
        return jsonify({'error': 'site_name is required'}), 400
    if not isinstance(selected_groups, list):
        return jsonify({'error': 'selected_groups must be a list'}), 400
    if not isinstance(selected_item_ids, list):
        return jsonify({'error': 'selected_item_ids must be a list'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    dst = inst_map.get(dest_id)
    if not src or not dst:
        return jsonify({'error': 'One or both instances not found'}), 400

    if not dest_branch:
        dest_branch = _derive_branch_from_source_site(src, site_name=site_name)

    if dest_branch:
        try:
            _ensure_destination_branch(dst, dest_branch)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    try:
        result = sync_site_data(
            _build_server_compare_instance(src),
            _build_server_compare_instance(dst, branch=dest_branch),
            site_name=site_name,
            selected_groups=selected_groups,
            selected_item_ids=selected_item_ids,
            dry_run=dry_run,
            workers=workers,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'result': result})


@app.route('/sync/api/compare', methods=['POST'])
@login_required
def sync_compare():
    data      = request.json or {}
    source_id = data.get('source_id')
    dest_id   = data.get('dest_id')
    types     = data.get('template_types', list(TEMPLATE_TYPES.keys()))

    if not source_id or not dest_id:
        return jsonify({'error': 'source_id and dest_id are required'}), 400
    if source_id == dest_id:
        return jsonify({'error': 'Source and destination must be different instances'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    dst = inst_map.get(dest_id)
    if not src or not dst:
        return jsonify({'error': 'One or both instances not found'}), 400

    all_results, errors = {}, {}
    for tt in types:
        if tt not in TEMPLATE_TYPES:
            continue
        try:
            items = compare_type(src['url'], src['token'], dst['url'], dst['token'], tt)
            all_results[tt] = {'label': TEMPLATE_TYPES[tt]['label'], 'items': items}
        except Exception as e:
            errors[tt] = str(e)

    return jsonify({'results': all_results, 'errors': errors})


@app.route('/sync/api/sync', methods=['POST'])
@login_required
def sync_do_sync():
    data      = request.json or {}
    source_id = data.get('source_id')
    dest_id   = data.get('dest_id')
    items     = data.get('items', [])
    requested_branch = _extract_requested_branch(data, key='dest_branch')
    if requested_branch == AUTO_BRANCH_SENTINEL:
        requested_branch = _extract_requested_branch(data, key='branch')
    if not source_id or not dest_id:
        return jsonify({'error': 'source_id and dest_id are required'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    dst = inst_map.get(dest_id)
    if not src or not dst:
        return jsonify({'error': 'One or both instances not found'}), 400

    branch = _normalize_requested_branch(requested_branch)
    if not branch or branch == AUTO_BRANCH_SENTINEL:
        branch = _derive_auto_branch_from_sync_items(items)
    if not branch:
        return jsonify({'error': 'Destination branch is required for Template Sync writes'}), 400
    branch = _clean_branch_name(branch)
    if not branch:
        return jsonify({'error': 'Destination branch name is invalid'}), 400

    item_types = {
        str((it or {}).get('template_type') or '').strip()
        for it in (items or [])
        if isinstance(it, dict)
    }
    branch_created = False
    try:
        branch_info = _ensure_destination_branch(dst, branch)
        branch_created = bool((branch_info or {}).get('created'))
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    try:
        branch_header_value = resolve_branch_header_value(_build_server_compare_instance(dst), branch)
    except Exception as e:
        return jsonify({'error': f'Failed to resolve destination branch header for "{branch}": {e}'}), 400
    if not branch_header_value:
        return jsonify({'error': f'Failed to resolve destination branch header for "{branch}"'}), 400

    dst_url_base = str(dst.get('url') or '').strip().rstrip('/')

    # New branches can take a short moment before API writes consistently land.
    # Warm the branch once so users do not need to run sync twice manually.
    if branch_created:
        warmup_endpoints = []
        for ttype in item_types:
            cfg = TEMPLATE_TYPES.get(str(ttype or '').strip())
            ep = str((cfg or {}).get('endpoint') or '').strip().strip('/')
            if ep and ep not in warmup_endpoints:
                warmup_endpoints.append(ep)
        if not warmup_endpoints:
            warmup_endpoints = ['dcim/sites']
        warmup_endpoints = warmup_endpoints[:4]
        for attempt in range(1, 7):
            warmed = False
            for ep in warmup_endpoints:
                ok_probe, _ = _probe_branch_endpoint(
                    dst.get('url'),
                    dst.get('token'),
                    branch_header_value,
                    endpoint=ep,
                )
                if ok_probe:
                    warmed = True
                    break
            if warmed:
                break
            time.sleep(min(0.6 * attempt, 2.0))

    def _sync_one_with_branch(tt, name, hdr_value):
        h_tok = REQUEST_BRANCH_HEADER.set(str(hdr_value or '').strip())
        u_tok = REQUEST_BRANCH_URL.set(dst_url_base)
        try:
            return sync_one_template(src['url'], src['token'], dst['url'], dst['token'], tt, name)
        finally:
            REQUEST_BRANCH_URL.reset(u_tok)
            REQUEST_BRANCH_HEADER.reset(h_tok)

    context_branch_cache = {}
    context_branch_bad = set()

    def _probe_context_branch_by_name(branch_name, ensure=False):
        candidate = _clean_branch_name(branch_name)
        if not candidate:
            return '', ''
        cached = context_branch_cache.get(candidate)
        if cached:
            return cached
        if not ensure and candidate in context_branch_bad:
            return '', ''
        try:
            if ensure:
                _ensure_destination_branch(dst, candidate)
            hdr = resolve_branch_header_value(_build_server_compare_instance(dst), candidate)
            if not hdr:
                context_branch_bad.add(candidate)
                return '', ''
            ok_probe, _ = _probe_branch_endpoint(
                dst.get('url'),
                dst.get('token'),
                hdr,
                endpoint='extras/config-contexts',
            )
            if ok_probe:
                context_branch_cache[candidate] = (candidate, hdr)
                return candidate, hdr
        except Exception:
            pass
        context_branch_bad.add(candidate)
        return '', ''

    def _candidate_context_branches(base_branch_name):
        base_name = _clean_branch_name(base_branch_name) or 'Tempalte-Sync-config-contexts'
        names = []
        seen = set()
        for initial in (base_name,):
            if initial and initial not in seen:
                seen.add(initial)
                names.append(initial)
        try:
            branch_data = netbox_list_branches(_build_server_compare_instance(dst), timeout=15, limit=500)
            for row in (branch_data.get('branches') or []):
                name = _clean_branch_name((row or {}).get('name', ''))
                if not name:
                    continue
                if name == base_name or name.startswith(f"{base_name}-"):
                    if name not in seen:
                        seen.add(name)
                        names.append(name)
        except Exception:
            pass
        if len(names) <= 1:
            return names
        exact = [n for n in names if n == base_name]
        variants = sorted((n for n in names if n != base_name), reverse=True)
        return exact + variants

    def _pick_healthy_context_branch(base_branch_name, create_attempts=0):
        base_name = _clean_branch_name(base_branch_name) or 'Tempalte-Sync-config-contexts'
        for candidate in _candidate_context_branches(base_name):
            ok_name, ok_hdr = _probe_context_branch_by_name(candidate, ensure=False)
            if ok_name and ok_hdr:
                return ok_name, ok_hdr
        attempts = max(0, int(create_attempts or 0))
        for _ in range(attempts):
            candidate = _clean_branch_name(
                f"{base_name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
            )
            if not candidate:
                continue
            ok_name, ok_hdr = _probe_context_branch_by_name(candidate, ensure=True)
            if ok_name and ok_hdr:
                return ok_name, ok_hdr
        return '', ''

    if 'config-contexts' in item_types:
        ok, probe_msg = _probe_branch_endpoint(dst.get('url'), dst.get('token'), branch_header_value, endpoint='extras/config-contexts')
        if not ok and _looks_like_branch_schema_name_error(500, probe_msg):
            fresh_branch, fresh_header = _pick_healthy_context_branch(branch, create_attempts=0)
            if fresh_branch and fresh_header:
                branch = fresh_branch
                branch_header_value = fresh_header

    results = []
    for item in items:
        tt   = item.get('template_type')
        name = item.get('name')
        item_branch = branch
        item_header = branch_header_value
        try:
            _sync_one_with_branch(tt, name, item_header)
            results.append({'name': name, 'template_type': tt, 'status': 'ok', 'branch': item_branch})
            continue
        except Exception as first_exc:
            first_msg = str(first_exc or '')
            if branch_created:
                try:
                    time.sleep(0.5)
                    _sync_one_with_branch(tt, name, item_header)
                    results.append({
                        'name': name,
                        'template_type': tt,
                        'status': 'ok',
                        'branch': item_branch,
                    })
                    continue
                except Exception as retry_same_branch_exc:
                    first_msg = str(retry_same_branch_exc or first_msg)
            can_retry_fresh = False
            if (
                str(tt or '').strip() == 'config-contexts'
                and _looks_like_branch_schema_name_error(500, first_msg)
            ):
                probe_ok, probe_msg = _probe_branch_endpoint(
                    dst.get('url'),
                    dst.get('token'),
                    item_header,
                    endpoint='extras/config-contexts',
                )
                can_retry_fresh = (not probe_ok) and _looks_like_branch_schema_name_error(500, probe_msg)
            if can_retry_fresh:
                try:
                    fresh_branch, fresh_header = _pick_healthy_context_branch(
                        item_branch or branch or 'Tempalte-Sync-config-contexts',
                        create_attempts=0,
                    )
                    if fresh_branch and fresh_header:
                        item_branch = fresh_branch
                        item_header = fresh_header
                        _sync_one_with_branch(tt, name, item_header)
                        if str(tt or '').strip() == 'config-contexts':
                            branch = item_branch
                            branch_header_value = item_header
                        results.append({'name': name, 'template_type': tt, 'status': 'ok', 'branch': item_branch})
                        continue
                except Exception as retry_exc:
                    first_msg = str(retry_exc or first_msg)
            results.append({
                'name': name,
                'template_type': tt,
                'status': 'error',
                'error': _friendly_legacy_sync_error(tt, first_msg, item_branch),
                'branch': item_branch,
            })

    return jsonify({'results': results, 'dest_branch': branch})


# ===========================================================================
# Routes — Settings (users + current user info)
# ===========================================================================

@app.route('/settings/api/users', methods=['GET'])
@login_required
@admin_required
def settings_get_users():
    users = load_users()
    safe = [{'id': u['id'], 'username': u['username'], 'role': u.get('role', 'admin'), 'created': u.get('created', '')}
            for u in users]
    current = _get_current_user() or {}
    return jsonify({
        'users': safe,
        'current_user': session.get('username'),
        'current_user_id': session.get('user_id'),
        'current_user_role': current.get('role', 'admin'),
    })


@app.route('/settings/api/users', methods=['POST'])
@login_required
@admin_required
def settings_add_user():
    data     = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = str(data.get('role') or 'admin').strip().lower()
    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400
    if role not in ('admin', 'operator'):
        return jsonify({'error': 'role must be admin or operator'}), 400
    pw_error = _validate_password_strength(password)
    if pw_error:
        return jsonify({'error': pw_error}), 400
    users = load_users()
    if any(u['username'] == username for u in users):
        return jsonify({'error': f"User '{username}' already exists"}), 400
    new_user = {
        'id': uuid.uuid4().hex[:8],
        'username': username,
        'password_hash': generate_password_hash(password),
        'role': role,
        'must_change_password': False,
        'created': datetime.utcnow().isoformat(),
    }
    users.append(new_user)
    save_users(users)
    return jsonify({'user': {'id': new_user['id'], 'username': new_user['username'], 'role': new_user['role']}})


@app.route('/settings/api/users/<user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def settings_reset_password(user_id):
    data   = request.json or {}
    new_pw = data.get('new_password', '')
    pw_error = _validate_password_strength(new_pw)
    if pw_error:
        return jsonify({'error': pw_error}), 400
    users = load_users()
    user  = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user['password_hash'] = generate_password_hash(new_pw)
    user['must_change_password'] = True
    save_users(users)
    return jsonify({'message': f"Password reset for {user['username']} (change required at next login)"})


@app.route('/settings/api/users/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def settings_delete_user(user_id):
    if session.get('user_id') == user_id:
        return jsonify({'error': 'You cannot delete your own account'}), 400
    users = load_users()
    if len(users) <= 1:
        return jsonify({'error': 'Cannot delete the last user'}), 400
    target = next((u for u in users if u['id'] == user_id), None)
    if not target:
        return jsonify({'error': 'User not found'}), 404
    if _is_admin_user(target):
        remaining_admins = sum(1 for u in users if _is_admin_user(u) and u.get('id') != user_id)
        if remaining_admins <= 0:
            return jsonify({'error': 'Cannot delete the last admin user'}), 400
    before = len(users)
    users  = [u for u in users if u['id'] != user_id]
    if len(users) == before:
        return jsonify({'error': 'User not found'}), 404
    save_users(users)
    return jsonify({'message': 'User deleted'})


@app.route('/settings/api/change-password', methods=['POST'])
@login_required
def settings_change_password():
    data       = request.json or {}
    current_pw = data.get('current_password', '')
    new_pw     = data.get('new_password', '')
    confirm_pw = data.get('confirm_password', '')
    if not current_pw or not new_pw:
        return jsonify({'error': 'current_password and new_password are required'}), 400
    pw_error = _validate_password_strength(new_pw)
    if pw_error:
        return jsonify({'error': pw_error}), 400
    if new_pw != confirm_pw:
        return jsonify({'error': 'New password and confirmation do not match'}), 400
    users   = load_users()
    user_id = session.get('user_id')
    user    = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({'error': 'Session user not found'}), 404
    if not check_password_hash(user['password_hash'], current_pw):
        return jsonify({'error': 'Current password is incorrect'}), 400
    user['password_hash'] = generate_password_hash(new_pw)
    user['must_change_password'] = False
    save_users(users)
    session.pop('force_password_change', None)
    return jsonify({'message': 'Password changed successfully'})


@app.route('/settings/api/ssl', methods=['GET'])
@login_required
@admin_required
def settings_get_ssl():
    """Get current SSL configuration (without exposing key file contents)."""
    ssl_config = load_ssl_config()
    # Don't expose sensitive paths in full detail, just whether it's enabled
    return jsonify({
        'enabled': ssl_config.get('enabled', False),
        'certfile': ssl_config.get('certfile', ''),
        'keyfile': ssl_config.get('keyfile', ''),
    })


@app.route('/settings/api/ssl', methods=['POST'])
@login_required
@admin_required
def settings_update_ssl():
    """Update SSL configuration."""
    data = request.json or {}
    
    new_config = {
        'enabled': _to_bool(data.get('enabled', False)),
        'certfile': str(data.get('certfile', '') or '').strip(),
        'keyfile': str(data.get('keyfile', '') or '').strip(),
    }
    
    # Validate if enabled
    if new_config['enabled']:
        valid, error_msg = verify_ssl_config(new_config)
        if not valid:
            return jsonify({'error': f'SSL validation failed: {error_msg}'}), 400
    
    # Save the configuration
    save_ssl_config(new_config)
    
    app.logger.info(
        'SSL configuration updated: enabled=%s, certfile=%s, keyfile=%s',
        new_config['enabled'],
        new_config.get('certfile', ''),
        new_config.get('keyfile', '')
    )
    
    return jsonify({
        'message': 'SSL configuration updated. The application must be restarted for changes to take effect.',
        'config': new_config,
    })


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == '__main__':
    _migrate_tokens()
    _init_default_user()
    _mark_bootstrap_admin_for_password_change()
    port = int(os.getenv('PORT', 81))
    
    # Load and configure SSL if enabled
    ssl_config = load_ssl_config()
    ssl_context = None
    
    if ssl_config.get('enabled'):
        valid, error_msg = verify_ssl_config(ssl_config)
        if not valid:
            app.logger.error('SSL configuration error: %s', error_msg)
            raise RuntimeError(f'SSL configuration error: {error_msg}')
        
        ssl_context = (ssl_config.get('certfile'), ssl_config.get('keyfile'))
        app.logger.info(
            'Starting HTTPS server on 0.0.0.0:%d (certfile: %s, keyfile: %s)',
            port,
            ssl_config.get('certfile'),
            ssl_config.get('keyfile')
        )
        app.run(host='0.0.0.0', port=port, debug=False, ssl_context=ssl_context)
    else:
        app.logger.info('Starting HTTP server on 0.0.0.0:%d', port)
        app.run(host='0.0.0.0', port=port, debug=False)
