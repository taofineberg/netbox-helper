import os
import json
import uuid
import difflib
import hmac
import hashlib
import base64
import secrets as _secrets
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from dotenv import load_dotenv

# Load .env from parent directory
_parent = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
load_dotenv(dotenv_path=os.path.join(_parent, '.env'))

# Suppress SSL warnings for self-signed certs
import urllib3


def _env_bool(name, default=False):
    raw = str(os.getenv(name, str(default))).strip().lower()
    return raw in ('1', 'true', 'yes', 'on')


TLS_VERIFY = _env_bool('NBH_TLS_VERIFY', True)
TLS_CA_BUNDLE = str(os.getenv('NBH_TLS_CA_BUNDLE', '') or '').strip()
if not TLS_VERIFY and not TLS_CA_BUNDLE:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _requests_verify():
    return TLS_CA_BUNDLE if TLS_CA_BUNDLE else TLS_VERIFY

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'template_sync_secret_key_change_me')

APP_USERNAME = os.getenv('APP_USERNAME', 'admin')
APP_PASSWORD = os.getenv('APP_PASSWORD', 'admin')

INSTANCES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instances.json')

# ---------------------------------------------------------------------------
# Template type definitions
# ---------------------------------------------------------------------------
# match_key  : field used to match records across instances (default: 'name')
# handler    : 'dcim-simple' | 'device-types' | 'module-types' | None (extras)
# ---------------------------------------------------------------------------

TEMPLATE_TYPES = {
    # ── Extras ──────────────────────────────────────────────────────────────
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
    # ── DCIM simple (no special dependencies) ───────────────────────────────
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
    # ── DCIM complex (components + dependency resolution) ───────────────────
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
    'rack-types': {
        'label': 'Rack Types',
        'endpoint': 'dcim/rack-types',
        'match_key': 'slug',
        'compare_fields': ['name', 'slug', 'manufacturer', 'model', 'form_factor', 'width', 'u_height', 'is_frame', 'description', 'comments'],
        'sync_fields':    ['name', 'slug', 'manufacturer', 'model', 'form_factor', 'width', 'u_height', 'is_frame', 'description', 'comments'],
    },
    'rack-roles': {
        'label': 'Rack Roles',
        'endpoint': 'dcim/rack-roles',
        'match_key': 'slug',
        'compare_fields': ['name', 'slug', 'color', 'description'],
        'sync_fields':    ['name', 'slug', 'color', 'description'],
    },
    'reservations': {
        'label': 'Reservations',
        'endpoint': 'dcim/reservations',
        'match_key': 'id',
        'compare_fields': ['user', 'reservation', 'description'],
        'sync_fields':    ['user', 'reservation', 'description'],
    },
}

# ---------------------------------------------------------------------------
# Component template definitions (device-types and module-types share these)
# Ordered so dependencies are resolved before dependents:
#   rear-port-templates → front-port-templates
#   power-port-templates → power-outlet-templates
# ---------------------------------------------------------------------------

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
# Token encryption (HMAC-CTR stream cipher, stdlib only)
# Tokens are encrypted at rest in instances.json.
# Encrypted values start with the prefix 'enc:'.
# ---------------------------------------------------------------------------

def _make_key():
    """Derive a 32-byte key from SECRET_KEY."""
    secret = os.getenv('SECRET_KEY', 'changeme_set_in_env')
    return hashlib.sha256(secret.encode('utf-8')).digest()


def encrypt_token(token):
    """Encrypt a plaintext token. Returns 'enc:<base64>' string."""
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
    """Decrypt a stored token. Falls back to plaintext for legacy values."""
    if not isinstance(stored, str) or not stored.startswith('enc:'):
        return stored   # legacy plaintext — will be encrypted on next save
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
        return stored   # if corrupt, return as-is

# ---------------------------------------------------------------------------
# Instance persistence
# ---------------------------------------------------------------------------

def load_instances():
    """Load instances, decrypting tokens for internal use."""
    if os.path.exists(INSTANCES_FILE):
        with open(INSTANCES_FILE, 'r') as f:
            instances = json.load(f).get('instances', [])
        for inst in instances:
            if 'token' in inst:
                inst['token'] = decrypt_token(inst['token'])
        return instances
    return []


def save_instances(instances):
    """Save instances, encrypting tokens at rest."""
    to_save = []
    for inst in instances:
        s = dict(inst)
        if 'token' in s and s['token'] and not s['token'].startswith('enc:'):
            s['token'] = encrypt_token(s['token'])
        to_save.append(s)
    with open(INSTANCES_FILE, 'w') as f:
        json.dump({'instances': to_save}, f, indent=2)


def _migrate_tokens():
    """One-time migration: encrypt any plaintext tokens already on disk."""
    if not os.path.exists(INSTANCES_FILE):
        return
    try:
        with open(INSTANCES_FILE, 'r') as f:
            raw = json.load(f).get('instances', [])
        if any(not (i.get('token', '') or '').startswith('enc:') for i in raw):
            save_instances(load_instances())
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Netbox API helpers
# ---------------------------------------------------------------------------

def nb_headers(token):
    return {'Authorization': f'Token {token}', 'Accept': 'application/json'}


def fetch_all(url, token, endpoint, params=None):
    """Paginated fetch from a Netbox API endpoint with optional filter params."""
    base = url.rstrip('/')
    qs = '&'.join(f'{k}={v}' for k, v in (params or {}).items())
    api_url = f"{base}/api/{endpoint}/?limit=1000{'&'+qs if qs else ''}"
    results = []
    while api_url:
        try:
            resp = requests.get(api_url, headers=nb_headers(token), verify=_requests_verify(), timeout=30)
        except requests.exceptions.ConnectionError as e:
            raise ValueError(f"Cannot connect to {base} — {e}")
        except requests.exceptions.Timeout:
            raise ValueError(f"Connection timed out for {base}")

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

        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get('results', []))
        api_url = data.get('next')
    return results


def nb_post(url, token, endpoint, payload):
    """POST to Netbox API, raise on failure."""
    h = {**nb_headers(token), 'Content-Type': 'application/json'}
    resp = requests.post(
        f"{url.rstrip('/')}/api/{endpoint}/",
        headers=h, json=payload, verify=_requests_verify(), timeout=30,
    )
    if not resp.ok:
        raise ValueError(f"POST {endpoint}: {resp.status_code} {resp.text[:250]}")
    return resp.json()


def nb_patch(url, token, endpoint, obj_id, payload):
    """PATCH to Netbox API, raise on failure."""
    h = {**nb_headers(token), 'Content-Type': 'application/json'}
    resp = requests.patch(
        f"{url.rstrip('/')}/api/{endpoint}/{obj_id}/",
        headers=h, json=payload, verify=_requests_verify(), timeout=30,
    )
    if not resp.ok:
        raise ValueError(f"PATCH {endpoint}/{obj_id}: {resp.status_code} {resp.text[:250]}")
    return resp.json()

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _enum(obj, field):
    """Extract .value from a Netbox enum field (type, feed_leg, subdevice_role, etc.)."""
    val = (obj or {}).get(field)
    if isinstance(val, dict):
        return val.get('value')
    return val


def _slug(obj, field):
    """Extract .slug from a nested Netbox object field."""
    val = (obj or {}).get(field)
    if isinstance(val, dict):
        return val.get('slug')
    return val


def _name(obj, field):
    """Extract .name from a nested Netbox object field."""
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


# ── Component template normalisation ────────────────────────────────────────

def normalize_component(tmpl, ctype_cfg):
    """Produce a stable comparison dict for one component template."""
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
                            rear_port_map=None, power_port_map=None,
                            src_rp_id_map=None):
    """Build the API payload to create/update a component template."""
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
        # NetBox < 4.x: rear_port is an inline object {id, name, ...}
        rp_name = _name(tmpl, 'rear_port')
        rp_position = tmpl.get('rear_port_position', 1)
        # NetBox 4.x: changed to rear_ports array [{position, rear_port: <id>, rear_port_position}]
        if not rp_name and tmpl.get('rear_ports') and src_rp_id_map:
            entry = tmpl['rear_ports'][0] if tmpl['rear_ports'] else None
            if entry:
                src_rp_id = entry.get('rear_port')
                rp_name = src_rp_id_map.get(src_rp_id)
                rp_position = entry.get('rear_port_position', 1)
        if rp_name and rp_name in rear_port_map:
            payload['rear_port'] = rear_port_map[rp_name]
            payload['rear_port_position'] = rp_position

    if ctype_cfg.get('resolve_power_port') and power_port_map:
        pp_name = _name(tmpl, 'power_port')
        if pp_name and pp_name in power_port_map:
            payload['power_port'] = power_port_map[pp_name]

    return payload


# ── Device / module type core normalisation ──────────────────────────────────

def normalize_device_type_core(dt):
    return {
        'model':                   dt.get('model'),
        'slug':                    dt.get('slug'),
        'manufacturer':            _slug(dt, 'manufacturer'),
        'part_number':             dt.get('part_number', ''),
        'u_height':                dt.get('u_height'),
        'exclude_from_utilization': dt.get('exclude_from_utilization', False),
        'is_full_depth':           dt.get('is_full_depth', True),
        'subdevice_role':          _enum(dt, 'subdevice_role'),
        'airflow':                 _enum(dt, 'airflow'),
        'weight':                  dt.get('weight'),
        'weight_unit':             _enum(dt, 'weight_unit'),
        'description':             dt.get('description', ''),
        'comments':                dt.get('comments', ''),
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


# ---------------------------------------------------------------------------
# Bulk component fetch
# ---------------------------------------------------------------------------

def fetch_components_bulk(url, token, parent_field):
    """
    Fetch ALL component templates from `url` for all device/module types.
    parent_field: 'device_type' or 'module_type'
    Returns: {parent_id: {endpoint: [normalized_component, ...]}}
    """
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

    # Sort each list by name for stable comparison
    for comps_by_ep in result.values():
        for lst in comps_by_ep.values():
            lst.sort(key=lambda t: t.get('name', ''))

    return result


def enrich_with_components(norm_core, parent_id, components_bulk):
    """Add component lists (sorted, normalised) to a core normalised dict."""
    comps = components_bulk.get(parent_id, {})
    for ctype in COMPONENT_TYPES:
        ep = ctype['endpoint']
        norm_core[ep] = comps.get(ep, [])
    return norm_core


# ---------------------------------------------------------------------------
# Core compare & sync logic — extras / simple DCIM
# ---------------------------------------------------------------------------

def compare_type(source_url, source_token, dest_url, dest_token, template_type):
    """Dispatch to the right compare function based on the type's handler."""
    cfg = TEMPLATE_TYPES[template_type]

    handler = cfg.get('handler')
    if handler == 'device-types':
        return compare_device_types(source_url, source_token, dest_url, dest_token)
    if handler == 'module-types':
        return compare_module_types(source_url, source_token, dest_url, dest_token)

    # Simple comparison (extras + manufacturers + module-type-profiles)
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


def sync_one(source_url, source_token, dest_url, dest_token, template_type, name):
    """Dispatch to the right sync function."""
    cfg = TEMPLATE_TYPES[template_type]

    handler = cfg.get('handler')
    if handler == 'device-types':
        return sync_device_type(source_url, source_token, dest_url, dest_token, name)
    if handler == 'module-types':
        return sync_module_type(source_url, source_token, dest_url, dest_token, name)

    # Simple sync (extras + manufacturers + module-type-profiles)
    endpoint   = cfg['endpoint']
    sync_fields = cfg['sync_fields']
    match_key  = cfg.get('match_key', 'name')

    src_items = fetch_all(source_url, source_token, endpoint)
    src = next((i for i in src_items if i[match_key] == name), None)
    if not src:
        raise ValueError(f"'{name}' not found in source")

    dst_items = fetch_all(dest_url, dest_token, endpoint)
    dst = next((i for i in dst_items if i[match_key] == name), None)

    payload = {f: src[f] for f in sync_fields if f in src}

    # Special handling for rack-types: resolve FK and normalize choice fields
    if template_type == 'rack-types':
        if 'manufacturer' in payload:
            mfr_slug = _slug(src, 'manufacturer')
            payload['manufacturer'] = _ensure_manufacturer(source_url, source_token, dest_url, dest_token, mfr_slug)
        if 'form_factor' in payload:
            payload['form_factor'] = _enum(src, 'form_factor')
        if 'width' in payload:
            payload['width'] = _enum(src, 'width')

    if dst:
        return nb_patch(dest_url, dest_token, endpoint, dst['id'], payload)
    else:
        return nb_post(dest_url, dest_token, endpoint, payload)

# ---------------------------------------------------------------------------
# Device-type compare & sync
# ---------------------------------------------------------------------------

def compare_device_types(src_url, src_token, dst_url, dst_token):
    try:
        src_dts = fetch_all(src_url, src_token, 'dcim/device-types')
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Source ({src_url}): {e}") from e
    try:
        dst_dts = fetch_all(dst_url, dst_token, 'dcim/device-types')
    except (requests.HTTPError, ValueError) as e:
        raise ValueError(f"Destination ({dst_url}): {e}") from e

    # Bulk-fetch component templates from both instances
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
    """Ensure a manufacturer with the given slug exists in destination. Returns its ID."""
    dst_mfrs = {m['slug']: m for m in fetch_all(dst_url, dst_token, 'dcim/manufacturers')}
    if mfr_slug in dst_mfrs:
        return dst_mfrs[mfr_slug]['id']

    # Create it from source
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
    """Ensure a module type profile exists in destination. Returns its ID."""
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
    """
    Sync all component templates from source parent to destination parent.
    parent_field: 'device_type' or 'module_type'
    """
    errors = []
    rear_port_map  = {}   # name → destination ID (built while syncing rear ports)
    power_port_map = {}   # name → destination ID (built while syncing power ports)
    # Persists across loop iterations: src rear-port-template ID → name.
    # Built during 'rear-port-templates' pass; consumed during 'front-port-templates' pass.
    src_rp_id_map  = {}

    for ctype in COMPONENT_TYPES:
        endpoint = ctype['endpoint']

        # Device bay templates belong to device types only. When syncing module
        # types, skip this endpoint to avoid creating invalid payloads.
        if parent_field == 'module_type' and endpoint == 'dcim/device-bay-templates':
            continue

        src_tmps = fetch_all(src_url, src_token, endpoint,
                             {f'{parent_field}_id': src_parent_id})
        dst_tmps = fetch_all(dst_url, dst_token, endpoint,
                             {f'{parent_field}_id': dst_parent_id})

        dst_name_map = {t['name']: t for t in dst_tmps}

        # Seed resolution maps from existing destination templates
        if endpoint == 'dcim/rear-port-templates':
            rear_port_map.update({t['name']: t['id'] for t in dst_tmps})
            src_rp_id_map = {t['id']: t['name'] for t in src_tmps}
        if endpoint == 'dcim/power-port-templates':
            power_port_map.update({t['name']: t['id'] for t in dst_tmps})

        for src_tmpl in src_tmps:
            name = src_tmpl['name']
            try:
                payload = build_component_payload(
                    src_tmpl, ctype, dst_parent_id, parent_field,
                    rear_port_map=rear_port_map, power_port_map=power_port_map,
                    src_rp_id_map=src_rp_id_map,
                )
                if name in dst_name_map:
                    result = nb_patch(dst_url, dst_token, endpoint,
                                      dst_name_map[name]['id'], payload)
                else:
                    result = nb_post(dst_url, dst_token, endpoint, payload)

                # Update resolution maps with newly created IDs
                if endpoint == 'dcim/rear-port-templates':
                    rear_port_map[name] = result['id']
                elif endpoint == 'dcim/power-port-templates':
                    power_port_map[name] = result['id']

            except Exception as e:
                errors.append(f"{endpoint}/{name}: {e}")

        # NetBox 4.x removed the writable 'rear_port' field on front-port-templates.
        # Associations must be set by PATCHing each rear-port-template with 'front_ports'.
        if endpoint == 'dcim/front-port-templates' and src_rp_id_map:
            dst_fp_tmps = fetch_all(dst_url, dst_token, endpoint,
                                    {f'{parent_field}_id': dst_parent_id})
            dst_fp_name_to_id = {t['name']: t['id'] for t in dst_fp_tmps}
            rp_fp_patches = {}  # dst_rp_id → list of front_ports entries
            for src_fp in src_tmps:
                fp_name = src_fp['name']
                dst_fp_id = dst_fp_name_to_id.get(fp_name)
                if dst_fp_id is None:
                    continue
                for entry in src_fp.get('rear_ports', []):
                    src_rp_id = entry.get('rear_port')
                    rp_name = src_rp_id_map.get(src_rp_id)
                    if not rp_name:
                        continue
                    dst_rp_id = rear_port_map.get(rp_name)
                    if dst_rp_id is None:
                        continue
                    rp_fp_patches.setdefault(dst_rp_id, []).append({
                        'front_port': dst_fp_id,
                        'front_port_position': entry.get('position', 1),
                        'rear_port_position': entry.get('rear_port_position', 1),
                    })
            for dst_rp_id, fp_list in rp_fp_patches.items():
                try:
                    # NetBox 4.x PATCH on nested lists appends; clear first, then set.
                    nb_patch(dst_url, dst_token, 'dcim/rear-port-templates',
                             dst_rp_id, {'front_ports': []})
                    nb_patch(dst_url, dst_token, 'dcim/rear-port-templates',
                             dst_rp_id, {'front_ports': fp_list})
                except Exception as e:
                    errors.append(f"dcim/rear-port-templates/{dst_rp_id} association: {e}")

    return errors


def sync_device_type(src_url, src_token, dst_url, dst_token, slug):
    """Sync one device type (by slug) from source → destination, including components."""
    src_dts = {dt['slug']: dt for dt in fetch_all(src_url, src_token, 'dcim/device-types')}
    src_dt = src_dts.get(slug)
    if not src_dt:
        raise ValueError(f"Device type '{slug}' not found in source")

    mfr_slug  = _slug(src_dt, 'manufacturer')
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

# ---------------------------------------------------------------------------
# Module-type compare & sync
# ---------------------------------------------------------------------------

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
    """Sync one module type (by model name) from source → destination."""
    src_mts = {mt['model']: mt for mt in fetch_all(src_url, src_token, 'dcim/module-types')}
    src_mt = src_mts.get(model)
    if not src_mt:
        raise ValueError(f"Module type '{model}' not found in source")

    mfr_slug  = _slug(src_mt, 'manufacturer')
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

    # Resolve profile
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
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if (request.form.get('username') == APP_USERNAME and
                request.form.get('password') == APP_PASSWORD):
            session['logged_in'] = True
            return redirect(url_for('index'))
        error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html')

# ---------------------------------------------------------------------------
# Routes — Instance management
# ---------------------------------------------------------------------------

@app.route('/api/instances', methods=['GET'])
@login_required
def get_instances():
    instances = load_instances()
    safe = [{'id': i['id'], 'name': i['name'], 'url': i['url']} for i in instances]
    return jsonify({'instances': safe})


@app.route('/api/instances', methods=['POST'])
@login_required
def add_instance():
    data  = request.json or {}
    name  = data.get('name', '').strip()
    url   = data.get('url', '').strip().rstrip('/')
    token = data.get('token', '').strip()

    if not name or not url or not token:
        return jsonify({'error': 'name, url, and token are required'}), 400
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

    instances = load_instances()
    if any(i['name'] == name for i in instances):
        return jsonify({'error': f"An instance named '{name}' already exists"}), 400

    new_inst = {
        'id': uuid.uuid4().hex[:8], 'name': name, 'url': url, 'token': token,
        'created': datetime.utcnow().isoformat(),
    }
    instances.append(new_inst)
    save_instances(instances)
    return jsonify({'instance': {'id': new_inst['id'], 'name': new_inst['name'], 'url': new_inst['url']}})


@app.route('/api/instances/<inst_id>', methods=['PATCH'])
@login_required
def update_instance(inst_id):
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
        inst['url'] = data['url'].strip().rstrip('/')
    if 'token' in data and data['token'].strip():
        inst['token'] = data['token'].strip()

    save_instances(instances)
    return jsonify({'instance': {'id': inst['id'], 'name': inst['name'], 'url': inst['url']}})


@app.route('/api/instances/<inst_id>', methods=['DELETE'])
@login_required
def delete_instance(inst_id):
    instances = load_instances()
    before = len(instances)
    instances = [i for i in instances if i['id'] != inst_id]
    if len(instances) == before:
        return jsonify({'error': 'Instance not found'}), 404
    save_instances(instances)
    return jsonify({'message': 'Instance deleted'})


@app.route('/api/instances/<inst_id>/test', methods=['POST'])
@login_required
def test_instance(inst_id):
    instances = load_instances()
    inst = next((i for i in instances if i['id'] == inst_id), None)
    if not inst:
        return jsonify({'error': 'Instance not found'}), 404
    try:
        resp = requests.get(
            f"{inst['url']}/api/",
            headers=nb_headers(inst['token']),
            verify=_requests_verify(), timeout=10,
        )
        resp.raise_for_status()
        info = resp.json()
        return jsonify({'ok': True, 'netbox_version': info.get('netbox-version', 'unknown')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

# ---------------------------------------------------------------------------
# Routes — Compare & Sync
# ---------------------------------------------------------------------------

@app.route('/api/template-types', methods=['GET'])
@login_required
def get_template_types():
    return jsonify({k: {'label': v['label']} for k, v in TEMPLATE_TYPES.items()})


@app.route('/api/compare', methods=['POST'])
@login_required
def compare():
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


@app.route('/api/sync', methods=['POST'])
@login_required
def sync():
    data      = request.json or {}
    source_id = data.get('source_id')
    dest_id   = data.get('dest_id')
    items     = data.get('items', [])

    if not source_id or not dest_id:
        return jsonify({'error': 'source_id and dest_id are required'}), 400

    inst_map = {i['id']: i for i in load_instances()}
    src = inst_map.get(source_id)
    dst = inst_map.get(dest_id)
    if not src or not dst:
        return jsonify({'error': 'One or both instances not found'}), 400

    results = []
    for item in items:
        tt   = item.get('template_type')
        name = item.get('name')
        try:
            sync_one(src['url'], src['token'], dst['url'], dst['token'], tt, name)
            results.append({'name': name, 'template_type': tt, 'status': 'ok'})
        except Exception as e:
            results.append({'name': name, 'template_type': tt, 'status': 'error', 'error': str(e)})

    return jsonify({'results': results})


if __name__ == '__main__':
    _migrate_tokens()
    port = int(os.getenv('SYNC_PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
