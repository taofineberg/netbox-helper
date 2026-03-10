"""Site-level NetBox sync helpers using CSV-import compatible group structure."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import logging
import pynetbox
import requests
import urllib3
import time
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from netbox_importer import NetboxImporter, _to_bool
from netbox_site_to_csv import fetch_site_export_data

logger = logging.getLogger(__name__)


SITE_GROUP_ORDER = [
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
    'ip-addresses',
]

SITE_GROUP_LABELS = {
    'sites': 'Sites',
    'locations': 'Locations',
    'racks': 'Racks',
    'power-panels': 'Power Panels',
    'devices': 'Devices',
    'power-feeds': 'Power Feeds',
    'modules': 'Modules',
    'cables': 'Cables',
    'power-cables': 'Power Cables',
    'vrf': 'VRFs',
    'prefixroles': 'Prefix Roles',
    'prefix': 'Prefixes',
    'ip-addresses': 'IP Addresses',
}

GROUP_DEPENDENCIES = {
    'sites': [],
    'locations': ['sites'],
    'racks': ['sites', 'locations'],
    'power-panels': ['sites'],
    'devices': ['sites', 'locations', 'racks'],
    'power-feeds': ['sites', 'racks', 'power-panels'],
    'modules': ['devices'],
    'cables': ['devices', 'modules'],
    'power-cables': ['devices', 'modules', 'power-feeds'],
    'vrf': [],
    'prefixroles': [],
    'prefix': ['sites', 'vrf', 'prefixroles'],
    'ip-addresses': ['devices', 'prefix'],
}

SITE_FETCH_RETRY_ATTEMPTS = 3
SITE_FETCH_RETRY_BACKOFF = 1.0


def _clean_str(value: Any) -> str:
    if value is None:
        return ''
    return str(value).strip()


def _make_api(instance: Dict[str, Any]) -> pynetbox.api:
    url = _clean_str(instance.get('url')).rstrip('/')
    token = _clean_str(instance.get('token'))
    if not url or not token:
        raise ValueError('Instance URL/token is required')

    api = pynetbox.api(url, token=token)
    session = requests.Session()
    verify = instance.get('verify')
    if verify is None:
        verify = not _to_bool(instance.get('skip_ssl_verify', False))
    session.verify = verify
    if session.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    retry_strategy = Retry(
        total=5,
        connect=5,
        read=5,
        status=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    api.http_session = session
    return api


def _is_transient_site_fetch_error(exc: Exception) -> bool:
    if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return True
    text = str(exc or '')
    markers = (
        'RemoteDisconnected',
        'Connection aborted',
        'Max retries exceeded',
        'Read timed out',
        'ConnectTimeout',
        'ConnectionError',
        '503 Service Unavailable',
        '502 Bad Gateway',
        '504 Gateway Time-out',
    )
    return any(m in text for m in markers)


def _fetch_site_export_data_with_retry(api: pynetbox.api, site_name: str) -> Tuple[str, Dict[str, List[Dict[str, str]]]]:
    max_attempts = max(1, int(SITE_FETCH_RETRY_ATTEMPTS))
    backoff = max(0.0, float(SITE_FETCH_RETRY_BACKOFF))
    attempt = 1
    while True:
        try:
            return fetch_site_export_data(api, site_name)
        except Exception as exc:
            if attempt >= max_attempts or not _is_transient_site_fetch_error(exc):
                raise
            wait_s = backoff * (2 ** (attempt - 1))
            logger.warning(
                "Transient site export fetch error for '%s' (attempt %s/%s): %s. Retrying in %.1fs",
                site_name, attempt, max_attempts, exc, wait_s,
            )
            if wait_s > 0:
                time.sleep(wait_s)
            attempt += 1


def _item_identifier(group: str, row: Dict[str, Any]) -> str:
    if group in {'sites', 'locations', 'racks', 'power-panels', 'power-feeds'}:
        return _clean_str(row.get('name')) or '(unnamed)'
    if group == 'devices':
        return _clean_str(row.get('name')) or '(unnamed device)'
    if group == 'modules':
        dev = _clean_str(row.get('device'))
        bay = _clean_str(row.get('module_bay'))
        mtype = _clean_str(row.get('module_type'))
        return f'{dev}/{bay} ({mtype})'.strip() or '(module)'
    if group in {'cables', 'power-cables'}:
        a_dev = _clean_str(row.get('side_a_device'))
        a_name = _clean_str(row.get('side_a_name'))
        b_dev = _clean_str(row.get('side_b_device'))
        b_name = _clean_str(row.get('side_b_name'))
        return f'{a_dev}:{a_name} -> {b_dev}:{b_name}'.strip() or '(cable)'
    if group == 'prefix':
        return _clean_str(row.get('prefix')) or '(prefix)'
    if group == 'ip-addresses':
        dev = _clean_str(row.get('device'))
        iface = _clean_str(row.get('interface'))
        addr = _clean_str(row.get('address'))
        return f'{dev}:{iface} {addr}'.strip() or '(ip-address)'
    return _clean_str(row.get('name')) or '(item)'


def _collect_plan_rows(data: Dict[str, List[Dict[str, str]]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    groups: List[Dict[str, Any]] = []
    items: List[Dict[str, Any]] = []

    for group in SITE_GROUP_ORDER:
        rows = list(data.get(group) or [])
        groups.append({
            'group': group,
            'label': SITE_GROUP_LABELS.get(group, group),
            'count': len(rows),
        })
        for idx, row in enumerate(rows):
            item_id = f'{group}::{idx}'
            items.append({
                'item_id': item_id,
                'group': group,
                'group_label': SITE_GROUP_LABELS.get(group, group),
                'index': idx,
                'identifier': _item_identifier(group, row),
            })

    return groups, items


def _safe_slug(name: str) -> str:
    out = ''.join(ch.lower() if ch.isalnum() else '-' for ch in (name or '').strip())
    while '--' in out:
        out = out.replace('--', '-')
    return out.strip('-')


def _augment_prefix_dependencies(data: Dict[str, List[Dict[str, str]]]) -> Dict[str, List[Dict[str, str]]]:
    out = {k: list(v or []) for k, v in (data or {}).items()}
    out.setdefault('vrf', [])
    out.setdefault('prefixroles', [])

    existing_vrfs = {_clean_str(r.get('name')) for r in out.get('vrf', []) if _clean_str(r.get('name'))}
    existing_roles = {_clean_str(r.get('name')) for r in out.get('prefixroles', []) if _clean_str(r.get('name'))}

    for row in out.get('prefix', []) or []:
        vrf_name = _clean_str((row or {}).get('vrf'))
        role_name = _clean_str((row or {}).get('role'))
        if vrf_name and vrf_name not in existing_vrfs:
            out['vrf'].append({'name': vrf_name})
            existing_vrfs.add(vrf_name)
        if role_name and role_name not in existing_roles:
            out['prefixroles'].append({'name': role_name, 'slug': _safe_slug(role_name)})
            existing_roles.add(role_name)

    return out


def build_site_sync_plan(source_instance: Dict[str, Any], site_name: str) -> Dict[str, Any]:
    site_name = _clean_str(site_name)
    if not site_name:
        raise ValueError('site_name is required')

    api = _make_api(source_instance)
    prefix, data = _fetch_site_export_data_with_retry(api, site_name)
    data = _augment_prefix_dependencies(data)
    groups, items = _collect_plan_rows(data)
    total_items = sum(int(g['count']) for g in groups)

    return {
        'site_name': site_name,
        'prefix': prefix,
        'groups': groups,
        'items': items,
        'total_items': total_items,
    }


def _normalize_group_list(raw_groups: Optional[List[Any]]) -> List[str]:
    normalized = []
    seen = set()
    for g in raw_groups or []:
        val = _clean_str(g)
        if val in SITE_GROUP_ORDER and val not in seen:
            normalized.append(val)
            seen.add(val)
    return normalized


def _parse_selected_items(raw_item_ids: Optional[List[Any]]) -> Dict[str, Set[int]]:
    selected: Dict[str, Set[int]] = {}
    for raw in raw_item_ids or []:
        item_id = _clean_str(raw)
        if '::' not in item_id:
            continue
        group, idx_raw = item_id.split('::', 1)
        if group not in SITE_GROUP_ORDER:
            continue
        try:
            idx = int(idx_raw)
        except Exception:
            continue
        if idx < 0:
            continue
        selected.setdefault(group, set()).add(idx)
    return selected


def _expand_dependencies(groups: List[str]) -> Tuple[List[str], List[str]]:
    expanded = set(groups)
    dependency_only = set()

    changed = True
    while changed:
        changed = False
        for group in list(expanded):
            for dep in GROUP_DEPENDENCIES.get(group, []):
                if dep not in expanded:
                    expanded.add(dep)
                    dependency_only.add(dep)
                    changed = True

    ordered_expanded = [g for g in SITE_GROUP_ORDER if g in expanded]
    ordered_dep_only = [g for g in SITE_GROUP_ORDER if g in dependency_only and g not in groups]
    return ordered_expanded, ordered_dep_only


def _filter_site_data(
    full_data: Dict[str, List[Dict[str, str]]],
    explicit_groups: List[str],
    selected_items: Dict[str, Set[int]],
) -> Tuple[Dict[str, List[Dict[str, str]]], List[str], List[str]]:
    if not explicit_groups and not selected_items:
        explicit_groups = list(SITE_GROUP_ORDER)

    group_from_items = [g for g in SITE_GROUP_ORDER if g in selected_items]
    merged_explicit = []
    seen = set()
    for g in [*explicit_groups, *group_from_items]:
        if g in SITE_GROUP_ORDER and g not in seen:
            merged_explicit.append(g)
            seen.add(g)

    expanded_groups, dependency_only = _expand_dependencies(merged_explicit)

    filtered: Dict[str, List[Dict[str, str]]] = {}
    for group in expanded_groups:
        rows = list(full_data.get(group) or [])
        if group in selected_items and group not in dependency_only:
            idxs = selected_items[group]
            subset = [rows[i] for i in sorted(idxs) if 0 <= i < len(rows)]
        else:
            subset = rows
        if subset:
            filtered[group] = subset

    sections = [g for g in SITE_GROUP_ORDER if g in filtered]
    return filtered, sections, dependency_only


def _flatten_totals(stats: Dict[str, Dict[str, int]]) -> Dict[str, int]:
    totals = {'created': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
    for section_stats in (stats or {}).values():
        for k in totals:
            totals[k] += int(section_stats.get(k, 0) or 0)
    return totals


def _emit_progress(progress_cb: Optional[Callable[[Dict[str, Any]], None]], payload: Dict[str, Any]):
    if not callable(progress_cb):
        return
    try:
        progress_cb(dict(payload or {}))
    except Exception:
        # Progress updates must never break a sync operation.
        return


def sync_site_data(
    source_instance: Dict[str, Any],
    dest_instance: Dict[str, Any],
    site_name: str,
    selected_groups: Optional[List[Any]] = None,
    selected_item_ids: Optional[List[Any]] = None,
    dry_run: bool = False,
    workers: int = 2,
    retry_attempts: int = 2,
    retry_backoff: float = 1.0,
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    site_name = _clean_str(site_name)
    if not site_name:
        raise ValueError('site_name is required')

    source_api = _make_api(source_instance)
    prefix, full_data = _fetch_site_export_data_with_retry(source_api, site_name)
    full_data = _augment_prefix_dependencies(full_data)

    explicit_groups = _normalize_group_list(selected_groups)
    selected_items = _parse_selected_items(selected_item_ids)

    filtered_data, sections, dependency_only = _filter_site_data(
        full_data,
        explicit_groups=explicit_groups,
        selected_items=selected_items,
    )

    if not sections:
        raise ValueError('No syncable data selected for this site')

    section_totals = {section: len(filtered_data.get(section, []) or []) for section in sections}
    item_count = sum(section_totals.values())

    worker_count = max(1, int(workers or 1))
    retry_count = max(0, int(retry_attempts or 0))
    retry_sleep = max(0.0, float(retry_backoff or 0.0))

    _emit_progress(progress_cb, {
        'event': 'planned',
        'site_name': site_name,
        'dry_run': bool(dry_run),
        'workers': int(worker_count),
        'retry_attempts': int(retry_count),
        'sections': list(sections),
        'dependency_sections': list(dependency_only),
        'section_totals': dict(section_totals),
        'total_sections': int(len(sections)),
        'total_items': int(item_count),
    })

    importer = NetboxImporter(
        csv_file=f'site-sync:{site_name}',
        dry_run=bool(dry_run),
        replace=True,
        interactive=False,
        netbox_url=_clean_str(dest_instance.get('url')).rstrip('/'),
        netbox_token=_clean_str(dest_instance.get('token')),
        netbox_skip_ssl_verify=_to_bool(dest_instance.get('skip_ssl_verify', False)),
        netbox_branch=_clean_str(dest_instance.get('branch')),
    )
    importer.import_data(
        filtered_data,
        sections=sections,
        workers=worker_count,
        retry_attempts=retry_count,
        retry_backoff=retry_sleep,
        progress_cb=progress_cb,
    )

    per_section_stats = {
        section: {
            'created': int(importer.stats.get(section, {}).get('created', 0) or 0),
            'updated': int(importer.stats.get(section, {}).get('updated', 0) or 0),
            'skipped': int(importer.stats.get(section, {}).get('skipped', 0) or 0),
            'errors': int(importer.stats.get(section, {}).get('errors', 0) or 0),
        }
        for section in sections
    }
    per_section_done = {
        section: int(per_section_stats.get(section, {}).get('created', 0) or 0)
        + int(per_section_stats.get(section, {}).get('updated', 0) or 0)
        + int(per_section_stats.get(section, {}).get('skipped', 0) or 0)
        + int(per_section_stats.get(section, {}).get('errors', 0) or 0)
        for section in sections
    }

    totals = _flatten_totals(per_section_stats)
    result = {
        'site_name': site_name,
        'prefix': prefix,
        'dry_run': bool(dry_run),
        'workers': int(worker_count),
        'retry_attempts': int(retry_count),
        'sections': sections,
        'dependency_sections': dependency_only,
        'item_count': item_count,
        'section_totals': dict(section_totals),
        'section_done': per_section_done,
        'section_stats': per_section_stats,
        'totals': totals,
    }
    _emit_progress(progress_cb, {
        'event': 'complete',
        'site_name': site_name,
        'result': result,
    })
    return result
