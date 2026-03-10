#!/usr/bin/env python3
"""Delete a complete NetBox site and related objects from a configured server."""

from __future__ import annotations

import argparse
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Set, Tuple

import pynetbox
import requests
import urllib3

from glitchtip_utils import init_glitchtip, capture_exception
from netbox_branching import resolve_branch_header_value
from netbox_importer import _to_bool, resolve_instance


DELETE_ORDER = [
    "cables",
    "ip-addresses",
    "prefixes",
    "modules",
    "power-feeds",
    "devices",
    "power-panels",
    "racks",
    "locations",
    "site",
]

init_glitchtip(service='netbox-delete-site-cli', with_flask=False)


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _obj_value(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _obj_id(obj: Any) -> str:
    value = _obj_value(obj, "id", "")
    return _clean_str(value)


def _nested_name(obj: Any, default: str = "") -> str:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return _clean_str(obj.get("name", default)) or default
    return _clean_str(getattr(obj, "name", default)) or default


def _obj_name(obj: Any) -> str:
    for key in ("name", "display", "display_name"):
        val = _clean_str(_obj_value(obj, key, ""))
        if val:
            return val
    oid = _obj_id(obj)
    return f"id={oid}" if oid else "(unknown)"


def _iter_records(queryset: Iterable[Any]) -> Iterable[Any]:
    for obj in queryset:
        yield obj


def _sort_records(records: List[Any]) -> List[Any]:
    return sorted(records, key=lambda obj: (_obj_name(obj).lower(), _obj_id(obj)))


def _term_object_type(term: Any) -> str:
    return _clean_str(_obj_value(term, "object_type", "")).lower()


def _term_name(term: Any) -> str:
    if isinstance(term, dict):
        inner = term.get("object") or {}
        return _clean_str(inner.get("name") or term.get("name") or "")
    return _clean_str(getattr(term, "name", ""))


def _term_device_name(term: Any) -> str:
    if isinstance(term, dict):
        inner = term.get("object") or {}
        dev = inner.get("device")
        if isinstance(dev, dict):
            return _clean_str(dev.get("name", ""))
        if isinstance(dev, str):
            return _clean_str(dev)
        return ""
    dev = getattr(term, "device", None)
    return _nested_name(dev, "")


def _term_matches(term: Any, device_names: Set[str], power_feed_names: Set[str]) -> bool:
    device_name = _term_device_name(term)
    if device_name and device_name in device_names:
        return True
    obj_type = _term_object_type(term)
    if obj_type in {"dcim.powerfeed", "powerfeed"}:
        term_name = _term_name(term)
        if term_name and term_name in power_feed_names:
            return True
    return False


def _resolve_server(server_ref: str) -> Dict[str, Any]:
    by_name_error = None
    try:
        return resolve_instance(instance_name=server_ref)
    except Exception as exc:
        by_name_error = str(exc)
    try:
        return resolve_instance(instance_id=server_ref)
    except Exception as exc:
        raise ValueError(
            f'Unable to resolve server "{server_ref}" by name or id. '
            f"By-name lookup error: {by_name_error}. By-id lookup error: {exc}"
        )


def _build_api(instance: Dict[str, Any], branch_ref: str | None = None) -> Tuple[pynetbox.api, str, str, str]:
    url = _clean_str(instance.get("url")).rstrip("/")
    token = _clean_str(instance.get("token"))
    name = _clean_str(instance.get("name")) or _clean_str(instance.get("id")) or "(unknown)"
    if not url or not token:
        raise ValueError(f'Instance "{name}" is missing URL/token')

    verify = instance.get("verify")
    if verify is None:
        verify = not _to_bool(instance.get("skip_ssl_verify", False))

    session = requests.Session()
    session.verify = verify
    if session.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    selected_branch = _clean_str(branch_ref if branch_ref is not None else instance.get("branch"))
    if selected_branch:
        header_value = resolve_branch_header_value(
            {
                "url": url,
                "token": token,
                "verify": session.verify,
            },
            selected_branch,
        )
        session.headers.update({"X-NetBox-Branch": header_value})

    api = pynetbox.api(url, token=token)
    api.http_session = session
    return api, name, url, selected_branch


def _collect_prefixes(api: pynetbox.api, site_id: Any) -> List[Any]:
    prefixes: Dict[str, Any] = {}

    try:
        for obj in _iter_records(api.ipam.prefixes.filter(scope_type="dcim.site", scope_id=site_id)):
            oid = _obj_id(obj)
            if oid:
                prefixes[oid] = obj
    except Exception:
        pass

    try:
        for obj in _iter_records(api.ipam.prefixes.filter(site_id=site_id)):
            oid = _obj_id(obj)
            if oid:
                prefixes[oid] = obj
    except Exception:
        pass

    return _sort_records(list(prefixes.values()))


def _collect_site_objects(api: pynetbox.api, site: Any) -> Dict[str, List[Any]]:
    site_id = _obj_value(site, "id")

    locations = _sort_records(list(_iter_records(api.dcim.locations.filter(site_id=site_id))))
    racks = _sort_records(list(_iter_records(api.dcim.racks.filter(site_id=site_id))))
    power_panels = _sort_records(list(_iter_records(api.dcim.power_panels.filter(site_id=site_id))))
    power_feeds = _sort_records(list(_iter_records(api.dcim.power_feeds.filter(site_id=site_id))))
    devices = _sort_records(list(_iter_records(api.dcim.devices.filter(site_id=site_id))))

    device_ids: List[Any] = []
    device_names: Set[str] = set()
    for dev in devices:
        did = _obj_value(dev, "id")
        if did is not None:
            device_ids.append(did)
        dname = _clean_str(_obj_value(dev, "name", ""))
        if dname:
            device_names.add(dname)

    power_feed_names: Set[str] = {
        _clean_str(_obj_value(feed, "name", "")) for feed in power_feeds if _clean_str(_obj_value(feed, "name", ""))
    }

    modules_map: Dict[str, Any] = {}
    for did in device_ids:
        for mod in _iter_records(api.dcim.modules.filter(device_id=did)):
            oid = _obj_id(mod)
            if oid:
                modules_map[oid] = mod
    modules = _sort_records(list(modules_map.values()))

    cables_map: Dict[str, Any] = {}
    for cable in _iter_records(api.dcim.cables.filter(limit=0)):
        terms = list(_obj_value(cable, "a_terminations", []) or []) + list(_obj_value(cable, "b_terminations", []) or [])
        if any(_term_matches(term, device_names, power_feed_names) for term in terms):
            oid = _obj_id(cable)
            if oid:
                cables_map[oid] = cable
    cables = _sort_records(list(cables_map.values()))

    ip_map: Dict[str, Any] = {}
    for addr in _iter_records(api.ipam.ip_addresses.filter(limit=0)):
        assigned = _obj_value(addr, "assigned_object")
        if assigned is None:
            continue
        assigned_device = _nested_name(_obj_value(assigned, "device"), "")
        if assigned_device and assigned_device in device_names:
            oid = _obj_id(addr)
            if oid:
                ip_map[oid] = addr
    ip_addresses = _sort_records(list(ip_map.values()))

    prefixes = _collect_prefixes(api, site_id)

    return {
        "cables": cables,
        "ip-addresses": ip_addresses,
        "prefixes": prefixes,
        "modules": modules,
        "power-feeds": power_feeds,
        "devices": devices,
        "power-panels": power_panels,
        "racks": racks,
        "locations": locations,
        "site": [site],
    }


def _print_plan(site_name: str, server_name: str, server_url: str, branch: str, plan: Dict[str, List[Any]]) -> int:
    print("")
    print(f"Server: {server_name} ({server_url})")
    if branch:
        print(f"Branch: {branch}")
    print(f"Site:   {site_name}")
    print("")
    print("Delete plan:")
    total = 0
    for group in DELETE_ORDER:
        count = len(plan.get(group) or [])
        total += count
        print(f"  - {group:12s}: {count}")
    print(f"  - {'TOTAL':12s}: {total}")
    return total


def _confirm(site_name: str, server_name: str) -> bool:
    prompt = (
        f'\nType exactly "{site_name}" to confirm deleting this site from "{server_name}": '
    )
    entered = input(prompt).strip()
    return entered == site_name


def _delete_plan(plan: Dict[str, List[Any]], dry_run: bool = False, verbose: bool = False) -> Tuple[Dict[str, Dict[str, int]], List[str]]:
    stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"deleted": 0, "errors": 0})
    errors: List[str] = []

    for group in DELETE_ORDER:
        objs = list(plan.get(group) or [])
        if not objs:
            continue

        print(f"\n{group}: {len(objs)} item(s)")
        for obj in objs:
            label = f"{_obj_name(obj)} [{_obj_id(obj)}]"
            if dry_run:
                stats[group]["deleted"] += 1
                if verbose:
                    print(f"  [DRY RUN] Would delete {label}")
                continue
            try:
                result = obj.delete()
                if result is False:
                    raise RuntimeError("API returned False")
                stats[group]["deleted"] += 1
                if verbose:
                    print(f"  Deleted {label}")
            except Exception as exc:
                stats[group]["errors"] += 1
                error_msg = f"{group}: {label} -> {exc}"
                errors.append(error_msg)
                print(f"  ERROR {error_msg}")

    return stats, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete a complete site and related CSV-import objects from NetBox."
    )
    parser.add_argument("site_name", help="Exact NetBox site name to delete.")
    parser.add_argument("server_name", help="Server name (or id) from template-sync/instances.json.")
    parser.add_argument("--branch", default=None, help="Optional branch name/id/schema_id to target.")
    parser.add_argument("--dry-run", action="store_true", help="Preview only; do not delete.")
    parser.add_argument("--yes", action="store_true", help="Skip interactive confirmation prompt.")
    parser.add_argument("--verbose", action="store_true", help="Show each item as it is deleted.")
    args = parser.parse_args()

    site_name = _clean_str(args.site_name)
    server_ref = _clean_str(args.server_name)
    if not site_name or not server_ref:
        raise SystemExit("site_name and server_name are required")

    instance = _resolve_server(server_ref)
    api, instance_name, base_url, active_branch = _build_api(instance, branch_ref=args.branch)

    site = api.dcim.sites.get(name=site_name)
    if not site:
        raise SystemExit(f'Site "{site_name}" not found on server "{instance_name}"')

    plan = _collect_site_objects(api, site)
    total = _print_plan(site_name, instance_name, base_url, active_branch, plan)
    if total <= 0:
        print("Nothing to delete.")
        return 0

    if args.dry_run:
        print("\nDry run complete. No changes were made.")
        return 0

    if not args.yes and not _confirm(site_name, instance_name):
        print("Confirmation failed. Aborting.")
        return 1

    stats, errors = _delete_plan(plan, dry_run=False, verbose=args.verbose)

    deleted_total = sum(v["deleted"] for v in stats.values())
    error_total = sum(v["errors"] for v in stats.values())

    print("\nSummary:")
    for group in DELETE_ORDER:
        if group not in stats:
            continue
        print(
            f"  - {group:12s}: deleted={stats[group]['deleted']} errors={stats[group]['errors']}"
        )
    print(f"  - {'TOTAL':12s}: deleted={deleted_total} errors={error_total}")

    if errors:
        print("\nErrors:")
        for msg in errors:
            print(f"  - {msg}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        capture_exception(exc, script='netbox_delete_site.py', route='main')
        raise
