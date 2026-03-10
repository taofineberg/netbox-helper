#!/usr/bin/env python3
"""
Export one NetBox site to Netbox-import CSV format.

The output layout (section order, identifiers, header columns, column count)
is copied from a reference CSV (default: data/MDT1PAPB.csv).
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import pynetbox
import requests
import urllib3

from glitchtip_utils import init_glitchtip, capture_exception
from netbox_importer import _to_bool, resolve_instance

init_glitchtip(service='netbox-site-to-csv-cli', with_flask=False)


def _val(x: Any, attr: str, default: str = "") -> str:
    try:
        if isinstance(x, dict):
            v = x.get(attr, default)
        else:
            v = getattr(x, attr, default)
        return "" if v is None else str(v)
    except Exception:
        return default


def _nested_name(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if isinstance(x, (str, int, float, bool)):
        return str(x)
    if isinstance(x, dict):
        return str(x.get("name") or x.get("display") or x.get("value") or default or "")
    return str(
        getattr(x, "name", None)
        or getattr(x, "display", None)
        or getattr(x, "value", None)
        or default
        or ""
    )


def _nested_model_or_name(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if isinstance(x, (str, int, float, bool)):
        return str(x)
    if isinstance(x, dict):
        return str(x.get("model") or x.get("name") or x.get("display") or default or "")
    return str(
        getattr(x, "model", None)
        or getattr(x, "name", None)
        or getattr(x, "display", None)
        or default
        or ""
    )


def _nested_value(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if isinstance(x, (str, int, float, bool)):
        return str(x)
    if isinstance(x, dict):
        return str(x.get("value") or x.get("name") or x.get("display") or default or "")
    return str(
        getattr(x, "value", None)
        or getattr(x, "name", None)
        or getattr(x, "display", None)
        or default
        or ""
    )


def _iter_records(queryset: Any) -> Iterable[Any]:
    for obj in queryset:
        yield obj


def _nested_id(x: Any, default: str = "") -> str:
    if x is None:
        return default
    if isinstance(x, dict):
        return str(x.get("id", default) or default)
    return str(getattr(x, "id", default) or default)


def _safe_slug(name: str) -> str:
    out = "".join(ch.lower() if ch.isalnum() else "-" for ch in (name or "").strip())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")


def _device_from_term(term: Any) -> str:
    if term is None:
        return ""
    if isinstance(term, dict):
        obj = term.get("object") or {}
        dev = obj.get("device")
        if isinstance(dev, dict):
            return str(dev.get("name", "") or "")
        if isinstance(dev, str):
            return dev
        return ""
    try:
        dev = getattr(term, "device", None)
        if dev is None:
            return ""
        return _nested_name(dev, "")
    except Exception:
        return ""


def _term_type_name(term: Any) -> Tuple[str, str]:
    # Returns (type_label, term_name) where type_label is the importer-friendly
    # lowercase token (interface/rearport/frontport/powerport/poweroutlet/...).
    if term is None:
        return "", ""
    if isinstance(term, dict):
        obj_type = str(term.get("object_type", "") or "").lower()
        obj = term.get("object") or {}
        tname = str(obj.get("name", "") or term.get("name", "") or "")
    else:
        obj_type = str(getattr(term, "object_type", "") or "").lower()
        tname = str(getattr(term, "name", "") or "")
    mapping = {
        "dcim.interface": "interface",
        "dcim.rearport": "rearport",
        "dcim.frontport": "frontport",
        "dcim.powerport": "powerport",
        "dcim.poweroutlet": "poweroutlet",
        "dcim.consoleport": "consoleport",
        "dcim.consoleserverport": "consoleserverport",
    }
    return mapping.get(obj_type, obj_type.split(".")[-1] if obj_type else ""), tname


def _powerfeed_panel_name(term: Any) -> str:
    if term is None:
        return ""
    if isinstance(term, dict):
        obj = term.get("object") or {}
        panel = obj.get("power_panel")
        if isinstance(panel, dict):
            return str(panel.get("name", "") or "")
        return ""
    try:
        panel = getattr(term, "power_panel", None)
        return _nested_name(panel, "")
    except Exception:
        return ""


@dataclass
class TemplateSection:
    import_type: str
    row_label: str
    headers: List[str]


def parse_reference_template(reference_csv: Path) -> Tuple[List[TemplateSection], int]:
    rows = list(csv.reader(reference_csv.open(newline="", encoding="utf-8")))
    max_cols = max((len(r) for r in rows), default=19)
    sections: List[TemplateSection] = []
    for row in rows:
        if not row:
            continue
        ident = (row[0] if len(row) > 0 else "").strip()
        if not ident.endswith("-h"):
            continue
        base = ident[:-2]
        first_lower = next((i for i, ch in enumerate(base) if ch.islower()), len(base))
        row_label = base[first_lower:] if first_lower < len(base) else base
        import_type = row_label
        headers = [h.strip() for h in row[2:] if str(h).strip()]
        if import_type == "devices" and "power_panel" in headers:
            import_type = "power-feeds"
        if import_type == "powercables":
            import_type = "power-cables"
        sections.append(TemplateSection(import_type=import_type, row_label=row_label, headers=headers))
    return sections, max_cols


def _build_site_row(site: Any) -> Dict[str, str]:
    return {
        "name": _val(site, "name"),
        "slug": _val(site, "slug") or _safe_slug(_val(site, "name")),
        "status": _nested_value(getattr(site, "status", None), "active"),
        "region": _nested_name(getattr(site, "region", None), ""),
        "group": _nested_name(getattr(site, "group", None), ""),
        "tenant": _nested_name(getattr(site, "tenant", None), ""),
        "facility": _val(site, "facility"),
        "physical_address": _val(site, "physical_address"),
        "latitude": _val(site, "latitude"),
        "longitude": _val(site, "longitude"),
    }


def fetch_site_export_data(api: pynetbox.api, site_name: str) -> Tuple[str, Dict[str, List[Dict[str, str]]]]:
    site = api.dcim.sites.get(name=site_name)
    if not site:
        raise ValueError(f'No site named "{site_name}"')

    prefix = (_val(site, "facility") or _safe_slug(_val(site, "slug")).upper()).strip()
    if not prefix:
        prefix = _safe_slug(_val(site, "name")).upper()[:12]

    data: Dict[str, List[Dict[str, str]]] = {
        "sites": [_build_site_row(site)],
        "locations": [],
        "racks": [],
        "power-panels": [],
        "devices": [],
        "power-feeds": [],
        "modules": [],
        "cables": [],
        "power-cables": [],
        "prefix": [],
        "ip-addresses": [],
    }

    site_id = _val(site, "id")
    location_ids: set[str] = set()
    site_vrf_names: set[str] = set()
    site_ip_values: list[str] = []

    for obj in _iter_records(api.dcim.locations.filter(site_id=site_id)):
        loc_id = _val(obj, "id")
        if loc_id:
            location_ids.add(loc_id)
        data["locations"].append({
            "site": _nested_name(getattr(obj, "site", None), _val(site, "name")),
            "name": _val(obj, "name"),
            "slug": _val(obj, "slug"),
            "status": _nested_value(getattr(obj, "status", None), "active"),
            "facility": _val(obj, "facility"),
            "tenant": _nested_name(getattr(obj, "tenant", None), ""),
        })

    for obj in _iter_records(api.dcim.racks.filter(site_id=site_id)):
        data["racks"].append({
            "rack_type": _nested_name(getattr(obj, "type", None), ""),
            "name": _val(obj, "name"),
            "facility_id": _val(obj, "facility_id"),
            "role": _nested_name(getattr(obj, "role", None), ""),
            "status": _nested_value(getattr(obj, "status", None), "active"),
            "site": _nested_name(getattr(obj, "site", None), _val(site, "name")),
            "location": _nested_name(getattr(obj, "location", None), ""),
            "tenant": _nested_name(getattr(obj, "tenant", None), ""),
        })

    for obj in _iter_records(api.dcim.power_panels.filter(site_id=site_id)):
        data["power-panels"].append({
            "site": _nested_name(getattr(obj, "site", None), _val(site, "name")),
            "name": _val(obj, "name"),
        })

    device_ids: List[str] = []
    device_names: set[str] = set()
    for obj in _iter_records(api.dcim.devices.filter(site_id=site_id)):
        did = _val(obj, "id")
        if did:
            device_ids.append(did)
        dname = _val(obj, "name")
        if dname:
            device_names.add(dname)
        data["devices"].append({
            "device_type": _nested_model_or_name(getattr(obj, "device_type", None), ""),
            "manufacturer": _nested_name(getattr(getattr(obj, "device_type", None), "manufacturer", None), ""),
            "role": _nested_name(getattr(obj, "role", None), ""),
            "name": dname,
            "rack": _nested_name(getattr(obj, "rack", None), ""),
            "position": _val(obj, "position"),
            "face": _nested_value(getattr(obj, "face", None), ""),
            "status": _nested_value(getattr(obj, "status", None), "active"),
            "site": _nested_name(getattr(obj, "site", None), _val(site, "name")),
            "location": _nested_name(getattr(obj, "location", None), ""),
            "tenant": _nested_name(getattr(obj, "tenant", None), ""),
        })

    for obj in _iter_records(api.dcim.power_feeds.filter(site_id=site_id)):
        data["power-feeds"].append({
            "site": _nested_name(getattr(obj, "site", None), _val(site, "name")),
            "name": _val(obj, "name"),
            "power_panel": _nested_name(getattr(obj, "power_panel", None), ""),
            "status": _nested_value(getattr(obj, "status", None), "active"),
            "type": _nested_value(getattr(obj, "type", None), ""),
            "supply": _nested_value(getattr(obj, "supply", None), ""),
            "phase": _nested_value(getattr(obj, "phase", None), ""),
            "voltage": _val(obj, "voltage"),
            "amperage": _val(obj, "amperage"),
            "max_utilization": _val(obj, "max_utilization"),
            "rack": _nested_name(getattr(obj, "rack", None), ""),
            "tenant": _nested_name(getattr(obj, "tenant", None), ""),
            "location": _nested_name(getattr(obj, "location", None), ""),
        })

    for did in device_ids:
        for obj in _iter_records(api.dcim.modules.filter(device_id=did)):
            data["modules"].append({
                "device": _nested_name(getattr(obj, "device", None), ""),
                "module_bay": _nested_name(getattr(obj, "module_bay", None), ""),
                "module_type": _nested_model_or_name(getattr(obj, "module_type", None), ""),
                "status": _nested_value(getattr(obj, "status", None), "active"),
            })

    # Cables: include only cables where either side references a device in this site.
    # NetBox API doesn't always support site filters for cables, so we filter client-side.
    for obj in _iter_records(api.dcim.cables.filter(limit=0)):
        a_terms = list(getattr(obj, "a_terminations", []) or [])
        b_terms = list(getattr(obj, "b_terminations", []) or [])
        if not a_terms or not b_terms:
            continue
        a_dev = _device_from_term(a_terms[0])
        b_dev = _device_from_term(b_terms[0])
        if a_dev not in device_names and b_dev not in device_names:
            continue
        a_type, a_name = _term_type_name(a_terms[0])
        b_type, b_name = _term_type_name(b_terms[0])
        row = {
            "side_a_device": a_dev,
            "side_a_type": a_type,
            "side_a_name": a_name,
            "side_b_device": b_dev,
            "side_b_type": b_type,
            "side_b_name": b_name,
            "type": _nested_value(getattr(obj, "type", None), ""),
            "status": _nested_value(getattr(obj, "status", None), "connected"),
            "color": _val(obj, "color"),
        }
        if a_type == "powerfeed":
            row["power_panel"] = _powerfeed_panel_name(a_terms[0])
            row["power_feed"] = a_name
        elif b_type == "powerfeed":
            row["power_panel"] = _powerfeed_panel_name(b_terms[0])
            row["power_feed"] = b_name
        cable_type = row["type"].lower()
        if "power" in cable_type or a_type in {"powerport", "poweroutlet"} or b_type in {"powerport", "poweroutlet"}:
            data["power-cables"].append(row)
        else:
            data["cables"].append(row)

    # Prefixes scoped to this site, including child location scopes.
    # Different NetBox versions/plugins may vary scope filter behavior, so fetch and filter safely.
    prefix_seen: set[tuple[str, str]] = set()
    for obj in _iter_records(api.ipam.prefixes.filter(limit=0)):
        scope_type = str(_val(obj, "scope_type") or "").strip().lower()
        scope = getattr(obj, "scope", None)
        scope_id = _nested_id(scope, "")
        include = False
        if scope_type in {"dcim.site", "dcim.sitegroup"}:
            include = bool(scope_id) and scope_id == site_id
        elif scope_type == "dcim.location":
            include = bool(scope_id) and scope_id in location_ids
        elif not scope_type:
            # Older behavior: site may be exposed directly on prefix.
            pref_site_id = _nested_id(getattr(obj, "site", None), "")
            include = bool(pref_site_id) and pref_site_id == site_id
        if not include:
            continue

        prefix_val = _val(obj, "prefix")
        vrf_name = _nested_name(getattr(obj, "vrf", None), "")
        dedupe_key = (prefix_val, vrf_name)
        if dedupe_key in prefix_seen:
            continue
        prefix_seen.add(dedupe_key)

        data["prefix"].append({
            "vrf": vrf_name,
            "prefix": prefix_val,
            "role": _nested_name(getattr(obj, "role", None), ""),
            "tenant": _nested_name(getattr(obj, "tenant", None), ""),
            "status": _nested_value(getattr(obj, "status", None), "active"),
            "is_pool": "true" if bool(getattr(obj, "is_pool", False)) else "false",
        })

    # IP addresses assigned to interfaces on site devices.
    for obj in _iter_records(api.ipam.ip_addresses.filter(limit=0)):
        assigned = getattr(obj, "assigned_object", None)
        if assigned is None:
            continue
        dev = _nested_name(getattr(assigned, "device", None), "")
        if dev not in device_names:
            continue
        vrf_name = _nested_name(getattr(obj, "vrf", None), "")
        if vrf_name:
            site_vrf_names.add(vrf_name)
        data["ip-addresses"].append({
            "device": dev,
            "interface": _val(assigned, "name"),
            "address": _val(obj, "address"),
            "status": _nested_value(getattr(obj, "status", None), "active"),
            "tenant": _nested_name(getattr(obj, "tenant", None), ""),
            "is_primary": "true" if bool(getattr(obj, "is_primary", False)) else "false",
            "vrf": vrf_name,
        })
        addr_val = _val(obj, "address")
        if addr_val:
            site_ip_values.append(addr_val)

    # Fallback: include unscoped/global prefixes if their VRF is used on this site's device IPs.
    # This aligns site export with how CSV imports often create prefixes without scope.
    if site_vrf_names:
        for obj in _iter_records(api.ipam.prefixes.filter(limit=0)):
            scope_type = str(_val(obj, "scope_type") or "").strip().lower()
            if scope_type:
                continue
            vrf_name = _nested_name(getattr(obj, "vrf", None), "")
            if not vrf_name or vrf_name not in site_vrf_names:
                continue
            prefix_val = _val(obj, "prefix")
            dedupe_key = (prefix_val, vrf_name)
            if dedupe_key in prefix_seen:
                continue
            prefix_seen.add(dedupe_key)
            data["prefix"].append({
                "vrf": vrf_name,
                "prefix": prefix_val,
                "role": _nested_name(getattr(obj, "role", None), ""),
                "tenant": _nested_name(getattr(obj, "tenant", None), ""),
                "status": _nested_value(getattr(obj, "status", None), "active"),
                "is_pool": "true" if bool(getattr(obj, "is_pool", False)) else "false",
            })

    # Additional fallback for global prefixes: include any prefix that contains
    # at least one IP assigned to a device in this site.
    site_ip_hosts = []
    for addr in site_ip_values:
        try:
            site_ip_hosts.append(ipaddress.ip_interface(addr).ip)
        except Exception:
            continue
    if site_ip_hosts:
        for obj in _iter_records(api.ipam.prefixes.filter(limit=0)):
            prefix_val = _val(obj, "prefix")
            if not prefix_val:
                continue
            try:
                net = ipaddress.ip_network(prefix_val, strict=False)
            except Exception:
                continue
            if not any(ip in net for ip in site_ip_hosts):
                continue
            vrf_name = _nested_name(getattr(obj, "vrf", None), "")
            dedupe_key = (prefix_val, vrf_name)
            if dedupe_key in prefix_seen:
                continue
            prefix_seen.add(dedupe_key)
            data["prefix"].append({
                "vrf": vrf_name,
                "prefix": prefix_val,
                "role": _nested_name(getattr(obj, "role", None), ""),
                "tenant": _nested_name(getattr(obj, "tenant", None), ""),
                "status": _nested_value(getattr(obj, "status", None), "active"),
                "is_pool": "true" if bool(getattr(obj, "is_pool", False)) else "false",
            })

    return prefix, data


def render_csv(
    sections: List[TemplateSection],
    max_cols: int,
    prefix: str,
    data: Dict[str, List[Dict[str, str]]],
) -> List[List[str]]:
    out: List[List[str]] = []
    for section in sections:
        ident_h = f"{prefix}{section.row_label}-h"
        header_row = [""] * max_cols
        header_row[0] = ident_h
        # Keep second column blank by convention.
        for i, h in enumerate(section.headers, start=2):
            if i < max_cols:
                header_row[i] = h
        out.append(header_row)

        rows = data.get(section.import_type, [])
        ident = f"{prefix}{section.row_label}"
        for rec in rows:
            row = [""] * max_cols
            row[0] = ident
            for i, h in enumerate(section.headers, start=2):
                if i < max_cols:
                    row[i] = str(rec.get(h, "") or "")
            out.append(row)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Export NetBox site to importer CSV format.")
    parser.add_argument("site_name", help="NetBox site name (exact match).")
    parser.add_argument("--instance-id", default=None, help="Instance id from template-sync/instances.json")
    parser.add_argument("--instance-name", default=None, help="Instance name from template-sync/instances.json")
    parser.add_argument("--reference", default="data/MDT1PAPB.csv", help="Reference CSV for output layout.")
    parser.add_argument("--output-dir", default="data", help="Output directory.")
    args = parser.parse_args()

    inst = resolve_instance(instance_id=args.instance_id, instance_name=args.instance_name)
    base_url = str(inst.get("url", "")).strip().rstrip("/")
    token = str(inst.get("token", "")).strip()
    if not base_url or not token:
        raise SystemExit(f'Instance "{inst.get("name", "unknown")}" missing url/token')

    api = pynetbox.api(base_url, token=token)
    session = requests.Session()
    session.verify = not _to_bool(inst.get("skip_ssl_verify", False))
    if session.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    api.http_session = session

    ref = Path(args.reference)
    if not ref.exists():
        raise SystemExit(f"Reference CSV not found: {ref}")
    sections, max_cols = parse_reference_template(ref)

    prefix, data = fetch_site_export_data(api, args.site_name)
    rows = render_csv(sections, max_cols, prefix, data)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{prefix}.csv"
    with out_path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)

    print(f"Site: {args.site_name}")
    print(f"Prefix: {prefix}")
    print(f"Wrote: {out_path}")
    print(f"Rows: {len(rows)}  Cols: {max_cols}")
    for sec in sections:
        print(f"  {sec.import_type}: {len(data.get(sec.import_type, []))}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        capture_exception(exc, script='netbox_site_to_csv.py', route='main')
        raise
