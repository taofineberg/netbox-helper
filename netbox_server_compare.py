"""Server-to-server NetBox compare and selective sync helpers.

This module is intentionally independent from Flask route code so the
compare/sync logic can be unit-tested or reused from multiple endpoints.
"""

from __future__ import annotations

import difflib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

from netbox_branching import resolve_branch_header_value


OBJECT_TYPE_ORDER = ["tenant", "region", "site", "device_type", "device"]
OBJECT_TYPE_META = {
    "tenant": {"label": "Tenants", "endpoint": "tenancy/tenants"},
    "region": {"label": "Regions", "endpoint": "dcim/regions"},
    "site": {"label": "Sites", "endpoint": "dcim/sites"},
    "device_type": {"label": "Device Types", "endpoint": "dcim/device-types"},
    "device": {"label": "Devices", "endpoint": "dcim/devices"},
}


class NetBoxClient:
    """Thin NetBox API client with list caching for sync workflows."""

    def __init__(self, instance: Dict[str, Any]):
        self.instance = dict(instance or {})
        self.url = str(self.instance.get("url") or "").strip().rstrip("/")
        self.token = str(self.instance.get("token") or "").strip()
        self.branch = str(self.instance.get("branch") or "").strip()
        self.verify = self.instance.get("verify")
        if self.verify is None:
            self.verify = not _to_bool(self.instance.get("skip_ssl_verify", False))
        if not self.url:
            raise ValueError("Instance URL is required")
        if not self.token:
            raise ValueError("Instance token is required")
        if self.branch:
            self.branch = resolve_branch_header_value(
                {
                    "url": self.url,
                    "token": self.token,
                    "verify": self.verify,
                },
                self.branch,
            )
        self._cache: Dict[str, List[Dict[str, Any]]] = {}

    def headers(self) -> Dict[str, str]:
        headers = {
            "Authorization": f"Token {self.token}",
            "Accept": "application/json",
        }
        if self.branch:
            # Supported by NetBox Branching plugin / branch-aware API stacks.
            headers["X-NetBox-Branch"] = self.branch
        return headers

    def fetch_all(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch all rows from a paginated NetBox endpoint."""
        ep = str(endpoint or "").strip().strip("/")
        if not ep:
            return []

        use_cache = not params
        if use_cache and ep in self._cache:
            return list(self._cache[ep])

        query = dict(params or {})
        if "limit" not in query:
            query["limit"] = 1000

        qs = "&".join(f"{k}={v}" for k, v in query.items())
        next_url = f"{self.url}/api/{ep}/?{qs}" if qs else f"{self.url}/api/{ep}/"
        rows: List[Dict[str, Any]] = []

        while next_url:
            try:
                resp = requests.get(next_url, headers=self.headers(), verify=self.verify, timeout=30)
            except requests.exceptions.ConnectionError as exc:
                raise ValueError(f"Cannot connect to {self.url} — {exc}") from exc
            except requests.exceptions.Timeout as exc:
                raise ValueError(f"Connection timed out for {self.url}") from exc

            if resp.status_code == 401:
                raise ValueError(f"Authentication failed for {self.url} — check API token")
            if resp.status_code == 404:
                raise ValueError(f"Endpoint '{ep}' not found at {self.url}")

            try:
                resp.raise_for_status()
            except requests.HTTPError as exc:
                body = (resp.text or "")[:250]
                branch_ctx = f" (branch={self.branch})" if self.branch else ""
                raise ValueError(f"GET {ep}: {resp.status_code}{branch_ctx} {body}") from exc

            data = resp.json() if resp.content else {}
            page_rows = data.get("results", []) if isinstance(data, dict) else []
            rows.extend([r for r in page_rows if isinstance(r, dict)])
            next_url = data.get("next") if isinstance(data, dict) else None

        if use_cache:
            self._cache[ep] = list(rows)
        return rows

    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        ep = str(endpoint or "").strip().strip("/")
        if not ep:
            raise ValueError("Endpoint is required")
        resp = requests.post(
            f"{self.url}/api/{ep}/",
            headers={**self.headers(), "Content-Type": "application/json"},
            json=payload,
            verify=self.verify,
            timeout=30,
        )
        if not resp.ok:
            raise ValueError(f"POST {ep}: {resp.status_code} {(resp.text or '')[:250]}")
        self.invalidate(ep)
        return resp.json() if resp.content else {}

    def patch(self, endpoint: str, obj_id: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
        ep = str(endpoint or "").strip().strip("/")
        if not ep:
            raise ValueError("Endpoint is required")
        resp = requests.patch(
            f"{self.url}/api/{ep}/{obj_id}/",
            headers={**self.headers(), "Content-Type": "application/json"},
            json=payload,
            verify=self.verify,
            timeout=30,
        )
        if not resp.ok:
            raise ValueError(f"PATCH {ep}/{obj_id}: {resp.status_code} {(resp.text or '')[:250]}")
        self.invalidate(ep)
        return resp.json() if resp.content else {}

    def invalidate(self, endpoint: str) -> None:
        ep = str(endpoint or "").strip().strip("/")
        self._cache.pop(ep, None)


# ---------------------------------------------------------------------------
# Value extraction / normalization helpers
# ---------------------------------------------------------------------------

def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _enum(row: Dict[str, Any], field: str) -> Any:
    val = (row or {}).get(field)
    if isinstance(val, dict):
        return val.get("value")
    return val


def _slug(row: Dict[str, Any], field: str) -> Any:
    val = (row or {}).get(field)
    if isinstance(val, dict):
        return val.get("slug")
    return val


def _name(row: Dict[str, Any], field: str) -> Any:
    val = (row or {}).get(field)
    if isinstance(val, dict):
        return val.get("name")
    return val


def _id(row: Dict[str, Any], field: str) -> Any:
    val = (row or {}).get(field)
    if isinstance(val, dict):
        return val.get("id")
    return val


def _address(row: Dict[str, Any], field: str) -> str:
    val = (row or {}).get(field)
    if isinstance(val, dict):
        raw = str(val.get("address") or "").strip()
        return raw
    return str(val or "").strip()


def _norm_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _norm_json(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: _norm_json(v) for k, v in sorted(val.items(), key=lambda kv: str(kv[0]))}
    if isinstance(val, list):
        return [_norm_json(v) for v in val]
    return val


def _safe_diff_path_part(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "item"
    out = []
    for ch in raw:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out)


def build_diff(source_norm: Dict[str, Any], dest_norm: Dict[str, Any], path_hint: str = "object.json") -> List[str]:
    src_json = json.dumps(_norm_json(source_norm), indent=2, sort_keys=True)
    dst_json = json.dumps(_norm_json(dest_norm), indent=2, sort_keys=True)
    a_file = f"a/{path_hint}"
    b_file = f"b/{path_hint}"
    lines = list(
        difflib.unified_diff(
            dst_json.splitlines(),
            src_json.splitlines(),
            fromfile=a_file,
            tofile=b_file,
            lineterm="",
        )
    )
    return [f"diff --git {a_file} {b_file}", *lines]


def _region_key(row: Dict[str, Any]) -> str:
    return _norm_text(row.get("slug") or row.get("name"))


def _site_key(row: Dict[str, Any]) -> str:
    return _norm_text(row.get("slug") or row.get("name"))


def _device_type_key(row: Dict[str, Any]) -> str:
    return _norm_text(row.get("slug") or row.get("model"))


def _device_key(row: Dict[str, Any]) -> str:
    return _norm_text(row.get("name"))


def _display_name(obj_type: str, row: Dict[str, Any]) -> str:
    if obj_type == "device_type":
        return _norm_text(row.get("model") or _device_type_key(row))
    if obj_type == "region":
        return _norm_text(row.get("name") or _region_key(row))
    if obj_type == "site":
        return _norm_text(row.get("name") or _site_key(row))
    return _norm_text(row.get("name") or _device_key(row))


def _row_key(obj_type: str, row: Dict[str, Any]) -> str:
    if obj_type == "region":
        return _region_key(row)
    if obj_type == "site":
        return _site_key(row)
    if obj_type == "device_type":
        return _device_type_key(row)
    if obj_type == "device":
        return _device_key(row)
    return ""


def _normalize_region(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": _norm_text(row.get("name")),
        "slug": _norm_text(row.get("slug")),
        "description": _norm_text(row.get("description")),
        "parent_slug": _norm_text(_slug(row, "parent")),
    }


def _normalize_site(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": _norm_text(row.get("name")),
        "slug": _norm_text(row.get("slug")),
        "status": _norm_text(_enum(row, "status")),
        "region_slug": _norm_text(_slug(row, "region")),
        "facility": _norm_text(row.get("facility")),
        "time_zone": _norm_text(row.get("time_zone")),
        "description": _norm_text(row.get("description")),
        "physical_address": _norm_text(row.get("physical_address")),
        "shipping_address": _norm_text(row.get("shipping_address")),
        "latitude": row.get("latitude"),
        "longitude": row.get("longitude"),
    }


def _normalize_device_type(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "model": _norm_text(row.get("model")),
        "slug": _norm_text(row.get("slug")),
        "manufacturer_slug": _norm_text(_slug(row, "manufacturer")),
        "part_number": _norm_text(row.get("part_number")),
        "u_height": row.get("u_height"),
        "is_full_depth": _to_bool(row.get("is_full_depth", True)),
        "subdevice_role": _norm_text(_enum(row, "subdevice_role")),
        "airflow": _norm_text(_enum(row, "airflow")),
        "weight": row.get("weight"),
        "weight_unit": _norm_text(_enum(row, "weight_unit")),
        "description": _norm_text(row.get("description")),
        "comments": _norm_text(row.get("comments")),
    }


def _normalize_device(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": _norm_text(row.get("name")),
        "status": _norm_text(_enum(row, "status")),
        "site_slug": _norm_text(_slug(row, "site")),
        "role_slug": _norm_text(_slug(row, "role")),
        "device_type_slug": _norm_text(_slug(row, "device_type")),
        "serial": _norm_text(row.get("serial")),
        "asset_tag": _norm_text(row.get("asset_tag")),
        "platform_slug": _norm_text(_slug(row, "platform")),
        "tenant_slug": _norm_text(_slug(row, "tenant")),
        "description": _norm_text(row.get("description")),
        "comments": _norm_text(row.get("comments")),
    }


def _normalize_for_type(obj_type: str, row: Dict[str, Any]) -> Dict[str, Any]:
    if obj_type == "region":
        return _normalize_region(row)
    if obj_type == "site":
        return _normalize_site(row)
    if obj_type == "device_type":
        return _normalize_device_type(row)
    if obj_type == "device":
        return _normalize_device(row)
    return {}


def _map_rows(obj_type: str, rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    mapped: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        key = _row_key(obj_type, row)
        if key:
            mapped[key] = row
    return mapped


def _compare_items_for_keys(
    obj_type: str,
    src_map: Dict[str, Dict[str, Any]],
    dst_map: Dict[str, Dict[str, Any]],
    keys: Iterable[str],
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for key in keys:
        in_src = key in src_map
        in_dst = key in dst_map
        diff_path = (
            f"{_safe_diff_path_part(obj_type)}/"
            f"{_safe_diff_path_part(key)}.json"
        )
        if in_src and not in_dst:
            row = src_map[key]
            src_norm = _normalize_for_type(obj_type, row)
            items.append(
                {
                    "key": key,
                    "name": _display_name(obj_type, row),
                    "status": "source_only",
                    "diff": build_diff(src_norm, {}, path_hint=diff_path),
                }
            )
            continue
        if in_dst and not in_src:
            row = dst_map[key]
            dst_norm = _normalize_for_type(obj_type, row)
            items.append(
                {
                    "key": key,
                    "name": _display_name(obj_type, row),
                    "status": "dest_only",
                    "diff": build_diff({}, dst_norm, path_hint=diff_path),
                }
            )
            continue

        src_norm = _normalize_for_type(obj_type, src_map[key])
        dst_norm = _normalize_for_type(obj_type, dst_map[key])
        if src_norm == dst_norm:
            items.append(
                {
                    "key": key,
                    "name": _display_name(obj_type, src_map[key]),
                    "status": "in_sync",
                    "diff": None,
                }
            )
        else:
            items.append(
                {
                    "key": key,
                    "name": _display_name(obj_type, src_map[key]),
                    "status": "different",
                    "diff": build_diff(src_norm, dst_norm, path_hint=diff_path),
                }
            )
    return items


def _collect_region_chain_keys(site_row: Optional[Dict[str, Any]], region_map: Dict[str, Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    if not site_row:
        return out
    seen = set()
    cur = _norm_text(_slug(site_row, "region"))
    while cur and cur not in seen:
        out.append(cur)
        seen.add(cur)
        region_row = region_map.get(cur)
        if not region_row:
            break
        cur = _norm_text(_slug(region_row, "parent"))
    return out


def _compare_site_scope_full(
    src: NetBoxClient,
    dst: NetBoxClient,
    selected_site_key: str,
) -> Dict[str, Dict[str, Any]]:
    site_key = _norm_text(selected_site_key)
    if not site_key:
        raise ValueError("Site selection is required for site scope compare")

    src_site_map = _map_rows("site", src.fetch_all(_endpoint_for_type("site")))
    dst_site_map = _map_rows("site", dst.fetch_all(_endpoint_for_type("site")))

    src_site_row = src_site_map.get(site_key)
    if not src_site_row:
        raise ValueError(f"Selected site '{site_key}' was not found in source")
    dst_site_row = dst_site_map.get(site_key)

    src_site_slug = _norm_text(src_site_row.get("slug") or site_key)
    dst_site_slug = _norm_text((dst_site_row or {}).get("slug") or src_site_slug)

    src_region_map = _map_rows("region", src.fetch_all(_endpoint_for_type("region")))
    dst_region_map = _map_rows("region", dst.fetch_all(_endpoint_for_type("region")))
    region_keys = sorted(
        set(_collect_region_chain_keys(src_site_row, src_region_map))
        | set(_collect_region_chain_keys(dst_site_row, dst_region_map))
    )

    src_devices = [
        row
        for row in src.fetch_all(_endpoint_for_type("device"))
        if _norm_text(_slug(row, "site")) == src_site_slug
    ]
    dst_devices = [
        row
        for row in dst.fetch_all(_endpoint_for_type("device"))
        if _norm_text(_slug(row, "site")) == dst_site_slug
    ]
    src_device_map = _map_rows("device", src_devices)
    dst_device_map = _map_rows("device", dst_devices)
    device_keys = sorted(set(src_device_map.keys()) | set(dst_device_map.keys()))

    src_dtype_ref_keys = {
        _norm_text(_slug(row, "device_type"))
        for row in src_devices
        if _norm_text(_slug(row, "device_type"))
    }
    dst_dtype_ref_keys = {
        _norm_text(_slug(row, "device_type"))
        for row in dst_devices
        if _norm_text(_slug(row, "device_type"))
    }
    dtype_keys = sorted(src_dtype_ref_keys | dst_dtype_ref_keys)

    all_src_dtypes = _map_rows("device_type", src.fetch_all(_endpoint_for_type("device_type")))
    all_dst_dtypes = _map_rows("device_type", dst.fetch_all(_endpoint_for_type("device_type")))
    src_dtype_map = {k: v for k, v in all_src_dtypes.items() if k in src_dtype_ref_keys}
    dst_dtype_map = {k: v for k, v in all_dst_dtypes.items() if k in dst_dtype_ref_keys}

    results: Dict[str, Dict[str, Any]] = {}
    results["region"] = {
        "label": _label_for_type("region"),
        "items": _compare_items_for_keys("region", src_region_map, dst_region_map, region_keys),
    }
    results["site"] = {
        "label": _label_for_type("site"),
        "items": _compare_items_for_keys("site", src_site_map, dst_site_map, [site_key]),
    }
    results["device_type"] = {
        "label": _label_for_type("device_type"),
        "items": _compare_items_for_keys("device_type", src_dtype_map, dst_dtype_map, dtype_keys),
    }
    results["device"] = {
        "label": _label_for_type("device"),
        "items": _compare_items_for_keys("device", src_device_map, dst_device_map, device_keys),
    }
    return results


def _endpoint_for_type(obj_type: str) -> str:
    meta = OBJECT_TYPE_META.get(obj_type)
    if not meta:
        raise ValueError(f"Unsupported object type: {obj_type}")
    return str(meta["endpoint"])


def _label_for_type(obj_type: str) -> str:
    meta = OBJECT_TYPE_META.get(obj_type)
    if not meta:
        raise ValueError(f"Unsupported object type: {obj_type}")
    return str(meta["label"])


# ---------------------------------------------------------------------------
# Public compare/options API
# ---------------------------------------------------------------------------

def list_compare_options(source_instance: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """Return source-side dropdown options for each supported scope."""
    src = NetBoxClient(source_instance)

    tenants = src.fetch_all(_endpoint_for_type("tenant"))
    regions = src.fetch_all(_endpoint_for_type("region"))
    sites = src.fetch_all(_endpoint_for_type("site"))
    dtypes = src.fetch_all(_endpoint_for_type("device_type"))
    devices = src.fetch_all(_endpoint_for_type("device"))

    tenant_options = [
        {
            "key": _norm_text(t.get("slug")),
            "name": _norm_text(t.get("name")),
        }
        for t in tenants
        if _norm_text(t.get("slug")) and _norm_text(t.get("name"))
    ]
    region_options = [
        {"key": _region_key(r), "name": _norm_text(r.get("name"))}
        for r in regions
        if _region_key(r)
    ]
    site_options = [
        {
            "key": _site_key(s),
            "name": _norm_text(s.get("name")),
            "facility": _norm_text(s.get("facility")),
        }
        for s in sites
        if _site_key(s)
    ]
    dtype_options = [
        {
            "key": _device_type_key(dt),
            "name": _norm_text(dt.get("model") or _device_type_key(dt)),
        }
        for dt in dtypes
        if _device_type_key(dt)
    ]

    device_options = []
    for dev in devices:
        key = _device_key(dev)
        if not key:
            continue
        site_name = _name(dev, "site")
        label = key if not site_name else f"{key} ({site_name})"
        device_options.append({"key": key, "name": label})

    tenant_options.sort(key=lambda x: x["name"].lower())
    region_options.sort(key=lambda x: x["name"].lower())
    site_options.sort(key=lambda x: x["name"].lower())
    dtype_options.sort(key=lambda x: x["name"].lower())
    device_options.sort(key=lambda x: x["name"].lower())

    return {
        "tenants": tenant_options,
        "regions": region_options,
        "sites": site_options,
        "device_types": dtype_options,
        "devices": device_options,
    }


def resolve_site_facility(
    source_instance: Dict[str, Any],
    selected_key: str = "",
    site_name: str = "",
) -> str:
    """Resolve a source site facility value by site key (slug/name) or name."""
    src = NetBoxClient(source_instance)
    key = _norm_text(selected_key)
    name = _norm_text(site_name)
    key_l = key.lower()
    name_l = name.lower()

    exact_name_facility = ""
    exact_key_as_name_facility = ""
    casefold_name_facility = ""
    casefold_key_as_name_facility = ""

    for row in src.fetch_all(_endpoint_for_type("site")):
        row_key = _site_key(row)
        row_name = _norm_text(row.get("name"))
        facility = _norm_text(row.get("facility"))
        if key and row_key == key:
            return facility
        if name and row_name == name:
            exact_name_facility = facility
        if key and row_name == key:
            exact_key_as_name_facility = facility
        if name and not casefold_name_facility and row_name.lower() == name_l:
            casefold_name_facility = facility
        if key and not casefold_key_as_name_facility and row_name.lower() == key_l:
            casefold_key_as_name_facility = facility

    if exact_name_facility:
        return exact_name_facility
    if exact_key_as_name_facility:
        return exact_key_as_name_facility
    if casefold_name_facility:
        return casefold_name_facility
    if casefold_key_as_name_facility:
        return casefold_key_as_name_facility
    return ""


def _scope_types(scope: str) -> List[str]:
    scope_norm = str(scope or "all").strip().lower()
    if scope_norm == "all":
        return list(OBJECT_TYPE_ORDER)
    if scope_norm in {"tenant", "region", "site", "device", "device_type"}:
        return [scope_norm]
    raise ValueError("scope must be one of: all, tenant, region, site, device_type, device")


def compare_instances(
    source_instance: Dict[str, Any],
    dest_instance: Dict[str, Any],
    scope: str = "all",
    selected_key: str = "",
) -> Dict[str, Dict[str, Any]]:
    """Compare source and destination for one scope or all scopes."""
    src = NetBoxClient(source_instance)
    dst = NetBoxClient(dest_instance)

    scope_norm = str(scope or "all").strip().lower()
    sel = _norm_text(selected_key)
    if scope_norm == "site" and sel:
        # Site scope with an explicit site now means full-site compare
        # (site + related regions + site devices + their device types).
        return _compare_site_scope_full(src, dst, sel)

    results: Dict[str, Dict[str, Any]] = {}

    for obj_type in _scope_types(scope_norm):
        endpoint = _endpoint_for_type(obj_type)
        src_map = _map_rows(obj_type, src.fetch_all(endpoint))
        dst_map = _map_rows(obj_type, dst.fetch_all(endpoint))

        keys = sorted(set(list(src_map.keys()) + list(dst_map.keys())))
        if sel:
            keys = [k for k in keys if k == sel]

        results[obj_type] = {
            "label": _label_for_type(obj_type),
            "items": _compare_items_for_keys(obj_type, src_map, dst_map, keys),
        }

    return results


# ---------------------------------------------------------------------------
# Sync implementation
# ---------------------------------------------------------------------------

def _find_row_by_key(client: NetBoxClient, obj_type: str, key: str) -> Optional[Dict[str, Any]]:
    rows = client.fetch_all(_endpoint_for_type(obj_type))
    mapped = _map_rows(obj_type, rows)
    return mapped.get(_norm_text(key))


def _ensure_region(src: NetBoxClient, dst: NetBoxClient, slug: str, stack: Optional[set] = None) -> int:
    key = _norm_text(slug)
    if not key:
        raise ValueError("Region slug is required")

    existing = _find_row_by_key(dst, "region", key)
    if existing:
        rid = existing.get("id")
        if rid is None:
            raise ValueError(f"Destination region '{key}' has no id")
        return int(rid)

    source_row = _find_row_by_key(src, "region", key)
    if not source_row:
        raise ValueError(f"Region '{key}' not found in source")

    stack = stack or set()
    if key in stack:
        raise ValueError(f"Circular region parent reference for '{key}'")
    stack.add(key)

    payload: Dict[str, Any] = {
        "name": _norm_text(source_row.get("name")),
        "slug": _norm_text(source_row.get("slug")),
        "description": _norm_text(source_row.get("description")),
    }
    parent_slug = _norm_text(_slug(source_row, "parent"))
    if parent_slug:
        payload["parent"] = _ensure_region(src, dst, parent_slug, stack=stack)

    created = dst.post(_endpoint_for_type("region"), payload)
    rid = created.get("id")
    if rid is None:
        raise ValueError(f"Region '{key}' create returned no id")
    return int(rid)


def _ensure_site(src: NetBoxClient, dst: NetBoxClient, slug: str) -> int:
    key = _norm_text(slug)
    if not key:
        raise ValueError("Site slug is required")

    existing = _find_row_by_key(dst, "site", key)
    if existing:
        sid = existing.get("id")
        if sid is None:
            raise ValueError(f"Destination site '{key}' has no id")
        return int(sid)

    source_row = _find_row_by_key(src, "site", key)
    if not source_row:
        raise ValueError(f"Site '{key}' not found in source")

    payload: Dict[str, Any] = {
        "name": _norm_text(source_row.get("name")),
        "slug": _norm_text(source_row.get("slug")),
        "status": _norm_text(_enum(source_row, "status") or "active"),
        "facility": _norm_text(source_row.get("facility")),
        "time_zone": _norm_text(source_row.get("time_zone")),
        "description": _norm_text(source_row.get("description")),
        "physical_address": _norm_text(source_row.get("physical_address")),
        "shipping_address": _norm_text(source_row.get("shipping_address")),
        "latitude": source_row.get("latitude"),
        "longitude": source_row.get("longitude"),
    }
    region_slug = _norm_text(_slug(source_row, "region"))
    if region_slug:
        payload["region"] = _ensure_region(src, dst, region_slug)

    created = dst.post(_endpoint_for_type("site"), payload)
    sid = created.get("id")
    if sid is None:
        raise ValueError(f"Site '{key}' create returned no id")
    return int(sid)


def _ensure_manufacturer(src: NetBoxClient, dst: NetBoxClient, slug: str) -> int:
    key = _norm_text(slug)
    if not key:
        raise ValueError("Manufacturer slug is required")

    dst_mfr_map = {_norm_text(m.get("slug")): m for m in dst.fetch_all("dcim/manufacturers")}
    if key in dst_mfr_map:
        mid = dst_mfr_map[key].get("id")
        if mid is None:
            raise ValueError(f"Destination manufacturer '{key}' has no id")
        return int(mid)

    src_mfr_map = {_norm_text(m.get("slug")): m for m in src.fetch_all("dcim/manufacturers")}
    src_mfr = src_mfr_map.get(key)
    if not src_mfr:
        raise ValueError(f"Manufacturer '{key}' not found in source")

    payload = {
        "name": _norm_text(src_mfr.get("name") or key),
        "slug": _norm_text(src_mfr.get("slug") or key),
        "description": _norm_text(src_mfr.get("description")),
        "comments": _norm_text(src_mfr.get("comments")),
    }
    created = dst.post("dcim/manufacturers", payload)
    mid = created.get("id")
    if mid is None:
        raise ValueError(f"Manufacturer '{key}' create returned no id")
    return int(mid)


def _ensure_device_type(src: NetBoxClient, dst: NetBoxClient, key: str) -> int:
    k = _norm_text(key)
    if not k:
        raise ValueError("Device type key is required")

    dst_row = _find_row_by_key(dst, "device_type", k)
    if dst_row:
        did = dst_row.get("id")
        if did is None:
            raise ValueError(f"Destination device type '{k}' has no id")
        return int(did)

    src_row = _find_row_by_key(src, "device_type", k)
    if not src_row:
        raise ValueError(f"Device type '{k}' not found in source")

    mfr_slug = _norm_text(_slug(src_row, "manufacturer"))
    if not mfr_slug:
        raise ValueError(f"Device type '{k}' is missing manufacturer slug")
    mfr_id = _ensure_manufacturer(src, dst, mfr_slug)

    payload: Dict[str, Any] = {
        "manufacturer": mfr_id,
        "model": _norm_text(src_row.get("model")),
        "slug": _norm_text(src_row.get("slug") or k),
        "part_number": _norm_text(src_row.get("part_number")),
        "u_height": src_row.get("u_height") if src_row.get("u_height") is not None else 1,
        "is_full_depth": _to_bool(src_row.get("is_full_depth", True)),
        "description": _norm_text(src_row.get("description")),
        "comments": _norm_text(src_row.get("comments")),
    }

    for enum_field in ("subdevice_role", "airflow", "weight_unit"):
        val = _enum(src_row, enum_field)
        if val is not None and _norm_text(val):
            payload[enum_field] = val
    if src_row.get("weight") is not None:
        payload["weight"] = src_row.get("weight")

    created = dst.post(_endpoint_for_type("device_type"), payload)
    did = created.get("id")
    if did is None:
        raise ValueError(f"Device type '{k}' create returned no id")
    return int(did)


def _ensure_device_role(src: NetBoxClient, dst: NetBoxClient, slug: str) -> int:
    key = _norm_text(slug)
    if not key:
        raise ValueError("Device role slug is required")

    dst_roles = {_norm_text(r.get("slug")): r for r in dst.fetch_all("dcim/device-roles")}
    if key in dst_roles:
        rid = dst_roles[key].get("id")
        if rid is None:
            raise ValueError(f"Destination device role '{key}' has no id")
        return int(rid)

    src_roles = {_norm_text(r.get("slug")): r for r in src.fetch_all("dcim/device-roles")}
    src_role = src_roles.get(key)
    if not src_role:
        raise ValueError(f"Device role '{key}' not found in source")

    payload = {
        "name": _norm_text(src_role.get("name") or key),
        "slug": _norm_text(src_role.get("slug") or key),
    }
    color = _norm_text(src_role.get("color"))
    if color:
        payload["color"] = color

    created = dst.post("dcim/device-roles", payload)
    rid = created.get("id")
    if rid is None:
        raise ValueError(f"Device role '{key}' create returned no id")
    return int(rid)


def _ensure_tenant(src: NetBoxClient, dst: NetBoxClient, slug: str) -> int:
    key = _norm_text(slug)
    if not key:
        raise ValueError("Tenant slug is required")

    dst_tenants = {_norm_text(t.get("slug")): t for t in dst.fetch_all("tenancy/tenants")}
    if key in dst_tenants:
        tid = dst_tenants[key].get("id")
        if tid is None:
            raise ValueError(f"Destination tenant '{key}' has no id")
        return int(tid)

    src_tenants = {_norm_text(t.get("slug")): t for t in src.fetch_all("tenancy/tenants")}
    src_tenant = src_tenants.get(key)
    if not src_tenant:
        raise ValueError(f"Tenant '{key}' not found in source")

    payload = {
        "name": _norm_text(src_tenant.get("name") or key),
        "slug": _norm_text(src_tenant.get("slug") or key),
        "description": _norm_text(src_tenant.get("description")),
        "comments": _norm_text(src_tenant.get("comments")),
    }

    created = dst.post("tenancy/tenants", payload)
    tid = created.get("id")
    if tid is None:
        raise ValueError(f"Tenant '{key}' create returned no id")
    return int(tid)


def _ensure_platform(src: NetBoxClient, dst: NetBoxClient, slug: str) -> int:
    key = _norm_text(slug)
    if not key:
        raise ValueError("Platform slug is required")

    dst_platforms = {_norm_text(p.get("slug")): p for p in dst.fetch_all("dcim/platforms")}
    if key in dst_platforms:
        pid = dst_platforms[key].get("id")
        if pid is None:
            raise ValueError(f"Destination platform '{key}' has no id")
        return int(pid)

    src_platforms = {_norm_text(p.get("slug")): p for p in src.fetch_all("dcim/platforms")}
    src_platform = src_platforms.get(key)
    if not src_platform:
        raise ValueError(f"Platform '{key}' not found in source")

    payload = {
        "name": _norm_text(src_platform.get("name") or key),
        "slug": _norm_text(src_platform.get("slug") or key),
        "description": _norm_text(src_platform.get("description")),
    }

    mfr_slug = _norm_text(_slug(src_platform, "manufacturer"))
    if mfr_slug:
        payload["manufacturer"] = _ensure_manufacturer(src, dst, mfr_slug)

    created = dst.post("dcim/platforms", payload)
    pid = created.get("id")
    if pid is None:
        raise ValueError(f"Platform '{key}' create returned no id")
    return int(pid)


def _sync_region(src: NetBoxClient, dst: NetBoxClient, key: str) -> str:
    src_row = _find_row_by_key(src, "region", key)
    if not src_row:
        raise ValueError(f"Region '{key}' not found in source")

    payload: Dict[str, Any] = {
        "name": _norm_text(src_row.get("name")),
        "slug": _norm_text(src_row.get("slug")),
        "description": _norm_text(src_row.get("description")),
    }
    parent_slug = _norm_text(_slug(src_row, "parent"))
    if parent_slug:
        payload["parent"] = _ensure_region(src, dst, parent_slug)
    else:
        payload["parent"] = None

    dst_row = _find_row_by_key(dst, "region", key)
    if dst_row:
        dst.patch(_endpoint_for_type("region"), dst_row["id"], payload)
        return "updated"
    dst.post(_endpoint_for_type("region"), payload)
    return "created"


def _sync_site(src: NetBoxClient, dst: NetBoxClient, key: str) -> str:
    src_row = _find_row_by_key(src, "site", key)
    if not src_row:
        raise ValueError(f"Site '{key}' not found in source")

    payload: Dict[str, Any] = {
        "name": _norm_text(src_row.get("name")),
        "slug": _norm_text(src_row.get("slug")),
        "status": _norm_text(_enum(src_row, "status") or "active"),
        "facility": _norm_text(src_row.get("facility")),
        "time_zone": _norm_text(src_row.get("time_zone")),
        "description": _norm_text(src_row.get("description")),
        "physical_address": _norm_text(src_row.get("physical_address")),
        "shipping_address": _norm_text(src_row.get("shipping_address")),
        "latitude": src_row.get("latitude"),
        "longitude": src_row.get("longitude"),
    }

    region_slug = _norm_text(_slug(src_row, "region"))
    if region_slug:
        payload["region"] = _ensure_region(src, dst, region_slug)
    else:
        payload["region"] = None

    dst_row = _find_row_by_key(dst, "site", key)
    if dst_row:
        dst.patch(_endpoint_for_type("site"), dst_row["id"], payload)
        return "updated"
    dst.post(_endpoint_for_type("site"), payload)
    return "created"


def _sync_device_type(src: NetBoxClient, dst: NetBoxClient, key: str) -> str:
    src_row = _find_row_by_key(src, "device_type", key)
    if not src_row:
        raise ValueError(f"Device type '{key}' not found in source")

    mfr_slug = _norm_text(_slug(src_row, "manufacturer"))
    if not mfr_slug:
        raise ValueError(f"Device type '{key}' is missing manufacturer slug")

    payload: Dict[str, Any] = {
        "manufacturer": _ensure_manufacturer(src, dst, mfr_slug),
        "model": _norm_text(src_row.get("model")),
        "slug": _norm_text(src_row.get("slug") or key),
        "part_number": _norm_text(src_row.get("part_number")),
        "u_height": src_row.get("u_height") if src_row.get("u_height") is not None else 1,
        "is_full_depth": _to_bool(src_row.get("is_full_depth", True)),
        "description": _norm_text(src_row.get("description")),
        "comments": _norm_text(src_row.get("comments")),
    }

    for enum_field in ("subdevice_role", "airflow", "weight_unit"):
        val = _enum(src_row, enum_field)
        if val is not None and _norm_text(val):
            payload[enum_field] = val
    if src_row.get("weight") is not None:
        payload["weight"] = src_row.get("weight")

    dst_row = _find_row_by_key(dst, "device_type", key)
    if dst_row:
        dst.patch(_endpoint_for_type("device_type"), dst_row["id"], payload)
        return "updated"
    dst.post(_endpoint_for_type("device_type"), payload)
    return "created"


def _sync_device(src: NetBoxClient, dst: NetBoxClient, key: str) -> str:
    src_row = _find_row_by_key(src, "device", key)
    if not src_row:
        raise ValueError(f"Device '{key}' not found in source")

    site_slug = _norm_text(_slug(src_row, "site"))
    role_slug = _norm_text(_slug(src_row, "role"))
    dtype_slug = _norm_text(_slug(src_row, "device_type"))

    if not site_slug:
        raise ValueError(f"Device '{key}' is missing site slug")
    if not role_slug:
        raise ValueError(f"Device '{key}' is missing role slug")
    if not dtype_slug:
        raise ValueError(f"Device '{key}' is missing device type slug")

    payload: Dict[str, Any] = {
        "name": _norm_text(src_row.get("name")),
        "status": _norm_text(_enum(src_row, "status") or "active"),
        "site": _ensure_site(src, dst, site_slug),
        "role": _ensure_device_role(src, dst, role_slug),
        "device_type": _ensure_device_type(src, dst, dtype_slug),
        "serial": _norm_text(src_row.get("serial")),
        "asset_tag": _norm_text(src_row.get("asset_tag")),
        "description": _norm_text(src_row.get("description")),
        "comments": _norm_text(src_row.get("comments")),
    }

    tenant_slug = _norm_text(_slug(src_row, "tenant"))
    payload["tenant"] = _ensure_tenant(src, dst, tenant_slug) if tenant_slug else None

    platform_slug = _norm_text(_slug(src_row, "platform"))
    payload["platform"] = _ensure_platform(src, dst, platform_slug) if platform_slug else None

    dst_row = _find_row_by_key(dst, "device", key)
    if dst_row:
        dst.patch(_endpoint_for_type("device"), dst_row["id"], payload)
        return "updated"
    dst.post(_endpoint_for_type("device"), payload)
    return "created"


def sync_one(source_instance: Dict[str, Any], dest_instance: Dict[str, Any], obj_type: str, key: str) -> str:
    """Sync one object from source to destination and return action."""
    obj = str(obj_type or "").strip().lower()
    item_key = _norm_text(key)
    if obj not in OBJECT_TYPE_META:
        raise ValueError(f"Unsupported object type '{obj_type}'")
    if not item_key:
        raise ValueError("item key is required")

    src = NetBoxClient(source_instance)
    dst = NetBoxClient(dest_instance)

    if obj == "region":
        return _sync_region(src, dst, item_key)
    if obj == "site":
        return _sync_site(src, dst, item_key)
    if obj == "device_type":
        return _sync_device_type(src, dst, item_key)
    if obj == "device":
        return _sync_device(src, dst, item_key)

    raise ValueError(f"Unsupported object type '{obj_type}'")


def sync_many(
    source_instance: Dict[str, Any],
    dest_instance: Dict[str, Any],
    items: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Sync many items from source to destination.

    Each item needs:
      - object_type: region|site|device_type|device
      - key: unique key for selected object
      - name: optional display name for response only
    """
    src = NetBoxClient(source_instance)
    dst = NetBoxClient(dest_instance)

    sync_order = {
        "region": 10,
        "site": 20,
        "device_type": 30,
        "device": 40,
    }
    indexed_items = list(enumerate(items or []))
    indexed_items.sort(
        key=lambda pair: (
            sync_order.get(str((pair[1] or {}).get("object_type") or "").strip().lower(), 999),
            pair[0],
        )
    )

    results: List[Dict[str, Any]] = []
    for _, item in indexed_items:
        obj_type = str((item or {}).get("object_type") or "").strip().lower()
        key = _norm_text((item or {}).get("key"))
        name = _norm_text((item or {}).get("name")) or key

        if obj_type not in OBJECT_TYPE_META:
            results.append(
                {
                    "object_type": obj_type,
                    "key": key,
                    "name": name,
                    "status": "error",
                    "error": f"Unsupported object type '{obj_type}'",
                }
            )
            continue

        if not key:
            results.append(
                {
                    "object_type": obj_type,
                    "key": key,
                    "name": name,
                    "status": "error",
                    "error": "Item key is required",
                }
            )
            continue

        try:
            if obj_type == "region":
                action = _sync_region(src, dst, key)
            elif obj_type == "site":
                action = _sync_site(src, dst, key)
            elif obj_type == "device_type":
                action = _sync_device_type(src, dst, key)
            else:
                action = _sync_device(src, dst, key)
            results.append(
                {
                    "object_type": obj_type,
                    "key": key,
                    "name": name,
                    "status": "ok",
                    "action": action,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "object_type": obj_type,
                    "key": key,
                    "name": name,
                    "status": "error",
                    "error": str(exc),
                }
            )

    return results
