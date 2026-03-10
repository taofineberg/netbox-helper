"""Helpers for NetBox Branching plugin discovery and branch creation."""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests


BRANCH_ENDPOINT_CANDIDATES = (
    "plugins/branching/branches",
    "plugins/netbox_branching/branches",
    "plugins/netbox-branching/branches",
)


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _instance_verify(instance: Dict[str, Any]) -> Any:
    verify = instance.get("verify")
    if verify is not None:
        return verify
    return not _to_bool(instance.get("skip_ssl_verify", False))


def _base_url(instance: Dict[str, Any]) -> str:
    return _clean_str(instance.get("url")).rstrip("/")


def _token(instance: Dict[str, Any]) -> str:
    return _clean_str(instance.get("token"))


def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
    }


def detect_branch_endpoint(instance: Dict[str, Any], timeout: int = 20) -> str:
    """Return the first reachable branch endpoint path (without /api prefix)."""
    base = _base_url(instance)
    token = _token(instance)
    if not base:
        raise ValueError("Instance URL is required")
    if not token:
        raise ValueError("Instance token is required")

    last_error = ""
    for endpoint in BRANCH_ENDPOINT_CANDIDATES:
        url = f"{base}/api/{endpoint}/?limit=1"
        try:
            resp = requests.get(url, headers=_headers(token), verify=_instance_verify(instance), timeout=timeout)
        except Exception as exc:
            last_error = str(exc)
            continue

        if resp.status_code == 200:
            return endpoint
        if resp.status_code == 401:
            raise ValueError(f"Authentication failed for {base} while probing branch API")
        if resp.status_code == 403:
            raise ValueError(f"Branch API denied access on {base} ({endpoint})")
        if resp.status_code == 404:
            continue
        body = (resp.text or "")[:250]
        last_error = f"{resp.status_code} {body}"

    if last_error:
        raise ValueError(f"NetBox branching API not available on {base}: {last_error}")
    raise ValueError(f"NetBox branching API not available on {base}")


def _find_branch(
    instance: Dict[str, Any],
    branch_name: str,
    endpoint: str,
    timeout: int = 20,
) -> Optional[Dict[str, Any]]:
    wanted = _clean_str(branch_name)
    if not wanted:
        return None

    base = _base_url(instance)
    token = _token(instance)
    verify = _instance_verify(instance)
    if not base or not token:
        return None

    params_list = (
        {"name": wanted, "limit": 100},
        {"q": wanted, "limit": 100},
        {"limit": 100},
    )
    wanted_l = wanted.lower()
    for params in params_list:
        resp = requests.get(
            f"{base}/api/{endpoint}/",
            headers=_headers(token),
            params=params,
            verify=verify,
            timeout=timeout,
        )
        if resp.status_code == 401:
            raise ValueError(f"Authentication failed for {base} while checking branch '{wanted}'")
        if resp.status_code != 200:
            body = (resp.text or "")[:250]
            raise ValueError(f"GET {endpoint}: {resp.status_code} {body}")

        payload = resp.json() if resp.content else {}
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(rows, list):
            rows = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_name = _clean_str(row.get("name"))
            row_schema_id = _clean_str(row.get("schema_id"))
            row_id = _clean_str(row.get("id"))
            if (
                row_name == wanted
                or row_name.lower() == wanted_l
                or row_schema_id == wanted
                or row_schema_id.lower() == wanted_l
                or row_id == wanted
            ):
                return row
    return None


def ensure_branch_exists(instance: Dict[str, Any], branch_name: str, timeout: int = 20) -> Dict[str, Any]:
    """Create destination branch if needed and return branch metadata."""
    wanted = _clean_str(branch_name)
    if not wanted:
        raise ValueError("Branch name is required")

    base = _base_url(instance)
    token = _token(instance)
    if not base:
        raise ValueError("Instance URL is required")
    if not token:
        raise ValueError("Instance token is required")

    endpoint = detect_branch_endpoint(instance, timeout=timeout)
    existing = _find_branch(instance, wanted, endpoint, timeout=timeout)
    if existing:
        return {
            "name": _clean_str(existing.get("name")) or wanted,
            "id": existing.get("id"),
            "schema_id": _clean_str(existing.get("schema_id")),
            "endpoint": endpoint,
            "created": False,
            "exists": True,
        }

    verify = _instance_verify(instance)
    resp = requests.post(
        f"{base}/api/{endpoint}/",
        headers={**_headers(token), "Content-Type": "application/json"},
        json={"name": wanted},
        verify=verify,
        timeout=timeout,
    )
    if resp.status_code in {200, 201}:
        data = resp.json() if resp.content else {}
        return {
            "name": _clean_str(data.get("name")) or wanted,
            "id": data.get("id"),
            "schema_id": _clean_str(data.get("schema_id")),
            "endpoint": endpoint,
            "created": True,
            "exists": True,
        }

    # Handle race/duplicate semantics from plugin by re-checking once.
    if resp.status_code in {400, 409}:
        existing = _find_branch(instance, wanted, endpoint, timeout=timeout)
        if existing:
            return {
                "name": _clean_str(existing.get("name")) or wanted,
                "id": existing.get("id"),
                "schema_id": _clean_str(existing.get("schema_id")),
                "endpoint": endpoint,
                "created": False,
                "exists": True,
            }

    body = (resp.text or "")[:350]
    raise ValueError(f"Failed to ensure branch '{wanted}' on {base}: {resp.status_code} {body}")


def list_branches(instance: Dict[str, Any], timeout: int = 20, limit: int = 500) -> Dict[str, Any]:
    """List branches from the detected branching endpoint."""
    base = _base_url(instance)
    token = _token(instance)
    if not base:
        raise ValueError("Instance URL is required")
    if not token:
        raise ValueError("Instance token is required")

    endpoint = detect_branch_endpoint(instance, timeout=timeout)
    verify = _instance_verify(instance)

    branches = []
    seen = set()
    offset = 0
    page_size = max(1, min(int(limit or 500), 500))

    while True:
        resp = requests.get(
            f"{base}/api/{endpoint}/",
            headers=_headers(token),
            params={"limit": page_size, "offset": offset},
            verify=verify,
            timeout=timeout,
        )
        if resp.status_code == 401:
            raise ValueError(f"Authentication failed for {base} while listing branches")
        if resp.status_code != 200:
            body = (resp.text or "")[:250]
            raise ValueError(f"GET {endpoint}: {resp.status_code} {body}")

        payload = resp.json() if resp.content else {}
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(rows, list):
            rows = []

        for row in rows:
            if not isinstance(row, dict):
                continue
            name = _clean_str(row.get("name"))
            if not name:
                continue
            row_id = _clean_str(row.get("id"))
            schema_id = _clean_str(row.get("schema_id"))
            key = (name.lower(), schema_id or row_id)
            if key in seen:
                continue
            seen.add(key)
            branches.append({
                "name": name,
                "id": row.get("id"),
                "schema_id": schema_id,
            })

        count = len(rows)
        if count < page_size:
            break
        offset += count
        if offset >= 5000:
            break

    branches.sort(key=lambda b: (str(b.get("name") or "").lower(), str(b.get("schema_id") or ""), str(b.get("id") or "")))
    return {"endpoint": endpoint, "branches": branches}


def _branch_header_candidates(row: Optional[Dict[str, Any]], fallback: str = "") -> list[str]:
    out: list[str] = []
    if isinstance(row, dict):
        for raw in (
            row.get("schema_id"),
            row.get("name"),
            row.get("id"),
        ):
            val = _clean_str(raw)
            if val and val not in out:
                out.append(val)
    fb = _clean_str(fallback)
    if fb and fb not in out:
        out.append(fb)
    return out


def _probe_branch_header_value(instance: Dict[str, Any], header_value: str, timeout: int = 20) -> Optional[bool]:
    """Best-effort probe for branch header compatibility.

    Returns:
      - True: looks valid for this NetBox instance
      - False: looks invalid
      - None: inconclusive (network/transient response)
    """
    base = _base_url(instance)
    token = _token(instance)
    candidate = _clean_str(header_value)
    if not base or not token or not candidate:
        return False

    try:
        resp = requests.get(
            f"{base}/api/dcim/sites/?limit=1",
            headers={**_headers(token), "X-NetBox-Branch": candidate},
            verify=_instance_verify(instance),
            timeout=timeout,
        )
    except Exception:
        return None

    if resp.status_code == 200:
        return True
    if resp.status_code == 401:
        raise ValueError(f"Authentication failed for {base} while validating branch header")
    if resp.status_code == 403:
        # Header likely accepted; token/user cannot list sites.
        return True

    body_l = str(resp.text or "").lower()
    if resp.status_code in {400, 404}:
        return False
    if resp.status_code >= 500 and (
        "schema_name" in body_l
        or ("branch" in body_l and "badrequest" in body_l)
        or ("x-netbox-branch" in body_l and "invalid" in body_l)
    ):
        return False

    return None


def resolve_branch_header_value(instance: Dict[str, Any], branch_ref: str, timeout: int = 20) -> str:
    """Resolve a user branch reference (name/id/schema_id) to header identifier."""
    wanted = _clean_str(branch_ref)
    if not wanted:
        return ""

    endpoint = detect_branch_endpoint(instance, timeout=timeout)
    row = _find_branch(instance, wanted, endpoint, timeout=timeout)
    if not row:
        # If not found, ensure by name and then resolve again from created row.
        info = ensure_branch_exists(instance, wanted, timeout=timeout)
        row = {
            "name": _clean_str(info.get("name")),
            "schema_id": _clean_str(info.get("schema_id")),
            "id": info.get("id"),
        }
        # Some NetBox Branching API variants return minimal create payloads.
        # Re-fetch by name to obtain schema_id/id needed for X-NetBox-Branch.
        if not _clean_str(row.get("schema_id")):
            try:
                refreshed = _find_branch(
                    instance,
                    _clean_str(info.get("name")) or wanted,
                    endpoint,
                    timeout=timeout,
                )
                if refreshed:
                    row = refreshed
            except Exception:
                pass

    candidates = _branch_header_candidates(row, fallback=wanted)
    if not candidates:
        return wanted

    # Prefer the first candidate (name-first), but validate when possible.
    first = candidates[0]
    inconclusive_fallback = ""
    for candidate in candidates:
        verdict = _probe_branch_header_value(instance, candidate, timeout=timeout)
        if verdict is True:
            return candidate
        if verdict is None and not inconclusive_fallback:
            inconclusive_fallback = candidate

    return inconclusive_fallback or first
