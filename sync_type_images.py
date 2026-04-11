#!/usr/bin/env python3
"""Post-sync image copier for NetBox device/module types.

This tool is intentionally separate from template sync. It copies image files from
source type objects and uploads them to matching type objects in destination.

Why separate:
- NetBox image fields (for example `front_image`) require multipart file upload.
- REST JSON sync cannot set these fields using plain URL/path strings.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import mimetypes
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings()


@dataclass
class Instance:
    url: str
    token: str
    verify: bool


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _make_key() -> bytes:
    secret = os.getenv("SECRET_KEY", "changeme_set_in_env")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def decrypt_token(stored: str) -> str:
    """Decrypt token values from instances.json that use the `enc:` format."""
    if not isinstance(stored, str) or not stored.startswith("enc:"):
        return stored
    try:
        key = _make_key()
        data = base64.urlsafe_b64decode(stored[4:])
        nonce, ct = data[:16], data[16:]
        blocks = (len(ct) + 31) // 32
        ks = b"".join(
            hmac.new(key, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest()
            for i in range(blocks)
        )
        pt = bytes(a ^ b for a, b in zip(ct, ks))
        return pt.decode("utf-8")
    except Exception:
        return stored


def load_instances(path: str) -> list[dict[str, Any]]:
    raw = json.loads(open(path, "r", encoding="utf-8").read())
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        if isinstance(raw.get("instances"), list):
            return raw["instances"]
        return [raw]
    return []


def resolve_instance(instances_file: str, selector: str) -> Instance:
    selector = str(selector or "").strip()
    if not selector:
        raise ValueError("instance selector cannot be empty")

    candidates = load_instances(instances_file)
    if not candidates:
        raise ValueError(f"No instances found in {instances_file}")

    for row in candidates:
        name = str(row.get("name", "")).strip()
        url = str(row.get("url", "")).strip().rstrip("/")
        if selector in {name, url}:
            token = decrypt_token(str(row.get("token", "")).strip())
            verify = not _to_bool(row.get("skip_ssl_verify", False))
            if not token:
                raise ValueError(f"No token available for instance '{selector}'")
            return Instance(url=url, token=token, verify=verify)

    raise ValueError(f"Instance '{selector}' not found in {instances_file}")


def api_get_all(inst: Instance, endpoint: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Token {inst.token}", "Accept": "application/json"}
    page_params = dict(params or {})
    if "limit" not in page_params:
        page_params["limit"] = 100
    if "offset" not in page_params:
        page_params["offset"] = 0

    results: list[dict[str, Any]] = []
    while True:
        r = requests.get(f"{inst.url}/api/{endpoint}/", headers=headers, params=page_params, verify=inst.verify, timeout=60)
        r.raise_for_status()
        payload = r.json() if r.content else {}
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(rows, list):
            rows = []
        results.extend(rows)

        if not payload.get("next"):
            break
        page_params["offset"] = int(page_params.get("offset", 0)) + len(rows)
        if len(rows) == 0:
            break

    return results


def extract_image_fields(obj: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("front_image", "rear_image", "image"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            out[key] = value.strip()
    return out


def make_media_url(base_url: str, value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if value.startswith("/"):
        return urljoin(base_url + "/", value)
    if value.startswith("media/"):
        return urljoin(base_url + "/", value)
    return urljoin(base_url + "/", f"media/{value}")


def download_image(inst: Instance, url: str) -> tuple[bytes, str]:
    headers = {"Authorization": f"Token {inst.token}", "Accept": "*/*"}
    r = requests.get(url, headers=headers, verify=inst.verify, timeout=30)
    r.raise_for_status()
    guessed = mimetypes.guess_type(url)[0] or "application/octet-stream"
    return r.content, guessed


def get_content_type_id_from_attachment(inst: Instance, obj_type_label: str) -> int | None:
    """Get content_type_id by fetching a sample attachment of the given type."""
    try:
        attachments = api_get_all(
            inst,
            "extras/image-attachments",
            params={"object_type": obj_type_label, "limit": 1},
        )
        if attachments and len(attachments) > 0:
            # Note: The API response shows object_type as a string like "dcim.devicetype"
            # but we might need to extract content_type_id if available
            # For now, we'll try to infer it from the response
            att = attachments[0]
            # Try common patterns
            if "content_type" in att and isinstance(att["content_type"], dict):
                return att["content_type"].get("id")
            if "content_type_id" in att:
                return att["content_type_id"]
    except Exception:
        pass
    return None


def sync_image_attachments(
    source: Instance,
    dest: Instance,
    src_obj_id: int,
    dst_obj_id: int,
    obj_type_label: str,
    obj_name: str,
    content_type_id: int,
    dry_run: bool,
) -> int:
    """Sync image attachments for a single device/module type.
    
    Returns the number of attachments synced.
    """
    actions = 0
    
    try:
        # Fetch attachments from source that are linked to this object
        # Use object_type filter instead of content_type_id (which requires elevated permissions)
        src_attachments = api_get_all(
            source,
            "extras/image-attachments",
            params={"object_type": obj_type_label, "object_id": src_obj_id, "limit": 100},
        )
        
        if not src_attachments:
            return actions
        
        print(f"    [attachments] found {len(src_attachments)} attachments for {obj_name}")
        
        # Get list of existing attachments on destination
        dst_attachments = api_get_all(
            dest,
            "extras/image-attachments",
            params={"object_type": obj_type_label, "object_id": dst_obj_id, "limit": 100},
        )
        dst_names = {a.get("name", ""): a for a in dst_attachments if a.get("name")}
        
        for src_att in src_attachments:
            att_name = src_att.get("name", f"attachment-{src_att.get('id')}")
            att_desc = src_att.get("description", "")
            att_image_url = src_att.get("image", {})
            
            if isinstance(att_image_url, dict):
                att_image_url = att_image_url.get("name", "")
            
            if not att_image_url:
                continue
            
            # Skip if already exists on destination with same name
            if att_name in dst_names:
                print(f"    [attachment] {obj_name}: {att_name} (already exists)")
                continue
            
            media_url = make_media_url(source.url, att_image_url)
            print(f"    [attachment] {obj_name}: {att_name} <= {media_url}")
            actions += 1
            
            if dry_run:
                continue
            
            try:
                content, content_type = download_image(source, media_url)
                
                # Prepare upload data
                files = {
                    "image": (att_image_url.split("/")[-1], content, content_type)
                }
                data = {
                    "object_type": obj_type_label,
                    "object_id": dst_obj_id,
                    "name": att_name,
                    "description": att_desc,
                }
                
                # If we have content_type_id, use it for compatibility
                if content_type_id:
                    data["content_type_id"] = content_type_id
                
                headers = {"Authorization": f"Token {dest.token}"}
                r = requests.post(
                    f"{dest.url}/api/extras/image-attachments/",
                    files=files,
                    data=data,
                    headers=headers,
                    verify=dest.verify,
                    timeout=30,
                )
                r.raise_for_status()
            except Exception as exc:
                print(f"      ! failed: {exc}")
    
    except Exception as exc:
        print(f"    ! error fetching attachments: {exc}")
    
    return actions


def download_image(inst: Instance, url: str) -> tuple[bytes, str]:
    headers = {"Authorization": f"Token {inst.token}", "Accept": "*/*"}
    r = requests.get(url, headers=headers, verify=inst.verify, timeout=120)
    r.raise_for_status()
    content_type = r.headers.get("Content-Type") or "application/octet-stream"
    return r.content, content_type


def get_content_type_id(inst: Instance, app: str, model: str) -> int | None:
    """Get the content type ID for a model by fetching an existing attachment."""
    try:
        headers = {"Authorization": f"Token {inst.token}", "Accept": "application/json"}
        
        # Fetch any image attachments to extract the content_type_id
        r = requests.get(
            f"{inst.url}/api/extras/image-attachments/",
            headers=headers,
            params={"limit": 1},
            verify=inst.verify,
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        
        if data.get("results") and len(data["results"]) > 0:
            ct_id = data["results"][0].get("content_type")
            if isinstance(ct_id, dict):
                ct_id = ct_id.get("id")
            if ct_id:
                print(f"Debug: Inferred content-type ID {ct_id} from existing attachment")
                return int(ct_id)
    
    except Exception as e:
        print(f"Warning: Could not infer content-type ID: {e}")
    
    # Fallback: try standard endpoints
    try:
        headers = {"Authorization": f"Token {inst.token}", "Accept": "application/json"}
        r = requests.get(
            f"{inst.url}/api/extras/content-types/",
            headers=headers,
            params={"app": app, "model": model},
            verify=inst.verify,
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("results") and len(data["results"]) > 0:
            return int(data["results"][0].get("id"))
    except Exception:
        pass
    
    print(f"Debug: No content-type found for {app}.{model}")
    return None


def patch_image(inst: Instance, endpoint: str, obj_id: int, field: str, filename: str, content: bytes, content_type: str) -> None:
    headers = {"Authorization": f"Token {inst.token}", "Accept": "application/json"}
    files = {field: (filename, content, content_type)}
    r = requests.patch(f"{inst.url}/api/{endpoint}/{obj_id}/", headers=headers, files=files, verify=inst.verify, timeout=120)
    r.raise_for_status()


def map_device_types(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        slug = str(row.get("slug", "")).strip()
        if slug:
            out[slug] = row
    return out


def map_module_types(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        model = str(row.get("model", "")).strip()
        mfr = str((row.get("manufacturer") or {}).get("slug", "")).strip()
        if model and mfr:
            out[(mfr, model)] = row
    return out


def sync_type_images(source: Instance, dest: Instance, sync_device_types: bool, sync_module_types: bool, dry_run: bool) -> int:
    actions = 0

    type_specs = []
    if sync_device_types:
        type_specs.append(("dcim/device-types", "device", "dcim", "devicetype"))
    if sync_module_types:
        type_specs.append(("dcim/module-types", "module", "dcim", "moduletype"))

    for endpoint, label, app, model in type_specs:
        src_rows = api_get_all(source, endpoint)
        dst_rows = api_get_all(dest, endpoint)

        if endpoint == "dcim/device-types":
            src_map = map_device_types(src_rows)
            dst_map = map_device_types(dst_rows)
            keys = sorted(set(src_map.keys()) & set(dst_map.keys()))
        else:
            src_map = map_module_types(src_rows)
            dst_map = map_module_types(dst_rows)
            keys = sorted(set(src_map.keys()) & set(dst_map.keys()))

        print(f"[{label}] matched types: {len(keys)}")

        # Get content type ID from SOURCE (for reference, though not strictly needed now)
        # Since we now use object_type directly, this is informational only
        content_type_id = get_content_type_id(source, app, model)
        if content_type_id:
            print(f"[{label}] content-type ID: {content_type_id}")
        else:
            print(f"[{label}] warning: could not retrieve content-type ID (expected if endpoint not available)")

        for key in keys:
            src_obj = src_map[key]
            dst_obj = dst_map[key]
            src_images = extract_image_fields(src_obj)
            
            obj_name = src_obj.get("slug") or src_obj.get("model") or str(src_obj.get("id"))
            src_obj_id = int(src_obj["id"])
            dst_obj_id = int(dst_obj["id"])

            # Sync front_image and rear_image fields
            if src_images:
                for field, value in src_images.items():
                    if not value:
                        continue
                    media_url = make_media_url(source.url, value)
                    parsed = urlparse(media_url)
                    filename = os.path.basename(parsed.path) or f"{obj_name}-{field}"
                    guessed = mimetypes.guess_type(filename)[0] or "application/octet-stream"

                    print(f"  - {obj_name}: {field} <= {media_url}")
                    actions += 1
                    if dry_run:
                        continue

                    try:
                        content, content_type_header = download_image(source, media_url)
                        patch_image(dest, endpoint, dst_obj_id, field, filename, content, content_type_header or guessed)
                    except Exception as exc:
                        print(f"    ! failed: {exc}")
            
            # Sync image attachments (now uses object_type instead of content_type_id)
            att_actions = sync_image_attachments(
                source,
                dest,
                src_obj_id,
                dst_obj_id,
                f"{app}.{model}",
                obj_name,
                content_type_id,
                dry_run,
            )
            actions += att_actions

    return actions


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Copy NetBox type images after template sync")
    p.add_argument("--source-url", default="", help="Source NetBox base URL")
    p.add_argument("--source-token", default="", help="Source NetBox API token")
    p.add_argument("--source-verify", default="true", help="Source SSL verify (true/false)")
    p.add_argument("--dest-url", default="", help="Destination NetBox base URL")
    p.add_argument("--dest-token", default="", help="Destination NetBox API token")
    p.add_argument("--dest-verify", default="true", help="Destination SSL verify (true/false)")

    p.add_argument("--instances-file", default="template-sync/instances.json")
    p.add_argument("--source-instance", default="", help="Source instance name or URL from instances file")
    p.add_argument("--dest-instance", default="", help="Destination instance name or URL from instances file")

    p.add_argument("--device-types", action="store_true", help="Sync device type images only")
    p.add_argument("--module-types", action="store_true", help="Sync module type images only")
    p.add_argument("--dry-run", action="store_true", help="Print planned actions without uploading")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.source_instance and args.dest_instance:
        source = resolve_instance(args.instances_file, args.source_instance)
        dest = resolve_instance(args.instances_file, args.dest_instance)
    else:
        if not args.source_url or not args.source_token or not args.dest_url or not args.dest_token:
            raise SystemExit("Provide either --source-instance/--dest-instance or explicit --source-url/token and --dest-url/token")
        source = Instance(url=args.source_url.rstrip("/"), token=args.source_token, verify=_to_bool(args.source_verify))
        dest = Instance(url=args.dest_url.rstrip("/"), token=args.dest_token, verify=_to_bool(args.dest_verify))

    sync_device = args.device_types or (not args.device_types and not args.module_types)
    sync_module = args.module_types or (not args.device_types and not args.module_types)

    print(f"source={source.url}")
    print(f"dest={dest.url}")
    print(f"sync_device_types={sync_device} sync_module_types={sync_module} dry_run={args.dry_run}")

    actions = sync_type_images(source, dest, sync_device, sync_module, args.dry_run)
    print(f"done actions={actions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
