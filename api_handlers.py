"""
Netbox API Handlers
Handles all API interactions with Netbox for different resource types
"""

import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Any
import ipaddress
import pynetbox

logger = logging.getLogger(__name__)


class NetboxAPIHandler:
    """Handles API interactions with Netbox"""
    
    def __init__(self, netbox_api: pynetbox.api):
        self.api = netbox_api
        # Cache hot lookup reads (site/rack/device/interface/role etc.) to
        # avoid repeated GET calls during large imports.
        try:
            cache_size = int(os.getenv('NBH_LOOKUP_CACHE_MAX', '20000'))
        except Exception:
            cache_size = 20000
        self._lookup_cache_max = max(1000, cache_size)
        self._lookup_cache: "OrderedDict[Any, Any]" = OrderedDict()
        self._lookup_cache_lock = threading.Lock()
        self._cache_miss = object()

    def _normalize_cache_value(self, value: Any) -> Any:
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        if isinstance(value, (list, tuple, set)):
            return tuple(self._normalize_cache_value(v) for v in value)
        if isinstance(value, dict):
            return tuple((str(k), self._normalize_cache_value(v)) for k, v in sorted(value.items(), key=lambda p: str(p[0])))
        obj_id = getattr(value, 'id', None)
        if isinstance(obj_id, (str, int)):
            return ('id', obj_id)
        return str(value)

    def _lookup_cache_key(self, endpoint: Any, kwargs: Dict[str, Any]) -> Optional[Any]:
        if not kwargs:
            return None
        endpoint_url = str(getattr(endpoint, 'url', '') or '').strip()
        if not endpoint_url:
            return None
        items = tuple(
            (str(k), self._normalize_cache_value(kwargs[k]))
            for k in sorted(kwargs.keys(), key=str)
        )
        return (endpoint_url, items)

    def _lookup_cache_get(self, key: Any) -> Any:
        if key is None:
            return self._cache_miss
        with self._lookup_cache_lock:
            value = self._lookup_cache.get(key, self._cache_miss)
            if value is not self._cache_miss:
                self._lookup_cache.move_to_end(key)
            return value

    def _lookup_cache_set(self, key: Any, value: Any):
        if key is None:
            return
        with self._lookup_cache_lock:
            self._lookup_cache[key] = value
            self._lookup_cache.move_to_end(key)
            while len(self._lookup_cache) > self._lookup_cache_max:
                self._lookup_cache.popitem(last=False)
        
    def get_or_none(self, endpoint, **kwargs):
        """Get an object or return None if not found"""
        cache_key = self._lookup_cache_key(endpoint, kwargs)
        cached = self._lookup_cache_get(cache_key)
        if cached is not self._cache_miss:
            return cached

        try:
            result = endpoint.get(**kwargs)
            # Cache hits only; avoid caching None so newly-created objects
            # can be discovered immediately without stale misses.
            if result is not None:
                self._lookup_cache_set(cache_key, result)
            return result
        except pynetbox.RequestError:
            return None
        except ValueError:
            # pynetbox raises ValueError when .get() returns more than one result.
            # Fall back to filter() and return the first match.
            results = list(endpoint.filter(**kwargs))
            return results[0] if results else None

    def _get_or_create_safe(self, endpoint, create_data: dict, dry_run: bool = False, **lookup_kwargs):
        """Get or create an object, safe for concurrent use.

        If two threads race to create the same object, one will succeed and the
        other will hit a duplicate error — we then fall back to a fresh lookup.
        """
        obj = self.get_or_none(endpoint, **lookup_kwargs)
        if obj is None and not dry_run:
            try:
                obj = endpoint.create(create_data)
            except Exception:
                # Another thread may have won the race — retry the lookup
                obj = self.get_or_none(endpoint, **lookup_kwargs)
        return obj

    def _missing_required_message(self, import_type: str, row: Dict[str, str], required: List[str]) -> str:
        missing = [f for f in required if not str(row.get(f, '') or '').strip()]
        context_keys = [
            'name', 'site', 'slug', 'device', 'device_type', 'role', 'power_panel',
            'module_bay', 'module_type', 'prefix', 'address'
        ]
        context_parts = []
        for key in context_keys:
            if key in row:
                raw = str(row.get(key, '') or '').strip()
                context_parts.append(f'{key}="{raw or "<empty>"}"')
        if not context_parts:
            keys = sorted([str(k) for k in row.keys()])[:12]
            context_parts.append(f'available_columns={keys}')
        return (
            f'Missing required field(s) for {import_type}: {", ".join(missing)}. '
            f'Row context: {", ".join(context_parts)}'
        )

    def _normalize_prefix(self, raw_prefix: str) -> str:
        value = str(raw_prefix or '').strip()
        if not value:
            return ''
        network = ipaddress.ip_network(value, strict=False)
        return network.with_prefixlen

    def _normalize_interface_address(self, raw_address: str) -> str:
        value = str(raw_address or '').strip()
        if not value:
            return ''
        iface = ipaddress.ip_interface(value)
        return iface.with_prefixlen

    def _is_unassignable_interface_address(self, raw_address: str) -> bool:
        value = str(raw_address or '').strip()
        if not value:
            return False
        iface = ipaddress.ip_interface(value)
        network = iface.network
        ip = iface.ip
        if ip == network.network_address:
            return True
        if isinstance(ip, ipaddress.IPv4Address) and network.prefixlen <= 30 and ip == network.broadcast_address:
            return True
        return False

    def _record_vrf_id(self, rec: Any) -> Optional[int]:
        try:
            vrf = getattr(rec, 'vrf', None)
            if isinstance(vrf, dict):
                rid = vrf.get('id')
                return int(rid) if rid is not None else None
            rid = getattr(vrf, 'id', None)
            return int(rid) if rid is not None else None
        except Exception:
            return None

    def _find_existing_ip(self, address: str, vrf_id: Optional[int]) -> Optional[Any]:
        try:
            rows = list(self.api.ipam.ip_addresses.filter(address=address, limit=100))
        except Exception:
            rows = []

        if not rows:
            return None

        if vrf_id is None:
            for rec in rows:
                if self._record_vrf_id(rec) is None:
                    return rec
            return rows[0]

        for rec in rows:
            if self._record_vrf_id(rec) == int(vrf_id):
                return rec
        return None

    def _compact_text(self, value: Any, max_len: int = 500) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."

    def _format_exception_detail(self, exc: Exception) -> str:
        if isinstance(exc, pynetbox.RequestError):
            req = getattr(exc, "req", None)
            status = getattr(req, "status_code", None)
            reason = getattr(req, "reason", "")

            detail = str(getattr(exc, "error", "") or "").strip()
            if detail:
                try:
                    detail = json.dumps(json.loads(detail), separators=(",", ":"))
                except Exception:
                    pass

            payload = getattr(exc, "request_body", None)
            payload_str = self._compact_text(payload, max_len=500) if payload else ""
            detail_str = self._compact_text(detail, max_len=800) if detail else ""

            parts = []
            if status is not None:
                parts.append(f"NetBox API {status} {reason}".strip())
            if detail_str:
                parts.append(f"response={detail_str}")
            if payload_str:
                parts.append(f"payload={payload_str}")
            if parts:
                return "; ".join(parts)
        return str(exc)

    def _is_portmapping_fk_create_error(self, exc: Exception) -> bool:
        text = str(exc or '')
        markers = (
            'dcim_portmapping',
            'fk_dcim_device_id',
            'foreign key constraint',
            'device_id',
        )
        if all(m in text for m in markers):
            return True
        # Some environments wrap the DB error behind requests RetryError.
        return (
            'too many 500 error responses' in text
            and '/api/dcim/devices/' in text
        )

    def _pick_surrogate_device_profile(
        self,
        site_id: int,
        target_device_type_id: Optional[int],
        target_role_id: Optional[int],
    ) -> Optional[Dict[str, int]]:
        # Prefer a profile from the same site to avoid invalid combinations.
        for dev in self.api.dcim.devices.filter(site_id=site_id):
            dev_type = getattr(getattr(dev, 'device_type', None), 'id', None)
            role = getattr(getattr(dev, 'role', None), 'id', None)
            if dev_type is None or role is None:
                continue
            if target_device_type_id and target_role_id and dev_type == target_device_type_id and role == target_role_id:
                continue
            return {'device_type': int(dev_type), 'role': int(role)}

        # Fallback: any existing device profile if site has none.
        for dev in self.api.dcim.devices.filter(limit=200):
            dev_type = getattr(getattr(dev, 'device_type', None), 'id', None)
            role = getattr(getattr(dev, 'role', None), 'id', None)
            if dev_type is None or role is None:
                continue
            if target_device_type_id and target_role_id and dev_type == target_device_type_id and role == target_role_id:
                continue
            return {'device_type': int(dev_type), 'role': int(role)}
        return None

    def _template_value(self, obj: Any, attr: str, default: Any = None) -> Any:
        try:
            raw = getattr(obj, attr, default)
        except Exception:
            raw = default
        if raw is None:
            return default
        if isinstance(raw, dict):
            if 'value' in raw and raw.get('value') is not None:
                return raw.get('value')
            if 'id' in raw and raw.get('id') is not None:
                return raw.get('id')
            if 'name' in raw and raw.get('name') is not None:
                return raw.get('name')
            return default
        if hasattr(raw, 'value'):
            return getattr(raw, 'value', default)
        if hasattr(raw, 'id'):
            return getattr(raw, 'id', default)
        return raw

    def _sync_device_components_from_type(
        self,
        device: Any,
        target_device_type_id: Optional[int],
    ) -> Dict[str, Any]:
        """
        Rebuild template-derived component instances for a device.

        Needed for environments where a create fallback uses a surrogate type first
        and then patches to target type (NetBox does not backfill all components on
        type change).
        """
        stats: Dict[str, Any] = {
            'deleted': 0,
            'power_ports': 0,
            'power_outlets': 0,
            'rear_ports': 0,
            'front_ports': 0,
            'module_bays': 0,
            'duration_seconds': 0.0,
        }
        started = time.monotonic()
        if not device or not target_device_type_id:
            stats['duration_seconds'] = round(time.monotonic() - started, 3)
            return stats

        dcim = self.api.dcim
        dev_id = getattr(device, 'id', None)
        if not dev_id:
            stats['duration_seconds'] = round(time.monotonic() - started, 3)
            return stats

        # Remove existing template-derived component types first.
        delete_order = [
            ('front_ports', {}),
            ('rear_ports', {}),
            ('power_outlets', {}),
            ('power_ports', {}),
            ('module_bays', {}),
        ]
        for endpoint_name, filt in delete_order:
            endpoint = getattr(dcim, endpoint_name, None)
            if endpoint is None:
                continue
            try:
                for rec in endpoint.filter(device_id=dev_id, **filt):
                    try:
                        rec.delete()
                        stats['deleted'] += 1
                    except Exception:
                        logger.debug(
                            'Failed deleting %s component id=%s',
                            endpoint_name,
                            getattr(rec, 'id', None),
                            exc_info=True,
                        )
            except Exception:
                logger.debug('Failed listing existing %s for device %s', endpoint_name, dev_id, exc_info=True)

        def _template_id(obj: Any) -> int:
            raw = self._template_value(obj, 'id', 0)
            try:
                return int(raw or 0)
            except Exception:
                return 0

        def _record_id(obj: Any) -> Optional[int]:
            raw = self._template_value(obj, 'id', None)
            try:
                return int(raw) if raw is not None else None
            except Exception:
                return None

        def _safe_templates(endpoint_name: str) -> List[Any]:
            endpoint = getattr(dcim, endpoint_name, None)
            if endpoint is None:
                return []
            try:
                return list(endpoint.filter(device_type_id=target_device_type_id))
            except Exception:
                logger.debug('%s template fetch failed for device %s', endpoint_name, dev_id, exc_info=True)
                return []

        def _bulk_create(endpoint: Any, payloads: List[Dict[str, Any]], label: str) -> List[Any]:
            if endpoint is None or not payloads:
                return []
            # Use NetBox bulk create when available; fallback to per-record on failure.
            try:
                request_payload: Any = payloads if len(payloads) > 1 else payloads[0]
                created = endpoint.create(request_payload)
                if created is None:
                    return []
                if isinstance(created, list):
                    return [item for item in created if item is not None]
                return [created]
            except Exception:
                if len(payloads) > 1:
                    logger.debug('%s bulk create failed; retrying per-record', label, exc_info=True)
                records: List[Any] = []
                for payload in payloads:
                    try:
                        rec = endpoint.create(payload)
                        if rec is not None:
                            records.append(rec)
                    except Exception:
                        logger.debug(
                            '%s create failed for payload name=%s',
                            label,
                            str(payload.get('name', '') or ''),
                            exc_info=True,
                        )
                return records

        def _map_created_records(templates: List[Any], created: List[Any], key_fields: List[str]) -> Dict[int, Any]:
            # Match created objects back to templates so dependent payloads can refer to new IDs.
            index: Dict[tuple, List[Any]] = {}
            for rec in created:
                key = tuple(str(self._template_value(rec, fld, '') or '') for fld in key_fields)
                index.setdefault(key, []).append(rec)

            mapped: Dict[int, Any] = {}
            for tmpl in templates:
                tid = _template_id(tmpl)
                if not tid:
                    continue
                key = tuple(str(self._template_value(tmpl, fld, '') or '') for fld in key_fields)
                bucket = index.get(key) or []
                if bucket:
                    mapped[tid] = bucket.pop(0)
            return mapped

        # Power ports from templates
        power_port_map: Dict[int, Any] = {}
        try:
            pp_templates = _safe_templates('power_port_templates')
            pp_payloads: List[Dict[str, Any]] = []
            for tmpl in pp_templates:
                payload = {
                    'device': dev_id,
                    'name': str(self._template_value(tmpl, 'name', '') or ''),
                }
                tval = self._template_value(tmpl, 'type')
                if tval:
                    payload['type'] = tval
                for fld in ('maximum_draw', 'allocated_draw', 'label', 'description'):
                    v = self._template_value(tmpl, fld)
                    if v not in (None, ''):
                        payload[fld] = v
                pp_payloads.append(payload)

            pp_created = _bulk_create(getattr(dcim, 'power_ports', None), pp_payloads, 'Power-port template rebuild')
            power_port_map = _map_created_records(pp_templates, pp_created, ['name', 'type'])
            stats['power_ports'] = len(pp_created)
        except Exception:
            logger.debug('Power-port template rebuild failed for device %s', dev_id, exc_info=True)

        # Power outlets from templates (map to created power ports)
        try:
            po_templates = _safe_templates('power_outlet_templates')
            po_payloads: List[Dict[str, Any]] = []
            for tmpl in po_templates:
                payload = {
                    'device': dev_id,
                    'name': str(self._template_value(tmpl, 'name', '') or ''),
                }
                tval = self._template_value(tmpl, 'type')
                if tval:
                    payload['type'] = tval
                pp_tmpl_id = self._template_value(tmpl, 'power_port')
                try:
                    pp_tmpl_id = int(pp_tmpl_id) if pp_tmpl_id not in (None, '') else None
                except Exception:
                    pp_tmpl_id = None
                if pp_tmpl_id:
                    mapped = power_port_map.get(pp_tmpl_id)
                    mapped_id = _record_id(mapped)
                    if mapped_id:
                        payload['power_port'] = mapped_id
                feed_leg = self._template_value(tmpl, 'feed_leg')
                if feed_leg not in (None, ''):
                    payload['feed_leg'] = feed_leg
                for fld in ('label', 'description'):
                    v = self._template_value(tmpl, fld)
                    if v not in (None, ''):
                        payload[fld] = v
                po_payloads.append(payload)

            po_created = _bulk_create(getattr(dcim, 'power_outlets', None), po_payloads, 'Power-outlet template rebuild')
            stats['power_outlets'] = len(po_created)
        except Exception:
            logger.debug('Power-outlet template rebuild failed for device %s', dev_id, exc_info=True)

        # Rear ports first
        rear_port_map: Dict[int, Any] = {}
        try:
            rp_templates = _safe_templates('rear_port_templates')
            rp_payloads: List[Dict[str, Any]] = []
            for tmpl in rp_templates:
                payload = {
                    'device': dev_id,
                    'name': str(self._template_value(tmpl, 'name', '') or ''),
                }
                tval = self._template_value(tmpl, 'type')
                if tval:
                    payload['type'] = tval
                positions = self._template_value(tmpl, 'positions')
                if positions not in (None, ''):
                    payload['positions'] = int(positions)
                for fld in ('label', 'description'):
                    v = self._template_value(tmpl, fld)
                    if v not in (None, ''):
                        payload[fld] = v
                rp_payloads.append(payload)

            rp_created = _bulk_create(getattr(dcim, 'rear_ports', None), rp_payloads, 'Rear-port template rebuild')
            rear_port_map = _map_created_records(rp_templates, rp_created, ['name', 'type', 'positions'])
            stats['rear_ports'] = len(rp_created)
        except Exception:
            logger.debug('Rear-port template rebuild failed for device %s', dev_id, exc_info=True)

        # Then front ports mapped to rear ports
        try:
            fp_templates = _safe_templates('front_port_templates')
            fp_payloads: List[Dict[str, Any]] = []
            for tmpl in fp_templates:
                payload = {
                    'device': dev_id,
                    'name': str(self._template_value(tmpl, 'name', '') or ''),
                }
                tval = self._template_value(tmpl, 'type')
                if tval:
                    payload['type'] = tval
                rear_tmpl_id = self._template_value(tmpl, 'rear_port')
                try:
                    rear_tmpl_id = int(rear_tmpl_id) if rear_tmpl_id not in (None, '') else None
                except Exception:
                    rear_tmpl_id = None
                if rear_tmpl_id:
                    mapped = rear_port_map.get(rear_tmpl_id)
                    mapped_id = _record_id(mapped)
                    if mapped_id:
                        payload['rear_port'] = mapped_id
                rear_pos = self._template_value(tmpl, 'rear_port_position')
                if rear_pos not in (None, ''):
                    payload['rear_port_position'] = int(rear_pos)
                for fld in ('label', 'description'):
                    v = self._template_value(tmpl, fld)
                    if v not in (None, ''):
                        payload[fld] = v
                fp_payloads.append(payload)

            fp_created = _bulk_create(getattr(dcim, 'front_ports', None), fp_payloads, 'Front-port template rebuild')
            stats['front_ports'] = len(fp_created)
        except Exception:
            logger.debug('Front-port template rebuild failed for device %s', dev_id, exc_info=True)

        # Module bays
        try:
            mb_templates = _safe_templates('module_bay_templates')
            mb_payloads: List[Dict[str, Any]] = []
            for tmpl in mb_templates:
                payload = {
                    'device': dev_id,
                    'name': str(self._template_value(tmpl, 'name', '') or ''),
                }
                for fld in ('label', 'description'):
                    v = self._template_value(tmpl, fld)
                    if v not in (None, ''):
                        payload[fld] = v
                mb_payloads.append(payload)

            mb_created = _bulk_create(getattr(dcim, 'module_bays', None), mb_payloads, 'Module-bay template rebuild')
            stats['module_bays'] = len(mb_created)
        except Exception:
            logger.debug('Module-bay template rebuild failed for device %s', dev_id, exc_info=True)
        stats['duration_seconds'] = round(time.monotonic() - started, 3)
        return stats

    def import_sites(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a site into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            name = row.get('name', '').strip()
            if not name:
                result['message'] = self._missing_required_message('site', row, ['name'])
                return result
                
            # Check if site exists
            existing = self.get_or_none(self.api.dcim.sites, name=name)
            
            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Site "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Prepare data
            data = {
                'name': name,
                'slug': row.get('slug', '').strip(),
                'status': row.get('status', 'active').strip(),
            }
            
            # Optional fields
            if row.get('region'):
                region = self.get_or_none(self.api.dcim.regions, name=row['region'].strip())
                if region:
                    data['region'] = region.id
                    
            if row.get('group'):
                group = self.get_or_none(self.api.dcim.site_groups, name=row['group'].strip())
                if group:
                    data['group'] = group.id
                    
            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id
                    
            if row.get('facility'):
                data['facility'] = row['facility'].strip()
            if row.get('physical_address'):
                data['physical_address'] = row['physical_address'].strip()
            if row.get('latitude'):
                try:
                    data['latitude'] = float(row['latitude'].strip())
                except ValueError:
                    pass
            if row.get('longitude'):
                try:
                    data['longitude'] = float(row['longitude'].strip())
                except ValueError:
                    pass
            
            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} site "{name}"'
                logger.info(result['message'])
                logger.debug(f'Data: {data}')
                return result
            
            # Create or update
            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated site "{name}"'
            else:
                self.api.dcim.sites.create(data)
                result['success'] = True
                result['message'] = f'Created site "{name}"'
                
            logger.info(result['message'])
            
        except Exception as e:
            result['message'] = f'Error importing site: {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_locations(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a location into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            name = row.get('name', '').strip()
            site_name = row.get('site', '').strip()

            # Some exports include an empty location row; treat it as non-fatal.
            if not name:
                result['success'] = True
                result['action'] = 'skipped'
                result['message'] = 'Location name is blank (skipped)'
                logger.info(result['message'])
                return result

            if not site_name:
                result['message'] = self._missing_required_message('location', row, ['site'])
                return result
            
            # Get site
            site = self.get_or_none(self.api.dcim.sites, name=site_name)
            if not site:
                result['message'] = f'Site "{site_name}" not found'
                return result
            
            # Check if location exists
            existing = self.get_or_none(self.api.dcim.locations, name=name, site_id=site.id)
            
            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Location "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Prepare data
            data = {
                'name': name,
                'slug': row.get('slug', '').strip(),
                'site': site.id,
                'status': row.get('status', 'active').strip(),
            }
            
            if row.get('facility'):
                data['facility'] = row['facility'].strip()
            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id
            
            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} location "{name}"'
                logger.info(result['message'])
                return result
            
            # Create or update
            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated location "{name}"'
            else:
                self.api.dcim.locations.create(data)
                result['success'] = True
                result['message'] = f'Created location "{name}"'
                
            logger.info(result['message'])
            
        except Exception as e:
            result['message'] = f'Error importing location: {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_racks(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a rack into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            name = row.get('name', '').strip()
            site_name = row.get('site', '').strip()
            
            if not name or not site_name:
                result['message'] = self._missing_required_message('rack', row, ['name', 'site'])
                return result
            
            # Get site
            site = self.get_or_none(self.api.dcim.sites, name=site_name)
            if not site:
                result['message'] = f'Site "{site_name}" not found'
                return result
            
            # Check if rack exists
            existing = self.get_or_none(self.api.dcim.racks, name=name, site_id=site.id)
            
            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Rack "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Prepare data
            data = {
                'name': name,
                'site': site.id,
                'status': row.get('status', 'active').strip(),
            }
            
            if row.get('rack_type'):
                rack_type_name = row['rack_type'].strip()
                # Lookup rack type by model
                rack_type = self.get_or_none(self.api.dcim.rack_types, model=rack_type_name)
                if rack_type:
                    data['rack_type'] = rack_type.id
                else:
                    logger.warning(f'Rack type "{rack_type_name}" not found')
            
            if row.get('facility_id'):
                data['facility_id'] = row['facility_id'].strip()
            if row.get('location'):
                location = self.get_or_none(self.api.dcim.locations, name=row['location'].strip(), site_id=site.id)
                if location:
                    data['location'] = location.id
            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id
            if row.get('role'):
                role = self.get_or_none(self.api.dcim.rack_roles, name=row['role'].strip())
                if role:
                    data['role'] = role.id
            
            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} rack "{name}"'
                logger.info(result['message'])
                return result
            
            # Create or update
            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated rack "{name}"'
            else:
                self.api.dcim.racks.create(data)
                result['success'] = True
                result['message'] = f'Created rack "{name}"'
                
            logger.info(result['message'])
            
        except Exception as e:
            result['message'] = f'Error importing rack: {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_power_panels(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a power panel into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            name = row.get('name', '').strip()
            site_name = row.get('site', '').strip()
            
            if not name or not site_name:
                result['message'] = self._missing_required_message('power-panel', row, ['name', 'site'])
                return result
            
            # Get site
            site = self.get_or_none(self.api.dcim.sites, name=site_name)
            if not site:
                result['message'] = f'Site "{site_name}" not found'
                return result
            
            # Check if power panel exists
            existing = self.get_or_none(self.api.dcim.power_panels, name=name, site_id=site.id)
            
            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Power panel "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Prepare data
            data = {
                'name': name,
                'site': site.id,
            }
            
            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} power panel "{name}"'
                logger.info(result['message'])
                return result
            
            # Create or update
            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated power panel "{name}"'
            else:
                self.api.dcim.power_panels.create(data)
                result['success'] = True
                result['message'] = f'Created power panel "{name}"'
                
            logger.info(result['message'])
            
        except Exception as e:
            result['message'] = f'Error importing power panel: {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_devices(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a device into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            name = row.get('name', '').strip()
            site_name = row.get('site', '').strip()
            device_type_name = row.get('device_type', '').strip()
            role_name = row.get('role', '').strip()
            
            if not name or not site_name or not device_type_name or not role_name:
                result['message'] = self._missing_required_message(
                    'device', row, ['name', 'site', 'device_type', 'role']
                )
                return result
            
            # Get site
            site = self.get_or_none(self.api.dcim.sites, name=site_name)
            if not site:
                result['message'] = f'Site "{site_name}" not found'
                return result
            
            # Get or create manufacturer
            manufacturer_name = row.get('manufacturer', '').strip()
            if not manufacturer_name:
                result['message'] = self._missing_required_message('device', row, ['manufacturer'])
                return result

            manufacturer = self._get_or_create_safe(
                self.api.dcim.manufacturers,
                {'name': manufacturer_name, 'slug': manufacturer_name.lower().replace(' ', '-')},
                dry_run=dry_run,
                name=manufacturer_name,
            )

            # Get or create device type
            device_type = None
            if manufacturer:
                device_type = self._get_or_create_safe(
                    self.api.dcim.device_types,
                    {
                        'model': device_type_name,
                        'slug': device_type_name.lower().replace(' ', '-').replace('/', '-').replace('+', 'plus'),
                        'manufacturer': manufacturer.id,
                    },
                    dry_run=dry_run,
                    model=device_type_name,
                    manufacturer_id=manufacturer.id,
                )

            # Get or create device role
            role = self._get_or_create_safe(
                self.api.dcim.device_roles,
                {'name': role_name, 'slug': role_name.lower().replace(' ', '-'), 'color': '2196f3'},
                dry_run=dry_run,
                name=role_name,
            )
            
            # Check if device exists
            existing = self.get_or_none(self.api.dcim.devices, name=name, site_id=site.id)
            
            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Device "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Prepare data
            data = {
                'name': name,
                'site': site.id,
                'status': row.get('status', 'active').strip(),
            }
            
            if device_type:
                data['device_type'] = device_type.id
            if role:
                data['role'] = role.id
            
            if row.get('rack'):
                rack = self.get_or_none(self.api.dcim.racks, name=row['rack'].strip(), site_id=site.id)
                if rack:
                    data['rack'] = rack.id
                    if row.get('position'):
                        try:
                            data['position'] = int(row['position'].strip())
                        except ValueError:
                            pass
                    if row.get('face'):
                        data['face'] = row['face'].strip()
                        
            if row.get('location'):
                location = self.get_or_none(self.api.dcim.locations, name=row['location'].strip(), site_id=site.id)
                if location:
                    data['location'] = location.id
                    
            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id
            
            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} device "{name}"'
                logger.info(result['message'])
                return result
            
            # Create or update
            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated device "{name}"'
            else:
                try:
                    self.api.dcim.devices.create(data)
                    result['success'] = True
                    result['message'] = f'Created device "{name}"'
                except Exception as create_exc:
                    if not self._is_portmapping_fk_create_error(create_exc):
                        raise

                    existing_after = self.get_or_none(self.api.dcim.devices, name=name, site_id=site.id)
                    if existing_after:
                        for key, value in data.items():
                            setattr(existing_after, key, value)
                        existing_after.save()
                        sync_stats = self._sync_device_components_from_type(existing_after, data.get('device_type'))
                        result['success'] = True
                        result['message'] = (
                            f'Updated device "{name}" after transient portmapping create error '
                            f'(component rebuild {sync_stats.get("duration_seconds", 0):.1f}s)'
                        )
                    else:
                        surrogate = self._pick_surrogate_device_profile(
                            site_id=site.id,
                            target_device_type_id=data.get('device_type'),
                            target_role_id=data.get('role'),
                        )
                        if not surrogate:
                            raise

                        seed = {
                            'name': name,
                            'site': site.id,
                            'status': data.get('status', 'active'),
                            'device_type': surrogate['device_type'],
                            'role': surrogate['role'],
                        }
                        created = self.api.dcim.devices.create(seed)
                        try:
                            for key, value in data.items():
                                setattr(created, key, value)
                            created.save()
                            sync_stats = self._sync_device_components_from_type(created, data.get('device_type'))
                            result['success'] = True
                            result['message'] = (
                                f'Created device "{name}" using surrogate create fallback '
                                f'(component rebuild {sync_stats.get("duration_seconds", 0):.1f}s, '
                                f'deleted={int(sync_stats.get("deleted", 0) or 0)}, '
                                f'pp={int(sync_stats.get("power_ports", 0) or 0)}, '
                                f'po={int(sync_stats.get("power_outlets", 0) or 0)}, '
                                f'rear={int(sync_stats.get("rear_ports", 0) or 0)}, '
                                f'front={int(sync_stats.get("front_ports", 0) or 0)}, '
                                f'mod_bays={int(sync_stats.get("module_bays", 0) or 0)})'
                            )
                        except Exception:
                            try:
                                created.delete()
                            except Exception:
                                pass
                            raise
                
            logger.info(result['message'])
            
        except Exception as e:
            dev_name = str((row or {}).get('name', '') or '').strip() or '<unknown>'
            result['message'] = f'Error importing device "{dev_name}": {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_power_feeds(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a power feed into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            name = row.get('name', '').strip()
            site_name = row.get('site', '').strip()
            power_panel_name = row.get('power_panel', '').strip()
            
            if not name or not site_name or not power_panel_name:
                result['message'] = self._missing_required_message(
                    'power-feed', row, ['name', 'site', 'power_panel']
                )
                return result
            
            # Get site
            site = self.get_or_none(self.api.dcim.sites, name=site_name)
            if not site:
                result['message'] = f'Site "{site_name}" not found'
                return result
            
            # Get power panel
            power_panel = self.get_or_none(self.api.dcim.power_panels, name=power_panel_name, site_id=site.id)
            if not power_panel:
                result['message'] = f'Power panel "{power_panel_name}" not found'
                return result
            
            # Check if power feed exists
            existing = self.get_or_none(self.api.dcim.power_feeds, name=name, power_panel_id=power_panel.id)
            
            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Power feed "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Prepare data
            data = {
                'name': name,
                'power_panel': power_panel.id,
                'status': row.get('status', 'active').strip(),
            }
            
            if row.get('type'):
                data['type'] = row['type'].strip()
            if row.get('supply'):
                data['supply'] = row['supply'].strip()
            if row.get('phase'):
                data['phase'] = row['phase'].strip()
            if row.get('voltage'):
                try:
                    data['voltage'] = int(row['voltage'].strip())
                except ValueError:
                    pass
            if row.get('amperage'):
                try:
                    data['amperage'] = int(row['amperage'].strip())
                except ValueError:
                    pass
            if row.get('max_utilization'):
                try:
                    data['max_utilization'] = int(row['max_utilization'].strip())
                except ValueError:
                    pass
            
            if row.get('rack'):
                rack = self.get_or_none(self.api.dcim.racks, name=row['rack'].strip(), site_id=site.id)
                if rack:
                    data['rack'] = rack.id
                    
            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id
            
            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} power feed "{name}"'
                logger.info(result['message'])
                return result
            
            # Create or update
            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated power feed "{name}"'
            else:
                self.api.dcim.power_feeds.create(data)
                result['success'] = True
                result['message'] = f'Created power feed "{name}"'
                
            logger.info(result['message'])
            
        except Exception as e:
            result['message'] = f'Error importing power feed: {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_modules(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a device module into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            device_name = row.get('device', '').strip()
            module_bay_name = row.get('module_bay', '').strip()
            module_type_name = row.get('module_type', '').strip()
            
            if not device_name or not module_bay_name or not module_type_name:
                result['message'] = self._missing_required_message(
                    'module', row, ['device', 'module_bay', 'module_type']
                )
                return result
            
            # Get device
            device = self.get_or_none(self.api.dcim.devices, name=device_name)
            if not device:
                result['message'] = f'Device "{device_name}" not found'
                return result
            
            # Resolve module bay — supports "ParentModule/ChildBay" slash notation for
            # nested module bays. Split on the LAST slash so module type names containing
            # slashes (e.g. "Slot15: OME 6500 SPAP-2 w/2xOSC 2xSFP/osc1") are handled correctly.
            if '/' in module_bay_name:
                parent_display, child_bay_name = module_bay_name.rsplit('/', 1)

                # Find the parent module on the device by matching its display name.
                # NetBox module display format is "{bay}: {module_type} (ID)" — strip the trailing ID.
                parent_modules = list(self.api.dcim.modules.filter(device_id=device.id))
                matched = [
                    m for m in parent_modules
                    if re.sub(r'\s*\(\d+\)\s*$', '', str(m)).strip() == parent_display.strip()
                ]
                if not matched:
                    result['message'] = (
                        f'Parent module "{parent_display}" not found on device "{device_name}". '
                        f'Available: {[str(m) for m in parent_modules]}'
                    )
                    return result
                parent_module = matched[0]

                # Find the child bay inside that parent module.
                # Filter by device + name, then match the parent module in Python
                # since module_id may not be a supported API filter.
                candidate_bays = list(self.api.dcim.module_bays.filter(device_id=device.id, name=child_bay_name))
                child_bays = [
                    b for b in candidate_bays
                    if getattr(b, 'module', None) and b.module.id == parent_module.id
                ]
                if not child_bays:
                    result['message'] = f'Child module bay "{child_bay_name}" not found in module "{parent_display}" on device "{device_name}"'
                    return result
                module_bay = child_bays[0]
                display_bay_name = module_bay_name
            else:
                module_bay = self._get_or_create_safe(
                    self.api.dcim.module_bays,
                    {'device': device.id, 'name': module_bay_name},
                    dry_run=dry_run,
                    device_id=device.id,
                    name=module_bay_name,
                )
                display_bay_name = module_bay_name

            # Check if module exists
            if module_bay:
                existing_modules = list(self.api.dcim.modules.filter(module_bay_id=module_bay.id))
                existing = existing_modules[0] if existing_modules else None
            else:
                existing = None
            
            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Module in bay "{display_bay_name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Get or create module type
            # First try to find ANY existing module type with this model name
            module_types = list(self.api.dcim.module_types.filter(model=module_type_name))
            module_type = None
            if module_types:
                # Prioritize non-Generic manufacturers if multiple exist
                for mt in module_types:
                    if mt.manufacturer.name != 'Generic':
                        module_type = mt
                        break
                if not module_type:
                    module_type = module_types[0]
            
            # If still not found, create it under the Generic manufacturer
            if not module_type and not dry_run:
                manufacturer = self._get_or_create_safe(
                    self.api.dcim.manufacturers,
                    {'name': 'Generic', 'slug': 'generic'},
                    dry_run=dry_run,
                    name='Generic',
                )
                if manufacturer:
                    module_type = self._get_or_create_safe(
                        self.api.dcim.module_types,
                        {'model': module_type_name, 'manufacturer': manufacturer.id},
                        dry_run=dry_run,
                        model=module_type_name,
                        manufacturer_id=manufacturer.id,
                    )
                logger.info(f'Created module type "{module_type_name}"')
            
            # Prepare data
            data = {
                'device': device.id,
                'module_bay': module_bay.id if module_bay else None,
                'module_type': module_type.id if module_type else None,
                'status': row.get('status', 'active').strip(),
            }

            logger.debug(f'Module create payload: {data}')

            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} module in bay "{display_bay_name}"'
                logger.info(result['message'])
                return result

            def _create_module(payload):
                """Try with replicate_components first; fall back without it on 500."""
                try:
                    return self.api.dcim.modules.create({**payload, 'replicate_components': True})
                except Exception as e:
                    if '500' in str(e) or 'RetryError' in type(e).__name__:
                        logger.warning(
                            f'Module create with replicate_components failed ({e}), '
                            f'retrying without it for bay "{display_bay_name}"'
                        )
                        return self.api.dcim.modules.create(payload)
                    raise

            # Create or update
            if existing and replace:
                existing.delete()
                _create_module(data)
                result['success'] = True
                result['message'] = f'Recreated module in bay "{display_bay_name}"'
            else:
                _create_module(data)
                result['success'] = True
                result['message'] = f'Created module in bay "{display_bay_name}"'
                
            logger.info(result['message'])
            
        except Exception as e:
            result['message'] = f'Error importing module: {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_cables(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a cable into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}
        
        try:
            def normalize_term_type(raw: str) -> str:
                key = str(raw or '').strip().lower()
                if not key:
                    return ''
                short_to_full = {
                    'interface': 'dcim.interface',
                    'powerport': 'dcim.powerport',
                    'poweroutlet': 'dcim.poweroutlet',
                    'consoleport': 'dcim.consoleport',
                    'consoleserverport': 'dcim.consoleserverport',
                    'rearport': 'dcim.rearport',
                    'frontport': 'dcim.frontport',
                    'powerfeed': 'dcim.powerfeed',
                }
                if key in short_to_full:
                    return short_to_full[key]
                if key.startswith('dcim.'):
                    return key
                return key
            
            # Type mapping for API lookups
            type_to_api = {
                'dcim.interface': self.api.dcim.interfaces,
                'dcim.powerport': self.api.dcim.power_ports,
                'dcim.poweroutlet': self.api.dcim.power_outlets,
                'dcim.consoleport': self.api.dcim.console_ports,
                'dcim.consoleserverport': self.api.dcim.console_server_ports,
                'dcim.rearport': self.api.dcim.rear_ports,
                'dcim.frontport': self.api.dcim.front_ports,
                'dcim.powerfeed': self.api.dcim.power_feeds,
            }

            def get_termination(side_prefix):
                term_type_raw = row.get(f'{side_prefix}_type', '').strip()
                term_type = normalize_term_type(term_type_raw)
                if not term_type:
                    return None, term_type, f"Missing {side_prefix}_type"
                
                if term_type == 'dcim.powerfeed':
                    panel_name = row.get('power_panel', '').strip() or row.get(f'{side_prefix}_device', '').strip()
                    feed_name = row.get('power_feed', '').strip() or row.get(f'{side_prefix}_name', '').strip()
                    
                    if not panel_name or not feed_name:
                        return None, term_type, f"Missing power_panel or power_feed for {side_prefix}"
                    
                    panel = self.get_or_none(self.api.dcim.power_panels, name=panel_name)
                    if not panel:
                        return None, term_type, f"Power Panel '{panel_name}' not found for {side_prefix}"
                    
                    term = self.get_or_none(self.api.dcim.power_feeds, power_panel_id=panel.id, name=feed_name)
                    if not term:
                        return None, term_type, f"Power Feed '{feed_name}' not found on panel '{panel_name}' for {side_prefix}"
                    return term, term_type, None
                else:
                    device_name = row.get(f'{side_prefix}_device', '').strip()
                    term_name = row.get(f'{side_prefix}_name', '').strip()
                    
                    if not device_name or not term_name:
                        return None, term_type, f"Missing device or name for {side_prefix}"
                    
                    device = self.get_or_none(self.api.dcim.devices, name=device_name)
                    if not device:
                        return None, term_type, f"Device '{device_name}' not found for {side_prefix}"
                    
                    endpoint = type_to_api.get(term_type)
                    if not endpoint:
                        return None, term_type, f"Unsupported termination type '{term_type_raw or term_type}' for {side_prefix}"
                    
                    term = self.get_or_none(endpoint, device_id=device.id, name=term_name)
                    if not term:
                        return None, term_type, f"Termination '{term_name}' not found on device '{device_name}' for {side_prefix}"
                    return term, term_type, None

            # Get terminations
            term_a, side_a_type, error_a = get_termination('side_a')
            if error_a:
                result['message'] = error_a
                return result
            
            term_b, side_b_type, error_b = get_termination('side_b')
            if error_b:
                result['message'] = error_b
                return result
                
            # Check if cable exists between these endpoints
            if term_a.cable or term_b.cable:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Cable already exists for Side A or Side B (skipped)'
                    result['success'] = True
                    return result
                else:
                    # If we should replace, we'll delete the existing cable(s) first
                    if not dry_run:
                        if term_a.cable:
                            term_a.cable.delete()
                        if term_b.cable and term_b.cable != term_a.cable:
                            term_b.cable.delete()
                    result['action'] = 'update'
            else:
                result['action'] = 'create'
            
            # Prepare data
            data = {
                'a_terminations': [{'object_type': side_a_type, 'object_id': term_a.id}],
                'b_terminations': [{'object_type': side_b_type, 'object_id': term_b.id}],
                'status': row.get('status', 'connected').strip(),
                'type': row.get('type', '').strip(),
                'color': row.get('color', '').strip().replace('#', ''),
            }
            
            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} cable connection'
                logger.info(result['message'])
                return result
            
            # Create the cable
            self.api.dcim.cables.create(data)
            result['success'] = True
            result['message'] = f'Created cable connection'
            logger.info(result['message'])
            
        except Exception as e:
            result['message'] = f'Error importing cable: {str(e)}'
            logger.error(result['message'], exc_info=True)
            
        return result
    
    def import_vrfs(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a VRF into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}

        try:
            name = row.get('name', '').strip()
            if not name:
                result['message'] = self._missing_required_message('vrf', row, ['name'])
                return result

            existing = self.get_or_none(self.api.ipam.vrfs, name=name)

            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'VRF "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'

            data = {'name': name}

            if row.get('description'):
                data['description'] = row['description'].strip()
            if row.get('enforce_unique'):
                val = row['enforce_unique'].strip().lower()
                data['enforce_unique'] = val in ('true', '1', 'yes')
            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id

            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} VRF "{name}"'
                logger.info(result['message'])
                return result

            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated VRF "{name}"'
            else:
                self.api.ipam.vrfs.create(data)
                result['success'] = True
                result['message'] = f'Created VRF "{name}"'

            logger.info(result['message'])

        except Exception as e:
            result['message'] = f'Error importing VRF: {str(e)}'
            logger.error(result['message'], exc_info=True)

        return result

    def import_prefix_roles(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a prefix role into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}

        try:
            name = row.get('name', '').strip()
            if not name:
                result['message'] = self._missing_required_message('prefix-role', row, ['name'])
                return result

            existing = self.get_or_none(self.api.ipam.roles, name=name)

            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Prefix role "{name}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'

            slug = row.get('slug', '').strip() or name.lower().replace(' ', '-')
            data = {'name': name, 'slug': slug}

            if row.get('weight'):
                try:
                    data['weight'] = int(row['weight'].strip())
                except ValueError:
                    pass

            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} prefix role "{name}"'
                logger.info(result['message'])
                return result

            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated prefix role "{name}"'
            else:
                self.api.ipam.roles.create(data)
                result['success'] = True
                result['message'] = f'Created prefix role "{name}"'

            logger.info(result['message'])

        except Exception as e:
            result['message'] = f'Error importing prefix role: {str(e)}'
            logger.error(result['message'], exc_info=True)

        return result

    def import_prefixes(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import a prefix into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}

        try:
            raw_prefix = row.get('prefix', '').strip()
            if not raw_prefix:
                result['message'] = self._missing_required_message('prefix', row, ['prefix'])
                return result

            try:
                prefix = self._normalize_prefix(raw_prefix)
            except Exception as exc:
                result['message'] = f'Invalid prefix "{raw_prefix}": {exc}'
                return result

            if prefix != raw_prefix:
                logger.info(f'Normalized prefix "{raw_prefix}" -> "{prefix}"')

            vrf = None
            vrf_name = row.get('vrf', '').strip()
            if vrf_name:
                vrf = self.get_or_none(self.api.ipam.vrfs, name=vrf_name)

            if vrf:
                existing = self.get_or_none(self.api.ipam.prefixes, prefix=prefix, vrf_id=vrf.id)
            else:
                existing = self.get_or_none(self.api.ipam.prefixes, prefix=prefix)

            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'Prefix "{prefix}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'

            data = {
                'prefix': prefix,
                'status': row.get('status', 'active').strip(),
            }

            if vrf:
                data['vrf'] = vrf.id
            if row.get('role'):
                role = self.get_or_none(self.api.ipam.roles, name=row['role'].strip())
                if role:
                    data['role'] = role.id
            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id
            if row.get('is_pool'):
                val = row['is_pool'].strip().lower()
                data['is_pool'] = val in ('true', '1', 'yes')

            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} prefix "{prefix}"'
                logger.info(result['message'])
                return result

            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                existing.save()
                result['success'] = True
                result['message'] = f'Updated prefix "{prefix}"'
            else:
                try:
                    self.api.ipam.prefixes.create(data)
                    result['success'] = True
                    result['message'] = f'Created prefix "{prefix}"'
                except Exception as create_exc:
                    create_text = str(create_exc).lower()
                    duplicate_hint = (
                        'already exists' in create_text
                        or 'duplicate' in create_text
                        or 'must make a unique set' in create_text
                    )
                    existing_after = None
                    if duplicate_hint:
                        if vrf:
                            existing_after = self.get_or_none(self.api.ipam.prefixes, prefix=prefix, vrf_id=vrf.id)
                        else:
                            existing_after = self.get_or_none(self.api.ipam.prefixes, prefix=prefix)
                    if existing_after:
                        result['success'] = True
                        result['action'] = 'skipped'
                        result['message'] = f'Prefix "{prefix}" already exists (skipped)'
                    else:
                        raise create_exc

            logger.info(result['message'])

        except Exception as e:
            result['message'] = f'Error importing prefix: {str(e)}'
            logger.error(result['message'], exc_info=True)

        return result

    def import_ip_addresses(self, row: Dict[str, str], dry_run: bool = False, replace: bool = False) -> Dict[str, Any]:
        """Import an IP address into Netbox"""
        result = {'success': False, 'action': None, 'message': ''}

        try:
            raw_address = row.get('address', '').strip()
            device_name = row.get('device', '').strip()
            interface_name = row.get('interface', '').strip()

            if not raw_address:
                result['message'] = self._missing_required_message('ip-address', row, ['address'])
                return result

            try:
                address = self._normalize_interface_address(raw_address)
            except Exception as exc:
                result['message'] = f'Invalid IP address "{raw_address}": {exc}'
                return result

            if address != raw_address:
                logger.info(f'Normalized IP address "{raw_address}" -> "{address}"')

            # Resolve VRF if specified
            vrf = None
            vrf_name = row.get('vrf', '').strip()
            if vrf_name:
                vrf = self.get_or_none(self.api.ipam.vrfs, name=vrf_name)

            # Check if IP address exists (scoped to VRF if provided)
            existing = self._find_existing_ip(address, vrf.id if vrf else None)

            if existing:
                if not replace:
                    result['action'] = 'skipped'
                    result['message'] = f'IP address "{address}" already exists (skipped)'
                    result['success'] = True
                    return result
                else:
                    result['action'] = 'update'
            else:
                result['action'] = 'create'

            # Prepare data
            data = {
                'address': address,
                'status': row.get('status', 'active').strip(),
            }

            if vrf:
                data['vrf'] = vrf.id

            # Try to find the device and interface for assignment
            device = None
            interface = None
            assignment_skipped = False
            if device_name and interface_name:
                device = self.get_or_none(self.api.dcim.devices, name=device_name)
                if device:
                    interface = self.get_or_none(self.api.dcim.interfaces, device_id=device.id, name=interface_name)
                    if interface:
                        if self._is_unassignable_interface_address(address):
                            assignment_skipped = True
                            logger.warning(
                                f'Address "{address}" is a network/broadcast address; '
                                f'skipping interface assignment for {device_name}:{interface_name}'
                            )
                        else:
                            data['assigned_object_type'] = 'dcim.interface'
                            data['assigned_object_id'] = interface.id

            if row.get('tenant'):
                tenant = self.get_or_none(self.api.tenancy.tenants, name=row['tenant'].strip())
                if tenant:
                    data['tenant'] = tenant.id

            if dry_run:
                result['success'] = True
                result['message'] = f'[DRY RUN] Would {result["action"]} IP address "{address}"'
                logger.info(result['message'])
                return result

            # Create or update
            if existing and replace:
                for key, value in data.items():
                    setattr(existing, key, value)
                if assignment_skipped:
                    setattr(existing, 'assigned_object_type', None)
                    setattr(existing, 'assigned_object_id', None)
                existing.save()
                ip_obj = existing
                result['success'] = True
                if assignment_skipped:
                    result['message'] = (
                        f'Updated IP address "{address}" without interface assignment '
                        f'(network/broadcast address)'
                    )
                else:
                    result['message'] = f'Updated IP address "{address}"'
            else:
                try:
                    ip_obj = self.api.ipam.ip_addresses.create(data)
                    result['success'] = True
                    if assignment_skipped:
                        result['message'] = (
                            f'Created IP address "{address}" without interface assignment '
                            f'(network/broadcast address)'
                        )
                    else:
                        result['message'] = f'Created IP address "{address}"'
                except Exception as create_exc:
                    create_text = f'{create_exc} {getattr(create_exc, "error", "")}'.lower()
                    duplicate_hint = (
                        'duplicate ip address' in create_text
                        or 'already exists' in create_text
                        or 'must make a unique set' in create_text
                    )
                    existing_after = None
                    if duplicate_hint:
                        existing_after = self._find_existing_ip(address, vrf.id if vrf else None)
                    if existing_after:
                        ip_obj = existing_after
                        result['success'] = True
                        result['action'] = 'skipped'
                        result['message'] = f'IP address "{address}" already exists (skipped)'
                    else:
                        detail = self._format_exception_detail(create_exc)
                        context = (
                            f'device="{device_name or "<none>"}", '
                            f'interface="{interface_name or "<none>"}", '
                            f'vrf="{vrf_name or "<none>"}"'
                        )
                        result['success'] = False
                        result['message'] = (
                            f'Error importing IP address "{address}" ({context}): {detail}'
                        )
                        logger.error(result['message'])
                        return result

            logger.info(result['message'])

            # Set as primary IP on the device if requested
            is_primary = row.get('is_primary', '').strip().lower()
            if is_primary in ('true', '1', 'yes') and device and ip_obj and not assignment_skipped:
                if ':' in address.split('/')[0]:
                    device.primary_ip6 = ip_obj.id
                else:
                    device.primary_ip4 = ip_obj.id
                device.save()
                logger.info(f'Set "{address}" as primary IP for device "{device_name}"')

        except Exception as e:
            address_display = locals().get('address') or locals().get('raw_address') or '<unknown>'
            device_display = locals().get('device_name') or '<none>'
            interface_display = locals().get('interface_name') or '<none>'
            vrf_display = locals().get('vrf_name') or '<none>'
            detail = self._format_exception_detail(e)
            result['message'] = (
                f'Error importing IP address "{address_display}" '
                f'(device="{device_display}", interface="{interface_display}", vrf="{vrf_display}"): '
                f'{detail}'
            )
            logger.error(result['message'], exc_info=True)

        return result
