
"""
Zabbix Device Management with ZabbixConfigurationGroup
Attaches devices to Zabbix using ZabbixConfigurationGroup and syncs NetBox tags
"""
import os
import sys
import json
import warnings
import hmac
import base64
import hashlib
import argparse
import requests
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import urllib3
from glitchtip_utils import init_glitchtip, capture_exception

# Load .env for local app settings (SECRET_KEY, TLS options, etc.)
load_dotenv('.env')
init_glitchtip(service='nbsync-helper-cli', with_flask=False)


def _env_bool(name, default=False):
    raw = str(os.getenv(name, str(default))).strip().lower()
    return raw in ('1', 'true', 'yes', 'on')


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


TLS_VERIFY = _env_bool('NBH_TLS_VERIFY', True)
TLS_CA_BUNDLE = str(os.getenv('NBH_TLS_CA_BUNDLE', '') or '').strip()
INSTANCE_SKIP_SSL_VERIFY = False
if not TLS_VERIFY and not TLS_CA_BUNDLE:
    warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)


def _requests_verify():
    if INSTANCE_SKIP_SSL_VERIFY:
        return False
    return TLS_CA_BUNDLE if TLS_CA_BUNDLE else TLS_VERIFY

# Request timeout (seconds)
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds between retries
DEVICE_PROCESSING_DELAY = 0.5  # seconds delay between processing devices

def safe_request(method, url, **kwargs):
    """Make a request with timeout, error handling, and automatic retries"""
    kwargs.setdefault('timeout', REQUEST_TIMEOUT)
    kwargs.setdefault('verify', _requests_verify())
    
    for attempt in range(MAX_RETRIES):
        try:
            response = method(url, **kwargs)
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                print(f"    ⚠️  Request timeout for {url} (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                print(f"    ❌ Request timeout for {url} after {MAX_RETRIES} attempts")
                return None
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                print(f"    ⚠️  Request error: {e} (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                print(f"    ❌ Request error after {MAX_RETRIES} attempts: {e}")
                return None
    
    return None

# Parse command line arguments
parser = argparse.ArgumentParser(description='Add devices to Zabbix via NetBox plugin assignments')
parser.add_argument('--device-id', type=int, help='Process only a specific device by ID')
parser.add_argument('--device-name', type=str, help='Process only a specific device by name')
parser.add_argument('--config-group-id', type=int, default=2, help='ZabbixConfigurationGroup ID (default: 2 for CustomerICMP)')
parser.add_argument('--limit', type=int, help='Limit the number of devices to process')
parser.add_argument('--parallel', type=int, default=1, help='Number of parallel workers (default: 1, use 3-5 for faster processing)')
parser.add_argument('--delay', type=float, default=0.5, help='Delay in seconds between processing devices (default: 0.5)')
parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
parser.add_argument('--removeserver', action='store_true', help='Remove Zabbix server assignment from device')
parser.add_argument('--instance-id', type=str, help='Instance ID from template-sync/instances.json')
parser.add_argument('--instance-name', type=str, help='Instance name from template-sync/instances.json')
args = parser.parse_args()

INSTANCES_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'template-sync',
    'instances.json',
)


def _make_key():
    secret = os.getenv('SECRET_KEY', 'changeme_set_in_env')
    return hashlib.sha256(secret.encode('utf-8')).digest()


def _decrypt_token(stored):
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


def load_instances():
    if not os.path.exists(INSTANCES_FILE):
        return []
    with open(INSTANCES_FILE, 'r', encoding='utf-8') as f:
        instances = json.load(f).get('instances', [])
    for inst in instances:
        if 'token' in inst:
            inst['token'] = _decrypt_token(inst.get('token'))
        inst['skip_ssl_verify'] = _to_bool(inst.get('skip_ssl_verify', False))
    return instances


def resolve_instance(instance_id=None, instance_name=None):
    instances = load_instances()
    if not instances:
        raise ValueError(f'No NetBox instances found in {INSTANCES_FILE}')

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


try:
    selected_instance = resolve_instance(args.instance_id, args.instance_name)
except ValueError as e:
    print(f"❌ Error: {e}")
    sys.exit(1)

NETBOX_URL = (selected_instance.get('url') or '').rstrip('/')
NETBOX_TOKEN = selected_instance.get('token') or ''
INSTANCE_SKIP_SSL_VERIFY = _to_bool(selected_instance.get('skip_ssl_verify', False))
if INSTANCE_SKIP_SSL_VERIFY:
    warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)

if not NETBOX_URL or not NETBOX_TOKEN:
    print(f"❌ Error: instance '{selected_instance.get('name', 'unknown')}' is missing URL or token")
    sys.exit(1)

headers = {'Authorization': f'Token {NETBOX_TOKEN}', 'Content-Type': 'application/json'}

# Global caches to minimize API calls
ZABBIX_TAGS_CACHE = {}  # {tag_name: tag_id}
ZABBIX_HOSTGROUPS_CACHE = {}  # {hostgroup_name: hostgroup_id}
CACHE_LOCK = threading.Lock()  # Thread safety for caches
PRINT_LOCK = threading.Lock()  # Thread safety for console output

print("=" * 80)
print("Zabbix Device Management with ZabbixConfigurationGroup")
print("=" * 80)
print(f"Instance: {selected_instance.get('name', 'unknown')} ({selected_instance.get('id', 'n/a')})")
print(f"NetBox URL: {NETBOX_URL}")
print(f"Configuration Group ID: {args.config_group_id}")
print("Device Filter: devices with Primary IPv4 set")
if args.dry_run:
    print("⚠️  DRY RUN MODE - No changes will be made")
print("=" * 80)
print()


def get_zabbix_server_from_config_group(config_group_id):
    """Get Zabbix server ID from configuration group via its host group assignments"""
    # Get host group assignments for this config group
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixhostgroupassignment/"
    params = {"zabbixconfigurationgroup_id": config_group_id}
    response = safe_request(requests.get, url, params=params, headers=headers)
    if response and response.status_code == 200 and response.json().get('results'):
        assignment = response.json()['results'][0]
        hostgroup_id = assignment.get('zabbixhostgroup')
        if hostgroup_id:
            # Get the host group details to find the Zabbix server
            hg_url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixhostgroup/{hostgroup_id}/"
            hg_response = safe_request(requests.get, hg_url, headers=headers)
            if hg_response and hg_response.status_code == 200:
                hostgroup = hg_response.json()
                zabbix_server = hostgroup.get('zabbixserver')
                if isinstance(zabbix_server, dict):
                    return zabbix_server.get('id')
                return zabbix_server
    return None


def get_or_create_hostgroup(hostgroup_name, zabbix_server_id):
    """Get or create a Zabbix host group"""
    # Check cache first (thread-safe)
    cache_key = f"{hostgroup_name}_{zabbix_server_id}"
    with CACHE_LOCK:
        if cache_key in ZABBIX_HOSTGROUPS_CACHE:
            hostgroup_id = ZABBIX_HOSTGROUPS_CACHE[cache_key]
            with PRINT_LOCK:
                print(f"    ✓ Host group '{hostgroup_name}' exists (ID: {hostgroup_id})")
            return hostgroup_id
    
    # Check if hostgroup exists in API
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixhostgroup/"
    params = {"name": hostgroup_name, "zabbixserver_id": zabbix_server_id}
    response = safe_request(requests.get, url, params=params, headers=headers)
    
    if response and response.status_code == 200 and response.json().get('results'):
        hostgroup = response.json()['results'][0]
        hostgroup_id = hostgroup['id']
        ZABBIX_HOSTGROUPS_CACHE[cache_key] = hostgroup_id
        print(f"    ✓ Host group '{hostgroup_name}' exists (ID: {hostgroup_id})")
        return hostgroup_id
    
    # Create hostgroup
    if args.dry_run:
        print(f"    [DRY RUN] Would create host group: {hostgroup_name}")
        return None
    
    print(f"    + Creating host group: {hostgroup_name}")
    hostgroup_data = {
        "name": hostgroup_name,
        "value": hostgroup_name,
        "zabbixserver": zabbix_server_id,
        "zabbixserver_id": zabbix_server_id
    }
    response = safe_request(requests.post, url, json=hostgroup_data, headers=headers)
    if response and response.status_code == 201:
        hostgroup_id = response.json()['id']
        with CACHE_LOCK:
            ZABBIX_HOSTGROUPS_CACHE[cache_key] = hostgroup_id
        with PRINT_LOCK:
            print(f"    ✓ Host group created (ID: {hostgroup_id})")
        return hostgroup_id
    elif response:
        with PRINT_LOCK:
            print(f"    ❌ Error creating host group: {response.status_code} - {response.text}")
    return None


def assign_hostgroup_to_device(device_id, hostgroup_id):
    """Assign a host group to a device"""
    # Check if already assigned
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixhostgroupassignment/"
    params = {"assigned_object_id": device_id}
    response = safe_request(requests.get, url, params=params, headers=headers)
    
    if response and response.status_code == 200:
        # Manually check if this specific host group is assigned (API filter doesn't work)
        for result in response.json().get('results', []):
            if result.get('zabbixhostgroup') == hostgroup_id:
                print(f"    ✓ Host group already assigned")
                return True
    
    if args.dry_run:
        print(f"    [DRY RUN] Would assign host group to device")
        return True
    
    # Create assignment
    print(f"    + Assigning host group to device")
    assignment_data = {
        "assigned_object_type": "dcim.device",
        "assigned_object_id": device_id,
        "zabbixhostgroup": hostgroup_id
    }
    response = safe_request(requests.post, url, json=assignment_data, headers=headers)
    if response and response.status_code == 201:
        print(f"    ✓ Host group assigned")
        return True
    elif response:
        print(f"    ❌ Error assigning host group: {response.status_code} - {response.text}")
        return False


def get_or_create_zabbix_tag(tag_name, zabbix_server_id):
    """Get or create a Zabbix tag in Zabbix"""
    # Check cache first
    if tag_name in ZABBIX_TAGS_CACHE:
        tag_id = ZABBIX_TAGS_CACHE[tag_name]
        print(f"    ✓ Zabbix tag '{tag_name}' exists (ID: {tag_id})")
        return tag_id
    
    # Check if tag exists in API
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixtag/"
    params = {"tag": tag_name}
    response = safe_request(requests.get, url, params=params, headers=headers)
    
    if response and response.status_code == 200 and response.json().get('results'):
        # Check if any results match the exact tag name (case-sensitive)
        for result in response.json()['results']:
            if result.get('tag') == tag_name:
                tag_id = result['id']
                ZABBIX_TAGS_CACHE[tag_name] = tag_id
                print(f"    ✓ Zabbix tag '{tag_name}' exists (ID: {tag_id})")
                return tag_id
    
    # Create tag
    if args.dry_run:
        print(f"    [DRY RUN] Would create Zabbix tag: {tag_name}")
        return None
    
    print(f"    + Creating Zabbix tag: {tag_name}")
    tag_data = {
        "name": f"NetBox Tag: {tag_name}",
        "tag": tag_name,
        "value": tag_name,
        "description": f"Auto-synced from NetBox tag: {tag_name}"
    }
    response = safe_request(requests.post, url, json=tag_data, headers=headers)
    if response and response.status_code == 201:
        tag_id = response.json()['id']
        ZABBIX_TAGS_CACHE[tag_name] = tag_id
        print(f"    ✓ Zabbix tag created (ID: {tag_id})")
        return tag_id
    elif response:
        print(f"    ❌ Error creating Zabbix tag: {response.status_code} - {response.text}")
        return None
    else:
        print(f"    ❌ Timeout creating Zabbix tag")
        return None


def assign_zabbix_tag_to_device(device_id, zabbix_tag_id):
    """Assign a Zabbix tag to a device"""
    # Check if already assigned
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixtagassignment/"
    params = {"assigned_object_id": device_id}
    response = safe_request(requests.get, url, params=params, headers=headers)
    
    if response and response.status_code == 200:
        # Manually check if this specific tag is assigned (API filter doesn't work)
        for result in response.json().get('results', []):
            if result.get('zabbixtag') == zabbix_tag_id:
                print(f"    ✓ Zabbix tag already assigned")
                return True
    
    if args.dry_run:
        print(f"    [DRY RUN] Would assign Zabbix tag to device")
        return True
    
    # Create assignment
    print(f"    + Assigning Zabbix tag to device (tag_id={zabbix_tag_id})")
    assignment_data = {
        "assigned_object_type": "dcim.device",
        "assigned_object_id": device_id,
        "zabbixtag": zabbix_tag_id
    }
    response = safe_request(requests.post, url, json=assignment_data, headers=headers)
    if response and response.status_code == 201:
        print(f"    ✓ Zabbix tag assigned successfully")
        return True
    elif response and response.status_code == 400 and "already exists" in response.text.lower():
        print(f"    ✓ Zabbix tag already assigned (skipped)")
        return True
    elif response:
        print(f"    ❌ Error assigning Zabbix tag: {response.status_code} - {response.text}")
        return False
    else:
        print(f"    ❌ Timeout assigning Zabbix tag")
        return False


def attach_configuration_group_to_device(device_id, config_group_id, zabbix_server_id):
    """Attach ZabbixConfigurationGroup to device"""
    # Check if already attached
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixconfigurationgroupassignment/"
    params = {"assigned_object_id": device_id, "zabbixconfigurationgroup_id": config_group_id}
    response = safe_request(requests.get, url, params=params, headers=headers)
    
    if response and response.status_code == 200 and response.json().get('results'):
        print(f"  ✓ ZabbixConfigurationGroup already attached")
        return True
    
    if args.dry_run:
        print(f"  [DRY RUN] Would attach ZabbixConfigurationGroup")
        return True
    
    # Create assignment
    print(f"  + Attaching ZabbixConfigurationGroup...")
    assignment_data = {
        "assigned_object_type": "dcim.device",
        "assigned_object_id": device_id,
        "zabbixconfigurationgroup": config_group_id
    }
    response = safe_request(requests.post, url, json=assignment_data, headers=headers)
    if response and response.status_code == 201:
        print(f"  ✓ ZabbixConfigurationGroup attached")
        return True
    elif response:
        print(f"  ❌ Error attaching ZabbixConfigurationGroup: {response.status_code} - {response.text}")
        return False
    else:
        print(f"  ❌ Timeout attaching ZabbixConfigurationGroup")
        return False


def remove_server_assignment(device_id):
    """Remove Zabbix server assignment from device"""
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixserverassignment/"
    params = {"assigned_object_id": device_id}
    response = safe_request(requests.get, url, params=params, headers=headers)
    
    if response and response.status_code == 200 and response.json().get('results'):
        for assignment in response.json()['results']:
            assignment_id = assignment['id']
            if args.dry_run:
                print(f"  [DRY RUN] Would remove Zabbix server assignment (ID: {assignment_id})")
            else:
                delete_url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixserverassignment/{assignment_id}/"
                delete_response = safe_request(requests.delete, delete_url, headers=headers)
                if delete_response and delete_response.status_code == 204:
                    print(f"  ✓ Removed Zabbix server assignment (ID: {assignment_id})")
                    return True
                else:
                    print(f"  ❌ Error removing server assignment")
                    return False
    else:
        print(f"  ℹ️  No Zabbix server assignment found")
    return False


def process_device(device):
    """Process a single device"""
    device_id = device['id']
    device_name = device['name']
    
    print(f"\n📦 Processing device: {device_name} (ID: {device_id})")
    print("-" * 80)
    
    # Get Zabbix server from config group
    zabbix_server_id = get_zabbix_server_from_config_group(args.config_group_id)
    if not zabbix_server_id:
        print(f"  ❌ Could not get Zabbix server from config group {args.config_group_id}")
        return
    
    # Skip devices already assigned to this config group.
    url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixconfigurationgroupassignment/"
    params = {"assigned_object_id": device_id, "zabbixconfigurationgroup_id": args.config_group_id}
    response = safe_request(requests.get, url, params=params, headers=headers)
    if response and response.status_code == 200 and response.json().get('results'):
        print(f"  ⏭️  Device already has config group assigned - skipping")
        return
    
    print(f"  Zabbix Server ID: {zabbix_server_id}")
    
    # Remove server assignment if requested
    if args.removeserver:
        print(f"\n  🗑️  Removing Zabbix server assignment...")
        remove_server_assignment(device_id)
        print(f"\n✅ Device processing complete: {device_name}")
        return
    
    # 1. Attach configuration group (server assignment happens automatically)
    if not attach_configuration_group_to_device(device_id, args.config_group_id, zabbix_server_id):
        return
    
    # 3. Get NetBox tags for this device.
    device_tags = list(device.get('tags', []))
    if device_tags:
        print(f"\n  📌 Processing {len(device_tags)} NetBox tags:")
        for tag in device_tags:
            tag_name = tag['name']
            tag_slug = tag['slug']
            print(f"\n    Tag: {tag_name} ({tag_slug})")
            
            # 3a. Create Zabbix tag and assign to device
            zabbix_tag_id = get_or_create_zabbix_tag(tag_name, zabbix_server_id)
            if zabbix_tag_id:
                assign_zabbix_tag_to_device(device_id, zabbix_tag_id)
            
            # 3b. Create host group with tag name and assign to device
            hostgroup_id = get_or_create_hostgroup(tag_name, zabbix_server_id)
            if hostgroup_id:
                assign_hostgroup_to_device(device_id, hostgroup_id)
    else:
        print(f"  ⚠️  No NetBox tags found for this device")
    
    print(f"\n  ℹ️  Device ready for sync - run 'nbxsync sync' to complete")

    print(f"\n✅ Device processing complete: {device_name}")


def fetch_devices(filters):
    """Fetch all devices for the given filters (follows pagination)."""
    url = f"{NETBOX_URL}/api/dcim/devices/"
    params = {'limit': 1000, **(filters or {})}
    devices = []

    while url:
        response = safe_request(requests.get, url, params=params, headers=headers)
        params = None  # follow `next` URLs directly

        if not response:
            return None, "Timeout fetching devices"
        if response.status_code != 200:
            return None, f"Error fetching devices: {response.status_code} - {response.text}"

        payload = response.json()
        results = payload.get('results')
        if isinstance(results, list):
            devices.extend(results)
            url = payload.get('next')
        elif isinstance(payload, list):
            devices.extend(payload)
            url = None
        else:
            return None, "Unexpected API response format for devices"

    return devices, None


def load_caches(zabbix_server_id):
    """Pre-load caches with existing Zabbix tags and host groups"""
    print("🔄 Loading existing Zabbix tags and host groups into cache...")
    
    # Load Zabbix tags
    tags_url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixtag/"
    tags_response = safe_request(requests.get, tags_url, params={"limit": 1000}, headers=headers)
    if tags_response and tags_response.status_code == 200:
        for tag in tags_response.json().get('results', []):
            tag_name = tag.get('tag')
            if tag_name:
                ZABBIX_TAGS_CACHE[tag_name] = tag['id']
        print(f"  ✓ Loaded {len(ZABBIX_TAGS_CACHE)} Zabbix tags")
    
    # Load host groups for this Zabbix server
    hg_url = f"{NETBOX_URL}/api/plugins/nbxsync/zabbixhostgroup/"
    hg_response = safe_request(requests.get, hg_url, params={"zabbixserver_id": zabbix_server_id, "limit": 1000}, headers=headers)
    if hg_response and hg_response.status_code == 200:
        for hg in hg_response.json().get('results', []):
            hg_name = hg.get('name')
            if hg_name:
                cache_key = f"{hg_name}_{zabbix_server_id}"
                ZABBIX_HOSTGROUPS_CACHE[cache_key] = hg['id']
        print(f"  ✓ Loaded {len(ZABBIX_HOSTGROUPS_CACHE)} host groups")
    print()


def main():
    """Main execution function"""
    try:
        # Query devices
        print("🔍 Fetching devices from NetBox...")
        filters = {}

        # Specific device overrides primary IPv4 filtering.
        if args.device_id:
            filters['id'] = args.device_id
        elif args.device_name:
            filters['name'] = args.device_name

        devices, err = fetch_devices(filters)
        if err:
            print(f"❌ {err}")
            sys.exit(1)

        if not args.device_id and not args.device_name:
            total_before = len(devices)
            devices = [d for d in devices if d.get('primary_ip4')]
            print(f"✓ Found {total_before} device(s); {len(devices)} with Primary IPv4 set")
        
        if not devices:
            print("⚠️  No devices found matching criteria")
            sys.exit(0)

        if args.device_id or args.device_name:
            print(f"✓ Found {len(devices)} device(s)")
        
        # Limit devices if requested
        if args.limit:
            devices = devices[:args.limit]
            print(f"⚠️  Processing limited to {len(devices)} device(s)")
        
        # Load caches before processing (get Zabbix server ID from first device or config group)
        if devices:
            # Get Zabbix server ID from config group
            zabbix_server_id = get_zabbix_server_from_config_group(args.config_group_id)
            if zabbix_server_id:
                load_caches(zabbix_server_id)
        
        # Process devices
        if args.parallel > 1:
            print(f"⚡ Processing with {args.parallel} parallel workers\n")
            with ThreadPoolExecutor(max_workers=args.parallel) as executor:
                futures = {executor.submit(process_device, device): device for device in devices}
                for future in as_completed(futures):
                    device = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        print(f"❌ Error processing device {device.get('name')}: {e}")
                        capture_exception(
                            e,
                            script='nbsync-helper.py',
                            device=device.get('name'),
                            service='nbsync',
                        )
        else:
            # Sequential processing with delay between devices
            for i, device in enumerate(devices):
                try:
                    process_device(device)
                    # Add delay between devices (except after the last one)
                    if i < len(devices) - 1 and args.delay > 0:
                        time.sleep(args.delay)
                except Exception as e:
                    print(f"❌ Error processing device {device.get('name')}: {e}")
                    capture_exception(
                        e,
                        script='nbsync-helper.py',
                        device=device.get('name'),
                        service='nbsync',
                    )
                    continue
        
        print("\n" + "=" * 80)
        print("✅ All devices processed successfully")
        print("=" * 80)
        
        if not args.dry_run:
            print("\n💡 Next steps:")
            print("   1. Run 'nbxsync sync' to sync devices to Zabbix")
            print("   2. Verify devices appear in Zabbix UI")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        capture_exception(e, script='nbsync-helper.py', service='nbsync', route='main')
        sys.exit(1)


if __name__ == "__main__":
    main()
