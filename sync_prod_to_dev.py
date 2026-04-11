#!/usr/bin/env python3
"""Run actual image sync from PBI PROD to PBI DEV."""

import sys
sys.path.insert(0, '/opt/netbox-helper')

from sync_type_images import (
    load_instances,
    decrypt_token,
    Instance,
    sync_type_images,
)
import urllib3

urllib3.disable_warnings()

print("=" * 80)
print("RUNNING IMAGE SYNC: PBI PROD → PBI DEV (LIVE)")
print("=" * 80)

# Load instances
instances = load_instances('template-sync/instances.json')
inst_map = {i.get('name'): i for i in instances}

prod = inst_map['PBI PROD']
dev = inst_map['PBI DEV']

print(f"\nSource (PROD):  {prod.get('url')}")
print(f"Dest (DEV):     {dev.get('url')}")

# Create Instance objects
src = Instance(
    url=prod['url'],
    token=decrypt_token(prod['token']),
    verify=False,
)

dst = Instance(
    url=dev['url'],
    token=decrypt_token(dev['token']),
    verify=False,
)

print("\n" + "=" * 80)
print("SYNCING: Device Types + Module Types")
print("=" * 80)

try:
    count = sync_type_images(
        source=src,
        dest=dst,
        sync_device_types=True,
        sync_module_types=True,
        dry_run=False,  # ACTUAL SYNC
    )
    print(f"\n✓ SYNC COMPLETE: {count} images synced to DEV")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
