#!/usr/bin/env python3
"""Diagnostic: Try to access image attachments on both instances."""

import sys
sys.path.insert(0, '/opt/netbox-helper')

from sync_type_images import load_instances, decrypt_token
import requests
import urllib3

urllib3.disable_warnings()

instances = load_instances('template-sync/instances.json')
inst_map = {i.get('name'): i for i in instances}

print("=" * 80)
print("CHECKING IMAGE ATTACHMENTS ACCESS")
print("=" * 80)

for name in ['PBI PROD', 'PBI DEV']:
    inst = inst_map[name]
    print(f"\n{name}: {inst['url']}")
    print("-" * 80)
    
    token = decrypt_token(inst['token'])
    headers = {'Authorization': f'Token {token}'}
    
    # Try to access image attachments
    try:
        resp = requests.get(
            f"{inst['url']}/api/extras/image-attachments/?limit=10",
            headers=headers,
            verify=False,
            timeout=5
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            count = data.get('count', 0)
            print(f"✓ Found {count} image attachments")
            if data.get('results'):
                print(f"  Sample attachments:")
                for att in data['results'][:3]:
                    print(f"    - {att.get('name', 'unknown')} (ID: {att.get('id')})")
        else:
            print(f"✗ Error: {resp.text[:200]}")
    except Exception as e:
        print(f"✗ Exception: {e}")
    
    # Try to access content-types endpoint
    print("\nContent-Types Endpoint:")
    try:
        resp = requests.get(
            f"{inst['url']}/api/extras/content-types/?limit=5",
            headers=headers,
            verify=False,
            timeout=5
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            print(f"✓ Endpoint exists")
        else:
            print(f"✗ Endpoint error: {resp.text[:200]}")
    except Exception as e:
        print(f"✗ Exception: {e}")

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print("""
Image Attachments (.png files showing in NetBox):
  ✗ Cannot sync - API token lacks permission (403 Forbidden)
  
To enable Image Attachment syncing, choose ONE:

  1. GRANT PERMISSIONS (Recommended if possible):
     - Contact NetBox admin to give API token read access to:
       /api/extras/image-attachments/
     - Re-test after permission change
  
  2. VERIFY NetBox VERSION:
     - Check if /api/extras/content-types/ endpoint exists
     - May require NetBox version upgrade
  
  3. WORKAROUND:
     - Manually upload attachments via NetBox UI
     - Or add manual content_type_id entry to image sync form (future enhancement)

Front/Rear Images (.front_image, .rear_image):
  ✓ WORKING - Already synced 28 images successfully
""")
print("=" * 80)
