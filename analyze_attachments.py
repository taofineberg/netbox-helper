#!/usr/bin/env python3
"""Check image attachment structure to find content_type_id pattern."""

import sys
sys.path.insert(0, '/opt/netbox-helper')

from sync_type_images import load_instances, decrypt_token, api_get_all, Instance
import json

instances = load_instances('template-sync/instances.json')
inst_map = {i.get('name'): i for i in instances}
prod = inst_map['PBI PROD']

src = Instance(
    url=prod['url'],
    token=decrypt_token(prod['token']),
    verify=False,
)

print("=" * 80)
print("IMAGE ATTACHMENT STRUCTURE ANALYSIS")
print("=" * 80)

try:
    attachments = api_get_all(src, "extras/image-attachments", params={"limit": 10})
    print(f"\nFound {len(attachments)} attachments\n")
    
    if attachments:
        print("First attachment structure:")
        att = attachments[0]
        print(json.dumps(att, indent=2))
        
        print("\n" + "-" * 80)
        print("Content-Type Info:")
        if 'content_type' in att:
            print(f"  content_type: {att['content_type']}")
        if 'object' in att:
            print(f"  object: {att['object']}")
        if 'object_id' in att:
            print(f"  object_id: {att['object_id']}")
        
        # Check if we can find devicetype references
        print("\nChecking all attachments for object references:")
        devicetype_count = 0
        moduletype_count = 0
        for a in attachments:
            if 'object' in a:
                if 'device-type' in str(a.get('object', '')).lower():
                    devicetype_count += 1
                if 'module-type' in str(a.get('object', '')).lower():
                    moduletype_count += 1
        
        print(f"  Device-Type attachments: {devicetype_count}")
        print(f"  Module-Type attachments: {moduletype_count}")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
