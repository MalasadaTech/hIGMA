#!/usr/bin/env python3
"""
Debug script to examine the exact YAML structure
"""

import yaml
import json
from pathlib import Path

rules_path = Path(__file__).parent.parent / "rules" / "landupdate808-backend-c2-pivot.yaml"

with open(rules_path, 'r', encoding='utf-8') as f:
    rules = yaml.safe_load(f)

print("=== Pivots section structure ===")
print(json.dumps(rules['pivots'], indent=2))

print("\n=== Analysis of each group ===")
for group_name, pivot_list in rules['pivots'].items():
    print(f"\nGroup: {group_name}")
    print(f"Type: {type(pivot_list)}")
    if isinstance(pivot_list, list):
        for i, item in enumerate(pivot_list):
            print(f"  Item {i}: {type(item)}")
            if isinstance(item, dict):
                for key, value in item.items():
                    print(f"    Key: '{key}' -> Type: {type(value)}, Value: {value}")
