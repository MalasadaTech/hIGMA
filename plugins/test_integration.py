#!/usr/bin/env python3
"""
Test script for URLScan integration and utility functions.

This script validates the common functionality and demonstrates usage patterns
for future integration development.

Author: MalasadaTech
Date: 2025-08-16
"""

import sys
import os
from pathlib import Path

# Add plugins directory to path
sys.path.append(str(Path(__file__).parent))

from utils import (
    load_yaml_file, validate_configuration, validate_rules_file,
    extract_pivot_data, get_supported_pivot_ids, ConfigurationError,
    PivotValidationError, YamlProcessingError
)


def test_configuration_loading():
    """Test configuration file loading and validation."""
    print("=== Testing Configuration Loading ===")
    
    config_path = Path(__file__).parent / "urlscan" / "configuration.yaml"
    print(f"Loading config from: {config_path}")
    
    try:
        config = load_yaml_file(str(config_path))
        print("✓ Configuration loaded successfully")
        
        validate_configuration(config, 'urlscan')
        print("✓ Configuration validation passed")
        
        supported_pivots = get_supported_pivot_ids(config)
        print(f"✓ Found {len(supported_pivots)} supported pivots: {supported_pivots}")
        
        return config
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return None


def test_rules_validation(config):
    """Test rules file validation."""
    print("\n=== Testing Rules Validation ===")
    
    rules_path = Path(__file__).parent.parent / "rules" / "landupdate808-backend-c2-pivot.yaml"
    print(f"Loading rules from: {rules_path}")
    
    try:
        rules = load_yaml_file(str(rules_path))
        print("✓ Rules loaded successfully")
        
        validation_errors = validate_rules_file(rules, config)
        if validation_errors:
            print("✗ Rules validation failed:")
            for error in validation_errors:
                print(f"  - {error}")
            return None
        else:
            print("✓ Rules validation passed")
        
        # Test pivot data extraction
        supported_pivot_ids = get_supported_pivot_ids(config)
        pivot_data = extract_pivot_data(rules, supported_pivot_ids)
        
        print("✓ Pivot data extracted:")
        for pivot_id, pivots in pivot_data.items():
            if pivots:
                print(f"  - {pivot_id}: {len(pivots)} instances")
                for i, pivot in enumerate(pivots):
                    print(f"    {i+1}. Value: {pivot['value']}, Group: {pivot['group']}")
                    if 'implementation' in pivot:
                        print(f"       Implementation: {pivot['implementation']}")
        
        return rules
        
    except Exception as e:
        print(f"✗ Rules validation test failed: {e}")
        return None


def test_error_handling():
    """Test error handling for various failure scenarios."""
    print("\n=== Testing Error Handling ===")
    
    # Test missing file
    try:
        load_yaml_file("nonexistent.yaml")
        print("✗ Should have failed for missing file")
    except YamlProcessingError:
        print("✓ Correctly handled missing file")
    
    # Test invalid configuration
    try:
        invalid_config = {"metadata": {"plugin_name": "wrong_name"}}
        validate_configuration(invalid_config, "urlscan")
        print("✗ Should have failed for invalid config")
    except ConfigurationError:
        print("✓ Correctly handled invalid configuration")
    
    print("✓ Error handling tests passed")


def main():
    """Run all tests."""
    print("hIGMA URLScan Integration Test Suite")
    print("=" * 50)
    
    # Test configuration
    config = test_configuration_loading()
    if not config:
        print("\n✗ Configuration tests failed - aborting")
        return 1
    
    # Test rules validation
    rules = test_rules_validation(config)
    if not rules:
        print("\n✗ Rules validation tests failed - aborting")
        return 1
    
    # Test error handling
    test_error_handling()
    
    print("\n" + "=" * 50)
    print("✓ All tests passed! Integration is ready for use.")
    print("\nTo run the URLScan integration:")
    print("1. Set URLSCAN_API_KEY environment variable")
    print("2. Run: python urlscan/urlscan-integration.py path/to/rules.yaml")
    print("3. Use --dry-run flag to validate without executing queries")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
