#!/usr/bin/env python3
"""
hIGMA Plugin Utilities

Common utilities and functions shared across all hIGMA plugin integrations.
This module provides standardized functionality for:
- Argument parsing
- Configuration validation
- YAML file processing
- Pivot validation
- Common data structures and error handling

Author: MalasadaTech
Date: 2025-08-16
Version: 1.0
"""

import argparse
import yaml
import sys
import os
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path


class HigmaError(Exception):
    """Base exception class for hIGMA-related errors."""
    pass


class ConfigurationError(HigmaError):
    """Raised when there are configuration-related errors."""
    pass


class PivotValidationError(HigmaError):
    """Raised when pivot validation fails."""
    pass


class YamlProcessingError(HigmaError):
    """Raised when YAML file processing fails."""
    pass


def setup_logging(debug: bool = False) -> logging.Logger:
    """
    Set up logging configuration for hIGMA plugins.
    
    Args:
        debug (bool): Enable debug logging level
        
    Returns:
        logging.Logger: Configured logger instance
    """
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger('hIGMA')


def parse_common_arguments(prog_name: str, description: str) -> argparse.ArgumentParser:
    """
    Create a standardized argument parser for hIGMA plugins.
    
    Args:
        prog_name (str): Name of the program/plugin
        description (str): Description of the plugin
        
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'yaml_file',
        help='Path to the hIGMA YAML file containing pivot rules'
    )
    
    parser.add_argument(
        '-c', '--config',
        default='configuration.yaml',
        help='Path to the plugin configuration file (default: configuration.yaml)'
    )
    
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: auto-generated filename in output/ folder)'
    )
    
    parser.add_argument(
        '--format',
        choices=['yaml', 'json', 'csv'],
        default='yaml',
        help='Output format (default: yaml)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate configuration and pivots without executing queries'
    )
    
    return parser


def load_yaml_file(file_path: str) -> Dict[str, Any]:
    """
    Load and parse a YAML file with error handling.
    
    Args:
        file_path (str): Path to the YAML file
        
    Returns:
        Dict[str, Any]: Parsed YAML content
        
    Raises:
        YamlProcessingError: If file cannot be loaded or parsed
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            raise YamlProcessingError(f"YAML file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f)
            
        if content is None:
            raise YamlProcessingError(f"YAML file is empty: {file_path}")
            
        return content
        
    except yaml.YAMLError as e:
        raise YamlProcessingError(f"Error parsing YAML file {file_path}: {e}")
    except Exception as e:
        raise YamlProcessingError(f"Error loading YAML file {file_path}: {e}")


def validate_configuration(config: Dict[str, Any], plugin_name: str) -> bool:
    """
    Validate the plugin configuration structure.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary
        plugin_name (str): Expected plugin name
        
    Returns:
        bool: True if configuration is valid
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Check required top-level sections
    required_sections = ['metadata', 'supported-pivots']
    for section in required_sections:
        if section not in config:
            raise ConfigurationError(f"Missing required section: {section}")
    
    # Validate metadata
    metadata = config['metadata']
    required_metadata = ['plugin_name', 'version', 'description']
    for field in required_metadata:
        if field not in metadata:
            raise ConfigurationError(f"Missing required metadata field: {field}")
    
    # Validate plugin name matches
    if metadata['plugin_name'] != plugin_name:
        raise ConfigurationError(
            f"Plugin name mismatch: expected '{plugin_name}', "
            f"got '{metadata['plugin_name']}'"
        )
    
    # Validate supported pivots structure
    supported_pivots = config['supported-pivots']
    if not isinstance(supported_pivots, list) or len(supported_pivots) == 0:
        raise ConfigurationError("supported-pivots must be a non-empty list")
    
    for i, pivot in enumerate(supported_pivots):
        if not isinstance(pivot, dict):
            raise ConfigurationError(f"Pivot {i} must be a dictionary")
        
        required_pivot_fields = ['id', 'name', 'description', 'input_type']
        for field in required_pivot_fields:
            if field not in pivot:
                raise ConfigurationError(
                    f"Pivot {i} missing required field: {field}"
                )
    
    return True


def get_supported_pivot_ids(config: Dict[str, Any]) -> List[str]:
    """
    Extract list of supported pivot IDs from configuration.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary
        
    Returns:
        List[str]: List of supported pivot IDs
    """
    return [pivot['id'] for pivot in config['supported-pivots']]


def validate_pivot_in_rules(pivot_id: str, pivot_data: Dict[str, Any], 
                          supported_pivots: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """
    Validate that a pivot from the rules file is supported by the plugin.
    
    Args:
        pivot_id (str): The pivot ID to validate
        pivot_data (Dict[str, Any]): The pivot data from rules file
        supported_pivots (List[Dict[str, Any]]): List of supported pivots from config
        
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    # Find the pivot configuration
    pivot_config = None
    for pivot in supported_pivots:
        if pivot['id'] == pivot_id:
            pivot_config = pivot
            break
    
    if not pivot_config:
        return False, f"Pivot {pivot_id} is not supported by this plugin"
    
    # Validate required fields in pivot data
    if 'value' not in pivot_data:
        return False, f"Pivot {pivot_id} missing required 'value' field"
    
    # Validate input type if specified
    expected_type = pivot_config.get('input_type')
    if expected_type:
        value = pivot_data['value']
        
        # Type validation with some flexibility for common conversions
        if expected_type == 'string':
            # Accept strings or convert numbers to strings for ASN-like values
            if not isinstance(value, (str, int, float)):
                return False, f"Pivot {pivot_id} value must be convertible to string"
        elif expected_type in ['number', 'integer']:
            if not isinstance(value, (int, float)):
                # Try to convert string to number
                if isinstance(value, str):
                    try:
                        if expected_type == 'integer':
                            int(value)
                        else:
                            float(value)
                    except ValueError:
                        return False, f"Pivot {pivot_id} value must be a {expected_type} or numeric string"
                else:
                    return False, f"Pivot {pivot_id} value must be a {expected_type}"
    
    # Validate implementation field for pivots that require it
    conditions = pivot_config.get('conditions', [])
    for condition in conditions:
        condition_lower = condition.lower()
        
        # Check for implementation field requirement
        if 'implementation field must specify' in condition_lower:
            if 'implementation' not in pivot_data:
                return False, f"Pivot {pivot_id} missing required 'implementation' field"
        
        # Check for supported hash types
        if 'supported hash types' in condition_lower and 'implementation' in pivot_data:
            # Extract supported hash types from condition
            # Format: "supported hash types for urlscan: SHA256"
            if ':' in condition:
                supported_types_part = condition.split(':')[1].strip()
                supported_types = [t.strip() for t in supported_types_part.split(',')]
                
                implementation = pivot_data['implementation'].upper()
                supported_types_upper = [t.upper() for t in supported_types]
                
                if implementation not in supported_types_upper:
                    return False, f"Pivot {pivot_id} implementation '{pivot_data['implementation']}' not supported. Supported types: {', '.join(supported_types)}"
    
    return True, ""


def validate_rules_file_permissive(rules: Dict[str, Any], config: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Validate the hIGMA rules file against the plugin configuration with permissive mode.
    Returns both errors (critical issues) and warnings (non-critical issues).
    
    Args:
        rules (Dict[str, Any]): Parsed rules file content
        config (Dict[str, Any]): Plugin configuration
        
    Returns:
        Tuple[List[str], List[str]]: (errors, warnings)
    """
    errors = []
    warnings = []
    
    # Check required top-level fields
    required_fields = ['title', 'id', 'author', 'pivots']
    for field in required_fields:
        if field not in rules:
            errors.append(f"Missing required field: {field}")
    
    if 'pivots' not in rules:
        return errors, warnings  # Can't validate pivots if section is missing
    
    # Get supported pivots
    supported_pivots = config['supported-pivots']
    
    # Validate each pivot group
    for group_name, pivot_list in rules['pivots'].items():
        if not isinstance(pivot_list, list):
            errors.append(f"Pivot group '{group_name}' must be a list")
            continue
        
        for i, pivot_item in enumerate(pivot_list):
            if not isinstance(pivot_item, dict):
                errors.append(f"Pivot item {i} in group '{group_name}' must be a dictionary")
                continue
            
            # Find the pivot ID (key with None value) and extract parameters
            pivot_id = None
            pivot_data = {}
            
            for key, value in pivot_item.items():
                if value is None and key.startswith('P'):
                    pivot_id = key
                else:
                    pivot_data[key] = value
            
            if not pivot_id:
                errors.append(f"Pivot item {i} in group '{group_name}' missing pivot ID")
                continue
            
            # Validate the pivot - but treat hash type issues as warnings
            is_valid, error_msg = validate_pivot_in_rules(pivot_id, pivot_data, supported_pivots)
            if not is_valid:
                # Check if this is a hash type issue (warning) or critical error
                if 'implementation' in error_msg and 'not supported' in error_msg:
                    warnings.append(f"Group '{group_name}', item {i}: {error_msg}")
                else:
                    errors.append(f"Group '{group_name}', item {i}: {error_msg}")
    
    return errors, warnings


def validate_rules_file(rules: Dict[str, Any], config: Dict[str, Any]) -> List[str]:
    """
    Validate the hIGMA rules file against the plugin configuration.
    
    Args:
        rules (Dict[str, Any]): Parsed rules file content
        config (Dict[str, Any]): Plugin configuration
        
    Returns:
        List[str]: List of validation errors (empty if valid)
    """
    errors = []
    
    # Check required top-level fields
    required_fields = ['title', 'id', 'author', 'pivots']
    for field in required_fields:
        if field not in rules:
            errors.append(f"Missing required field: {field}")
    
    if 'pivots' not in rules:
        return errors  # Can't validate pivots if section is missing
    
    # Get supported pivots
    supported_pivots = config['supported-pivots']
    
    # Validate each pivot group
    for group_name, pivot_list in rules['pivots'].items():
        if not isinstance(pivot_list, list):
            errors.append(f"Pivot group '{group_name}' must be a list")
            continue
        
        for i, pivot_item in enumerate(pivot_list):
            if not isinstance(pivot_item, dict):
                errors.append(f"Pivot item {i} in group '{group_name}' must be a dictionary")
                continue
            
            # Find the pivot ID (key with None value) and extract parameters
            pivot_id = None
            pivot_data = {}
            
            for key, value in pivot_item.items():
                if value is None and key.startswith('P'):
                    # This is likely the pivot ID
                    pivot_id = key
                else:
                    # This is a parameter
                    pivot_data[key] = value
            
            if not pivot_id:
                errors.append(f"Pivot item {i} in group '{group_name}' missing pivot ID (key with None value)")
                continue
            
            # Validate the pivot
            is_valid, error_msg = validate_pivot_in_rules(pivot_id, pivot_data, supported_pivots)
            if not is_valid:
                errors.append(f"Group '{group_name}', item {i}, pivot {pivot_id}: {error_msg}")
    
    return errors


def extract_pivot_data(rules: Dict[str, Any], supported_pivot_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract and organize pivot data from rules file for processing.
    
    Args:
        rules (Dict[str, Any]): Parsed rules file content
        supported_pivot_ids (List[str]): List of pivot IDs supported by the plugin
        
    Returns:
        Dict[str, List[Dict[str, Any]]]: Organized pivot data by pivot ID
    """
    pivot_data = {pivot_id: [] for pivot_id in supported_pivot_ids}
    
    if 'pivots' not in rules:
        return pivot_data
    
    for group_name, pivot_list in rules['pivots'].items():
        if not isinstance(pivot_list, list):
            continue
        
        for pivot_item in pivot_list:
            if not isinstance(pivot_item, dict):
                continue
            
            # Find the pivot ID (key with None value) and extract parameters
            pivot_id = None
            pivot_params = {}
            
            for key, value in pivot_item.items():
                if value is None and key.startswith('P'):
                    # This is likely the pivot ID
                    pivot_id = key
                else:
                    # This is a parameter
                    pivot_params[key] = value
            
            if pivot_id and pivot_id in supported_pivot_ids:
                pivot_info = pivot_params.copy()
                pivot_info['group'] = group_name
                pivot_data[pivot_id].append(pivot_info)
    
    return pivot_data


def find_configuration_file(config_path: str, plugin_dir: str) -> str:
    """
    Find the configuration file, checking both relative and absolute paths.
    
    Args:
        config_path (str): Provided configuration file path
        plugin_dir (str): Directory containing the plugin
        
    Returns:
        str: Absolute path to configuration file
        
    Raises:
        ConfigurationError: If configuration file cannot be found
    """
    # Try the provided path as-is first
    if os.path.isabs(config_path):
        if os.path.exists(config_path):
            return config_path
    else:
        # Try relative to plugin directory
        plugin_config = os.path.join(plugin_dir, config_path)
        if os.path.exists(plugin_config):
            return plugin_config
        
        # Try relative to current working directory
        if os.path.exists(config_path):
            return os.path.abspath(config_path)
    
    raise ConfigurationError(f"Configuration file not found: {config_path}")


def print_validation_summary(rules: Dict[str, Any], config: Dict[str, Any], 
                           supported_pivot_ids: List[str], logger: logging.Logger) -> None:
    """
    Print a summary of the validation results.
    
    Args:
        rules (Dict[str, Any]): Parsed rules file content
        config (Dict[str, Any]): Plugin configuration
        supported_pivot_ids (List[str]): List of supported pivot IDs
        logger (logging.Logger): Logger instance
    """
    logger.info(f"=== Validation Summary ===")
    logger.info(f"Rules file: {rules.get('title', 'Unknown')}")
    logger.info(f"Plugin: {config['metadata']['plugin_name']} v{config['metadata']['version']}")
    logger.info(f"Supported pivots: {len(supported_pivot_ids)}")
    
    # Count pivots by type
    pivot_data = extract_pivot_data(rules, supported_pivot_ids)
    total_pivots = sum(len(pivots) for pivots in pivot_data.values())
    logger.info(f"Total pivot instances found: {total_pivots}")
    
    for pivot_id, pivots in pivot_data.items():
        if pivots:
            logger.info(f"  {pivot_id}: {len(pivots)} instances")


def handle_common_errors(func):
    """
    Decorator to handle common hIGMA exceptions and provide user-friendly error messages.
    
    Args:
        func: Function to wrap
        
    Returns:
        Wrapped function with error handling
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ConfigurationError as e:
            print(f"Configuration Error: {e}", file=sys.stderr)
            sys.exit(1)
        except PivotValidationError as e:
            print(f"Pivot Validation Error: {e}", file=sys.stderr)
            sys.exit(1)
        except YamlProcessingError as e:
            print(f"YAML Processing Error: {e}", file=sys.stderr)
            sys.exit(1)
        except HigmaError as e:
            print(f"hIGMA Error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    return wrapper
