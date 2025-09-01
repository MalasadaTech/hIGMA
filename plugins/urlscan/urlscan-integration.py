#!/usr/bin/env python3
"""
URLScan.io Query Builder for hIGMA

This plugin generates URLScan.io search queries based on pivots defined in hIGMA rules files.
It outputs structured JSON containing the queries that can be executed by other tools.

Author: MalasadaTech
Dat    # Initialize query builder and process rules
    query_builder = URLScanQueryBuilder(config, args.debug)
    results = query_builder.process_rules(rules)
    
    # Determine output path
    if args.output:
        output_path = args.output
    else:
        # Generate automatic filename: YYYYMMDD-HHMMSS-{yaml_filename}.json
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        yaml_filename = Path(args.yaml_file).stem  # Get filename without extension
        filename = f"{timestamp}-{yaml_filename}.json"
        
        # Use output folder in plugin directory
        plugin_dir = Path(__file__).parent
        output_dir = plugin_dir / "output"
        output_dir.mkdir(exist_ok=True)  # Ensure output directory exists
        output_path = output_dir / filename
    
    # Output results
    output_data = json.dumps(results, indent=2, ensure_ascii=False)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(output_data)
    logger.info(f"Queries written to: {output_path}")
Version: 1.0

Supported Pivots:
- P0201: Reverse lookup (IP address)
- P0203: Network ASN pivots
- P0401.001: HTTP page title analysis
- P0401.004: HTTP same resources (hash-based)
- P0401.006: HTTP same resource name
- P0401.007: HTTP response code analysis
"""

import json
import sys
import time
import os
from typing import Dict, List, Any, Tuple
from pathlib import Path
from datetime import datetime
import yaml

# Import common utilities
sys.path.append(str(Path(__file__).parent.parent))
from utils import (
    setup_logging, parse_common_arguments, load_yaml_file, validate_configuration,
    validate_rules_file, validate_rules_file_permissive, extract_pivot_data, get_supported_pivot_ids,
    find_configuration_file, print_validation_summary, handle_common_errors,
    validate_pivot_in_rules, PivotValidationError
)


class URLScanQueryBuilder:
    """Query builder for URLScan.io searches."""
    
    def __init__(self, config: Dict[str, Any], debug: bool = False):
        """
        Initialize URLScan query builder.
        
        Args:
            config (Dict[str, Any]): Plugin configuration
            debug (bool): Enable debug logging
        """
        self.config = config
        self.logger = setup_logging(debug)
        self.supported_pivots = get_supported_pivot_ids(config)
        
    def build_ip_query(self, ip_value: str) -> str:
        """
        Build URLScan query for IP reverse lookup pivot (P0201).
        
        Args:
            ip_value (str): IP address
            
        Returns:
            str: URLScan query string
        """
        # Simple validation that it looks like an IP address
        import re
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if not re.match(ip_pattern, ip_value):
            raise PivotValidationError(f"Invalid IP address format: {ip_value}")

        return ip_value

    def build_asn_query(self, asn_value: str) -> str:
        """
        Build URLScan query for ASN pivot (P0203).
        
        Args:
            asn_value (str): ASN number
            
        Returns:
            str: URLScan query string
        """
        # Remove 'AS' prefix if present and validate
        asn_clean = asn_value.replace('AS', '').replace('as', '')
        try:
            int(asn_clean)  # Validate it's a number
        except ValueError:
            raise PivotValidationError(f"Invalid ASN format: {asn_value}")
        
        return f"page.asn:AS{asn_clean}"
    
    def build_hash_query(self, hash_value: str, hash_type: str) -> str:
        """
        Build URLScan query for resource hash pivot (P0401.004).
        
        Args:
            hash_value (str): Hash value
            hash_type (str): Hash type (SHA256, SSDEEP, etc.)
            
        Returns:
            str: URLScan query string
        """
        if hash_type.upper() == 'SHA256':
            return f"hash:{hash_value}"
        else:
            raise PivotValidationError(f"Unsupported hash type for URLScan: {hash_type}. Only SHA256 is supported.")
    
    def build_resource_name_query(self, resource_name: str) -> str:
        """
        Build URLScan query for resource name pivot (P0401.006).
        
        Args:
            resource_name (str): Resource filename
            
        Returns:
            str: URLScan query string
        """
        return f"task.url:\"{resource_name}\""
    
    def build_response_code_query(self, response_code: int) -> str:
        """
        Build URLScan query for HTTP response code pivot (P0401.007).
        
        Args:
            response_code (int): HTTP response code
            
        Returns:
            str: URLScan query string
        """
        return f"page.status:{response_code}"
    
    def build_title_query(self, title: str) -> str:
        """
        Build URLScan query for page title pivot (P0401.001).
        
        Args:
            title (str): Page title to search for
            
        Returns:
            str: URLScan query string
        """
        return f'page.title:"{title}"'
    
    def build_pivot_query(self, pivot_id: str, pivot_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a query for a single pivot.
        
        Args:
            pivot_id (str): Pivot identifier
            pivot_data (Dict[str, Any]): Pivot parameters
            
        Returns:
            Dict[str, Any]: Query information with metadata
        """
        self.logger.info(f"Building query for pivot {pivot_id} with value: {pivot_data['value']}")
        
        # First validate the pivot against configuration conditions
        is_valid, validation_error = validate_pivot_in_rules(
            pivot_id, pivot_data, self.config['supported-pivots']
        )
        
        if not is_valid:
            self.logger.warning(f"Pivot validation failed for {pivot_id}: {validation_error}")
            return {
                'pivot_id': pivot_id,
                'value': pivot_data['value'],
                'implementation': pivot_data.get('implementation'),
                'query': None,
                'query_type': self._get_query_type(pivot_id),
                'status': 'validation_failed',
                'error_message': validation_error,
                'implementation_notes': f"Validation failed: {validation_error}"
            }
        
        try:
            # Build query based on pivot type
            if pivot_id == "P0201":
                query = self.build_ip_query(str(pivot_data['value']))
                query_type = "ip"
            elif pivot_id == "P0203":
                query = self.build_asn_query(str(pivot_data['value']))
                query_type = "asn"
            elif pivot_id == "P0401.001":
                query = self.build_title_query(str(pivot_data['value']))
                query_type = "title"
            elif pivot_id == "P0401.004":
                hash_type = pivot_data.get('implementation', 'SHA256')
                query = self.build_hash_query(str(pivot_data['value']), hash_type)
                query_type = "hash"
            elif pivot_id == "P0401.006":
                query = self.build_resource_name_query(str(pivot_data['value']))
                query_type = "url"
            elif pivot_id == "P0401.007":
                query = self.build_response_code_query(int(pivot_data['value']))
                query_type = "status"
            else:
                raise PivotValidationError(f"Unsupported pivot: {pivot_id}")
            
            self.logger.debug(f"Generated URLScan query: {query}")
            
            return {
                'pivot_id': pivot_id,
                'value': pivot_data['value'],
                'implementation': pivot_data.get('implementation'),
                'query': query,
                'query_type': query_type,
                'status': 'success',
                'implementation_notes': self._get_implementation_notes(pivot_id, pivot_data)
            }
            
        except Exception as e:
            self.logger.error(f"Error building query for pivot {pivot_id}: {e}")
            return {
                'pivot_id': pivot_id,
                'value': pivot_data['value'],
                'implementation': pivot_data.get('implementation'),
                'query': None,
                'query_type': self._get_query_type(pivot_id),
                'status': 'error',
                'error_message': str(e),
                'implementation_notes': f"Error occurred: {str(e)}"
            }
    
    def _get_query_type(self, pivot_id: str) -> str:
        """Get the query type for a pivot ID."""
        query_type_map = {
            "P0201": "ip",
            "P0203": "asn",
            "P0401.001": "title",
            "P0401.004": "hash", 
            "P0401.006": "url",
            "P0401.007": "status"
        }
        return query_type_map.get(pivot_id, "unknown")
    
    def _get_implementation_notes(self, pivot_id: str, pivot_data: Dict[str, Any]) -> str:
        """Get implementation notes for a pivot."""
        if pivot_id == "P0201":
            return "IP address mapped to URLScan IP field for reverse lookup"
        elif pivot_id == "P0401.004":
            hash_type = pivot_data.get('implementation', 'SHA256')
            if hash_type.upper() == 'SHA256':
                return "SHA256 hash mapped to URLScan hash field"
            else:
                return f"Hash type {hash_type} not supported by URLScan"
        elif pivot_id == "P0203":
            return "ASN mapped to URLScan page.asn field"
        elif pivot_id == "P0401.001":
            return "Page title mapped to URLScan page.title field"
        elif pivot_id == "P0401.006":
            return "Resource name mapped to URLScan task.url field"
        elif pivot_id == "P0401.007":
            return "HTTP status code mapped to URLScan page.status field"
        return "Standard mapping"
    
    def process_rules(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process all pivots in the rules file and generate queries.
        
        Args:
            rules (Dict[str, Any]): Parsed rules file
            
        Returns:
            Dict[str, Any]: Complete query set with metadata
        """
        self.logger.info(f"Processing rules: {rules.get('title', 'Unknown')}")
        
        # Extract pivot data
        pivot_data = extract_pivot_data(rules, self.supported_pivots)
        
        # Build all individual pivot queries
        all_pivot_queries = []
        total_pivots = sum(len(pivots) for pivots in pivot_data.values())
        current_pivot = 0
        
        for pivot_id, pivots in pivot_data.items():
            if not pivots:
                continue
                
            self.logger.info(f"Processing {len(pivots)} instances of pivot {pivot_id}")
            
            for pivot in pivots:
                current_pivot += 1
                self.logger.info(f"Building query {current_pivot}/{total_pivots}")
                
                query_info = self.build_pivot_query(pivot_id, pivot)
                all_pivot_queries.append(query_info)
        
        # Check for conditions in the rules
        condition = rules.get('condition')
        
        # Now process pivots by groups (e.g., ads_php, ads_panel_hash-01, etc.)
        queries = []
        failed_queries = []
        warnings = []
        pivot_ids_used = []
        
        # Group pivots by their rule names
        pivots_section = rules.get('pivots', {})
        
        # Handle condition-based query generation
        if condition and self._should_combine_queries(condition, pivots_section):
            combined_query_info = self._build_condition_based_query(condition, pivots_section, all_pivot_queries, rules)
            if combined_query_info:
                if combined_query_info['status'] == 'success':
                    queries.append(combined_query_info)
                    pivot_ids_used.extend(combined_query_info['pivot_ids'])
                else:
                    failed_queries.append({
                        'query_id': 'condition_based_query',
                        'pivot_ids': combined_query_info.get('pivot_ids', []),
                        'query_type': 'combined',
                        'error_message': combined_query_info.get('error_message', 'Unknown error'),
                        'implementation_notes': combined_query_info.get('implementation_notes', ''),
                        'description': f"Failed condition-based query: {condition}"
                    })
            return self._build_final_results(rules, queries, failed_queries, warnings, pivot_ids_used, all_pivot_queries)
        
        # Original group-based processing when no combining condition is present
        
        # Original group-based processing when no combining condition is present
        for pivot_group_name, pivot_group in pivots_section.items():
            group_queries = []
            group_failed = []
            group_pivot_ids = []
            
            # Process each pivot in this group
            for pivot_dict in pivot_group:
                # Extract pivot ID (the key that has None value)
                pivot_id = None
                pivot_spec = {}
                
                for key, value in pivot_dict.items():
                    if value is None and key.startswith('P'):
                        pivot_id = key
                    elif key in ['value', 'implementation']:
                        pivot_spec[key] = value
                
                if not pivot_id:
                    self.logger.warning(f"No pivot ID found in dict: {pivot_dict}")
                    continue
                
                # Find the corresponding processed query
                matching_query = None
                for pq in all_pivot_queries:
                    if (pq['pivot_id'] == pivot_id and 
                        str(pq['value']) == str(pivot_spec.get('value', ''))):
                        matching_query = pq
                        break
                
                if matching_query:
                    group_pivot_ids.append(pivot_id)
                    if matching_query['status'] == 'success':
                        group_queries.append(matching_query['query'])
                    else:
                        group_failed.append({
                            'pivot_id': pivot_id,
                            'value': matching_query['value'],
                            'error_message': matching_query.get('error_message', 'Unknown error'),
                            'implementation_notes': matching_query.get('implementation_notes', '')
                        })
                        if matching_query['status'] == 'validation_failed':
                            warnings.append(f"Pivot {pivot_id} validation failed: {matching_query.get('error_message', '')}")
                else:
                    self.logger.warning(f"No matching query found for {pivot_id}")
            
            # Create combined query if we have successful queries
            if group_queries:
                combined_query = " AND ".join(group_queries)
                
                # Determine query type based on pivot types
                query_types = list(set(q.get('query_type', 'unknown') for q in all_pivot_queries 
                                     if q['pivot_id'] in group_pivot_ids and q['status'] == 'success'))
                query_type = "combined" if len(query_types) > 1 else (query_types[0] if query_types else "unknown")
                
                try:
                    query_entry = {
                        'query_id': pivot_group_name,
                        'query': combined_query,
                        'pivot_ids': group_pivot_ids,
                        'query_type': query_type,
                        'description': self._generate_description(pivot_group_name, group_pivot_ids, rules),
                        'implementation_notes': self._generate_group_implementation_notes(group_pivot_ids, all_pivot_queries)
                    }
                    queries.append(query_entry)
                except Exception as e:
                    self.logger.error(f"Error creating query entry for {pivot_group_name}: {e}")
                    raise
                
                pivot_ids_used.extend(group_pivot_ids)
            
            # Add failed queries to the list
            if group_failed:
                for failed in group_failed:
                    try:
                        failed_queries.append({
                            'query_id': f"{pivot_group_name}_failed_{failed['pivot_id']}",
                            'pivot_ids': [failed['pivot_id']],
                            'query_type': self._get_query_type(failed['pivot_id']),
                            'error_message': failed['error_message'],
                            'implementation_notes': failed['implementation_notes'],
                            'description': f"Failed query for {pivot_group_name}"
                        })
                    except Exception as e:
                        self.logger.error(f"Error creating failed query entry: {e}")
                        raise
        
        return self._build_final_results(rules, queries, failed_queries, warnings, pivot_ids_used, all_pivot_queries)
    
    def _should_combine_queries(self, condition: str, pivots_section: Dict[str, Any]) -> bool:
        """
        Determine if queries should be combined based on the condition.
        
        Args:
            condition (str): The condition string from the rules
            pivots_section (Dict): The pivots section from the rules
            
        Returns:
            bool: True if queries should be combined
        """
        # Check for 'and' or 'or' conditions between named pivot groups
        if ' and ' in condition.lower() or ' or ' in condition.lower():
            # Check if the condition references pivot group names that exist
            pivot_group_names = list(pivots_section.keys())
            for group_name in pivot_group_names:
                if group_name in condition:
                    return True
        return False
    
    def _build_condition_based_query(self, condition: str, pivots_section: Dict[str, Any], 
                                   all_pivot_queries: List[Dict], rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a combined query based on the condition.
        
        Args:
            condition (str): The condition string from the rules
            pivots_section (Dict): The pivots section from the rules  
            all_pivot_queries (List[Dict]): All individual pivot queries
            rules (Dict): The full rules dictionary
            
        Returns:
            Dict[str, Any]: Combined query information
        """
        self.logger.info(f"Building condition-based query for: {condition}")
        
        # Parse simple 'and' conditions (e.g., "chrome_logo_png and chrome_logo_svg")
        if ' and ' in condition.lower():
            return self._build_and_condition_query(condition, pivots_section, all_pivot_queries, rules)
        
        # Parse simple 'or' conditions (e.g., "verification_ip or verification_title")  
        elif ' or ' in condition.lower():
            return self._build_or_condition_query(condition, pivots_section, all_pivot_queries, rules)
        
        # For other conditions, fall back to original behavior for now
        return None
    
    def _build_and_condition_query(self, condition: str, pivots_section: Dict[str, Any],
                                 all_pivot_queries: List[Dict], rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a combined query for 'and' conditions.
        
        Args:
            condition (str): The condition string containing 'and'
            pivots_section (Dict): The pivots section from the rules
            all_pivot_queries (List[Dict]): All individual pivot queries  
            rules (Dict): The full rules dictionary
            
        Returns:
            Dict[str, Any]: Combined query information
        """
        # Split condition by 'and' and clean up group names
        parts = [part.strip() for part in condition.split(' and ')]
        
        successful_queries = []
        failed_groups = []
        all_pivot_ids = []
        
        for group_name in parts:
            if group_name not in pivots_section:
                self.logger.warning(f"Pivot group '{group_name}' referenced in condition not found in pivots section")
                continue
                
            # Get queries for this group
            group_queries, group_failed, group_pivot_ids = self._get_group_queries(
                group_name, pivots_section[group_name], all_pivot_queries
            )
            
            if group_queries:
                # For hash queries, we want to combine the hash values, not the full queries
                if all(query.startswith('hash:') for query in group_queries):
                    # Extract hash values and combine them
                    hash_values = [query.replace('hash:', '') for query in group_queries]
                    if len(hash_values) == 1:
                        successful_queries.append(hash_values[0])
                    else:
                        # Multiple hashes in same group - this shouldn't happen normally but handle it
                        successful_queries.extend(hash_values)
                else:
                    # For non-hash queries, just add them as they are
                    successful_queries.extend(group_queries)
                all_pivot_ids.extend(group_pivot_ids)
            else:
                failed_groups.append(group_name)
        
        if not successful_queries:
            return {
                'status': 'error',
                'error_message': f"No successful queries found for condition: {condition}",
                'implementation_notes': f"All referenced groups failed: {', '.join(failed_groups)}"
            }
        
        # Build the combined query
        if all(any(q['pivot_id'] == 'P0401.004' for q in all_pivot_queries if q['value'] == hash_val) 
               for hash_val in successful_queries):
            # All queries are hash-based (P0401.004), combine them in URLScan hash syntax
            combined_query = f"hash:({' AND '.join(successful_queries)})"
        else:
            # Mix of different query types, use general AND syntax
            combined_query = ' AND '.join(successful_queries)
        
        self.logger.info(f"Generated combined query: {combined_query}")
        
        return {
            'query_id': f"condition_{condition.replace(' and ', '_and_').replace(' ', '_')}",
            'query': combined_query,
            'pivot_ids': list(set(all_pivot_ids)),
            'query_type': 'combined',
            'status': 'success',
            'description': f"Combined query based on condition: {condition}",
            'implementation_notes': f"Combined query using AND logic for: {', '.join(parts)}"
        }
    
    def _build_or_condition_query(self, condition: str, pivots_section: Dict[str, Any],
                                all_pivot_queries: List[Dict], rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a combined query for 'or' conditions.
        
        Args:
            condition (str): The condition string containing 'or'
            pivots_section (Dict): The pivots section from the rules
            all_pivot_queries (List[Dict]): All individual pivot queries  
            rules (Dict): The full rules dictionary
            
        Returns:
            Dict[str, Any]: Combined query information
        """
        # Split condition by 'or' and clean up group names
        parts = [part.strip() for part in condition.split(' or ')]
        
        successful_queries = []
        failed_groups = []
        all_pivot_ids = []
        
        for group_name in parts:
            if group_name not in pivots_section:
                self.logger.warning(f"Pivot group '{group_name}' referenced in condition not found in pivots section")
                continue
                
            # Get queries for this group
            group_queries, group_failed, group_pivot_ids = self._get_group_queries(
                group_name, pivots_section[group_name], all_pivot_queries
            )
            
            if group_queries:
                # For OR conditions, we want to keep the full query syntax for each part
                successful_queries.extend(group_queries)
                all_pivot_ids.extend(group_pivot_ids)
            else:
                failed_groups.append(group_name)
        
        if not successful_queries:
            return {
                'status': 'error',
                'error_message': f"No successful queries found for condition: {condition}",
                'implementation_notes': f"All referenced groups failed: {', '.join(failed_groups)}"
            }
        
        # Build the combined OR query
        # For OR conditions, we join the full queries with " OR "
        combined_query = ' OR '.join(successful_queries)
        
        self.logger.info(f"Generated combined OR query: {combined_query}")
        
        return {
            'query_id': f"condition_{condition.replace(' or ', '_or_').replace(' ', '_')}",
            'query': combined_query,
            'pivot_ids': list(set(all_pivot_ids)),
            'query_type': 'combined',
            'status': 'success',
            'description': f"Combined query based on condition: {condition}",
            'implementation_notes': f"Combined query using OR logic for: {', '.join(parts)}"
        }
    
    def _get_group_queries(self, group_name: str, pivot_group: List[Dict], 
                          all_pivot_queries: List[Dict]) -> Tuple[List[str], List[Dict], List[str]]:
        """
        Get queries for a specific pivot group.
        
        Args:
            group_name (str): Name of the pivot group
            pivot_group (List[Dict]): The pivot group definition
            all_pivot_queries (List[Dict]): All individual pivot queries
            
        Returns:
            Tuple[List[str], List[Dict], List[str]]: successful queries, failed queries, pivot IDs
        """
        group_queries = []
        group_failed = []
        group_pivot_ids = []
        
        for pivot_dict in pivot_group:
            # Extract pivot ID and spec
            pivot_id = None
            pivot_spec = {}
            
            for key, value in pivot_dict.items():
                if value is None and key.startswith('P'):
                    pivot_id = key
                elif key in ['value', 'implementation']:
                    pivot_spec[key] = value
            
            if not pivot_id:
                continue
                
            # Find matching query
            matching_query = None
            for pq in all_pivot_queries:
                if (pq['pivot_id'] == pivot_id and 
                    str(pq['value']) == str(pivot_spec.get('value', ''))):
                    matching_query = pq
                    break
            
            if matching_query:
                group_pivot_ids.append(pivot_id)
                if matching_query['status'] == 'success':
                    group_queries.append(matching_query['query'])
                else:
                    group_failed.append({
                        'pivot_id': pivot_id,
                        'value': matching_query['value'],
                        'error_message': matching_query.get('error_message', 'Unknown error'),
                        'implementation_notes': matching_query.get('implementation_notes', '')
                    })
        
        return group_queries, group_failed, group_pivot_ids
    
    def _build_final_results(self, rules: Dict[str, Any], queries: List[Dict], 
                           failed_queries: List[Dict], warnings: List[str], 
                           pivot_ids_used: List[str], all_pivot_queries: List[Dict]) -> Dict[str, Any]:
        """
        Build the final results dictionary.
        
        Args:
            rules (Dict): The rules dictionary
            queries (List[Dict]): Successful queries
            failed_queries (List[Dict]): Failed queries
            warnings (List[str]): Warnings list
            pivot_ids_used (List[str]): Pivot IDs used
            all_pivot_queries (List[Dict]): All pivot queries
            
        Returns:
            Dict[str, Any]: Final results structure
        """
        # Remove duplicates from pivot_ids_used and sort numerically
        pivot_ids_used = list(set(pivot_ids_used))
        # Sort pivot IDs numerically by extracting the numeric parts
        def pivot_sort_key(pivot_id):
            # Extract numbers from pivot ID (e.g., "P0401.004" -> [401, 4])
            import re
            numbers = re.findall(r'\d+', pivot_id)
            return [int(num) for num in numbers]
        
        pivot_ids_used.sort(key=pivot_sort_key)
        
        # Compile statistics
        total_queries = len(queries)
        failed_count = len(failed_queries)
        
        return {
            'metadata': {
                'rules_title': rules.get('title'),
                'rules_id': rules.get('id'),
                'rules_author': rules.get('author'),
                'rules_date': rules.get('date'),
                'threat_actor': rules.get('threat_actor'),
                'references': rules.get('references'),
                'plugin': self.config['metadata']['plugin_name'],
                'plugin_version': self.config['metadata']['version'],
                'generation_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                'total_queries': total_queries,
                'failed_queries': failed_count,
                'pivot_ids': pivot_ids_used,
                'description': rules.get('description', 'No description available')
            },
            'queries': queries,
            'failed_queries': failed_queries if failed_queries else None,
            'summary': {
                'total_queries': total_queries,
                'failed_queries': failed_count,
                'success_rate': f"{(total_queries / (total_queries + failed_count) * 100):.1f}%" if (total_queries + failed_count) > 0 else "0.0%",
                'pivot_distribution': {
                    pivot_id: len([q for q in queries if pivot_id in q.get('pivot_ids', [])])
                    for pivot_id in pivot_ids_used
                },
                'query_types': list(set(q['query_type'] for q in queries if q.get('query_type')))
            },
            'warnings': warnings if warnings else None
        }
    
    def _generate_description(self, pivot_group_name: str, pivot_ids: List[str], rules: Dict[str, Any]) -> str:
        """Generate a human-readable description for a query group."""
        base_description = rules.get('description', '')
        
        if len(pivot_ids) == 1:
            pivot_id = pivot_ids[0]
            if pivot_id == "P0201":
                return f"Search for domains hosted on specific IP address (from {pivot_group_name})"
            elif pivot_id == "P0203":
                return f"Search for resources hosted on specific ASN (from {pivot_group_name})"
            elif pivot_id == "P0401.004":
                return f"Search for specific hash/resource (from {pivot_group_name})"
            elif pivot_id == "P0401.006":
                return f"Search for specific URL/resource name (from {pivot_group_name})"
            elif pivot_id == "P0401.007":
                return f"Search for specific HTTP status code (from {pivot_group_name})"
        
        return f"Combined search for {pivot_group_name}: {base_description[:100]}..." if base_description else f"Combined search using pivots: {', '.join(pivot_ids)}"
    
    def _generate_group_implementation_notes(self, pivot_ids: List[str], all_queries: List[Dict]) -> str:
        """Generate implementation notes for a group of pivots."""
        notes = []
        for pivot_id in pivot_ids:
            matching_query = next((q for q in all_queries if q['pivot_id'] == pivot_id), None)
            if matching_query and matching_query.get('implementation_notes'):
                notes.append(f"{pivot_id}: {matching_query['implementation_notes']}")
        
        return "; ".join(notes) if notes else "Standard URLScan mapping"


@handle_common_errors
def main():
    """Main entry point for URLScan query builder."""
    
    # Set up argument parsing
    parser = parse_common_arguments(
        'urlscan-query-builder',
        'URLScan.io query builder for hIGMA pivot framework'
    )
    args = parser.parse_args()
    
    # Set up logging
    logger = setup_logging(args.debug)
    logger.info("Starting URLScan hIGMA query builder")
    
    # Find and load configuration file
    plugin_dir = str(Path(__file__).parent)
    config_path = find_configuration_file(args.config, plugin_dir)
    logger.info(f"Loading configuration from: {config_path}")
    config = load_yaml_file(config_path)
    
    # Validate configuration
    validate_configuration(config, 'urlscan')
    logger.info("Configuration validation passed")
    
    # Load rules file
    logger.info(f"Loading rules from: {args.yaml_file}")
    rules = load_yaml_file(args.yaml_file)
    
    # Validate rules against configuration
    validation_errors, validation_warnings = validate_rules_file_permissive(rules, config)
    if validation_errors:
        logger.error("Rules validation failed:")
        for error in validation_errors:
            logger.error(f"  - {error}")
        raise PivotValidationError("Rules file validation failed")
    
    if validation_warnings:
        logger.warning("Rules validation warnings:")
        for warning in validation_warnings:
            logger.warning(f"  - {warning}")
    
    logger.info("Rules validation passed")
    
    # Print validation summary
    supported_pivot_ids = get_supported_pivot_ids(config)
    print_validation_summary(rules, config, supported_pivot_ids, logger)
    
    # Check for dry run
    if args.dry_run:
        logger.info("Dry run completed successfully - no queries generated")
        return
    
    # Initialize query builder and process rules
    query_builder = URLScanQueryBuilder(config, args.debug)
    results = query_builder.process_rules(rules)
    
    # Determine output path
    if args.output:
        output_path = args.output
    else:
        # Generate automatic filename: YYYYMMDD-HHMMSS-{yaml_filename}.{format}
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        yaml_filename = Path(args.yaml_file).stem  # Get filename without extension
        file_extension = args.format if args.format != 'csv' else 'yaml'  # Use yaml for csv as fallback
        filename = f"{timestamp}-{yaml_filename}.{file_extension}"
        
        # Use output folder in plugin directory
        plugin_dir = Path(__file__).parent
        output_dir = plugin_dir / "output"
        output_dir.mkdir(exist_ok=True)  # Ensure output directory exists
        output_path = output_dir / filename
    
    # Format output data based on requested format
    if args.format == 'json':
        def json_serializer(obj):
            """JSON serializer for objects not serializable by default json code"""
            import datetime
            if isinstance(obj, datetime.date):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
        
        output_data = json.dumps(results, indent=2, ensure_ascii=False, default=json_serializer)
    elif args.format == 'yaml':
        # Create a custom YAML dumper that quotes IP addresses
        class IPQuotingDumper(yaml.SafeDumper):
            def write_literal(self, text):
                return super().write_literal(text)
            
            def represent_str(self, data):
                import re
                # If the string is an IP address, force quotes
                if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', data):
                    return self.represent_scalar('tag:yaml.org,2002:str', data, style='"')
                return super().represent_str(data)
        
        IPQuotingDumper.add_representer(str, IPQuotingDumper.represent_str)
        output_data = yaml.dump(results, Dumper=IPQuotingDumper, default_flow_style=False, allow_unicode=True, sort_keys=False)
    else:  # csv or other formats - default to yaml for now
        output_data = yaml.dump(results, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    # Write output file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(output_data)
    logger.info(f"Queries written to: {output_path}")
    
    # Print summary
    metadata = results['metadata']
    summary = results['summary']
    logger.info("=== Query Generation Summary ===")
    logger.info(f"Rules: {metadata['rules_title']} by {metadata.get('rules_author', 'Unknown')}")
    logger.info(f"Threat Actor: {metadata.get('threat_actor', 'Unknown')}")
    logger.info(f"Total queries generated: {metadata['total_queries']}")
    logger.info(f"Failed queries: {metadata['failed_queries']}")
    logger.info(f"Success rate: {summary['success_rate']}")
    logger.info(f"Pivot IDs used: {', '.join(metadata['pivot_ids'])}")
    
    if results.get('warnings'):
        logger.warning("=== Warnings ===")
        for warning in results['warnings']:
            logger.warning(f"  - {warning}")


if __name__ == '__main__':
    main()
