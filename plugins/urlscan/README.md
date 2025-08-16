# hIGMA URLScan.io Integration

## Overview
This integration converts hIGMA YAML rule files into URLScan.io search queries. The output is a structured YAML file containing query metadata, combined queries, validation results, and implementation details.

## Features
- **Query Generation**: Converts hIGMA pivots into URLScan.io search syntax
- **Validation**: Validates pivots against configuration and reports failures
- **Query Combination**: Combines multiple pivots within rule groups using AND logic
- **Comprehensive Output**: Includes metadata, descriptions, implementation notes, and statistics
- **Error Handling**: Graceful handling of unsupported pivot types with detailed error reporting

## Supported Pivots
| Pivot ID | URLScan Mapping | Input Type | Supported Hash Types |
|----------|-----------------|------------|---------------------|
| P0203 | `page.asn:AS{value}` | string (ASN number) | N/A |
| P0401.004 | `hash:{value}` | string (hash) | SHA256 only |
| P0401.006 | `task.url:"{value}"` | string (URL/resource) | N/A |
| P0401.007 | `page.status:{value}` | number (HTTP status) | N/A |

## Output Format
The integration outputs structured YAML files with the following sections:

### Metadata
```yaml
metadata:
  rules_title: LandUpdate808 Backend C2 Pivot
  rules_author: MalasadaTech
  threat_actor: LandUpdate808
  references:
    - https://malasada.tech/landupdate808-backend-c2-analysis/
  total_queries: 2
  failed_queries: 1
  pivot_ids: [P0203, P0401.004, P0401.006, P0401.007]
```

### Queries
```yaml
queries:
- query_id: ads_php
  query: task.url:"ads.php" AND page.status:200 AND page.asn:AS399629
  query_type: combined
  pivot_ids: [P0401.006, P0401.007, P0203]
  description: Combined search for multiple pivots
  implementation_notes: Details about URLScan field mappings
```

### Failed Queries & Validation
```yaml
failed_queries:
- query_id: ads_panel_hash-02_failed_P0401.004
  error_message: 'Pivot P0401.004 implementation 'SSDEEP' not supported'
  pivot_ids: [P0401.004]

warnings:
- 'Pivot P0401.004 validation failed: SSDEEP not supported'
```

## Usage Examples

### Basic Usage
```bash
python urlscan-integration.py rules/landupdate808-backend-c2-pivot.yaml
```

### With Debug Output
```bash
python urlscan-integration.py --debug rules/landupdate808-backend-c2-pivot.yaml
```

### Custom Output File
```bash
python urlscan-integration.py --output custom-queries.yaml rules/landupdate808-backend-c2-pivot.yaml
```

### Dry Run (Validation Only)
```bash
python urlscan-integration.py --dry-run rules/landupdate808-backend-c2-pivot.yaml
```

## Output Files
- **Default Location**: `plugins/urlscan/output/`
- **Naming Convention**: `YYYYMMDD-HHMMSS-{rules-filename}.yaml`
- **Format**: YAML (default), JSON available with `--format json`

## Integration Architecture
The integration uses shared utilities from `plugins/utils.py` for:
- Argument parsing and validation
- YAML file loading and processing
- Pivot validation against configuration
- Error handling and logging

## Configuration
See `configuration.yaml` for supported pivots, validation rules, and API settings. The configuration defines which hash types are supported for each pivot and provides validation constraints.
