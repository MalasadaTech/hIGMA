# hIGMA URLScan.io Integration

## Overview
This integration converts hIGMA YAML rule files into URLScan.io search queries. The output is a structured YAML file containing query metadata, combined queries, validation results, and implementation details.

## Features
- **Query Generation**: Converts hIGMA pivots into URLScan.io search syntax
- **Condition Support**: Handles logical AND/OR/NOT conditions to combine pivot groups into single queries
- **Validation**: Validates pivots against configuration and reports failures
- **Query Combination**: Combines multiple pivots within rule groups using AND logic (legacy behavior)
- **Comprehensive Output**: Includes metadata, descriptions, implementation notes, and statistics
- **Error Handling**: Graceful handling of unsupported pivot types with detailed error reporting

## Supported Pivots
| Pivot ID | URLScan Mapping | Input Type | Supported Hash Types |
|----------|-----------------|------------|---------------------|
| P0102 | `page.domain:{value}` | string (domain name) | N/A |
| P0201 | `{value}` | string (IP address) | N/A |
| P0203 | `page.asn:AS{value}` | string (ASN number) | N/A |
| P0401.001 | `page.title:"{value}"` | string (page title) | N/A |
| P0401.004 | `hash:{value}` | string (hash) | SHA256 only |
| P0401.006 | `task.url:"{value}"` | string (URL/resource) | N/A |
| P0401.007 | `page.status:{value}` | number (HTTP status) | N/A |

### Pivot Details

#### P0201 - IP Address Reverse Lookup
- **Purpose**: Find domains hosted on a specific IP address
- **Input**: Valid IPv4 address (e.g., "185.117.91.141")
- **Use Case**: Identify shared hosting infrastructure or C2 servers

#### P0102 - Domain Name Analysis
- **Purpose**: Find resources associated with a specific domain
- **Input**: Valid domain name (e.g., "example.com", "sub.example.com")
- **Use Case**: Identify domain-specific infrastructure or exclude legitimate domains from searches

## Condition Processing

The URLScan integration supports logical conditions from hIGMA rules to combine pivot groups into single, optimized queries:

### AND Conditions
When pivot groups are combined with `and`, the integration creates optimized URLScan queries:

**Hash-based AND queries** (P0401.004):
```yaml
condition: chrome_logo_png and chrome_logo_svg
# Generates: hash:(hash1 AND hash2)
```

**Mixed pivot AND queries**:
```yaml
condition: group1 and group2
# Generates: query1 AND query2
```

### OR Conditions
When pivot groups are combined with `or`, the integration preserves full query syntax:

```yaml
condition: verification_ip or verification_title
# Generates: 185.117.91.141 OR page.title:"Verification Gateway"
```

### NOT Conditions
When pivot groups are combined with `not`, the integration uses URLScan's NOT operator for exclusion:

```yaml
condition: page_title and not legit_page_domain
# Generates: page.title:"Title" AND NOT page.domain:example.com
```

### Example: AND Condition
```yaml
pivots:
  chrome_logo_png:
    - P0401.004:
      value: "2bb1a2c9b9ae4d36f62ea53811554636cf3c5b74d9845e1dbacca0ce62dc7880"
      implementation: SHA256
  chrome_logo_svg:
    - P0401.004:
      value: "46c86deeb625c7616a77777ca7ee7bea12493b9611923c66405796f3dcce3185"
      implementation: SHA256
condition: chrome_logo_png and chrome_logo_svg
```

**Generated Query**:
```
hash:(2bb1a2c9b9ae4d36f62ea53811554636cf3c5b74d9845e1dbacca0ce62dc7880 AND 46c86deeb625c7616a77777ca7ee7bea12493b9611923c66405796f3dcce3185)
```

### Example: OR Condition
```yaml
pivots:
  verification_ip:
    - P0201:
      value: "185.117.91.141"
  verification_title:
    - P0401.001:
      value: "Verification Gateway"
condition: verification_ip or verification_title
```

**Generated Query**:
```
185.117.91.141 OR page.title:"Verification Gateway"
```

### Example: NOT Condition with Domain Exclusion
```yaml
pivots:
  page_title:
    - P0401.001:
      value: "Download Microsoft Teams Desktop and Mobile Apps | Microsoft Teams"
  legit_page_domain:
    - P0102:
      value: "www.microsoft.com"
condition: page_title and not legit_page_domain
```

**Generated Query**:
```
page.title:"Download Microsoft Teams Desktop and Mobile Apps | Microsoft Teams" AND NOT page.domain:www.microsoft.com
```

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
  pivot_ids: [P0102, P0201, P0203, P0401.004, P0401.006, P0401.007]
```

### Queries
```yaml
queries:
- query_id: condition_verification_ip_or_verification_title
  query: 185.117.91.141 OR page.title:"Verification Gateway"
  query_type: combined
  pivot_ids: [P0201, P0401.001]
  description: Combined query based on condition: verification_ip or verification_title
  implementation_notes: Combined query using OR logic for: verification_ip, verification_title
- query_id: condition_chrome_logo_png_and_chrome_logo_svg
  query: hash:(2bb1a2c9b9ae4d36f62ea53811554636cf3c5b74d9845e1dbacca0ce62dc7880 AND 46c86deeb625c7616a77777ca7ee7bea12493b9611923c66405796f3dcce3185)
  query_type: combined
  pivot_ids: [P0401.004]
  description: Combined query based on condition: chrome_logo_png and chrome_logo_svg
  implementation_notes: Combined query using AND logic for: chrome_logo_png, chrome_logo_svg
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

### AND Condition Example
```bash
python urlscan-integration.py rules/chromusimus-fake-update.yaml
# Generates: hash:(hash1 AND hash2)
```

### OR Condition Example
```bash
python urlscan-integration.py rules/clickfix-verification-script-inject.yaml
# Generates: 185.117.91.141 OR page.title:"Verification Gateway"
```

### NOT Condition Example
```bash
python urlscan-integration.py rules/fake-msteams-to-deliver-oyster.yaml
# Generates: page.title:"Download Microsoft Teams..." AND NOT page.domain:www.microsoft.com
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
