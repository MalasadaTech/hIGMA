
<div align="center">
  <img src="logo.png" alt="hIGMA Logo">
</div>

# hIGMA
A sigma inspired data sharing concept (hunter's SIGMA). Share pivots just like SIGMA except it specific to pivots and uses DTF. The outputs can feed into masq-monitor, or thrintel sharing. hIGMA is for thruntellisearch analysts what SIGMA is for detection engineers.

# [DTF integration](https://github.com/MalasadaTech/defenders-threatmesh-framework)

See [EX0017: LandUpdate808 Backend C2 Analysis](https://github.com/MalasadaTech/defenders-threatmesh-framework/blob/main/examples/EX0017.md#higma) for the first example of how hIGMA integrates with DTF.

## hIGMA Specification

hIGMA is a SIGMA-inspired framework for documenting DTF-based pivots for threat hunting, structured in YAML for consistency and automation. It defines pivot logic and metadata to enable sharing and integration with tools like masq-monitor and Threporter within the bot-o orchestrator. This specification outlines the metadata fields and pivot section format.

## Metadata Fields

Metadata provides context, attribution, and operational details for hIGMA pivot rules, ensuring traceability and compatibility with downstream tools.

- **title**: Descriptive name for the pivot rule (e.g., "Lumma C2 Domain to IP Mapping").
- **id**: Unique identifier for the pivot rule (e.g., UUID).
- **author**: Creator of the rule (e.g., "MalasadaTech").
- **date**: Creation or last modification date (e.g., "2025-08-14").
- **threat_actor**: Associated threat actor or campaign (e.g., "SocGholish").
- **description**: Brief explanation of the pivot’s purpose (e.g., "Maps domains to IPs via WHOIS").
- **dtf_version**: DTF framework version used (e.g., "1.0").
- **references**: Source links or IDs (e.g., threatfox, blog URLs).
- **tags**: Categorization keywords (e.g., ["malware", "C2"]).
- **confidence**: Reliability level of the pivot (e.g., "high", "medium").
- **falsepositives**: Potential scenarios where the pivot may yield incorrect results (e.g., "Legitimate CDN IPs shared with C2 servers").
- **status**: Rule status (e.g., "active", "experimental").

## Pivot Section Format

The pivot section defines DTF-codified pivot logic, structured in YAML for consistency and automation. It uses a `pivots` key to group pivots, with `-##` suffixes for multiple instances, and a `condition` key for logical combinations, inspired by SIGMA’s `detection` field.

### Format
```yaml
pivots:
  <grouping>[-##]:
    - id: <pivot_id>
      value: <pivot_value>
      implementation: <optional_instructions>
    - id: <pivot_id>
      value: <pivot_value>
      implementation: <optional_instructions>
condition: <logical_expression>
```

## Examples

### landupdate808-backend-c2-pivot.yaml
```yaml
title: LandUpdate808 Backend C2 Pivot
id: 4e5f6a7b-3c2d-4e8f-9a0b-1c2d3e4f5a6b
author: MalasadaTech
date: 2025-08-15
threat_actor: LandUpdate808
description: Identifies LandUpdate808 backend C2 domains, or "Injected Link Providers", that provide the injected link to load the LandUpdate808 exploit kit. These normally return a B64-encoded string that is the injected URL. This search will return the scan jobs that scanned the ads.php route, got a 200 response, and is hosted on AS399629.
dtf_version: 1.0
references:
  - https://malasada.tech/landupdate808-backend-c2-analysis/
tags:
  - C2
  - domain
  - backend
confidence: medium
falsepositives:
  - Malicious ads.php resources that can't be confirmed to serve a B64 encoded string.
status: experimental
pivots:
  ads_php:
    - P0401.006:
      value: "ads.php"
    - P0401.007:
      value: 200
    - P0203:
      value: 399629
  ads_panel_hash-01:
    - P0401.004:
      value: "314217a41cc73d73a4022b439572f5c45f0cedd2ac9fc94a79b1ce0d37d5a43c"
      implementation: SHA256
  ads_panel_hash-02:
    - P0401.004:
      value: "3:qVZxQXbZ6iWtBqTRlvN3LBAdhH7vZVjexRoAqRAdTwIAqo76GRoAqWQoMhFIeAqM:qzxO96PKvp2dhHiXdq3v7rdqWQoMTpAN"
      implementation: SSDEEP  
condition: ads_php or 1 of ads_panel_hash-*
```

## Plugin Integrations

### URLScan.io Integration

The URLScan.io plugin (`plugins/urlscan/`) converts hIGMA rules into URLScan.io search queries. It provides:

- **Query Generation**: Converts DTF pivots into URLScan.io syntax
- **Validation**: Validates pivots against supported types and configurations
- **Comprehensive Output**: Structured YAML with metadata, queries, and validation results

#### Supported Pivots
- **P0203**: Network ASN → `page.asn:AS{value}`
- **P0401.001**: Page Title → `page.title:"{value}"`
- **P0401.004**: File Hash → `hash:{value}` (SHA256 only)
- **P0401.006**: Resource Name → `task.url:"{value}"`
- **P0401.007**: HTTP Status → `page.status:{value}`

#### Example Output
```yaml
metadata:
  rules_title: LandUpdate808 Backend C2 Pivot
  threat_actor: LandUpdate808
  total_queries: 2
  failed_queries: 1

queries:
- query_id: ads_php
  query: task.url:"ads.php" AND page.status:200 AND page.asn:AS399629
  query_type: combined
  pivot_ids: [P0401.006, P0401.007, P0203]
```

#### Usage
```bash
cd plugins/urlscan
python urlscan-integration.py ../../rules/landupdate808-backend-c2-pivot.yaml
```

See [plugins/urlscan/README.md](plugins/urlscan/README.md) for detailed documentation.
