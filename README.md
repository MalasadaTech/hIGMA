
<div align="center">
  <img src="logo.png" alt="hIGMA Logo">
</div>

# hIGMA
A sigma inspired data sharing concept (hunter's SIGMA). Share pivots just like SIGMA except it specific to pivots and uses DTF. The outputs can feed into masq-monitor, or thrintel sharing.

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

The pivot section defines DTF-codified pivot logic, structured in YAML for consistency and automation. It uses a `pivots` key to group pivot definitions by DTF pivot ID, with `-##` suffixes for multiple instances, and a `condition` key for logical combinations, inspired by SIGMA’s `detection` field.

### Format
```yaml
pivots:
  <DTF_pivot_id>[-##]:
    - type: <pivot_type>
      value: <pivot_value>
      implementation: <optional_instructions>
    - type: <pivot_type>
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
description: Identifies LandUpdate808 backend C2 domains, or "Injected Link Providers", that provide the injected link to load the LandUpdate808 exploit kit. These normally return a B64-encoded string that is the injected URL.
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
  P0401.006:
    - type: "HTTP: Same Resource Name"
      value: "ads.php"
  P0401.007:
    - type: "HTTP: Response Code"
      value: 200
  P0203:
    - type: AS
      value: 399629
condition: all of them
```
