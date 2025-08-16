# hIGMA urlscan.io integration

## Overview
This integration will be used to convert a hIGMA YAML into a working query or queries. The output will be a JSON file with the query or queries and any pertinent meta fields (TBD).

## Planned Course of Action
The first integration will be able to process [landupdate808-backend-c2-pivot.yaml](https://github.com/MalasadaTech/hIGMA/blob/main/rules/landupdate808-backend-c2-pivot.yaml) into a working query.

The capabilities will be expanded as the hIGMA YAML files are created.

## General Concept
The general concept is to be able to take a hIGMA YAML file, and output a JSON file that contains a platform-specific query or queries. The output can be manually actioned by a thruntellisearch analyst, or it can be used as input for the next tool. In the future, I plan to modify [masq-monitor](https://github.com/MalasadaTech/masq-monitor) to create a config file from the hIGMA JSON output.

## App Workflow
1. Verify access to the configuration.yaml file that stores the currently supported pivots
2. Check the CLI arguments to check   
    a. Check for debug option   
    b. Check for YAML file localtion/name   
3. Check YAML file for the pivots and conditions section   
    a. Verify format is good   
    b. Verify the pivots are supported-per condition   
    c. Validate input type per pivot   
4. Process the conditions and generate the output   

## Configuration File

The `configuration.yaml` file defines the plugin's capabilities, supported pivots, and operational settings. This file serves as the authoritative source for determining which pivots the URLScan integration can process.

### Structure

The configuration file contains the following main sections:

- **metadata**: Plugin information including name, version, description, author, and date
- **supported-pivots**: Array of pivot definitions with their specifications
- **configuration**: API settings, validation rules, and output formatting options

### Supported Pivots

Currently, the following pivots are supported:

| Pivot ID | Name | Input Type | Reference |
|----------|------|------------|-----------|
| P0203 | Network: ASN | string | [P0203](https://github.com/MalasadaTech/defenders-threatmesh-framework/blob/main/pivots/P0203.md) |
| P0401.004 | HTTP: Same Resources | string | [P0401.004](https://github.com/MalasadaTech/defenders-threatmesh-framework/blob/main/pivots/P0401.004.md) |
| P0401.006 | HTTP: Same Resource Name | string | [P0401.006](https://github.com/MalasadaTech/defenders-threatmesh-framework/blob/main/pivots/P0401.006.md) |
| P0401.007 | HTTP: Response Code | number | [P0401.007](https://github.com/MalasadaTech/defenders-threatmesh-framework/blob/main/pivots/P0401.007.md) |

Each pivot includes:
- Unique identifier and descriptive name
- Input data type expected by the pivot
- Validation conditions
- Reference documentation or standards

**Note**: All pivots generate URLScan.io API queries as output, regardless of the specific data they are designed to search for.

### Configuration Settings

- **API Endpoint**: `https://urlscan.io/api/v1/`
- **Rate Limit**: 100 requests per minute
- **Timeout**: 30 seconds
- **Output Format**: JSON with optional metadata inclusion

## Usage example
``` cmd
python urlscan-integration.py landupdate808-backend-c2-pivot.yaml
```
