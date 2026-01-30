# Threat Hunting Cheatsheet

## SIGMA Rules
Generic signature format for SIEM systems.

### Basic Structure
```yaml
title: Suspicious Process Creation
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: '/c powershell'
    condition: selection
level: medium
```

## Hayabusa
Fast timeline generator and threat hunting tool for Windows Event Logs.

```powershell
# Basic scan
hayabusa-2.x.x-win-x64.exe csv-timeline -d C:\Windows\System32\winevt\Logs -o timeline.csv

# Scan with specific profile
hayabusa.exe csv-timeline -d ./logs -p "standard"

# Live analysis
hayabusa.exe live-response
```

## Chainsaw
Rapidly search and hunt through Windows Event Logs.

```powershell
# Search using Sigma rules
./chainsaw search C:\logs\ --sigma rules/ --mapping mappings/sigma-mapping.yml

# Hunt using built-in logic
./chainsaw hunt C:\logs\ --rules rules/ 
```

## DeepBlueCLI
PowerShell script for threat hunting via Windows Event Logs.

```powershell
# Analyze local security log
./DeepBlue.ps1 -log security

# Analyze evtx file
./DeepBlue.ps1 C:\logs\Security.evtx
```
