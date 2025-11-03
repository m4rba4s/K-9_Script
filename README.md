# K-9 — Defensive APT Mitigation Toolkit

K-9 is a defensive PowerShell toolkit designed to detect, report, and (optionally) mitigate common APT-like behaviours in authorized, laboratory, or controlled environments. The project is under active development.

This repository contains the core script(s) for quick forensic checks, heuristic detection of persistence mechanisms and suspicious activity, and a safe remediation mode that is disabled by default.

## Important disclaimer

- K-9 is intended for use in test labs, sandboxes, and on systems for which you have explicit written permission.  
- Do not run this software on production systems without prior authorization. Improper use can disrupt services.  
- The authors accept no liability for damage or data loss resulting from misuse.

## Features (Draft)

- Quick heuristic scan for common persistence mechanisms: Services, Scheduled Tasks, Run Keys, and WMI persistence.  
- Process and network behaviour heuristics to surface suspicious indicators.  
- Dry-run mode is the default and reports actions without changing the system.  
- Optional remediation actions gated behind explicit confirmation.  
- Audit logging and JSON report export.  
- CI-friendly: includes Pester tests and PSScriptAnalyzer integration (suggested).

> Note: Feature set will expand as development continues. See the roadmap in `CHANGELOG.md`.

## Installation

Clone the repository and import the module or run the script directly:

```powershell
git clone https://github.com/m4rba4s/K-9_Script.git
cd K-9_Script
# Import as module (if you provide a psm1)
Import-Module .\K9.psm1
# Or execute the script directly
pwsh .\K9.ps1 -ScanQuick -DryRun
