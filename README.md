# K-9 — Defensive APT Mitigation Toolkit

<<<<<<< HEAD
K-9 is a defensive PowerShell toolkit that scans Windows endpoints for common persistence tricks, suspicious in-memory activity, and network tampering. It is designed for authorized laboratory environments and blue-team sandboxes where rapid situational awareness matters more than stealth.

The current build ships with a **session-aware terminal UI**, per-module telemetry, and a firmware posture audit so analysts can capture a full “mission debrief” for every run.

> **Important**  
> - Use only on systems where you have explicit, written authorization.  
> - Dry-run behaviour is the default; remediation requires interactive confirmation.  
> - The authors are not responsible for damage or service disruption caused by misuse.

## Feature Highlights

- 🎛️ **Mission Control UX** – Unique session ID, operator metadata, and real-time module scoreboard with end-of-run debrief.
- 🔍 **RegistryReaper** – Autorun / AppInit / BHO harvesting with guided cleanup prompts.
- 🧠 **MemoryHunter** – Fileless process checks, parent/child heuristics, and LOLBAS command-line matching.
- 🌐 **NetworkNinja** – ARP anomaly detection, hosts-file inspection, and DNS server scrutiny.
- 🛡️ **FirmwarePhantom** – Secure Boot, TPM, Device Guard posture, plus UEFI boot path anomaly reporting.
- 📄 **Dry-Run First** – Every destructive action requires `Y/N` confirmation. Suitable for baseline assessment scripts.
- 🧪 **CI Friendly** – PowerShell 5.1+ compatible; simple to hook into Pester or pipeline smoke tests.

## Layout

```
K-9_Script/
├─ K9.ps1                # entrypoint / orchestrator
└─ modules/
   ├─ VenomUI.ps1        # session UI, logging, summary
   ├─ RegistryReaper.ps1 # registry persistence checks
   ├─ MemoryHunter.ps1   # process heuristics
   ├─ NetworkNinja.ps1   # network anomaly detection
   └─ FirmwarePhantom.ps1# firmware/UEFI posture audit
```

## Quick Start
=======
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
>>>>>>> origin/main

```powershell
git clone https://github.com/m4rba4s/K-9_Script.git
cd K-9_Script
<<<<<<< HEAD

# Run with full interactive experience
pwsh .\K9.ps1

# Target a specific module without the banner
pwsh .\K9.ps1 -Firmware -NoBanner

# Run everything non-interactively (prompts auto-denied)
function Read-Host { 'N' }
pwsh .\K9.ps1 -All -NoBanner
Remove-Item function:\Read-Host
```

### Useful Switches

| Switch      | Description                                                |
|-------------|------------------------------------------------------------|
| `-Registry` | Run only RegistryReaper                                    |
| `-Memory`   | Run only MemoryHunter                                      |
| `-Network`  | Run only NetworkNinja                                      |
| `-Firmware` | Run only FirmwarePhantom (requires admin rights)           |
| `-All`      | Execute every module sequentially                          |
| `-NoBanner` | Skip ASCII splash screen (useful for CI pipelines)         |

## Smoke Test Recipes

```powershell
pwsh .\K9.ps1 -Firmware -NoBanner
pwsh .\K9.ps1 -Memory   -NoBanner
pwsh .\K9.ps1 -Network  -NoBanner
pwsh .\K9.ps1 -Registry -NoBanner
function Read-Host { 'N' }; pwsh .\K9.ps1 -All -NoBanner; Remove-Item function:\Read-Host
```

For interactive QA, launch `pwsh .\K9.ps1` and exercise the menu (`[1]-[4]`, `[A]`, `[Q]`). Confirm the “Mission Debrief” block lists modules, status, and runtime.

## Roadmap (excerpt)

- `-Stealth`, `-AutoApprove`, and JSON reporting hooks.
- Baseline snapshot / diff mode for repeat assessments.
- Extended UEFI heuristics for vendor-specific boot paths.
- Optional integration with Pester tests & PSScriptAnalyzer.

See `CHANGELOG.md` for progress once available.

## License

Released under the MIT License. See `LICENSE` for details.

Stay paranoid. 🐾
=======
# Import as module (if you provide a psm1)
Import-Module .\K9.psm1
# Or execute the script directly
pwsh .\K9.ps1 -ScanQuick -DryRun
>>>>>>> origin/main
