# K-9 - Defensive APT Mitigation Toolkit

K-9 is an operator-first PowerShell toolkit for blue teams hunting stealthy persistence, fileless tradecraft, and covert pivoting on Windows endpoints. Every module runs in **dry-run mode** and requires interactive confirmation before deleting or changing anything, making it safe for first-pass triage in labs or controlled environments where situational awareness matters more than stealth.

> **Warning**  
> Run K-9 only on systems where you have explicit written authorization. The authors are not liable for damage, data loss, or service interruption caused by misuse.

## Modules & Capabilities

| Module             | Focus                                                                                             |
|--------------------|---------------------------------------------------------------------------------------------------|
| `RegistryReaper`   | Autoruns, AppInit_DLLs, IFEO/Debugger hooks, Winlogon hijacks, stealth Scheduled Tasks, WMI subs (with baseline diff) |
| `MemoryHunter`     | Process heuristics, LOLBAS command-line matching, suspicious parent/child trees                   |
| `NetworkNinja`     | ARP spoofing, hosts/DNS tampering, netsh portproxy, reverse shell telemetry, DNS tunneling, routing anomalies + scoring |
| `FirmwarePhantom`  | Secure Boot, TPM and Device Guard posture checks, UEFI boot chain inspection                      |
| `ForensicsWarden`  | Hidden VM/disk image sweep, WSL/Hyper-V/VMware artifacts, tunnel binary hunts, YARA/string scan, forensic snapshots, baseline/diff |
| `DriverSentinel`   | Driver baseline/blocklist diff, DLL sideload hunting, Event 7045 audit (with deep mode)         |
| `K9State`          | Baseline store, scoring engine, operator tip registry, settings (YARA paths, etc.)               |

Recent additions:

- Disk-wide search with hashing/entropy sampling for `.vhd/.vhdx/.vmdk/.qcow2/.img/.raw/.iso` images plus Hyper-V/VirtualBox/VMware/WSL metadata discovery. Compact/minimal profiles skip the heaviest WSL paths for CI.  
- Reverse-proxy intelligence: `netsh interface portproxy`, ssh `-R/-L/-D` enumeration, long-lived outbound correlation (process ⇔ socket ⇔ parent), and baseline tracking for DNS/portproxy shifts.  
- DNS tunneling heuristics (entropy, TXT/NULL prevalence, single-domain cache floods) and routing stack sanity checks for pivot detection.  
- Persistence hunting beyond run keys: IFEO debugger hijacks, Winlogon shell/userinit swaps, scheduled tasks launching from user/temp paths, WMI event subscriptions.  
- Optional YARA integration (auto-detects local `yara.exe` or user-specified binary) with string-hunt fallback plus comprehensive "mission snapshot" export (`processes.csv`, network endpoints, autoruns, tasks, event logs, drivers, ARP, routes).  
- DriverSentinel module for BYOVD/DLL sideload detection: unsigned/blocklisted drivers, suspicious module loads, Event 7045 installs (enable `-Deep` for service metadata + forced event audit).  
- JSON reporting hook via `-ReportPath` or the `K9_REPORT_PATH` environment variable captures per-module findings + threat score as structured output.
- Threat scoring + operator tips: every module emits weighted indicators, summarized in the mission debrief with actionable remediation hints. MemoryHunter also baselines executable hashes and reports new processes.

## Layout

```
K-9_Script/
├─ K9.ps1                # orchestrator / interactive UX
└─ modules/
   ├─ K9Utils.ps1        # shared helpers (entropy, path utils, IP classifiers)
   ├─ K9State.ps1        # baseline store, score/tip registries, config helpers
   ├─ VenomUI.ps1        # banner, module logging, session summary
   ├─ RegistryReaper.ps1 # persistence + autorun hunter
   ├─ MemoryHunter.ps1   # process/memory heuristics
   ├─ NetworkNinja.ps1   # network/pivot/dns detection
   ├─ FirmwarePhantom.ps1# firmware posture
   └─ ForensicsWarden.ps1# disk/VM/YARA/snapshot module
```

## Quick Start

```powershell
git clone https://github.com/m4rba4s/K-9_Script.git
cd K-9_Script

# Full interactive menu (default)
pwsh .\K9.ps1

# Target specific modules w/out banner noise
pwsh .\K9.ps1 -Registry  -NoBanner
pwsh .\K9.ps1 -Network   -NoBanner
pwsh .\K9.ps1 -Forensics -NoBanner

# Non-interactive smoke (auto-answers "N" to prompts)
function Read-Host { 'N' }
pwsh .\K9.ps1 -All -NoBanner
Remove-Item function:\Read-Host
```

### Useful Switches

| Switch        | Description                                                                    |
|---------------|--------------------------------------------------------------------------------|
| `-Registry`   | Run RegistryReaper only                                                        |
| `-Memory`     | Run MemoryHunter only                                                          |
| `-Network`    | Run NetworkNinja only                                                          |
| `-Firmware`   | Run FirmwarePhantom only (requires admin for best coverage)                    |
| `-Forensics`  | Run ForensicsWarden (VM artifacts, tunnels, YARA, mission snapshot)            |
| `-Driver`     | Run DriverSentinel (driver baseline/blocklist + DLL sideload hunt)             |
| `-Driver -Deep` | Extend driver telemetry with version/company metadata and force Event 7045 audit |
| `-All`        | Execute every module sequentially                                              |
| `-NoBanner`   | Skip ASCII art + session slate (useful for CI)                                 |

## Recommended Workflow

1. Launch `pwsh .\K9.ps1 -NoBanner -All` in a controlled console.  
2. Review per-module findings and respond to prompts (deletions are never automatic).  
3. Let the new baseline engine capture first-run state (VM images, portproxy rules, autoruns, DNS servers). Subsequent runs highlight diffs automatically.  
4. Use ForensicsWarden’s optional snapshot to preserve CSV/log artifacts before remediation.  
5. Rerun modules with `-All` or targeted switches to confirm cleanup and watch the threat score drop.

## Configurable Paths (YARA, etc.)

- Settings live in `%LOCALAPPDATA%\K9Watchdog\config\settings.json`.  
- Supported keys:
  - `YaraExecutable`: full path to `yara.exe`/`yara64.exe` if it is not on `PATH`.  
  - `YaraRulesPath`: folder containing `.yar/.yara` signatures (defaults to `.\yara_rules`).  
  - `ForensicsScope`: `Full` (default), `Compact`, or `Minimal`. Compact/Minimal limit disk roots, skip legacy WSL enumerations, and cap artifact/tunnel results for faster triage/CI.  
  - `DriverBlocklistPath`: optional override for the driver blocklist CSV (defaults to `.\data\driver_blocklist.csv`). Use this to feed your own LOLDrivers/Microsoft blocklist exports.  
  - `K9_REPORT_PATH` (env var) or CLI `-ReportPath`: emit a JSON report containing module findings, threat score, and tips.

### DriverSentinel Deep Mode

```
pwsh .\K9.ps1 -Driver -NoBanner            # quick check (baseline + DLL sideload)
pwsh .\K9.ps1 -Driver -NoBanner -Deep      # adds version/publisher metadata + forces Event 7045 audit
```

Deep mode captures per-driver company/version/signature/start account details and logs them into the JSON report (if enabled) so you can diff drivers across engagements. It also ignores the `-SkipEventAudit` flag to guarantee Event 7045 coverage.
- Example:

```json
{
  "YaraExecutable": "D:\\Tools\\yara64.exe",
  "YaraRulesPath": "D:\\Intel\\rules"
}
```

## Test / Smoke Suite

Use the bundled smoke runner to dry-run major modules with safe defaults (autoruns/network/forensics minimal scope):

```powershell
pwsh .\tests\Smoke.ps1          # full smoke
pwsh .\tests\Smoke.ps1 -SkipNetwork  # if network calls are blocked
```

The script auto-denies destructive prompts, forces ForensicsWarden into `-Scope Minimal -SkipSnapshot -Roots <repo>`, and now exercises DriverSentinel (with event log audit disabled for speed) so CI still finishes quickly.

## Roadmap (excerpt)

- Baseline/diff engine to compare mission snapshots over time.  
- JSON report export + webhook/SIEM forwarding.  
- Local hash allow/deny lists + TI lookups.  
- Optional kill-switch helpers (network isolation guidance, not automatic).

MIT licensed. Stay paranoid.
