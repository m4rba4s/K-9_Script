function Invoke-MemoryScan {
    Write-HostInfo "Initializing MemoryHunter..."

    # --- Technique 1: Fileless Process Scan ---
    Write-HostInfo "[1/3] Scanning for fileless processes (Refined Logic)..."
    $suspiciousProcesses = @()
    $whitelist = @('System', 'Idle', 'csrss', 'wininit', 'services', 'lsass', 'smss', 'svchost')

    $processes = Get-Process -IncludeUserName
    foreach ($process in $processes) {
        try {
            $path = $process.Path
            if ($null -eq $path) {
                if ($process.ProcessName -in $whitelist) { continue }
                if ($process.UserName -eq 'NT AUTHORITY\SYSTEM') { continue }

                $suspiciousProcesses += $process
                Write-HostDanger "[Fileless Process?] Process '(${$process.ProcessName})' (PID: $($process.Id)) is running without a file path. Owner: $($process.UserName)"
            } elseif (-not (Test-Path -Path $path -PathType Leaf)) {
                $suspiciousProcesses += $process
                Write-HostDanger "[Path Mismatch] Process '(${$process.ProcessName})' (PID: $($process.Id)) points to a non-existent file: $path"
            }
        } catch {
            # Some processes might deny access, that's okay.
        }
    }

    if ($suspiciousProcesses.Count -eq 0) {
        Write-HostSuccess "  No suspicious fileless processes found."
    }

    # --- Technique 2: Suspicious Parent-Child Scan ---
    Write-HostInfo "[2/3] Scanning for suspicious parent-child relationships..."
    $suspiciousParentsFound = 0
    $suspiciousPairs = @{
        "svchost.exe" = @("cmd.exe", "powershell.exe");
        "services.exe" = @("cmd.exe", "powershell.exe");
        "winword.exe" = @("powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe");
        "excel.exe" = @("powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe");
        "explorer.exe" = @("powershell.exe"); # Can be legit, but worth a warning
        "lsass.exe" = @("*") # Anything spawning from lsass is bad
    }

    foreach ($proc in $processes) {
        try {
            $parent = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($proc.ParentProcessId)").Name
            if ($null -eq $parent) { continue }

            if ($suspiciousPairs.ContainsKey($parent)) {
                $suspiciousChildren = $suspiciousPairs[$parent]
                if (($suspiciousChildren -contains "*") -or ($suspiciousChildren -contains $proc.Name)) {
                    Write-HostDanger "[Suspicious Parent] Process '($($proc.Name))' (PID: $($proc.Id)) was spawned by a suspicious parent '($parent)' (PID: $($proc.ParentProcessId))"
                    $suspiciousParentsFound++
                }
            }
        } catch {
            # Can't get parent, that's fine
        }
    }

    if ($suspiciousParentsFound -eq 0) {
        Write-HostSuccess "  No suspicious parent-child relationships found."
    }

    # --- Technique 3: LOLBAS Usage Scan ---
    Write-HostInfo "[3/3] Scanning for suspicious LOLBAS usage..."
    $lolbasRules = @(
        @{ ProcessName = "certutil.exe"; Pattern = ".* -urlcache .*" },
        @{ ProcessName = "rundll32.exe"; Pattern = ".*javascript:.*" },
        @{ ProcessName = "powershell.exe"; Pattern = ".* -enc .*" },
        @{ ProcessName = "powershell.exe"; Pattern = ".* -e .*" },
        @{ ProcessName = "mshta.exe"; Pattern = ".*(javascript:|vbscript:).*" },
        @{ ProcessName = "regsvr32.exe"; Pattern = ".* /s /u /i:http.*" }
    )

    $lolbasFound = 0
    try {
        $processesWithCmd = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId, Name, CommandLine
        foreach ($rule in $lolbasRules) {
            $matchingProcesses = $processesWithCmd | Where-Object { $_.Name -eq $rule.ProcessName -and $_.CommandLine -match $rule.Pattern }
            if ($matchingProcesses) {
                foreach ($proc in $matchingProcesses) {
                    $lolbasFound++
                    Write-HostDanger "[LOLBAS USAGE DETECTED]"
                    Write-HostDanger "  Process    : $($proc.Name) (PID: $($proc.ProcessId))"
                    Write-HostDanger "  CommandLine: $($proc.CommandLine)"
                }
            }
        }
    } catch {
        Write-HostWarning "Could not retrieve process command lines."
    }

    if ($lolbasFound -eq 0) {
        Write-HostSuccess "  No suspicious LOLBAS usage detected."
    }

    Write-HostInfo "MemoryHunter scan complete."
}