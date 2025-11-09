function Invoke-MemoryScan {
    Write-HostInfo "Initializing MemoryHunter..."

    Add-K9ScoreboardMemoryContext

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
    } else {
        Add-K9Score -Module 'MemoryHunter' -Indicator 'Fileless Processes' -Points ([Math]::Min(30, $suspiciousProcesses.Count * 5)) -Detail 'Fileless or hollowed processes'
        Add-K9ReportEntry -Module 'MemoryHunter' -Indicator 'FilelessProcesses' -Data (
            $suspiciousProcesses | Select-Object ProcessName, Id, UserName
        )
    }

    # --- Technique 2: Suspicious Parent-Child Scan ---
    Write-HostInfo "[2/3] Scanning for suspicious parent-child relationships..."
    $suspiciousParentsFound = 0
    $parentHits = New-Object System.Collections.Generic.List[object]
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
                    $parentHits.Add([PSCustomObject]@{
                        ChildName  = $proc.Name
                        ChildPid   = $proc.Id
                        ParentName = $parent
                        ParentPid  = $proc.ParentProcessId
                    }) | Out-Null
                }
            }
        } catch {
            # Can't get parent, that's fine
        }
    }

    if ($suspiciousParentsFound -eq 0) {
        Write-HostSuccess "  No suspicious parent-child relationships found."
    } else {
        Add-K9Score -Module 'MemoryHunter' -Indicator 'Bad Parent Chain' -Points ([Math]::Min(20, $suspiciousParentsFound * 4)) -Detail 'Suspicious parent-child spawns'
        Add-K9ReportEntry -Module 'MemoryHunter' -Indicator 'ParentChild' -Data ($parentHits | Select-Object -First 50)
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
    $lolbasHits = New-Object System.Collections.Generic.List[object]
    try {
        $processesWithCmd = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId, Name, CommandLine
        foreach ($rule in $lolbasRules) {
            $matchingProcesses = $processesWithCmd | Where-Object { $_.Name -eq $rule.ProcessName -and $_.CommandLine -match $rule.Pattern }
            if ($matchingProcesses) {
                foreach ($proc in $matchingProcesses) {
                    $lolbasFound++
                    $lolbasHits.Add($proc) | Out-Null
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
    } else {
        Add-K9Score -Module 'MemoryHunter' -Indicator 'LOLBAS Abuse' -Points ([Math]::Min(25, $lolbasFound * 5)) -Detail 'Suspicious built-in tool usage'
        Add-K9ReportEntry -Module 'MemoryHunter' -Indicator 'LOLBAS' -Data (
            $lolbasHits | Select-Object Name, ProcessId, CommandLine
        )
    }

    Write-HostInfo "MemoryHunter scan complete."

    Invoke-MemoryHunterBaseline -Processes $processes -CommandLines $processesWithCmd
}

function Invoke-MemoryHunterBaseline {
    param(
        $Processes,
        $CommandLines
    )

    $snapshot = New-Object System.Collections.Generic.List[object]
    foreach ($proc in $Processes) {
        if (-not $proc.Path) { continue }
        $hash = 'HASH_ERR'
        try {
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $proc.Path -ErrorAction Stop).Hash
        } catch {}

        $snapshot.Add([PSCustomObject]@{
            ProcessName = $proc.ProcessName
            Id          = $proc.Id
            Path        = $proc.Path
            Hash        = $hash
        }) | Out-Null
    }

    $diff = Compare-K9Baseline -Key 'MemoryHunter_Processes' -Current ($snapshot.ToArray()) -UniqueProperties @('ProcessName','Path','Hash')
    if ($diff.Status -eq 'BaselineCreated') {
        Write-HostInfo "  MemoryHunter baseline created."
        return
    }

    if ($diff.Status -eq 'Diff') {
        if ($diff.Added.Count -gt 0) {
            Write-HostWarning ("  [BASELINE] {0} new executable(s) spawned." -f $diff.Added.Count)
            $diff.Added | Select-Object -First 5 | Format-Table ProcessName, Path -AutoSize
            Add-K9Score -Module 'MemoryHunter' -Indicator 'New Processes' -Points ([Math]::Min(20, $diff.Added.Count * 4)) -Detail 'Process baseline changed'
            Add-K9ReportEntry -Module 'MemoryHunter' -Indicator 'BaselineNewProcesses' -Data (
                $diff.Added | Select-Object -First 50
            )
        }
    }
}

function Add-K9ScoreboardMemoryContext {
    try {
        $null = Get-K9Scoreboard
    } catch {}
}
