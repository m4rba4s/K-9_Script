Set-StrictMode -Version Latest

function Invoke-ForensicsScan {
    param(
        [ValidateSet('Auto', 'Full', 'Compact', 'Minimal')]
        [string]$Scope = 'Auto',

        [string[]]$Roots,

        [string[]]$YaraRoots,

        [string[]]$TunnelRoots,

        [switch]$SkipSnapshot
    )

    Write-HostInfo "Initializing ForensicsWarden..."

    $profile = Get-ForensicsProfile -Scope $Scope
    if ($Roots -and $Roots.Count -gt 0) {
        $validRoots = @(
            $Roots |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
        )
        if ($validRoots.Count -gt 0) {
            $profile.Roots = $validRoots
        }
    }

    if ($YaraRoots -and $YaraRoots.Count -gt 0) {
        $profile.YaraRoots = @(
            $YaraRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
        )
    }

    if ($TunnelRoots -and $TunnelRoots.Count -gt 0) {
        $profile.TunnelRoots = @(
            $TunnelRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
        )
    }

    Write-HostInfo ("Profile: {0}" -f $profile.Scope)
    $roots = $profile.Roots
    Write-HostInfo ("Roots: {0}" -f ($roots -join ', '))

    $hashMode = Confirm-Action -Prompt "Hash discovered VM/VDI images? (slower)"
    $vmImages = Find-VMImages -Roots $roots -DryRun:(-not $hashMode) -ThrottleMilliseconds $profile.ThrottleMilliseconds -MaxResults $profile.MaxVmImages
    if ($null -eq $vmImages) { $vmImages = @() }

    $vmDiff = Compare-K9Baseline -Key 'Forensics_VMImages' -Current $vmImages -UniqueProperties @('Path')
    if ($vmDiff.Status -eq 'BaselineCreated') {
        Write-HostInfo "  VM image baseline captured (rerun to diff)."
    } elseif ($vmDiff.Status -eq 'Diff') {
        if ($vmDiff.Added.Count -gt 0) {
            Write-HostDanger ("  [BASELINE] {0} new VM image(s) since last run." -f $vmDiff.Added.Count)
            $vmDiff.Added | Select-Object -First 5 | ForEach-Object {
                Write-HostDanger ("    + {0}" -f $_.Path)
            }
            Add-K9Score -Module 'ForensicsWarden' -Indicator 'New VM Images' -Points 15 -Detail 'New container images detected'
            Publish-K9Tip -Code 'VMImages' -Message 'Mount suspicious VHD/VMDK read-only (diskpart attach vdisk readonly=true) before inspection.'
        }
        if ($vmDiff.Removed.Count -gt 0) {
            Write-HostWarning ("  [BASELINE] {0} previously seen VM image(s) missing." -f $vmDiff.Removed.Count)
        }
    }

    if ($vmImages.Count -gt 0) {
        Write-HostWarning ("[VM IMAGES] Found {0} large virtual disk candidate(s)." -f $vmImages.Count)
        $vmImages |
            Sort-Object SizeMB -Descending |
            Select-Object -First 25 |
            Format-Table Path, SizeMB, LastWrite, Hash, Entropy, Signature -AutoSize
        Add-K9Score -Module 'ForensicsWarden' -Indicator 'VM Image Presence' -Points 8 -Detail 'Large virtualization disks present'
    } else {
        Write-HostSuccess "No oversized VM/container image files detected in scanned roots."
    }

    $artifactSummary = Detect-VMArtifacts -SkipWslLegacy:$profile.SkipWslLegacy -MaxArtifactsPerPlatform $profile.MaxArtifactsPerPlatform -MaxTotalArtifacts $profile.MaxTotalArtifacts
    $artifactDiff = Compare-K9Baseline -Key 'Forensics_VMArtifacts' -Current $artifactSummary.Artifacts -UniqueProperties @('Path')
    if ($artifactDiff.Status -eq 'BaselineCreated') {
        Write-HostInfo "  Hypervisor artifact baseline saved."
    } elseif ($artifactDiff.Status -eq 'Diff' -and $artifactDiff.Added.Count -gt 0) {
        Write-HostWarning ("  [BASELINE] {0} new virtualization artifacts present." -f $artifactDiff.Added.Count)
        Add-K9Score -Module 'ForensicsWarden' -Indicator 'VM Artifact Growth' -Points 10 -Detail 'New virtualization artifacts discovered'
    }

    if ($artifactSummary.Artifacts.Count -gt 0 -or $artifactSummary.Wsl.Count -gt 0) {
        Write-HostWarning ("[VM ARTIFACTS] {0} filesystem hits, {1} WSL distro entries." -f $artifactSummary.Artifacts.Count, $artifactSummary.Wsl.Count)
        foreach ($entry in $artifactSummary.Artifacts) {
            Write-HostDanger ("  {0} :: {1} (LastWrite {2:u})" -f $entry.Platform, $entry.Path, $entry.LastWriteTime)
        }
        if ($artifactSummary.WslLines.Count -gt 0) {
            Write-HostInfo "  WSL detail:"
            $artifactSummary.WslLines | ForEach-Object { Write-Host "    $_" }
        }
        Publish-K9Tip -Code 'HypervisorHunt' -Message 'Inspect Hyper-V/VirtualBox folders for rogue VMs; export config + disk before powering them.'
    } else {
        Write-HostSuccess "No resident Hyper-V/VMware/VirtualBox/WSL footprints detected."
    }

    $tunnelHits = Find-TunnelBinaries -AdditionalNames @() -SearchRoots $profile.TunnelRoots -MaxResultsPerRoot $profile.TunnelMaxPerRoot -MaxResultsOverall $profile.TunnelMaxTotal
    if ($null -eq $tunnelHits) { $tunnelHits = @() }
    $tunnelDiff = Compare-K9Baseline -Key 'Forensics_TunnelBins' -Current $tunnelHits -UniqueProperties @('FullName')
    if ($tunnelDiff.Status -eq 'BaselineCreated') {
        Write-HostInfo "  Tunnel binary baseline saved."
    } elseif ($tunnelDiff.Status -eq 'Diff' -and $tunnelDiff.Added.Count -gt 0) {
        Write-HostDanger ("  [BASELINE] {0} new tunnel tool(s) dropped since last run." -f $tunnelDiff.Added.Count)
        Add-K9Score -Module 'ForensicsWarden' -Indicator 'Tunnel Droppers' -Points 18 -Detail 'New tunnel binaries on disk'
        Publish-K9Tip -Code 'TunnelRemoval' -Message 'Quarantine tunnel utilities; verify parent process tree before deletion.'
    }

    if ($tunnelHits.Count -gt 0) {
        Write-HostWarning ("[TUNNEL BINARIES] Located {0} suspicious binaries/scripts." -f $tunnelHits.Count)
        $tunnelHits |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 30 |
            Format-Table Name, FullName, SizeMB, LastWriteTime -AutoSize
        Add-K9Score -Module 'ForensicsWarden' -Indicator 'Tunnel Tool Inventory' -Points 10 -Detail 'Known tunnel utilities present'
    } else {
        Write-HostSuccess "No ngrok/chisel/frp-style binaries discovered in targeted paths."
    }

    $yaraResult = Invoke-YaraStringSweep -TargetRoots $profile.YaraRoots
    if ($yaraResult -and $yaraResult.Hits -gt 0) {
        Add-K9Score -Module 'ForensicsWarden' -Indicator 'YARA Hits' -Points 20 -Detail ("{0} signature(s) fired" -f $yaraResult.Hits)
        Publish-K9Tip -Code 'YaraFollowup' -Message 'Pull YARA-positive binaries into a sandbox; consider uploading hashes to internal TI.'
    }

    if ($SkipSnapshot) {
        Write-HostInfo "Snapshot collection skipped (parameter override)."
    } elseif (Confirm-Action -Prompt "Capture mission snapshot (processes/net/connections/autostarts)?") {
        $snapshotPath = Capture-MissionSnapshot
        if ($snapshotPath) {
            Write-HostSuccess ("Mission snapshot stored in '{0}'" -f $snapshotPath)
            Publish-K9Tip -Code 'SnapshotReview' -Message 'Zip & exfil the mission snapshot to your forensic share for timeline diffing.'
        } else {
            Write-HostWarning "Mission snapshot failed; see errors above."
        }
    } else {
        Write-HostInfo "Snapshot collection skipped."
    }

    Write-HostInfo "ForensicsWarden scan complete."
}

function Get-ForensicsProfile {
    param(
        [ValidateSet('Auto', 'Full', 'Compact', 'Minimal')]
        [string]$Scope = 'Auto'
    )

    $configuredScope = Get-K9SettingValue -Name 'ForensicsScope' -Default 'Full'
    $effectiveScope = if ($Scope -and $Scope -ne 'Auto') { $Scope } elseif ($configuredScope) { $configuredScope } else { 'Full' }
    $effectiveScope = $effectiveScope.ToUpperInvariant()

    switch ($effectiveScope) {
        'COMPACT' {
            $profile = @{
                Scope                  = 'COMPACT'
                Roots                  = @("$env:SystemDrive", (Join-Path $env:SystemDrive 'Users'))
                ThrottleMilliseconds   = 5
                MaxVmImages            = 250
                SkipWslLegacy          = $true
                MaxArtifactsPerPlatform= 25
                MaxTotalArtifacts      = 150
                TunnelRoots            = @("$env:USERPROFILE", "C:\ProgramData")
                TunnelMaxPerRoot       = 60
                TunnelMaxTotal         = 150
                YaraRoots              = @("$env:USERPROFILE")
            }
        }
        'MINIMAL' {
            $profile = @{
                Scope                  = 'MINIMAL'
                Roots                  = @("$env:SystemDrive")
                ThrottleMilliseconds   = 0
                MaxVmImages            = 80
                SkipWslLegacy          = $true
                MaxArtifactsPerPlatform= 10
                MaxTotalArtifacts      = 60
                TunnelRoots            = @("$env:USERPROFILE")
                TunnelMaxPerRoot       = 40
                TunnelMaxTotal         = 80
                YaraRoots              = @("$env:USERPROFILE")
            }
        }
        default {
            $profile = @{
                Scope                  = 'FULL'
                Roots                  = (Get-K9LogicalRoots)
                ThrottleMilliseconds   = 15
                MaxVmImages            = 2000
                SkipWslLegacy          = $false
                MaxArtifactsPerPlatform= 80
                MaxTotalArtifacts      = 600
                TunnelRoots            = @("$env:USERPROFILE", "C:\Users\Public", "C:\ProgramData", "$env:SystemRoot\Temp")
                TunnelMaxPerRoot       = 200
                TunnelMaxTotal         = 800
                YaraRoots              = @("$env:USERPROFILE", "C:\ProgramData")
            }
        }
    }

    $profile.Roots = @(
        $profile.Roots |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
    )
    if ($profile.Roots.Count -eq 0) {
        $profile.Roots = Get-K9LogicalRoots
    }

    $profile.TunnelRoots = @(
        $profile.TunnelRoots |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
    )
    if ($profile.TunnelRoots.Count -eq 0) {
        $profile.TunnelRoots = @("$env:USERPROFILE")
    }

    $profile.YaraRoots = @(
        $profile.YaraRoots |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) }
    )
    if ($profile.YaraRoots.Count -eq 0) {
        $profile.YaraRoots = @("$env:USERPROFILE")
    }

    return [PSCustomObject]$profile
}

function Find-VMImages {
    param(
        [string[]]$Roots = (Get-K9LogicalRoots),
        [int]$MinSizeMB = 64,
        [string[]]$ExcludedRoots = @(
            "$env:SystemRoot\WinSxS",
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SoftwareDistribution",
            "$env:SystemRoot\Logs",
            "$env:SystemDrive\Recovery"
        ),
        [int]$ThrottleMilliseconds = 15,
        [switch]$DryRun,
        [int]$MaxResults = 1000
    )

    $extensions = '.vhd', '.vhdx', '.vmdk', '.qcow', '.qcow2', '.img', '.raw', '.iso'
    $minSizeBytes = $MinSizeMB * 1MB

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }
        if ($results.Count -ge $MaxResults) { break }
        Write-HostInfo ("  Scanning {0} for hypervisor images..." -f $root)

        try {
            foreach ($file in Get-ChildItem -Path $root -File -Recurse -ErrorAction SilentlyContinue) {
                if ($results.Count -ge $MaxResults) { break }

                $extension = $file.Extension.ToLowerInvariant()
                if ($extensions -notcontains $extension) { continue }
                if ($file.Length -lt $minSizeBytes) { continue }
                if (Test-K9PathExcluded -Path $file.FullName -ExcludedRoots $ExcludedRoots) { continue }

                $metadata = Get-VMImageMetadata -Item $file -DryRun:$DryRun
                if ($metadata) { $results.Add($metadata) | Out-Null }
                if ($ThrottleMilliseconds -gt 0) {
                    Start-Sleep -Milliseconds $ThrottleMilliseconds
                }
            }
        } catch {
            Write-HostWarning ("    Failed scanning {0}: {1}" -f $root, $_.Exception.Message)
        }
    }

    return $results.ToArray()
}

function Get-VMImageMetadata {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$Item,
        [switch]$DryRun
    )

    $sizeMb = [Math]::Round($Item.Length / 1MB, 2)

    $hash = $null
    $entropy = $null
    $signature = $null

    if (-not $DryRun) {
        try {
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Item.FullName -ErrorAction Stop).Hash
        } catch {
            $hash = "HASH_ERR"
        }

        $entropy = Get-K9FileEntropy -Path $Item.FullName
        $signature = Get-K9FileSignature -Path $Item.FullName
    }

    return [PSCustomObject]@{
        Path        = $Item.FullName
        Name        = $Item.Name
        SizeMB      = $sizeMb
        LastWrite   = $Item.LastWriteTime
        Hash        = if ($DryRun) { 'SKIPPED (DryRun)' } else { $hash }
        Entropy     = if ($DryRun) { $null } else { $entropy }
        Signature   = if ($DryRun) { $null } else { $signature }
    }
}

function Detect-VMArtifacts {
    param(
        [switch]$SkipWslLegacy,
        [int]$MaxArtifactsPerPlatform = 50,
        [int]$MaxTotalArtifacts = 400
    )

    $platforms = @(
        @{ Platform = 'WSL Legacy'; Path = "$env:LOCALAPPDATA\Packages"; Pattern = '*Linux*' },
        @{ Platform = 'WSL Sparse'; Path = "$env:ProgramData\Microsoft\Windows\WSL"; Pattern = '*' },
        @{ Platform = 'Hyper-V'; Path = "C:\ProgramData\Microsoft\Windows\Hyper-V"; Pattern = '*' },
        @{ Platform = 'Hyper-V VHD'; Path = "C:\Users\Public\Documents\Hyper-V\Virtual Hard Disks"; Pattern = '*.vhd*' },
        @{ Platform = 'VirtualBox'; Path = "$env:USERPROFILE\VirtualBox VMs"; Pattern = '*' },
        @{ Platform = 'VMware'; Path = "C:\ProgramData\VMware"; Pattern = '*' },
        @{ Platform = 'VMware Player'; Path = "$env:USERPROFILE\Documents\Virtual Machines"; Pattern = '*' },
        @{ Platform = 'Docker Desktop'; Path = "$env:LOCALAPPDATA\Docker"; Pattern = '*' },
        @{ Platform = 'Windows Subsystem'; Path = "$env:ProgramFiles\WindowsApps"; Pattern = '*CanonicalGroupLimited*' }
    )

    $artifactList = New-Object System.Collections.Generic.List[object]
    $perPlatformCount = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    $stopGlobal = $false
    foreach ($entry in $platforms) {
        if ($stopGlobal) { break }
        if ($SkipWslLegacy -and $entry.Platform -like 'WSL*') { continue }
        $candidatePath = $executioncontext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($entry.Path)
        if (-not (Test-Path $candidatePath)) { continue }
        if (-not $perPlatformCount.ContainsKey($entry.Platform)) {
            $perPlatformCount[$entry.Platform] = 0
        }

        try {
            foreach ($item in Get-ChildItem -Path $candidatePath -Filter $entry.Pattern -Recurse -ErrorAction SilentlyContinue) {
                if ($item.PSIsContainer) { continue }
                if ($artifactList.Count -ge $MaxTotalArtifacts) { $stopGlobal = $true; break }
                if ($perPlatformCount[$entry.Platform] -ge $MaxArtifactsPerPlatform) { break }

                $artifactList.Add([PSCustomObject]@{
                    Platform       = $entry.Platform
                    Path           = $item.FullName
                    Size           = Format-K9Size -Bytes $item.Length
                    LastWriteTime  = $item.LastWriteTime
                }) | Out-Null
                $perPlatformCount[$entry.Platform]++
            }
        } catch {
            Write-HostWarning ("    Unable to enumerate {0}: {1}" -f $candidatePath, $_.Exception.Message)
        }
    }

    $wslInfo = Get-WSLInventory

    return [PSCustomObject]@{
        Artifacts = $artifactList.ToArray()
        Wsl       = $wslInfo.Distributions
        WslLines  = $wslInfo.RawOutput
    }
}

function Get-WSLInventory {
    $result = @{
        Distributions = @()
        RawOutput     = @()
    }

    try {
        $raw = & wsl.exe --list --verbose 2>&1
        if ($raw) {
            $result.RawOutput = $raw
            $parsed = $raw | Where-Object { $_ -match '^\s*\w' -and -not ($_ -like '*NAME*STATE*VERSION*') }
            foreach ($line in $parsed) {
                $columns = $line -split '\s{2,}' | Where-Object { $_ -ne '' }
                if ($columns.Length -ge 3) {
                    $result.Distributions += [PSCustomObject]@{
                        Name    = $columns[0].Trim()
                        State   = $columns[1].Trim()
                        Version = $columns[2].Trim()
                    }
                }
            }
        }
    } catch {
        Write-HostWarning "WSL not installed or inaccessible."
    }

    try {
        $status = & wsl.exe --status 2>&1
        if ($status) {
            $result.RawOutput += ''
            $result.RawOutput += $status
        }
    } catch {}

    return $result
}

function Find-TunnelBinaries {
    param(
        [string[]]$SearchRoots = @(
            "$env:USERPROFILE",
            "C:\Users\Public",
            "C:\ProgramData",
            "$env:SystemRoot\Temp"
        ),
        [string[]]$AdditionalNames = @(),
        [int]$MaxResultsPerRoot = 200,
        [int]$MaxResultsOverall = 800
    )

    $names = @(
        'ngrok', 'chisel', 'frpc', 'frps', 'rclone', 'sshuttle',
        'socat', 'meterpreter', 'msfconsole', 'plink', 'autotunnel',
        'cloudflared', 'tunsocks', 'htran', 'lcx', 'gotunnel'
    ) + $AdditionalNames

    $extensions = '.exe', '.dll', '.ps1', '.bat', '.cmd', '.sh'

    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($root in $SearchRoots) {
        if (-not (Test-Path $root)) { continue }
        if ($hits.Count -ge $MaxResultsOverall) { break }

        $count = 0
        try {
            foreach ($file in (Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue)) {
                if ($hits.Count -ge $MaxResultsOverall) { break }
                $ext = $file.Extension.ToLowerInvariant()
                if ($extensions -notcontains $ext) { continue }

                $nameMatch = $false
                foreach ($pattern in $names) {
                    if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
                    if ($file.Name -like "*$pattern*" -or $file.FullName -like "*$pattern*") {
                        $nameMatch = $true
                        break
                    }
                }

                if (-not $nameMatch) { continue }

                $hits.Add([PSCustomObject]@{
                    Name          = $file.Name
                    FullName      = $file.FullName
                    SizeMB        = [Math]::Round($file.Length / 1MB, 2)
                    LastWriteTime = $file.LastWriteTime
                }) | Out-Null
                $count++
                if ($count -ge $MaxResultsPerRoot) { break }
            }
        } catch {
            Write-HostWarning ("    Error scanning {0}: {1}" -f $root, $_.Exception.Message)
        }
    }

    return $hits.ToArray()
}

function Invoke-YaraStringSweep {
    param(
        [string]$RulesDirectory = (Get-K9SettingValue -Name 'YaraRulesPath' -Default "$PSScriptRoot\..\yara_rules"),
        [string[]]$TargetRoots = @("$env:USERPROFILE", "C:\ProgramData")
    )

    Write-HostInfo "[YARA] Running signature sweep (if rules/tool available)..."

    $totalHits = 0
    $mode = 'None'

    $yaraExe = Get-YaraExecutable
    if ($yaraExe -and (Test-Path $RulesDirectory)) {
        $mode = 'YARA'
        $rules = Get-ChildItem -Path $RulesDirectory -Filter *.yar* -File -ErrorAction SilentlyContinue
        if (-not $rules) {
            Write-HostWarning "  No YARA rules found."
        } else {
            foreach ($rule in $rules) {
                foreach ($target in $TargetRoots) {
                    if (-not (Test-Path $target)) { continue }
                    try {
                        $arguments = @('-r', "`"$($rule.FullName)`"", "`"$target`"")
                        $output = & $yaraExe @arguments 2>&1
                        if ($LASTEXITCODE -gt 1) {
                            Write-HostWarning ("  YARA error for {0}: {1}" -f $target, ($output -join '; '))
                            continue
                        }

                        if ($output) {
                            Write-HostDanger ("  [YARA HIT] Rule '{0}' triggered in '{1}'" -f $rule.Name, $target)
                            $output | ForEach-Object { Write-Host "    $_" }
                            $totalHits += ($output | Measure-Object).Count
                        }
                    } catch {
                        Write-HostWarning ("  Unable to run YARA for {0}: {1}" -f $target, $_.Exception.Message)
                    }
                }
            }
        }
        return [PSCustomObject]@{ Mode = $mode; Hits = $totalHits }
    }

    Write-HostWarning "  YARA binary/rules missing. Falling back to heuristic string scan."
    $mode = 'Strings'
    $totalHits += Invoke-StringHunt -TargetRoots $TargetRoots
    return [PSCustomObject]@{ Mode = $mode; Hits = $totalHits }
}

function Get-YaraExecutable {
    $configured = Get-K9SettingValue -Name 'YaraExecutable'
    if ($configured -and (Test-Path $configured)) {
        return (Resolve-K9Path -Path $configured)
    }

    $candidates = @('yara64.exe', 'yara.exe')
    foreach ($candidate in $candidates) {
        $cmd = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }

    $local = Join-Path -Path $PSScriptRoot -ChildPath "..\tools\yara64.exe"
    if (Test-Path $local) { return (Resolve-K9Path -Path $local) }

    return $null
}

function Invoke-StringHunt {
    param([string[]]$TargetRoots)

    $patterns = @(
        'Invoke-WebRequest.*ngrok',
        'New-Object.*System\.Net\.Sockets\.TcpClient',
        'ssh\s+-[RLD]',
        'powershell.*-nop.*-enc',
        'System\.Net\.WebSockets',
        'Start-Job.*Invoke-Expression',
        'IEX'
    )

    $hits = 0
    foreach ($root in $TargetRoots) {
        if (-not (Test-Path $root)) { continue }
        Write-HostInfo ("  [Strings] scanning {0}" -f $root)

        try {
            Get-ChildItem -Path $root -Recurse -Include *.ps1,*.psm1,*.bat,*.cmd,*.vbs,*.js,*.py -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                ForEach-Object {
                    foreach ($pattern in $patterns) {
                        try {
                            $matches = Select-String -Path $_.FullName -Pattern $pattern -SimpleMatch:$false -AllMatches -ErrorAction SilentlyContinue
                            if ($matches) {
                                Write-HostDanger ("  [STRINGS] {0} hit in {1}" -f $pattern, $_.FullName)
                                $hits += $matches.Matches.Count
                            }
                        } catch {}
                    }
                }
        } catch {
            Write-HostWarning ("    Failed string scan against {0}: {1}" -f $root, $_.Exception.Message)
        }
    }

    return $hits
}

function Capture-MissionSnapshot {
    param([string]$OutDir = (Join-Path -Path (Get-Location) -ChildPath ("K9_snapshot_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))))

    try {
        $folder = New-Item -Path $OutDir -ItemType Directory -Force -ErrorAction Stop
    } catch {
        Write-HostFatal ("Unable to create snapshot directory: {0}" -f $_.Exception.Message)
        return $null
    }

    Write-HostInfo ("  Capturing forensic artifacts to {0}" -f $folder.FullName)

    try {
        Get-Process | Select-Object Id, ProcessName, Path, StartTime |
            Export-Csv (Join-Path $folder.FullName 'processes.csv') -NoTypeInformation
    } catch { Write-HostWarning "    Failed to export processes." }

    try {
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Export-Csv (Join-Path $folder.FullName 'net_tcp.csv') -NoTypeInformation
        Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Export-Csv (Join-Path $folder.FullName 'net_udp.csv') -NoTypeInformation
    } catch { Write-HostWarning "    Failed to export network endpoints." }

    try {
        Get-Service | Export-Csv (Join-Path $folder.FullName 'services.csv') -NoTypeInformation
    } catch { Write-HostWarning "    Failed to export services." }

    try {
        schtasks /Query /FO LIST /V > (Join-Path $folder.FullName 'schtasks.txt')
    } catch { Write-HostWarning "    Failed to export scheduled tasks." }

    try {
        reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" (Join-Path $folder.FullName 'run_hklm.reg') /y 2>$null
        reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" (Join-Path $folder.FullName 'run_hkcu.reg') /y 2>$null
    } catch { Write-HostWarning "    Failed to export registry autoruns." }

    try {
        ipconfig /all > (Join-Path $folder.FullName 'ipconfig.txt')
        arp -a > (Join-Path $folder.FullName 'arp.txt')
        route PRINT > (Join-Path $folder.FullName 'routes.txt')
        netsh interface portproxy show all > (Join-Path $folder.FullName 'portproxy.txt')
    } catch { Write-HostWarning "    Failed to export network configs." }

    try {
        wevtutil qe System /c:200 /f:text > (Join-Path $folder.FullName 'System_last200.log')
        wevtutil qe Security /c:200 /f:text > (Join-Path $folder.FullName 'Security_last200.log')
    } catch { Write-HostWarning "    Failed to export event logs (System/Security)." }

    try {
        driverquery /v > (Join-Path $folder.FullName 'drivers.txt')
    } catch { Write-HostWarning "    Failed to export driver inventory." }

    return $folder.FullName
}
