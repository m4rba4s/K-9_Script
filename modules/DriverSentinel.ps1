Set-StrictMode -Version Latest

$script:DriverBlocklist = $null

function Invoke-DriverSentinel {
    param(
        [switch]$SkipProcessModules,
        [switch]$SkipDriverBaseline,
        [switch]$SkipEventAudit,
        [switch]$Deep
    )

    Write-HostInfo "Initializing DriverSentinel..."

    if ($Deep) {
        $SkipEventAudit = $false
        Write-HostInfo "  Deep mode enabled (extended metadata + event audit)."
    }

    if (-not $SkipDriverBaseline) {
        Invoke-DriverInventory -Deep:$Deep
    } else {
        Write-HostInfo "  Driver baseline skipped."
    }

    if (-not $SkipProcessModules) {
        Invoke-ProcessModuleAudit -Deep:$Deep
    } else {
        Write-HostInfo "  DLL sideload audit skipped."
    }

    if (-not $SkipEventAudit) {
        Invoke-DriverEventAudit
    } else {
        Write-HostInfo "  Event log audit skipped."
    }

    Write-HostInfo "DriverSentinel scan complete."
}

function Invoke-DriverInventory {
    param([switch]$Deep)

    Write-HostInfo "[1/3] Enumerating kernel drivers..."

    $drivers = @(
        Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, StartMode, ServiceType, PathName
    )

    if (-not $drivers) {
        Write-HostWarning "  Unable to query driver inventory."
        return
    }

    $normalized = $drivers |
        Select-Object Name,
                      DisplayName,
                      State,
                      StartMode,
                      ServiceType,
                      @{Name='ImagePath';Expression={ Extract-ImagePath $_.PathName }}

    $diff = Compare-K9Baseline -Key 'DriverSentinel_Inventory' -Current $normalized -UniqueProperties @('Name','ImagePath')
    switch ($diff.Status) {
        'BaselineCreated' {
            Write-HostInfo "  Driver baseline saved."
        }
        'Diff' {
            if ($diff.Added.Count -gt 0) {
                Write-HostDanger ("  [BASELINE] {0} new driver(s) installed." -f $diff.Added.Count)
                Publish-K9Tip -Code 'DriverDiff' -Message 'Review recent driver installations (Event 7045) for BYOVD.'
                Add-K9Score -Module 'DriverSentinel' -Indicator 'New Drivers' -Points ([Math]::Min(40, $diff.Added.Count * 8)) -Detail 'Driver inventory changed'
            }
        }
    }

    $issues = @()
    $deepMetadata = New-Object System.Collections.Generic.List[object]
    foreach ($driver in $normalized) {
        if ([string]::IsNullOrWhiteSpace($driver.ImagePath)) { continue }
        try {
            $signature = Get-AuthenticodeSignature -FilePath $driver.ImagePath -ErrorAction Stop
        } catch {
            Write-HostWarning ("    Unable to read signature for {0}: {1}" -f $driver.ImagePath, $_.Exception.Message)
            continue
        }
        $signatureState = if ($signature) { $signature.Status } else { 'Unknown' }
        $fileMeta = $null
        if ($Deep -and (Test-Path $driver.ImagePath)) {
            try {
                $serviceInfo = Get-CimInstance Win32_Service -Filter "Name = '$($driver.Name)'" -ErrorAction SilentlyContinue
                $item = Get-Item -LiteralPath $driver.ImagePath -ErrorAction Stop
                $versionInfo = $item.VersionInfo
                $fileMeta = [PSCustomObject]@{
                    Name        = $driver.Name
                    Path        = $driver.ImagePath
                    Company     = $versionInfo.CompanyName
                    Product     = $versionInfo.ProductName
                    FileVersion = $versionInfo.FileVersion
                    Signature   = $signatureState
                    StartMode   = $driver.StartMode
                    ServiceType = $driver.ServiceType
                    StartName   = if ($serviceInfo) { $serviceInfo.StartName } else { $null }
                    Description = if ($serviceInfo) { $serviceInfo.Description } else { $null }
                }
                $deepMetadata.Add($fileMeta) | Out-Null
            } catch {}
        }

        if ($signatureState -ne 'Valid') {
            $issues += [PSCustomObject]@{
                Name      = $driver.Name
                Path      = $driver.ImagePath
                Signature = $signatureState
            }
        } else {
            $blocklistHit = Test-DriverBlocklist -Path $driver.ImagePath
            if ($blocklistHit) {
                $issues += [PSCustomObject]@{
                    Name      = $driver.Name
                    Path      = $driver.ImagePath
                    Signature = 'In Blocklist'
                    Blocklist = $blocklistHit
                }
            }
        }
    }

    if ($Deep -and $deepMetadata.Count -gt 0) {
        Add-K9ReportEntry -Module 'DriverSentinel' -Indicator 'DriverMetadata' -Data ($deepMetadata | Select-Object -First 200)
    }

    if ($issues.Count -gt 0) {
        Write-HostDanger ("  [DRIVER] {0} suspicious or unsigned driver(s)." -f $issues.Count)
        $issues | Select-Object -First 20 | Format-Table Name, Signature, Path -AutoSize
        Add-K9Score -Module 'DriverSentinel' -Indicator 'Driver Integrity' -Points ([Math]::Min(60, $issues.Count * 6)) -Detail 'Unsigned/blocklisted drivers present'
        Publish-K9Tip -Code 'DriverUnsigned' -Message 'Block unsigned drivers via Device Guard / memory integrity; investigate driver services before removal.'
        Add-K9ReportEntry -Module 'DriverSentinel' -Indicator 'DriverIntegrity' -Data (
            $issues | Select-Object Name, Signature, Path, Blocklist
        )
    } else {
        Write-HostSuccess "  All loaded drivers appear signed/trusted."
    }
}

function Invoke-ProcessModuleAudit {
    param([switch]$Deep)

    Write-HostInfo "[2/3] Auditing process modules for sideloading..."

    $targets = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -like "$env:SystemDrive\*" }

    $findings = @()
    foreach ($proc in $targets) {
        try {
            foreach ($module in $proc.Modules) {
                $path = $module.FileName
                if ([string]::IsNullOrWhiteSpace($path)) { continue }
                if (-not (Test-Path $path)) {
                    $suspiciousPath = $true
                } else {
                    $suspiciousPath =
                        $path -like "$env:USERPROFILE\*" -or
                        $path -like "$env:LOCALAPPDATA\*" -or
                        $path -like "$env:APPDATA\*" -or
                        $path -like "$env:TEMP\*" -or
                        $path -like "$env:ProgramData\*" -or
                        $path -like "$env:SystemRoot\Temp\*"
                }

                if (-not $suspiciousPath) { continue }
                if ($path -like "$env:LOCALAPPDATA\Microsoft\OneDrive\*" -and $proc.ProcessName -eq 'OneDrive') { continue }

                $signature = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                if ($signature.Status -eq 'Valid') { continue }

                $findings += [PSCustomObject]@{
                    Process = $proc.ProcessName
                    PID     = $proc.Id
                    Module  = $module.ModuleName
                    Path    = $path
                    Signature = $signature.Status
                }
            }
        } catch {
            continue
        }
    }

    if ($findings.Count -gt 0) {
        Write-HostDanger ("  [MODULE] {0} unsigned DLL(s) loaded from user paths." -f $findings.Count)
        $findings | Select-Object -First 20 | Format-Table Process, PID, Module, Signature -AutoSize
        Add-K9Score -Module 'DriverSentinel' -Indicator 'DLL Sideload' -Points ([Math]::Min(50, $findings.Count * 5)) -Detail 'Unsigned modules in memory'
        Publish-K9Tip -Code 'Sideloader' -Message 'Dump the offending DLLs and check persistence (App Paths, KnownDLLs, folder ACLs).'
        Add-K9ReportEntry -Module 'DriverSentinel' -Indicator 'Sideloader' -Data (
            $findings | Select-Object -First 100
        )
    } else {
        Write-HostSuccess "  No unsigned modules loaded from user/temp paths."
    }
}

function Invoke-DriverEventAudit {
    Write-HostInfo "[3/3] Reviewing recent driver/service installs..."

    $events = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ID = 7045 } -MaxEvents 100 -ErrorAction SilentlyContinue
    } catch {}

    $recent = @()
    foreach ($event in $events) {
        $message = $event.Message
        if ($message -match 'Service Name:\s*(?<name>.+?)\s') {
            $svcName = $matches['name'].Trim()
        } else {
            $svcName = 'Unknown'
        }

        if ($message -match 'Service File Name:\s*(?<path>.+)') {
            $svcPath = $matches['path'].Trim()
        } else {
            $svcPath = 'Unknown'
        }

        $recent += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            ServiceName = $svcName
            Path        = $svcPath
        }
    }

    if ($recent.Count -gt 0) {
        Write-HostWarning ("  [EVENT] {0} recent service/driver install(s) detected." -f $recent.Count)
        $recent | Sort-Object TimeCreated -Descending | Select-Object -First 10 | Format-Table TimeCreated, ServiceName, Path -AutoSize
        Add-K9Score -Module 'DriverSentinel' -Indicator 'Driver Install Events' -Points ([Math]::Min(30, $recent.Count * 3)) -Detail 'Event 7045 activity'
        Publish-K9Tip -Code 'Event7045' -Message 'Correlate Event 7045 with suspicious binaries to catch BYOVD installs.'
        Add-K9ReportEntry -Module 'DriverSentinel' -Indicator 'Event7045' -Data (
            $recent | Sort-Object TimeCreated -Descending | Select-Object -First 10
        )
    } else {
        Write-HostSuccess "  No recent driver/service install events observed."
    }
}

function Extract-ImagePath {
    param([string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }

    $trimmed = $PathName.Trim()
    $trimmed = $trimmed -replace '^\\\\\?\\', ''
    $trimmed = $trimmed -replace '^\\\?\?\\', ''
    if ($trimmed.StartsWith('"')) {
        $end = $trimmed.IndexOf('"', 1)
        if ($end -gt 1) {
            $trimmed = $trimmed.Substring(1, $end - 1)
        }
    } else {
        $match = [System.Text.RegularExpressions.Regex]::Match($trimmed, '^(?<path>.+?\.(sys|exe|dll))(\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success) {
            $trimmed = $match.Groups['path'].Value
        }
    }

    if ($trimmed -like '\SystemRoot\*') {
        $suffix = $trimmed.Substring(11).TrimStart('\')
        return Join-Path -Path $env:SystemRoot -ChildPath $suffix
    }

    if ($trimmed -like 'SystemRoot\*') {
        $suffix = $trimmed.Substring(10).TrimStart('\')
        return Join-Path -Path $env:SystemRoot -ChildPath $suffix
    }

    return $trimmed
}

function Load-DriverBlocklist {
    if ($script:DriverBlocklist) { return $script:DriverBlocklist }

    $blocklistPath = Get-K9SettingValue -Name 'DriverBlocklistPath'
    if (-not $blocklistPath) {
        $blocklistPath = Join-Path -Path $PSScriptRoot -ChildPath '..\data\driver_blocklist.csv'
    }

    if (Test-Path $blocklistPath) {
        try {
            $script:DriverBlocklist = Import-Csv -Path $blocklistPath -ErrorAction Stop
        } catch {
            $script:DriverBlocklist = @()
        }
    } else {
        $script:DriverBlocklist = @()
    }

    return $script:DriverBlocklist
}

function Test-DriverBlocklist {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $list = Load-DriverBlocklist
    if (-not $list -or $list.Count -eq 0) {
        return $null
    }

    $fileName = [System.IO.Path]::GetFileName($Path)
    $hash = $null

    foreach ($entry in $list) {
        if ($entry.SHA256 -and $entry.SHA256.Length -gt 0) {
            if (-not $hash) {
                try {
                    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLowerInvariant()
                } catch {
                    $hash = ''
                }
            }
            if ($hash -and $hash.Equals($entry.SHA256.ToLowerInvariant())) {
                return $entry.Description
            }
        }

        if ($entry.FileName -and $entry.FileName.Equals($fileName, [System.StringComparison]::InvariantCultureIgnoreCase)) {
            return $entry.Description
        }
    }

    return $null
}
