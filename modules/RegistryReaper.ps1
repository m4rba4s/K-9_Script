Set-StrictMode -Version Latest

function Invoke-RegistryScan {
    Write-HostInfo "Initializing RegistryReaper..."

    Invoke-AutorunHiveScan
    Invoke-AppInitScan
    Invoke-BrowserHelperScan
    Invoke-IFEOScan
    Invoke-WinlogonScan
    Invoke-ScheduledTaskAudit
    Invoke-WmiSubscriptionAudit

    Write-HostInfo "RegistryReaper scan complete."
}

function Invoke-AutorunHiveScan {
    Write-HostInfo "[1/7] Scanning autorun keys..."

    $pathsToScan = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
    )

    if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
        $pathsToScan += @(
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
    }

    $findings = 0
    $autorunEntries = New-Object System.Collections.Generic.List[object]
    foreach ($path in $pathsToScan) {
        Write-HostInfo ("  Checking {0}" -f $path)
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($null -eq $items) { continue }

            $props = $items.PSObject.Properties | Where-Object { $_.Name -ne "(default)" }
            foreach ($prop in $props) {
                if ($prop.Name -like 'PS*') { continue }
                $findings++
                Write-HostDanger ("    [AUTORUN] {0} => {1}" -f $prop.Name, $prop.Value)

                $autorunEntries.Add([PSCustomObject]@{
                    Path       = $path
                    Name       = $prop.Name
                    Value      = $prop.Value
                    ValueHash  = Get-K9StringHash -Text ([string]$prop.Value)
                }) | Out-Null

                if (Confirm-Action -Prompt "Delete this autorun entry?") {
                    try {
                        Remove-ItemProperty -Path $path -Name $prop.Name -ErrorAction Stop
                        Write-HostSuccess ("      Entry '{0}' removed." -f $prop.Name)
                    } catch {
                        Write-HostFatal ("      Failed to delete entry: {0}" -f $_.Exception.Message)
                    }
                }
            }
        } catch {
            Write-HostWarning ("    Unable to read {0}: {1}" -f $path, $_.Exception.Message)
        }
    }

    if ($findings -eq 0) {
        Write-HostSuccess "  No suspicious autoruns discovered."
    } else {
        Write-HostWarning ("  Autorun review complete: {0} entries listed." -f $findings)
        Add-K9Score -Module 'RegistryReaper' -Indicator 'Autoruns' -Points ([Math]::Min(20, $findings * 3)) -Detail ("{0} autorun values" -f $findings)
    }

    $diff = Compare-K9Baseline -Key 'Registry_Autoruns' -Current $autorunEntries -UniqueProperties @('Path','Name','ValueHash')
    if ($diff.Status -eq 'BaselineCreated') {
        Write-HostInfo "  Autorun baseline saved."
    } elseif ($diff.Status -eq 'Diff') {
        if ($diff.Added.Count -gt 0) {
            Write-HostDanger ("  [BASELINE] {0} new autorun value(s)." -f $diff.Added.Count)
            Publish-K9Tip -Code 'AutorunDiff' -Message 'Export HKCU/HKLM Run keys after each hunt; diff against baseline to catch re-droppers.'
        }
        if ($diff.Removed.Count -gt 0) {
            Write-HostInfo ("  [BASELINE] {0} autorun value(s) removed." -f $diff.Removed.Count)
        }
    }
}

function Invoke-AppInitScan {
    Write-HostInfo "[2/7] Checking AppInit_DLLs & Image Hijacks..."

    $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    try {
        $appInitEnabled = (Get-ItemProperty -Path $appInitPath -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs
        $appInitDlls = (Get-ItemProperty -Path $appInitPath -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs

        if ($appInitEnabled -eq 1 -and -not [string]::IsNullOrWhiteSpace($appInitDlls)) {
            Write-HostDanger ("  [APPINIT] LoadAppInit_DLLs enabled with payload: {0}" -f $appInitDlls)
            Add-K9Score -Module 'RegistryReaper' -Indicator 'AppInit Hijack' -Points 15 -Detail $appInitDlls
            Publish-K9Tip -Code 'AppInitFix' -Message 'Set HKLM\\...\\LoadAppInit_DLLs=0 and delete AppInit_DLLs after backing up the key.'
        } else {
            Write-HostSuccess "  AppInit_DLLs not weaponized."
        }
    } catch {
        Write-HostWarning "  AppInit inspection failed."
    }
}

function Invoke-BrowserHelperScan {
    Write-HostInfo "[3/7] Enumerating Browser Helper Objects..."

    $bhoPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    $found = 0

    try {
        $bhoClsids = Get-ChildItem -Path $bhoPath -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }

            foreach ($clsid in $bhoClsids) {
                $found++
                $bhoName = (Get-ItemProperty -Path "$bhoPath\$clsid" -ErrorAction SilentlyContinue).'(default)'
                $dllPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'

                Write-HostDanger ("  [BHO] CLSID {0} -> {1}" -f $clsid, $dllPath)
                if ($bhoName) {
                    Write-HostDanger ("       Name: {0}" -f $bhoName.Trim())
                }
                Add-K9Score -Module 'RegistryReaper' -Indicator 'Browser Helper Object' -Points 8 -Detail $clsid

                if (Confirm-Action -Prompt "Disable this BHO?") {
                    try {
                        Remove-Item -Path "$bhoPath\$clsid" -Recurse -Force -ErrorAction Stop
                        Write-HostSuccess "       BHO removed."
                } catch {
                    Write-HostFatal ("       Failed removing BHO: {0}" -f $_.Exception.Message)
                }
            }
        }
    } catch {}

    if ($found -eq 0) {
        Write-HostSuccess "  No BHOs detected."
    }
}

function Invoke-IFEOScan {
    Write-HostInfo "[4/7] Inspecting Image File Execution Options (IFEO)..."

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    )

    $suspicious = 0
    foreach ($path in $paths) {
        if (-not (Test-Path $path)) { continue }
        try {
            foreach ($subKey in Get-ChildItem -Path $path -ErrorAction SilentlyContinue) {
                $props = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }

                $debugger = $props.Debugger
                $globalFlag = $props.GlobalFlag
                if ([string]::IsNullOrWhiteSpace($debugger) -and [string]::IsNullOrWhiteSpace($globalFlag)) {
                    continue
                }

                $suspicious++
                Write-HostDanger ("  [IFEO] {0} => Debugger='{1}' GlobalFlag='{2}'" -f $subKey.PSChildName, $debugger, $globalFlag)
                Add-K9Score -Module 'RegistryReaper' -Indicator 'IFEO Hook' -Points 12 -Detail $subKey.PSChildName
            }
        } catch {
            Write-HostWarning ("  Failed reading IFEO path {0}" -f $path)
        }
    }

    if ($suspicious -eq 0) {
        Write-HostSuccess "  No debugger hijacks configured."
    } else {
        Publish-K9Tip -Code 'IFEOReset' -Message 'Clear IFEO Debugger values via `reg delete ... /va` to stop process hijacks.'
    }
}

function Invoke-WinlogonScan {
    Write-HostInfo "[5/7] Auditing Winlogon shell/Userinit entries..."
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    try {
        $props = Get-ItemProperty -Path $winlogonPath -ErrorAction Stop
    } catch {
        Write-HostWarning "  Unable to read Winlogon key."
        return
    }

    $shell = $props.Shell
    $userInit = $props.Userinit
    $notifyProp = $props.PSObject.Properties['Notify']
    $notify = if ($notifyProp) { $notifyProp.Value } else { $null }

    if ($shell -and ($shell -notmatch 'explorer\.exe')) {
        Write-HostDanger ("  [WINLOGON] Custom shell detected: {0}" -f $shell)
        Add-K9Score -Module 'RegistryReaper' -Indicator 'Winlogon Shell' -Points 12 -Detail $shell
        Publish-K9Tip -Code 'WinlogonShell' -Message 'Reset HKLM\\...\\Winlogon Shell to explorer.exe to restore normal desktop.'
    } else {
        Write-HostSuccess "  Shell set to explorer.exe"
    }

    if ($userInit -and ($userInit -notmatch 'userinit\.exe')) {
        Write-HostDanger ("  [WINLOGON] Userinit override: {0}" -f $userInit)
        Add-K9Score -Module 'RegistryReaper' -Indicator 'Winlogon Userinit' -Points 10 -Detail $userInit
    } else {
        Write-HostSuccess "  Userinit appears default."
    }

    if ($notify) {
        Write-HostWarning ("  [WINLOGON] Notify packages configured: {0}" -f $notify)
        Add-K9Score -Module 'RegistryReaper' -Indicator 'Winlogon Notify' -Points 6 -Detail $notify
    }
}

function Invoke-ScheduledTaskAudit {
    Write-HostInfo "[6/7] Reviewing scheduled tasks for stealth persistence..."

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        Write-HostWarning "  Scheduled task enumeration failed."
        return
    }

    $suspiciousTasks = @()
    foreach ($task in $tasks) {
        $actions = @($task.Actions)
        foreach ($action in $actions) {
            $execProp = $action.PSObject.Properties['Execute']
            if (-not $execProp) { continue }
            $path = $execProp.Value
            if (-not $path) { continue }
            $normalizedPath = $path.Trim('"')
            try { $normalizedPath = [System.IO.Path]::GetFullPath($normalizedPath) } catch {}

            $systemDirs = @("$env:SystemRoot", "$env:ProgramFiles", ${env:ProgramFiles(x86)}) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            $inSystemDir = $false
            foreach ($dir in $systemDirs) {
                if ($normalizedPath.StartsWith($dir, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $inSystemDir = $true
                    break
                }
            }

            if ($normalizedPath -like "$env:USERPROFILE\*" -or
                $normalizedPath -like "$env:LOCALAPPDATA\*" -or
                $normalizedPath -like "$env:TEMP\*" -or
                -not $inSystemDir) {
                $suspiciousTasks += [PSCustomObject]@{
                    TaskName   = $task.TaskName
                    Author     = $task.Author
                    Hidden     = $task.Settings.Hidden
                    Path       = $path
                    Arguments  = $action.Arguments
                }
            }
        }
    }

    if ($suspiciousTasks.Count -gt 0) {
        Write-HostDanger ("  [TASKS] {0} tasks execute from user/temp paths." -f $suspiciousTasks.Count)
        $suspiciousTasks | Select-Object -First 15 | Format-Table TaskName, Hidden, Path -AutoSize
        Add-K9Score -Module 'RegistryReaper' -Indicator 'Suspicious Tasks' -Points ([Math]::Min(25, $suspiciousTasks.Count * 4)) -Detail 'Tasks launching from user space'
        Publish-K9Tip -Code 'TaskDisable' -Message 'Disable rogue tasks with `schtasks /Change /TN <task> /Disable` before deleting.'
    } else {
        Write-HostSuccess "  Scheduled task inventory looks clean."
    }
}

function Invoke-WmiSubscriptionAudit {
    Write-HostInfo "[7/7] Enumerating WMI Event Subscriptions..."

    try {
        $filters = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue)
        $consumers = @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue)
        $bindings = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue)
    } catch {
        Write-HostWarning "  Failed to enumerate WMI subscriptions."
        return
    }

    if ($filters) {
        Write-HostWarning ("  [WMI] {0} filters present." -f $filters.Count)
        $filters | Select-Object -First 10 | Format-Table Name, Query -AutoSize
        Add-K9Score -Module 'RegistryReaper' -Indicator 'WMI Filters' -Points 8 -Detail ("{0} filter(s)" -f $filters.Count)
    } else {
        Write-HostSuccess "  No WMI filters discovered."
    }

    if ($consumers) {
        Write-HostWarning ("  [WMI] {0} consumers present." -f $consumers.Count)
        $consumers | Select-Object -First 10 | Format-Table Name, TemplateName -AutoSize
        Add-K9Score -Module 'RegistryReaper' -Indicator 'WMI Consumers' -Points 8 -Detail ("{0} consumer(s)" -f $consumers.Count)
    }

    if ($bindings) {
        Write-HostWarning ("  [WMI] {0} bindings present." -f $bindings.Count)
        $bindings | Select-Object -First 10 | Format-Table Filter, Consumer -AutoSize
        Publish-K9Tip -Code 'WMICleanup' -Message 'Use `wbemtest` or `PowerShell` to delete rogue __EventFilter/__EventConsumer bindings carefully.'
        Add-K9Score -Module 'RegistryReaper' -Indicator 'WMI Bindings' -Points 6 -Detail ("{0} binding(s)" -f $bindings.Count)
    }
}
