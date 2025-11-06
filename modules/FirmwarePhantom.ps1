function Invoke-FirmwareScan {
    Write-HostInfo "Initializing FirmwarePhantom..."

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUser = [Security.Principal.WindowsPrincipal]::new($currentIdentity)

    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-HostFatal "Administrative privileges are required for firmware analysis. Please re-run as Administrator."
        return
    }

    Write-HostInfo "[0/3] Collecting platform metadata..."
    $biosInfo = $null
    try { $biosInfo = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop } catch {}
    $systemInfo = $null
    try { $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch {}

    if ($biosInfo) {
        Write-HostInfo "  BIOS Vendor  : $($biosInfo.Manufacturer)"
        Write-HostInfo "  BIOS Version : $($biosInfo.SMBIOSBIOSVersion)"

        if ($biosInfo.ReleaseDate) {
            try {
                $biosDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($biosInfo.ReleaseDate)
                $ageDays = (New-TimeSpan -Start $biosDate -End (Get-Date)).TotalDays
                Write-HostInfo ("  BIOS Release : {0:yyyy-MM-dd} ({1:N0} days old)" -f $biosDate, $ageDays)
                if ($ageDays -gt 1095) {
                    Write-HostWarning "  BIOS/UEFI firmware is older than 3 years. Check vendor advisories for security updates."
                }
            } catch {
                Write-HostWarning "  Firmware release date is reported but could not be parsed."
            }
        } else {
            Write-HostWarning "  Firmware release date not reported by system."
        }
    } else {
        Write-HostWarning "  Failed to retrieve BIOS information from WMI."
    }

    if ($systemInfo) {
        Write-HostInfo "  System SKU   : $($systemInfo.Model)"
        Write-HostInfo "  Manufacturer : $($systemInfo.Manufacturer)"
    }

    $deviceGuardCmd = Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue
    if ($deviceGuardCmd) {
        try {
            $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
            if ($deviceGuard.SecurityServicesConfigured -contains 1) {
                Write-HostSuccess "  Credential Guard / virtualization-based security is configured."
            } else {
                Write-HostWarning "  Device Guard VBS not configured. Consider enabling for additional firmware resilience."
            }
        } catch {
            Write-HostWarning "  Device Guard information unavailable: $($_.Exception.Message)"
        }
    }

    $tpmCmd = Get-Command -Name Get-Tpm -ErrorAction SilentlyContinue
    if ($null -ne $tpmCmd) {
        try {
            $tpm = Get-Tpm
            if (-not $tpm.TpmPresent) {
                Write-HostWarning "  TPM not detected. Modern firmware security features may be limited."
            } elseif (-not ($tpm.TpmEnabled -and $tpm.TpmActivated)) {
                Write-HostWarning "  TPM is present but not fully enabled/activated."
            } else {
                Write-HostSuccess "  TPM is present, enabled and activated."
            }
        } catch {
            Write-HostWarning "  Unable to query TPM state: $($_.Exception.Message)"
        }
    } else {
        Write-HostWarning "  TPM management cmdlet not available on this system."
    }

    Write-HostInfo "[1/2] Checking Secure Boot status..."
    $secureBootCmd = Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($null -ne $secureBootCmd) {
        try {
            if (Confirm-SecureBootUEFI -ErrorAction Stop) {
                Write-HostSuccess "  Secure Boot appears to be enabled."
            } else {
                Write-HostWarning "  Secure Boot is disabled. Verify whether this is intentional."
            }
        } catch {
            Write-HostWarning "  Unable to determine Secure Boot status: $($_.Exception.Message)"
        }
    } else {
        Write-HostWarning "  Secure Boot cmdlet not available on this system."
    }

    Write-HostInfo "[2/2] Enumerating firmware boot entries for anomalies..."
    $bcdOutput = $null
    try {
        $bcdOutput = bcdedit /enum firmware 2>$null
    } catch {
        Write-HostFatal "  Failed to execute bcdedit: $($_.Exception.Message)"
        return
    }

    if ($LASTEXITCODE -ne 0 -or -not $bcdOutput) {
        Write-HostWarning "  Could not retrieve firmware boot entries. Ensure the system supports UEFI and Secure Boot is not locking access."
        return
    }

    $parsedEntries = @()
    $currentEntry = [ordered]@{}

    foreach ($line in $bcdOutput) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($currentEntry.Count -gt 0) {
                $parsedEntries += [PSCustomObject]$currentEntry
                $currentEntry = [ordered]@{}
            }
            continue
        }

        $trimmed = $line.Trim()
        if ($trimmed -match '^(identifier|device|path|description)\s+(.*)$') {
            $key = $matches[1].ToLowerInvariant()
            $value = $matches[2].Trim()
            $currentEntry[$key] = $value
        }
    }

    if ($currentEntry.Count -gt 0) {
        $parsedEntries += [PSCustomObject]$currentEntry
    }

    if ($parsedEntries.Count -eq 0) {
        Write-HostWarning "  No firmware entries were returned by bcdedit."
        return
    }

    $expectedPathPatterns = @(
        '^\\EFI\\Microsoft\\Boot\\',
        '^\\EFI\\Boot\\Boot(x64|ia32|arm|arm64)\.efi$'
    )

    $entrySummary = @()
    $suspiciousEntries = 0
    foreach ($entry in $parsedEntries) {
        $summaryItem = [ordered]@{
            Identifier  = ''
            Description = ''
            Device      = ''
            Path        = ''
            Flags       = @()
        }

        if ($entry.PSObject.Properties.Name -contains 'identifier') {
            $summaryItem.Identifier = $entry.identifier
        }

        if ($entry.PSObject.Properties.Name -contains 'description') {
            $summaryItem.Description = $entry.description
        }

        if ($entry.PSObject.Properties.Name -contains 'device') {
            $summaryItem.Device = $entry.device
        }

        if ($entry.PSObject.Properties.Name -contains 'path') {
            $summaryItem.Path = $entry.path
        }

        if (-not ($entry.PSObject.Properties.Name -contains 'path')) {
            if ($summaryItem.Description -and $summaryItem.Identifier) {
                $summaryItem.Flags += 'no-path'
                $entrySummary += [PSCustomObject]$summaryItem
            }
            continue
        }

        $path = $entry.path
        $device = $summaryItem.Device
        $identifier = $summaryItem.Identifier

        $isExpected = $false
        foreach ($pattern in $expectedPathPatterns) {
            if ($path -match $pattern) {
                $isExpected = $true
                break
            }
        }

        if (-not $isExpected) {
            $suspiciousEntries++
            $summaryItem.Flags += 'path-anomaly'
            Write-HostDanger "[UNUSUAL BOOT PATH] Identifier '$identifier' uses path '$path' (device: $device)"
            $entrySummary += [PSCustomObject]$summaryItem
            continue
        }

        if ($device -and $device -match 'ramdisk|unknown|usb|network') {
            $summaryItem.Flags += 'device-review'
            Write-HostWarning "[CHECK BOOT DEVICE] Identifier '$identifier' boots from '$device'. Confirm legitimacy."
        }

        if (-not $summaryItem.Description) {
            $summaryItem.Flags += 'no-description'
            Write-HostWarning "[MISSING DESCRIPTION] Identifier '$identifier' has no friendly name."
        }

        $entrySummary += [PSCustomObject]$summaryItem
    }

    if ($suspiciousEntries -eq 0) {
        Write-HostSuccess "  No unusual firmware boot paths detected."
    }

    if ($entrySummary.Count -gt 0) {
        Write-HostInfo "  Boot entry snapshot:"
        $table = $entrySummary |
            Sort-Object Flags |
            Select-Object Identifier, Description, Device, Path, @{Name='Flags';Expression={($_.Flags -join ',')}} |
            Format-Table -AutoSize |
            Out-String
        Write-Host $table
    }

    Write-HostInfo "FirmwarePhantom scan complete."
}
