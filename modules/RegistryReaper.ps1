function Invoke-RegistryScan {
    Write-HostInfo "Initializing RegistryReaper..."
    Write-HostInfo "Scanning common autorun registry keys..."

    $pathsToScan = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices", # Older, but still possible
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

    $foundEntries = 0
    foreach ($path in $pathsToScan) {
        Write-HostInfo "\n[*] Scanning path: $path"
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($null -eq $items) { continue }

            $propertyNames = $items.PSObject.Properties | ForEach-Object { $_.Name }

            if ($propertyNames.Count -eq 0) {
                Write-HostSuccess "  No entries found."
                continue
            }

            foreach ($name in $propertyNames) {
                if ($name -eq "(default)") { continue } # Skip default entry
                $value = $items.$name
                $foundEntries++

                Write-HostDanger "[SUSPICIOUS REGISTRY ENTRY]"
                Write-HostDanger "  Path : $path"
                Write-HostDanger "  Name : $name"
                Write-HostDanger "  Value: $value"

                if (Confirm-Action -Prompt "Delete this entry?") {
                    try {
                        Remove-ItemProperty -Path $path -Name $name -ErrorAction Stop
                        Write-HostSuccess "  Entry '$name' deleted successfully."
                    } catch {
                        Write-HostFatal "  Failed to delete entry '$name': $($_.Exception.Message)"
                    }
                } else {
                    Write-HostInfo "  Deletion skipped for entry '$name'."
                }
            }
        } catch {
            Write-HostWarning "  Error accessing path '$path': $($_.Exception.Message)"
        }
    }

                if ($foundEntries -eq 0) {

                    Write-HostSuccess "No suspicious autorun registry entries found."

                } else {

                    Write-HostWarning "RegistryReaper found $foundEntries potential autorun entries. Review carefully."

                }

            

                    # --- AppInit_DLLs Scan ---

            

                    Write-HostInfo "\n[*] Scanning for AppInit_DLLs hijacking..."

            

                    $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"

            

                    $appInitEnabled = (Get-ItemProperty -Path $appInitPath -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs

            

                    $appInitDlls = (Get-ItemProperty -Path $appInitPath -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs

            

                

            

                    if ($appInitEnabled -eq 1 -and -not [string]::IsNullOrEmpty($appInitDlls)) {

            

                        Write-HostDanger "[APPINIT_DLLS HIJACKING DETECTED] AppInit_DLLs is enabled and contains entries!"

            

                        Write-HostDanger "  DLLs: $appInitDlls"

            

                    } else {

            

                        Write-HostSuccess "  No signs of AppInit_DLLs hijacking detected."

            

                    }

            

                

            

                    # --- BHO Scan ---

            

                    Write-HostInfo "\n[*] Scanning for Browser Helper Objects (BHOs)..."

            

                    $bhoPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"

            

                    $foundBHOs = 0

            

                    try {

            

                        $bhoClsids = Get-ChildItem -Path $bhoPath -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }

            

                        if ($bhoClsids) {

            

                            foreach ($clsid in $bhoClsids) {

            

                                $foundBHOs++

            

                                $bhoName = (Get-ItemProperty -Path "$bhoPath\$clsid" -ErrorAction SilentlyContinue).'(default)' | Out-String -Stream

            

                                $dllPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)' | Out-String -Stream

            

                

            

                                Write-HostDanger "[BHO DETECTED]"

            

                                Write-HostDanger "  Name: $bhoName"

            

                                Write-HostDanger "  CLSID: $clsid"

            

                                Write-HostDanger "  DLL Path: $dllPath"

            

                

            

                                if (Confirm-Action -Prompt "Disable this BHO?") {

            

                                    try {

            

                                        Remove-Item -Path "$bhoPath\$clsid" -Recurse -Force -ErrorAction Stop

            

                                        Write-HostSuccess "  BHO with CLSID '$clsid' disabled successfully."

            

                                    } catch {

            

                                        Write-HostFatal "  Failed to disable BHO: $($_.Exception.Message)"

            

                                    }

            

                                }

            

                            }

            

                        }

            

                    } catch {}

            

                

            

                    if ($foundBHOs -eq 0) {

            

                        Write-HostSuccess "  No Browser Helper Objects found."

            

                    }

            

                

            

                    Write-HostInfo "RegistryReaper scan complete."

            

                }

            

                

            

        

    