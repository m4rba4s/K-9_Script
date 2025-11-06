function Invoke-NetworkScan {
    Write-HostInfo "Initializing NetworkNinja..."

    # --- Technique 1: ARP Spoofing Detection ---
    Write-HostInfo "[1/3] Scanning for ARP spoofing..."

    $arpOutput = arp -a
    $macTable = @{}

    $regex = '\s*([0-9]{1,3}(\.[0-9]{1,3}){3})\s+(([0-9a-f]{2}-){5}[0-9a-f]{2})\s+\w+'

    foreach ($line in $arpOutput) {
        if ($line -match $regex) {
            $ip = $matches[1]
            $mac = $matches[3]

            if (-not $macTable.ContainsKey($mac)) {
                $macTable[$mac] = New-Object System.Collections.ArrayList
            }
            $macTable[$mac].Add($ip) | Out-Null
        }
    }

    $spoofingDetected = $false
    foreach ($mac in $macTable.Keys) {
        if ($mac -eq 'ff-ff-ff-ff-ff-ff') { continue } # Ignore broadcast MAC
        if ($macTable[$mac].Count -gt 1) {
            $spoofingDetected = $true
            $ipList = $macTable[$mac] -join ', '
            Write-HostDanger "[ARP SPOOFING DETECTED] MAC address '$mac' is associated with multiple IP addresses: $ipList"
        }
    }

    if (-not $spoofingDetected) {
        Write-HostSuccess "  No signs of ARP spoofing detected."
    }

    # --- Technique 2: Hosts File Scan ---
    Write-HostInfo "[2/3] Scanning hosts file for DNS hijacking..."
    $hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsFileContent = Get-Content $hostsFilePath -ErrorAction SilentlyContinue

    $hostsHijackDetected = $false
    if ($null -ne $hostsFileContent) {
        $hostsWhitelist = @(
            '127.0.0.1\s+localhost',
            '::1\s+localhost',
            '.*host\.docker\.internal',
            '.*gateway\.docker\.internal',
            '.*kubernetes\.docker\.internal'
        )

        foreach ($line in $hostsFileContent) {
            $trimmedLine = $line.Trim()
            if (-not ([string]::IsNullOrEmpty($trimmedLine)) -and -not ($trimmedLine.StartsWith('#'))) {
                $isWhitelisted = $false
                foreach ($pattern in $hostsWhitelist) {
                    if ($trimmedLine -match $pattern) {
                        $isWhitelisted = $true
                        break
                    }
                }
                if (-not $isWhitelisted) {
                    $hostsHijackDetected = $true
                    Write-HostDanger "[DNS HIJACKING DETECTED] Suspicious entry in hosts file: $trimmedLine"
                }
            }
        }
    }

    if (-not $hostsHijackDetected) {
        Write-HostSuccess "  No suspicious entries found in hosts file."
    }

        # --- Technique 4: DNS Server Scan ---

        Write-HostInfo "[4/4] Scanning for suspicious DNS servers..."

        $dnsHijackDetected = $false

        $wellKnownDns = @(

            "8.8.8.8", "8.8.4.4", # Google

            "1.1.1.1", "1.0.0.1", # Cloudflare

            "9.9.9.9", "149.112.112.112"  # Quad9

        )

    

        try {

            $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'TRUE'"

            foreach ($adapter in $adapters) {

                if ($adapter.DNSServerSearchOrder) {

                    foreach ($dns in $adapter.DNSServerSearchOrder) {

                        if ($dns -in $wellKnownDns) { continue }

                        if ($dns -match '^127\.' -or $dns -match '^192\.168\.' -or $dns -match '^10\.' -or $dns -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { continue } # Ignore localhost and private ranges

    

                                            $dnsHijackDetected = $true

    

                                            Write-HostWarning "[UNCOMMON DNS DETECTED] DNS server '$dns' found on adapter '($($adapter.Description))'. Verify if this is legitimate."

                    }

                }

            }

        } catch {

            Write-HostWarning "Could not retrieve DNS server information."

        }

    

        if (-not $dnsHijackDetected) {

            Write-HostSuccess "  No suspicious DNS servers detected."

        }

    

        Write-HostInfo "NetworkNinja scan complete."

    }

    