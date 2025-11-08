Set-StrictMode -Version Latest

function Invoke-NetworkScan {
    Write-HostInfo "Initializing NetworkNinja..."

    Invoke-ArpSpoofingSweep
    Invoke-HostsFileScan
    Invoke-DnsServerInventory
    Invoke-PortProxyRecon
    Invoke-SuspiciousOutboundScan
    Invoke-TunnelProcessScan
    Invoke-DnsAnomalyScan
    Invoke-RouteStackReview

    Write-HostInfo "NetworkNinja scan complete."
}

function Invoke-ArpSpoofingSweep {
    Write-HostInfo "[1/8] Scanning for ARP spoofing..."

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
        if ($mac -eq 'ff-ff-ff-ff-ff-ff') { continue }
        if ($macTable[$mac].Count -gt 1) {
            $spoofingDetected = $true
            $ipList = $macTable[$mac] -join ', '
            Write-HostDanger ("  [ARP] MAC {0} maps to multiple IPs: {1}" -f $mac, $ipList)
            Add-K9Score -Module 'NetworkNinja' -Indicator 'ARP Conflict' -Points 12 -Detail ("{0}->{1}" -f $mac, $ipList)
        }
    }

    if (-not $spoofingDetected) {
        Write-HostSuccess "  No overlapping ARP entries detected."
    } else {
        Publish-K9Tip -Code 'ArpSpoof' -Message 'Flush ARP cache (`arp -d *`) and force switch port security if spoofing persists.'
    }
}

function Invoke-HostsFileScan {
    Write-HostInfo "[2/8] Scanning hosts file for hijacks..."
    $hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsFileContent = Get-Content $hostsFilePath -ErrorAction SilentlyContinue

    $hostsWhitelist = @(
        '127.0.0.1\s+localhost',
        '::1\s+localhost',
        '.*host\.docker\.internal',
        '.*gateway\.docker\.internal',
        '.*kubernetes\.docker\.internal'
    )

    $hijackDetected = $false
    if ($null -ne $hostsFileContent) {
        foreach ($line in $hostsFileContent) {
            $trimmedLine = $line.Trim()
            if ([string]::IsNullOrEmpty($trimmedLine) -or $trimmedLine.StartsWith('#')) {
                continue
            }

            $isWhitelisted = $false
            foreach ($pattern in $hostsWhitelist) {
                if ($trimmedLine -match $pattern) {
                    $isWhitelisted = $true
                    break
                }
            }

            if (-not $isWhitelisted) {
                $hijackDetected = $true
                Write-HostDanger ("  [HOSTS] Suspicious entry: {0}" -f $trimmedLine)
                Add-K9Score -Module 'NetworkNinja' -Indicator 'Hosts Hijack' -Points 8 -Detail $trimmedLine
            }
        }
    }

    if (-not $hijackDetected) {
        Write-HostSuccess "  No suspicious hosts entries."
    } else {
        Publish-K9Tip -Code 'HostsReset' -Message 'Reset hosts file via `Copy-Item $env:SystemRoot\\System32\\drivers\\etc\\hosts.default hosts` then lock ACLs.'
    }
}

function Invoke-DnsServerInventory {
    Write-HostInfo "[3/8] Scanning for untrusted DNS resolvers..."

    $commonDns = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112")
    $flagged = $false
    $records = New-Object System.Collections.Generic.List[object]

    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'TRUE'"
        foreach ($adapter in $adapters) {
            if ($adapter.DNSServerSearchOrder) {
                foreach ($dns in $adapter.DNSServerSearchOrder) {
                    $records.Add([PSCustomObject]@{
                        Adapter = $adapter.Description
                        Address = $dns
                    }) | Out-Null

                    if ($dns -in $commonDns) { continue }
                    if (Test-K9PrivateIPv4 -Address $dns) { continue }
                    $flagged = $true
                    Write-HostWarning ("  [DNS] Adapter '{0}' uses uncommon resolver {1}" -f $adapter.Description, $dns)
                    Add-K9Score -Module 'NetworkNinja' -Indicator 'Untrusted DNS' -Points 10 -Detail ("{0} -> {1}" -f $adapter.Description, $dns)
                }
            }
        }
    } catch {
        Write-HostWarning "  Unable to enumerate DNS servers."
    }

    if (-not $flagged) {
        Write-HostSuccess "  DNS servers appear trusted/expected."
    } else {
        Publish-K9Tip -Code 'DNSServerAudit' -Message 'Validate DNS servers via ipconfig /all; lock NIC configs or DHCP scope if rogue IPs appear.'
    }

    if ($records.Count -gt 0) {
        $diff = Compare-K9Baseline -Key 'Network_DnsServers' -Current $records -UniqueProperties @('Adapter','Address')
        if ($diff.Status -eq 'BaselineCreated') {
            Write-HostInfo "  DNS resolver baseline stored."
        } elseif ($diff.Status -eq 'Diff' -and $diff.Added.Count -gt 0) {
            Write-HostWarning ("  [BASELINE] {0} new DNS resolver mapping(s)." -f $diff.Added.Count)
        }
    }
}

function Invoke-PortProxyRecon {
    Write-HostInfo "[4/8] Inspecting netsh portproxy rules..."

    $rules = Get-PortProxyRules
    if (-not $rules -or $rules.Count -eq 0) {
        Write-HostSuccess "  No active portproxy bindings."
        return
    }

    $diff = Compare-K9Baseline -Key 'Network_PortProxy' -Current $rules -UniqueProperties @('ListenAddress','ListenPort','ConnectAddress','ConnectPort')
    if ($diff.Status -eq 'BaselineCreated') {
        Write-HostInfo "  Portproxy baseline saved (re-run for diffs)."
    } elseif ($diff.Status -eq 'Diff') {
        if ($diff.Added.Count -gt 0) {
            Write-HostWarning ("  [BASELINE] {0} new portproxy rule(s)." -f $diff.Added.Count)
            Add-K9Score -Module 'NetworkNinja' -Indicator 'New PortProxy' -Points 12 -Detail 'Portproxy table changed'
        }
        if ($diff.Removed.Count -gt 0) {
            Write-HostInfo ("  [BASELINE] {0} rule(s) removed since last run." -f $diff.Removed.Count)
        }
    }

    foreach ($rule in $rules) {
        $suspicious = $false

        if (-not (Test-K9PrivateIPv4 -Address $rule.ConnectAddress)) {
            $suspicious = $true
        }

        if ($rule.ListenPort -eq 3389 -or $rule.ConnectPort -eq 3389) {
            $suspicious = $true
        }

        $indicator = if ($suspicious) { '[!] ' } else { '    ' }
        $message = "{0}Listen {1}:{2} => {3}:{4} ({5})" -f $indicator, $rule.ListenAddress, $rule.ListenPort, $rule.ConnectAddress, $rule.ConnectPort, $rule.Type

        if ($suspicious) {
            Write-HostDanger ("  [PORTPROXY] {0}" -f $message.Trim())
            Add-K9Score -Module 'NetworkNinja' -Indicator 'PortProxy Public' -Points 15 -Detail ("{0}->{1}" -f $rule.ListenPort, $rule.ConnectAddress)
            Publish-K9Tip -Code 'PortProxyCleanup' -Message 'Use `netsh interface portproxy delete v4tov4 listenport=<port>` to rip rogue relays (requires admin).'
        } else {
            Write-HostInfo ("  [PORTPROXY] {0}" -f $message.Trim())
        }
    }
}

function Get-PortProxyRules {
    $output = netsh interface portproxy show all 2>&1
    if (-not $output) { return @() }

    $rules = @()
    foreach ($line in $output) {
        if ($line -match '^\s*(?<listen>[\w\.\:]+)\s+(?<listenPort>\d+)\s+(?<connect>[\w\.\:]+)\s+(?<connectPort>\d+)') {
            $rules += [PSCustomObject]@{
                ListenAddress = $matches['listen']
                ListenPort    = [int]$matches['listenPort']
                ConnectAddress= $matches['connect']
                ConnectPort   = [int]$matches['connectPort']
                Type          = 'v4tov4'
            }
        }
    }

    return $rules
}

function Invoke-SuspiciousOutboundScan {
    Write-HostInfo "[5/8] Profiling outbound TCP sessions..."

    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    if (-not $connections) {
        Write-HostWarning "  No established connections retrieved."
        return
    }

    $processMap = @{}
    $cimMap = @{}
    try {
        $cims = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
        foreach ($cim in $cims) {
            $cimMap[$cim.ProcessId] = $cim
        }
    } catch {}

    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        $processMap[$proc.Id] = $proc
    }

    $commonPorts = @(80, 443, 53, 123, 3389, 5985, 5986, 22)
    $now = Get-Date
    $findings = @()

    foreach ($conn in $connections) {
        if (-not $conn.RemoteAddress) { continue }
        if (Test-K9PrivateIPv4 -Address $conn.RemoteAddress) { continue }

        $procInfo = $processMap[$conn.OwningProcess]
        $cimInfo = $cimMap[$conn.OwningProcess]
        $parentName = $null
        $commandLine = $null
        $path = $null
        $uptimeMinutes = $null

        if ($cimInfo) {
            $path = $cimInfo.ExecutablePath
            $commandLine = $cimInfo.CommandLine
            if ($cimInfo.ParentProcessId -ne 0 -and $cimMap.ContainsKey($cimInfo.ParentProcessId)) {
                $parentName = $cimMap[$cimInfo.ParentProcessId].Name
            }
            if ($cimInfo.CreationDate) {
                try {
                    $start = [System.Management.ManagementDateTimeConverter]::ToDateTime($cimInfo.CreationDate)
                    if ($start) {
                        $uptimeMinutes = [Math]::Round(($now - $start).TotalMinutes, 1)
                    }
                } catch {
                    $uptimeMinutes = $null
                }
            }
        } elseif ($procInfo) {
            $path = $procInfo.Path
            $parentName = 'Unknown'
            if ($procInfo.StartTime) {
                $uptimeMinutes = [Math]::Round(($now - $procInfo.StartTime).TotalMinutes, 1)
            }
        }

        $score = 0
        if ($conn.RemotePort -gt 1024 -and $commonPorts -notcontains $conn.RemotePort) { $score += 2 }
        if ($path -and ($path -like "$env:USERPROFILE\*" -or $path -like "$env:LOCALAPPDATA\*" -or $path -like "$env:TEMP\*")) { $score += 2 }
        if (-not $path) { $score += 1 }
        if ($uptimeMinutes -and $uptimeMinutes -gt 60) { $score += 1 }
        if ($commandLine -match '-enc ' -or $commandLine -match '-EncodedCommand' -or $commandLine -match '-nop') { $score += 2 }

        if ($score -ge 2) {
            $findings += [PSCustomObject]@{
                Process    = if ($procInfo) { $procInfo.ProcessName } elseif ($cimInfo) { $cimInfo.Name } else { "PID $($conn.OwningProcess)" }
                PID        = $conn.OwningProcess
                Parent     = if ($parentName) { $parentName } else { 'Unknown' }
                Local      = "{0}:{1}" -f $conn.LocalAddress, $conn.LocalPort
                Remote     = "{0}:{1}" -f $conn.RemoteAddress, $conn.RemotePort
                Path       = $path
                UptimeMin  = $uptimeMinutes
                Score      = $score
            }
        }
    }

    if ($findings.Count -gt 0) {
        Write-HostDanger ("  [OUTBOUND] {0} candidate reverse-shell/tunnel sessions detected." -f $findings.Count)
        $findings |
            Sort-Object Score -Descending |
            Select-Object -First 20 |
            Format-Table Process, PID, Parent, Remote, UptimeMin, Score -AutoSize
        $points = [Math]::Min(40, $findings.Count * 5)
        Add-K9Score -Module 'NetworkNinja' -Indicator 'Suspicious Outbound' -Points $points -Detail ("{0} reverse-shell candidates" -f $findings.Count)
        Publish-K9Tip -Code 'ReverseShellContain' -Message 'Terminate the owning process and block egress IP/port before forensic triage when reverse shells are confirmed.'
    } else {
        Write-HostSuccess "  No suspicious outbound sessions found."
    }
}

function Invoke-TunnelProcessScan {
    Write-HostInfo "[6/8] Hunting tunnel utilities & ssh -R/-L usage..."

    $keywords = @('ngrok', 'chisel', 'frpc', 'frps', 'rclone', 'sshuttle', 'socat', 'cloudflared', 'plink', 'ssh', 'powershell', 'cmd', 'python')
    $hits = @()

    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            $name = $proc.Name
            $cmd = $proc.CommandLine

            if ($name -match 'ssh|plink|putty' -and $cmd -match '\s-[RLD]\s') {
                $hits += [PSCustomObject]@{
                    Process = $name
                    PID     = $proc.ProcessId
                    Command = $cmd
                    Note    = 'SSH tunnel switches detected'
                }
                continue
            }

            foreach ($keyword in $keywords) {
                if ($name -match [Regex]::Escape($keyword) -or ($cmd -and $cmd -match $keyword)) {
                    if ($keyword -eq 'powershell' -and -not ($cmd -match '-enc|-EncodedCommand|-nop')) { continue }
                    $hits += [PSCustomObject]@{
                        Process = $name
                        PID     = $proc.ProcessId
                        Command = $cmd
                        Note    = "Keyword '$keyword'"
                    }
                    break
                }
            }
        }
    } catch {
        Write-HostWarning "  Unable to enumerate running processes for tunnel keywords."
    }

    if ($hits.Count -gt 0) {
        Write-HostDanger ("  [TUNNELS] {0} live process indicators spotted." -f $hits.Count)
        $hits |
            Select-Object -First 20 |
            Format-Table Process, PID, Note -AutoSize
        Add-K9Score -Module 'NetworkNinja' -Indicator 'Tunnel Processes' -Points ([Math]::Min(30, $hits.Count * 4)) -Detail 'Live tunnel utilities detected'
    } else {
        Write-HostSuccess "  No active tunnel binaries detected via process scan."
    }
}

function Invoke-DnsAnomalyScan {
    Write-HostInfo "[7/8] Evaluating DNS cache for tunneling patterns..."

    try {
        $cache = Get-DnsClientCache
    } catch {
        Write-HostWarning "  Unable to read DNS client cache."
        return
    }

    if (-not $cache) {
        Write-HostWarning "  DNS cache is empty."
        return
    }

    $longRequests = @()
    foreach ($entry in $cache) {
        if (-not $entry.Entry) { continue }
        $entropy = Measure-K9StringEntropy -Text $entry.Entry
        if ($entry.Entry.Length -gt 80 -or $entropy -gt 3.8 -or $entry.Entry -match '\d{6,}') {
            $longRequests += [PSCustomObject]@{
                Name      = $entry.Entry
                Type      = (Get-DnsTypeName -Type $entry.Type)
                TTL       = $entry.TimeToLive
                Entropy   = $entropy
            }
        }
    }

    $domainCounts = $cache |
        Group-Object { Get-K9BaseDomain -HostName $_.Entry } |
        Where-Object { $_.Count -gt 25 }

    $txtRecords = @($cache | Where-Object { $_.Type -eq 16 })
    $nullRecords = @($cache | Where-Object { $_.Type -eq 10 })

    if ($longRequests.Count -gt 0) {
        Write-HostDanger ("  [DNS] {0} high-entropy or oversized queries detected." -f $longRequests.Count)
        $longRequests | Select-Object -First 10 | Format-Table Name, Type, TTL, Entropy -AutoSize
        Add-K9Score -Module 'NetworkNinja' -Indicator 'DNS Tunneling' -Points 18 -Detail 'High entropy cache entries'
        Publish-K9Tip -Code 'DNSTunnel' -Message 'Capture DNS pcap + look for TXT/NULL beacons; consider sinkholing the parent domain.'
    } else {
        Write-HostSuccess "  No abnormally long/high-entropy DNS names observed."
    }

    foreach ($group in $domainCounts) {
        Write-HostWarning ("  [DNS] {0} cache entries reference domain '{1}'" -f $group.Count, $group.Name)
        Add-K9Score -Module 'NetworkNinja' -Indicator 'DNS Beaconing' -Points 6 -Detail ("Cache flood from {0}" -f $group.Name)
    }

    if ($txtRecords.Count -gt 0 -or $nullRecords.Count -gt 0) {
        if ($txtRecords.Count -gt 0) {
            Write-HostWarning ("  [DNS] {0} TXT records cached (possible data exfil)." -f $txtRecords.Count)
            Add-K9Score -Module 'NetworkNinja' -Indicator 'DNS TXT Traffic' -Points 5 -Detail 'TXT queries recorded'
        }
        if ($nullRecords.Count -gt 0) {
            Write-HostWarning ("  [DNS] {0} NULL records cached (rare legitimate use)." -f $nullRecords.Count)
            Add-K9Score -Module 'NetworkNinja' -Indicator 'DNS NULL Traffic' -Points 5 -Detail 'NULL queries recorded'
        }
    }
}

function Invoke-RouteStackReview {
    Write-HostInfo "[8/8] Reviewing routing table & neighbors..."

    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $routes) {
        Write-HostWarning "  Unable to read routing table."
        return
    }

    $defaultRoutes = $routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }
    if ($defaultRoutes.Count -gt 1) {
        Write-HostWarning ("  [ROUTE] {0} default gateways present." -f $defaultRoutes.Count)
        Add-K9Score -Module 'NetworkNinja' -Indicator 'Multiple Default Routes' -Points 6 -Detail 'Multiple gateways detected'
    }

    foreach ($route in $defaultRoutes) {
        if (-not (Test-K9PrivateIPv4 -Address $route.NextHop)) {
            Write-HostDanger ("  [ROUTE] Default route via public hop {0} (Interface {1})" -f $route.NextHop, $route.InterfaceAlias)
            Add-K9Score -Module 'NetworkNinja' -Indicator 'Public Gateway' -Points 12 -Detail $route.NextHop
            Publish-K9Tip -Code 'RouteIsolation' -Message 'Check `route print` for rogue gateways; remove with `route delete 0.0.0.0` if malicious.'
        }
    }

    $exoticRoutes = $routes | Where-Object {
        $policyProp = $_.PSObject.Properties['PolicyStore']
        $policyValue = if ($policyProp) { $policyProp.Value } else { $null }
        ($policyValue -and $policyValue -ne 'ActiveStore') -and $_.DestinationPrefix -ne '0.0.0.0/0'
    }
    foreach ($route in $exoticRoutes) {
        Write-HostWarning ("  [ROUTE] Non-active store entry {0} via {1}" -f $route.DestinationPrefix, $route.NextHop)
        Add-K9Score -Module 'NetworkNinja' -Indicator 'Policy Route' -Points 4 -Detail $route.DestinationPrefix
    }

    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $duplicateMacs = $neighbors | Group-Object LinkLayerAddress | Where-Object { $_.Count -gt 1 -and $_.Name -ne 'ff-ff-ff-ff-ff-ff' }
        foreach ($dup in $duplicateMacs) {
            Write-HostWarning ("  [NEIGHBOR] MAC {0} owns multiple IPs ({1})" -f $dup.Name, (($dup.Group | Select-Object -ExpandProperty IPAddress) -join ', '))
        }
    } catch {}
}

function Get-DnsTypeName {
    param([int]$Type)

    $map = @{
        1  = 'A'
        2  = 'NS'
        5  = 'CNAME'
        6  = 'SOA'
        10 = 'NULL'
        12 = 'PTR'
        15 = 'MX'
        16 = 'TXT'
        28 = 'AAAA'
        33 = 'SRV'
    }

    if ($map.ContainsKey($Type)) {
        return $map[$Type]
    }

    return "TYPE$Type"
}
