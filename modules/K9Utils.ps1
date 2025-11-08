Set-StrictMode -Version Latest

function Get-K9LogicalRoots {
    $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayRoot -eq $null -and $_.Description -ne 'Temp' }

    if (-not $drives) {
        return @('C:\')
    }

    return ($drives | Select-Object -ExpandProperty Root | Sort-Object -Unique)
}

function Resolve-K9Path {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        return [System.IO.Path]::GetFullPath($Path)
    } catch {
        return $Path
    }
}

function Test-K9PathExcluded {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string[]]$ExcludedRoots
    )

    if (-not $ExcludedRoots -or $ExcludedRoots.Count -eq 0) {
        return $false
    }

    $normalized = Resolve-K9Path -Path $Path
    foreach ($root in $ExcludedRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $normalizedRoot = Resolve-K9Path -Path $root
        if ($normalized.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-K9FileSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$MaxBytes = 8
    )

    try {
        $bytes = Get-Content -Path $Path -Encoding Byte -TotalCount $MaxBytes -ErrorAction Stop
        if (-not $bytes) { return $null }
        return ($bytes | ForEach-Object { $_.ToString("X2") }) -join ' '
    } catch {
        return $null
    }
}

function Get-K9FileEntropy {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$SampleKB = 768
    )

    try {
        $file = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($file.Length -eq 0) { return 0 }

        $sampleSize = [Math]::Min($file.Length, $SampleKB * 1024)
        $buffer = New-Object byte[] $sampleSize

        $stream = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $read = $stream.Read($buffer, 0, $sampleSize)
        } finally {
            $stream.Dispose()
        }

        if ($read -le 0) { return 0 }

        $counts = New-Object int[] 256
        for ($i = 0; $i -lt $read; $i++) {
            $counts[$buffer[$i]]++
        }

        $entropy = 0.0
        for ($i = 0; $i -lt 256; $i++) {
            if ($counts[$i] -eq 0) { continue }
            $p = $counts[$i] / $read
            $entropy -= $p * [Math]::Log($p, 2)
        }

        return [Math]::Round($entropy, 3)
    } catch {
        return $null
    }
}

function Measure-K9StringEntropy {
    param([Parameter(Mandatory = $true)][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 0
    }

    $chars = $Text.ToCharArray()
    $counts = @{}
    foreach ($c in $chars) {
        if (-not $counts.ContainsKey($c)) {
            $counts[$c] = 0
        }
        $counts[$c]++
    }

    $entropy = 0.0
    foreach ($count in $counts.Values) {
        $p = $count / $chars.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }

    return [Math]::Round($entropy, 3)
}

function Get-K9BaseDomain {
    param([Parameter(Mandatory = $true)][string]$HostName)

    $parts = $HostName -split '\.'
    if ($parts.Length -lt 2) {
        return $HostName
    }

    $lastTwo = $parts[-2..-1]
    return ($lastTwo -join '.')
}

function Test-K9PrivateIPv4 {
    param([Parameter(Mandatory = $true)][string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return $false
    }

    if ($Address -eq '::1' -or $Address -eq '127.0.0.1') {
        return $true
    }

    if ($Address.Contains(':')) {
        return $false
    }

    try {
        $ip = [System.Net.IPAddress]::Parse($Address)
        $bytes = $ip.GetAddressBytes()
    } catch {
        return $false
    }

    switch ($bytes[0]) {
        10 { return $true }
        127 { return $true }
        192 { if ($bytes[1] -eq 168) { return $true } }
        172 { if ($bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true } }
    }

    return $false
}

function Format-K9Size {
    param([Parameter(Mandatory = $true)][double]$Bytes)

    if ($Bytes -ge 1GB) {
        return ("{0:N2} GB" -f ($Bytes / 1GB))
    } elseif ($Bytes -ge 1MB) {
        return ("{0:N2} MB" -f ($Bytes / 1MB))
    } elseif ($Bytes -ge 1KB) {
        return ("{0:N0} KB" -f ($Bytes / 1KB))
    }

    return ("{0:N0} B" -f $Bytes)
}

function Get-K9StringHash {
    param([Parameter(Mandatory = $true)][string]$Text)

    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($bytes)
        return ($hash | ForEach-Object { $_.ToString("x2") }) -join ''
    } catch {
        return $null
    }
}
