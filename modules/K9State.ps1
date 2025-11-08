Set-StrictMode -Version Latest

$script:K9Scoreboard = $null
$script:K9TipBucket = $null
$script:K9DataRoot = $null
$script:K9Settings = $null

function Initialize-K9State {
    Reset-K9Scoreboard
    Reset-K9Tips
    Get-K9DataRoot | Out-Null
    Get-K9Settings | Out-Null
}

function Get-K9DataRoot {
    if ($script:K9DataRoot) {
        return $script:K9DataRoot
    }

    $preferred = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'K9Watchdog'
    $fallback = Join-Path -Path $env:TEMP -ChildPath 'K9Watchdog'

    $path = $preferred
    if ([string]::IsNullOrWhiteSpace($path)) {
        $path = $fallback
    }

    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $script:K9DataRoot = $path
    } catch {
        $script:K9DataRoot = $fallback
    }

    foreach ($child in @('baseline', 'config')) {
        $childPath = Join-Path -Path $script:K9DataRoot -ChildPath $child
        try {
            if (-not (Test-Path $childPath)) {
                New-Item -Path $childPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {}
    }

    return $script:K9DataRoot
}

function Get-K9BaselinePath {
    param([Parameter(Mandatory = $true)][string]$Key)
    $safeKey = ($Key -replace '[^\w\-]', '_')
    return Join-Path -Path (Join-Path (Get-K9DataRoot) 'baseline') -ChildPath ("{0}.json" -f $safeKey)
}

function Get-K9Baseline {
    param([Parameter(Mandatory = $true)][string]$Key)

    $path = Get-K9BaselinePath -Key $Key
    if (-not (Test-Path $path)) { return $null }

    try {
        $content = Get-Content -Path $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) { return $null }
        return $content | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
}

function Save-K9Baseline {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][object]$Data
    )

    $path = Get-K9BaselinePath -Key $Key
    try {
        $json = $Data | ConvertTo-Json -Depth 6
        $json | Out-File -FilePath $path -Encoding UTF8
        return $true
    } catch {
        return $false
    }
}

function Compare-K9Baseline {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter()][object]$Current = $null,
        [string[]]$UniqueProperties = @('Id')
    )

    $currentList = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Current) {
        if ($Current -is [System.Collections.IEnumerable] -and -not ($Current -is [string])) {
            foreach ($item in $Current) { $currentList.Add($item) | Out-Null }
        } else {
            $currentList.Add($Current) | Out-Null
        }
    }

    $baseline = Get-K9Baseline -Key $Key
    if (-not $baseline) {
        Save-K9Baseline -Key $Key -Data ($currentList.ToArray()) | Out-Null
        return [PSCustomObject]@{
            Status = 'BaselineCreated'
            Added  = @()
            Removed = @()
        }
    }

    $baselineMap = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    foreach ($item in $baseline) {
        $keyValue = Get-K9BaselineKey -Item $item -Properties $UniqueProperties
        if (-not $baselineMap.ContainsKey($keyValue)) {
            $baselineMap[$keyValue] = $item
        }
    }

    $currentMap = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    foreach ($item in $currentList) {
        $keyValue = Get-K9BaselineKey -Item $item -Properties $UniqueProperties
        if (-not $currentMap.ContainsKey($keyValue)) {
            $currentMap[$keyValue] = $item
        }
    }

    $added = @()
    foreach ($key in $currentMap.Keys) {
        if (-not $baselineMap.ContainsKey($key)) {
            $added += $currentMap[$key]
        }
    }

    $removed = @()
    foreach ($key in $baselineMap.Keys) {
        if (-not $currentMap.ContainsKey($key)) {
            $removed += $baselineMap[$key]
        }
    }

    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        return [PSCustomObject]@{
            Status = 'NoChange'
            Added  = @()
            Removed = @()
        }
    }

    Save-K9Baseline -Key $Key -Data ($currentList.ToArray()) | Out-Null

    return [PSCustomObject]@{
        Status  = 'Diff'
        Added   = $added
        Removed = $removed
    }
}

function Get-K9BaselineKey {
    param(
        [Parameter(Mandatory = $true)]$Item,
        [string[]]$Properties
    )

    if (-not $Properties -or $Properties.Count -eq 0) {
        return ($Item | ConvertTo-Json -Depth 4)
    }

    $values = foreach ($prop in $Properties) {
        if ($Item.PSObject.Properties[$prop]) {
            $Item.$prop
        } else {
            $null
        }
    }

    return ($values -join '|')
}

function Reset-K9Scoreboard {
    $script:K9Scoreboard = [ordered]@{
        Total      = 0
        Indicators = New-Object System.Collections.Generic.List[object]
    }
}

function Add-K9Score {
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Indicator,
        [Parameter()][int]$Points = 5,
        [string]$Detail
    )

    if (-not $script:K9Scoreboard) {
        Reset-K9Scoreboard
    }

    $script:K9Scoreboard.Total += [Math]::Max(1, $Points)
    $script:K9Scoreboard.Indicators.Add(
        [PSCustomObject]@{
            Module    = $Module
            Indicator = $Indicator
            Points    = [Math]::Max(1, $Points)
            Detail    = if ($Detail) { $Detail } else { '-' }
        }
    ) | Out-Null
}

function Get-K9Scoreboard {
    if (-not $script:K9Scoreboard) {
        Reset-K9Scoreboard
    }
    return $script:K9Scoreboard
}

function Reset-K9Tips {
    $script:K9TipBucket = New-Object 'System.Collections.Generic.Dictionary[string,string]'
}

function Publish-K9Tip {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $script:K9TipBucket) {
        Reset-K9Tips
    }

    if (-not $script:K9TipBucket.ContainsKey($Code)) {
        $script:K9TipBucket[$Code] = $Message
    }
}

function Get-K9Tips {
    if (-not $script:K9TipBucket) {
        Reset-K9Tips
    }
    return $script:K9TipBucket
}

function Get-K9SettingsFile {
    return Join-Path -Path (Join-Path (Get-K9DataRoot) 'config') -ChildPath 'settings.json'
}

function Get-K9Settings {
    if ($script:K9Settings) {
        return $script:K9Settings
    }

    $file = Get-K9SettingsFile
    $script:K9Settings = @{}

    if (-not (Test-Path $file)) {
        return $script:K9Settings
    }

    try {
        $content = Get-Content -Path $file -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) {
            return $script:K9Settings
        }

        $parsed = $content | ConvertFrom-Json -ErrorAction Stop
        if ($parsed) {
            foreach ($prop in $parsed.PSObject.Properties) {
                $script:K9Settings[$prop.Name] = $prop.Value
            }
        }
    } catch {
        $script:K9Settings = @{}
    }

    return $script:K9Settings
}

function Get-K9SettingValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )

    $settings = Get-K9Settings
    if ($settings.ContainsKey($Name)) {
        return $settings[$Name]
    }

    return $Default
}

function Set-K9SettingValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value
    )

    $settings = Get-K9Settings
    $settings[$Name] = $Value

    $file = Get-K9SettingsFile
    try {
        $settings | ConvertTo-Json -Depth 6 | Out-File -FilePath $file -Encoding UTF8
        return $true
    } catch {
        return $false
    }
}
