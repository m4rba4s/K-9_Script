[CmdletBinding()]
param(
    [switch]$Registry,
    [switch]$Memory,
    [switch]$Network,
    [switch]$Firmware,
    [switch]$All,
    [switch]$NoBanner
)

Set-StrictMode -Version Latest

if (-not $NoBanner) {
    Clear-Host
}

$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
. "$PSScriptRoot\modules\VenomUI.ps1"
. "$PSScriptRoot\modules\RegistryReaper.ps1"
. "$PSScriptRoot\modules\MemoryHunter.ps1"
. "$PSScriptRoot\modules\NetworkNinja.ps1"
. "$PSScriptRoot\modules\FirmwarePhantom.ps1"

Initialize-K9Session -ShowBanner:$(-not $NoBanner)

$moduleDefinitions = @(
    [PSCustomObject]@{
        Key         = '1'
        Name        = 'RegistryReaper'
        Aliases     = @('registry', 'reg')
        Description = 'Scan for persistence in registry'
        Action      = { Invoke-RegistryScan }
    }
    [PSCustomObject]@{
        Key         = '2'
        Name        = 'MemoryHunter'
        Aliases     = @('memory', 'mem')
        Description = 'Scan for in-memory threats'
        Action      = { Invoke-MemoryScan }
    }
    [PSCustomObject]@{
        Key         = '3'
        Name        = 'NetworkNinja'
        Aliases     = @('network', 'net')
        Description = 'Network threat analysis'
        Action      = { Invoke-NetworkScan }
    }
    [PSCustomObject]@{
        Key         = '4'
        Name        = 'FirmwarePhantom'
        Aliases     = @('firmware', 'fw')
        Description = 'Firmware posture audit & boot integrity check (requires admin)'
        Action      = { Invoke-FirmwareScan }
    }
)

function Resolve-K9Module {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Selection
    )

    $normalized = $Selection.Trim()
    if ([string]::IsNullOrEmpty($normalized)) {
        return $null
    }

    $normalizedUpper = $normalized.ToUpperInvariant()
    foreach ($module in $moduleDefinitions) {
        if ($module.Key -eq $normalizedUpper) {
            return $module
        }

        if ($module.Name.Equals($normalized, [System.StringComparison]::InvariantCultureIgnoreCase)) {
            return $module
        }

        foreach ($alias in $module.Aliases) {
            if ($alias.Equals($normalized, [System.StringComparison]::InvariantCultureIgnoreCase)) {
                return $module
            }
        }
    }

    return $null
}

function Invoke-K9Module {
    param(
        [Parameter(Mandatory = $true)]
        $Module
    )

    Write-ModuleStart -ModuleName $Module.Name -Description $Module.Description
    Reset-K9ModuleStatusOverride

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'
    $detail = ''

    try {
        & $Module.Action
    } catch {
        $status = 'FAIL'
        $detail = $_.Exception.Message
        Write-HostFatal ("Module '{0}' threw an error: {1}" -f $Module.Name, $detail)
    }

    $stopwatch.Stop()

    $override = Get-K9ModuleStatusOverride
    if ($override) {
        $status = $override.Status
        if (-not [string]::IsNullOrWhiteSpace($override.Detail)) {
            $detail = $override.Detail
        }
    }

    Write-ModuleResult -ModuleName $Module.Name -Status $status -Duration $stopwatch.Elapsed -Detail $detail
}

$requestedModules = @()

if ($All) {
    $requestedModules = @($moduleDefinitions)
} else {
    if ($Registry) { $requestedModules += Resolve-K9Module -Selection 'registry' }
    if ($Memory)   { $requestedModules += Resolve-K9Module -Selection 'memory' }
    if ($Network)  { $requestedModules += Resolve-K9Module -Selection 'network' }
    if ($Firmware) { $requestedModules += Resolve-K9Module -Selection 'firmware' }
}

$requestedModules = @(
    $requestedModules |
        Where-Object { $_ -ne $null } |
        Sort-Object -Property Name -Unique
)

if ($requestedModules.Length -gt 0) {
    foreach ($module in $requestedModules) {
        Invoke-K9Module -Module $module
        Write-Host ""
    }
    Show-K9Summary
    return
}

while ($true) {
    Write-HostInfo "Select a module to run:"
    foreach ($module in $moduleDefinitions) {
        Write-Host "  [$($module.Key)] $($module.Name) - $($module.Description)"
    }
    Write-Host "  [A] Run all modules"
    Write-Host "  [Q] Quit"

    $choice = Read-Host "K9>"
    if ($null -eq $choice) {
        continue
    }

    $normalizedChoice = $choice.Trim()
    if ([string]::IsNullOrEmpty($normalizedChoice)) {
        Write-HostWarning "No selection provided. Try again."
        continue
    }

    $upperChoice = $normalizedChoice.ToUpperInvariant()
    if ($upperChoice -eq 'Q') {
        Write-HostSuccess "Stay paranoid. Exiting."
        break
    }

    if ($upperChoice -eq 'A') {
        foreach ($module in $moduleDefinitions) {
            Invoke-K9Module -Module $module
            Write-Host ""
        }
        continue
    }

    $resolvedModule = Resolve-K9Module -Selection $normalizedChoice
    if ($null -eq $resolvedModule) {
        Write-HostDanger "Invalid choice '$normalizedChoice'. Try again."
        continue
    }

    Invoke-K9Module -Module $resolvedModule
    Write-Host ""
}

Show-K9Summary
