param(
    [switch]$SkipNetwork
)

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptRoot '..')
Set-Location $projectRoot

. "$projectRoot\modules\K9Utils.ps1"
. "$projectRoot\modules\K9State.ps1"
. "$projectRoot\modules\VenomUI.ps1"
. "$projectRoot\modules\ForensicsWarden.ps1"
. "$projectRoot\modules\NetworkNinja.ps1"
. "$projectRoot\modules\RegistryReaper.ps1"
. "$projectRoot\modules\MemoryHunter.ps1"
. "$projectRoot\modules\DriverSentinel.ps1"

function Invoke-SmokeStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-Host "==> $Name" -ForegroundColor Cyan
    try {
        & $Action
        Write-Host "    PASS" -ForegroundColor Green
        return [PSCustomObject]@{ Name = $Name; Status = 'PASS' }
    } catch {
        Write-Host "    FAIL: $($_.Exception.Message)" -ForegroundColor Red
        return [PSCustomObject]@{ Name = $Name; Status = 'FAIL'; Error = $_.Exception }
    }
}

function Disable-ConfirmPrompts {
    Set-Item function:Confirm-Action -Value {
        param([string]$Prompt)
        return $false
    }
}

Disable-ConfirmPrompts

$results = New-Object System.Collections.Generic.List[object]

$rr = Invoke-SmokeStep -Name 'RegistryReaper' -Action {
    Invoke-RegistryScan
}
$results.Add($rr) | Out-Null

$mh = Invoke-SmokeStep -Name 'MemoryHunter' -Action {
    Invoke-MemoryScan
}
$results.Add($mh) | Out-Null

if (-not $SkipNetwork) {
    $net = Invoke-SmokeStep -Name 'NetworkNinja' -Action {
        Invoke-NetworkScan
    }
    $results.Add($net) | Out-Null
}

$fw = Invoke-SmokeStep -Name 'ForensicsWarden Minimal' -Action {
    Invoke-ForensicsScan -Scope Minimal -Roots @(Get-Location) -YaraRoots @(Get-Location) -SkipSnapshot
}
$results.Add($fw) | Out-Null

$drv = Invoke-SmokeStep -Name 'DriverSentinel (quick)' -Action {
    Invoke-DriverSentinel -SkipEventAudit
}
$results.Add($drv) | Out-Null

$resultsArray = $results.ToArray()
$failed = $resultsArray | Where-Object { $_ -and $_.PSObject.Properties['Status'] -and $_.Status -ne 'PASS' }
$failureCount = ($failed | Measure-Object).Count
if ($failureCount -gt 0) {
    Write-Host ""
    Write-Host "Smoke run completed with failures." -ForegroundColor Red
    $failed | Format-Table Name, Status | Out-String | Write-Host
    exit 1
}

Write-Host ""
Write-Host "Smoke run completed successfully." -ForegroundColor Green
