Set-StrictMode -Version Latest

$script:K9SessionData = $null
$script:K9ModuleOverride = $null

function Show-Banner {
    $banner = @"
+------------------------------------------------------------------------+
|   __  __      ______        ____            __                         |
|  |  \/  |    |  ____|      / __ \          / _|                        |
|  | \  / | ___| |__   ___  | |  | |_ __ ___| |_ ___  _ __              |
|  | |\/| |/ _ \  __| / __| | |  | | '__/ _ \  _/ _ \| '__|             |
|  | |  | |  __/ |____\__ \ | |__| | | |  __/ || (_) | |                |
|  |_|  |_|\___|______|___/  \____/|_|  \___|_| \___/|_|                |
|                                                                        |
|                   K-9 WATCHDOG // TERMINAL DEFENSE                     |
+------------------------------------------------------------------------+
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Initialize-K9Session {
    param(
        [switch]$ShowBanner
    )

    $script:K9SessionData = [ordered]@{
        SessionId   = ('K9-' + (Get-Random -Minimum 100000 -Maximum 999999))
        StartTime   = Get-Date
        ModuleRuns  = New-Object System.Collections.Generic.List[object]
        PowerShell  = $PSVersionTable.PSVersion.ToString()
        HostName    = $env:COMPUTERNAME
        UserName    = $env:USERNAME
    }

    $script:K9ModuleOverride = $null

    if ($ShowBanner) {
        Show-Banner
        Write-Host ""
    }

    Show-SessionSlate
}

function Show-SessionSlate {
    if (-not $script:K9SessionData) { return }
    $session = $script:K9SessionData

    Write-Host "====================== SESSION CONTEXT ======================" -ForegroundColor DarkCyan
    Write-Host (" Session ID : {0}" -f $session.SessionId) -ForegroundColor Gray
    Write-Host (" Start Time : {0:u}" -f $session.StartTime.ToUniversalTime()) -ForegroundColor Gray
    Write-Host (" Host       : {0}" -f $session.HostName) -ForegroundColor Gray
    Write-Host (" Operator   : {0}" -f $session.UserName) -ForegroundColor Gray
    Write-Host (" PowerShell : {0}" -f $session.PowerShell) -ForegroundColor Gray
    Write-Host "=============================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-ModuleStart {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Write-Host ""
    Write-Host "----------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ("[>] Deploying {0}" -f $ModuleName.ToUpper()) -ForegroundColor Cyan
    Write-Host ("    {0}" -f $Description) -ForegroundColor Gray
    Write-Host "----------------------------------------------------------------" -ForegroundColor DarkCyan
}

function Register-K9ModuleResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [TimeSpan]$Duration,

        [string]$Detail
    )

    if (-not $script:K9SessionData) { return }
    $script:K9SessionData.ModuleRuns.Add(
        [PSCustomObject]@{
            Module   = $ModuleName
            Status   = $Status
            Duration = [Math]::Round($Duration.TotalSeconds, 2)
            Detail   = if ([string]::IsNullOrWhiteSpace($Detail)) { "-" } else { $Detail }
        }
    ) | Out-Null
}

function Reset-K9ModuleStatusOverride {
    $script:K9ModuleOverride = $null
}

function Set-K9ModuleStatus {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'WARN', 'FAIL', 'SKIP')]
        [string]$Status,

        [string]$Detail
    )

    $script:K9ModuleOverride = [PSCustomObject]@{
        Status = $Status
        Detail = $Detail
    }
}

function Get-K9ModuleStatusOverride {
    return $script:K9ModuleOverride
}

function Write-ModuleResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [TimeSpan]$Duration,

        [string]$Detail
    )

    $color = switch ($Status) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'SKIP' { 'DarkGray' }
        default { 'Gray' }
    }

    $durationText = ("{0:N2}s" -f $Duration.TotalSeconds)
    Write-Host ("[=] {0,-10} :: {1,-6} :: {2}" -f $ModuleName, $Status, $durationText) -ForegroundColor $color
    if (-not [string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host ("     -> {0}" -f $Detail) -ForegroundColor Gray
    }

    Register-K9ModuleResult -ModuleName $ModuleName -Status $Status -Duration $Duration -Detail $Detail
    Reset-K9ModuleStatusOverride
}

function Show-K9Summary {
    if (-not $script:K9SessionData) { return }
    $session = $script:K9SessionData
    $runtime = (Get-Date) - $session.StartTime

    Write-Host ""
    Write-Host "======================= MISSION DEBRIEF ======================" -ForegroundColor DarkCyan
    Write-Host (" Total Runtime : {0}" -f $runtime.ToString("hh\:mm\:ss")) -ForegroundColor Gray
    Write-Host (" Modules Run   : {0}" -f $session.ModuleRuns.Count) -ForegroundColor Gray

    if ($session.ModuleRuns.Count -eq 0) {
        Write-Host " No modules were executed in this session." -ForegroundColor Yellow
        Write-Host "=============================================================" -ForegroundColor DarkCyan
        return
    }

    $table = $session.ModuleRuns |
        Select-Object Module,
                      Status,
                      @{ Name = 'Time(s)'; Expression = { "{0:N2}" -f $_.Duration } },
                      @{ Name = 'Notes';   Expression = { $_.Detail } } |
        Format-Table -AutoSize |
        Out-String

    Write-Host $table -ForegroundColor Gray
    Write-Host "=============================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-HostSuccess {
    param([string]$Message)
    Write-Host "[+]" -ForegroundColor Green -NoNewline
    Write-Host " $Message"
}

function Write-HostInfo {
    param([string]$Message)
    Write-Host "[*]" -ForegroundColor Cyan -NoNewline
    Write-Host " $Message"
}

function Write-HostWarning {
    param([string]$Message)
    Write-Host "[!]" -ForegroundColor Yellow -NoNewline
    Write-Host " $Message"
}

function Write-HostDanger {
    param([string]$Message)
    Write-Host "[X]" -ForegroundColor Red -NoNewline
    Write-Host " $Message"
}

function Write-HostFatal {
    param([string]$Message)
    Write-Host "[#]" -ForegroundColor Magenta -NoNewline
    Write-Host " $Message"
}

function Confirm-Action {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )
    Write-Host "[?] $Prompt (Y/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    return ($response -eq 'Y' -or $response -eq 'y')
}
