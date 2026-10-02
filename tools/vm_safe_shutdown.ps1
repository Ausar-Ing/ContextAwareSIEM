# Safe host shutdown with the baseline VM running -- HOST SIDE (Windows 11 host).
#
# Use this INSTEAD of Start -> Shut down while the VM baseline runs
# (COLLECTION_RECORD.md Part G, G.1 row 11). A Start-menu shutdown kills the
# headless VM mid-save and the guest logs 41/6008 on its next boot.
#
# What it does:
#   1. If vm-win11-target is running, press its ACPI power button (a clean
#      guest shutdown, the same as Start -> Shut down inside the VM).
#   2. Wait up to -TimeoutSec for the VM to reach PoweredOff.
#   3. If it has not, SAVE its state (never a hard power-off: the guest may be
#      installing updates). The next start resumes from the saved state.
#   4. Append one line to provenance\raw\vm_shutdown_log.csv.
#   5. Shut the host down normally (no /f, so unsaved work still prompts).
#
# Run it NON-elevated, the same way the VM is started. Shortcut target:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Personal\UniStuff\Project\ContextAwareSIEM\tools\vm_safe_shutdown.ps1"
# It asks for confirmation (type Y) unless -Yes is given.
# Test without shutting the host down:
#   .\tools\vm_safe_shutdown.ps1 -NoHostShutdown

param(
    [string]$VmName = "vm-win11-target",
    [int]$TimeoutSec = 300,
    [switch]$NoHostShutdown,
    [switch]$Yes            # skip the confirmation prompt
)

if (-not $Yes -and -not $NoHostShutdown) {
    Write-Host "This shuts down the VM ($VmName) cleanly, then shuts down THIS PC." -ForegroundColor Yellow
    $ans = Read-Host "Type Y and press Enter to continue (anything else cancels)"
    if ($ans -ne "Y" -and $ans -ne "y") { Write-Host "Cancelled. Nothing was changed."; Start-Sleep -Seconds 2; exit 0 }
}

$ErrorActionPreference = "Continue"
$vbm  = Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"
$root = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $root "provenance\raw"
$log  = Join-Path $logDir "vm_shutdown_log.csv"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
if (-not (Test-Path $log)) {
    "started_at,finished_at,vm,initial_state,outcome,seconds,host_shutdown" | Out-File -Encoding utf8 $log
}

function Get-VmState {
    $line = & $vbm showvminfo $VmName --machinereadable 2>$null | Select-String '^VMState='
    if (-not $line) { return "unknown" }
    return ($line.ToString() -replace '^VMState="?([^"]*)"?$', '$1')
}

$t0 = Get-Date
$initial = Get-VmState
Write-Host "[$($t0.ToString('HH:mm:ss'))] $VmName state: $initial"

$outcome = "not_running"
if ($initial -eq "running") {
    Write-Host "Pressing the VM's ACPI power button (clean guest shutdown)..."
    & $vbm controlvm $VmName acpipowerbutton | Out-Null
    $deadline = $t0.AddSeconds($TimeoutSec)
    $state = $initial
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $state = Get-VmState
        $left = [int]($deadline - (Get-Date)).TotalSeconds
        Write-Host ("  state={0}  ({1}s left)" -f $state, [math]::Max($left,0))
        if ($state -eq "poweroff") { break }
    }
    if ($state -eq "poweroff") {
        $outcome = "acpi_clean"
    } else {
        Write-Host "Guest did not finish in ${TimeoutSec}s -- saving VM state instead of powering off."
        & $vbm controlvm $VmName savestate | Out-Null
        $outcome = "timeout_savestate:" + (Get-VmState)
    }
} elseif ($initial -eq "unknown") {
    $outcome = "vm_not_found"
}

$t1 = Get-Date
$secs = [int]($t1 - $t0).TotalSeconds
$hostAction = if ($NoHostShutdown) { "no" } else { "yes" }
"{0},{1},{2},{3},{4},{5},{6}" -f $t0.ToString("o"), $t1.ToString("o"), $VmName, $initial, $outcome, $secs, $hostAction |
    Out-File -Append -Encoding utf8 $log
Write-Host "Outcome: $outcome after ${secs}s. Logged to $log"

if ($NoHostShutdown) {
    Write-Host "-NoHostShutdown given: leaving the host running."
    Read-Host "Press Enter to close"
} else {
    Write-Host "Shutting the host down..."
    shutdown.exe /s /t 0
}
