# VM baseline configuration -- RUNS INSIDE THE VM (vm-win11-target), ELEVATED.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File \\VBoxSvr\repo\tools\vm_configure.ps1
#
# Applies, then verifies, everything in COLLECTION_RECORD.md Part G that is not
# the Wazuh agent:
#   1. audit policy  = exact copy of the HOST's (auditpol /restore of the host backup)
#   2. command-line capture confirmed OFF
#   3. Sysmon = same binary + same config as the host (tools/sysmon/)
#   4. Defender ON + exclusion C:\AtomicRedTeam
#   5. outbound firewall isolation (G.1 row 4)
# Writes a full verification report to \\VBoxSvr\out\ (host: provenance\raw\vm_out\).
#
# Input: transient VirtualBox shares (repo -> project root, read-only;
# out -> provenance\raw\vm_out) OR the CASIEM VM media ISO attached as a CD
# (built from the same files; then the report goes to C:\Tools\vm_out and the
# clipboard). Run from the CD:  powershell -NoProfile -ExecutionPolicy Bypass -File D:\tools\vm_configure.ps1
# Re-running is safe: every step is idempotent.

$ErrorActionPreference = "Continue"
# Input: the read-only VirtualBox share \\VBoxSvr\repo if it works, otherwise the
# CASIEM VM media ISO in the CD drive (same folder layout; marker file at its root).
$repo = "\\VBoxSvr\repo"
$out  = "\\VBoxSvr\out"
if (-not (Test-Path "$repo\tools\sysmon\Sysmon64.exe")) {
    $cd = Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path (Join-Path $_.Root "CASIEM_VM_MEDIA.txt") } | Select-Object -First 1
    if ($cd) { $repo = $cd.Root.TrimEnd('\') }
}
if (-not (Test-Path $out)) {
    $out = "C:\Tools\vm_out"
    New-Item -ItemType Directory -Force -Path $out | Out-Null
}
$ts   = Get-Date -Format "yyyyMMddTHHmmss"
$report = Join-Path $out "vm_configure_$ts.txt"
function Say($t) { $t = ("$t" -replace "`0", ""); Write-Host $t; Add-Content -Path $report -Value $t }
function Hdr($t) { Say "`n==================== $t ====================" }

# --- 0. preconditions -------------------------------------------------------
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
          [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "NOT ELEVATED. auditpol fails silently with 0x522 here. Re-run as Administrator." -ForegroundColor Red; exit 1 }
if (-not (Test-Path "$repo\tools\sysmon\Sysmon64.exe")) { Write-Host "Neither \\VBoxSvr\repo nor the CASIEM VM media CD is available." -ForegroundColor Red; exit 1 }
$auditBackup = "$repo\provenance\raw\host_auditpol_backup.csv"
if (-not (Test-Path $auditBackup)) { Write-Host "Missing $auditBackup (run auditpol /backup on the HOST first)" -ForegroundColor Red; exit 1 }

Hdr "SNAPSHOT"
Say ("captured_at      " + (Get-Date -Format "o"))
Say ("timezone         " + (Get-TimeZone).Id + "  utc_offset_h " + (Get-TimeZone).BaseUtcOffset.TotalHours)
Say ("computer         $env:COMPUTERNAME")
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Say ("os               " + $cv.ProductName + " / " + $cv.DisplayVersion + " / " + $cv.CurrentBuild + "." + $cv.UBR)

# --- 1. audit policy ----------------------------------------------------------
Hdr "1. AUDIT POLICY (restore host backup, then verify)"
Say ("input root: $repo   report dir: $out")
Say ("host backup SHA-256: " + (Get-FileHash $auditBackup -Algorithm SHA256).Hash)
$r = & auditpol /restore /file:"$auditBackup" 2>&1
Say ("auditpol /restore exit=$LASTEXITCODE : " + ($r -join " "))
$vmAudit = & auditpol /get /category:* 2>&1
$vmAudit | ForEach-Object { Say $_ }
$hostFull = "$repo\provenance\raw\host_auditpol_full.txt"
if (Test-Path $hostFull) {
    $norm = { param($lines) $lines | Where-Object { $_ -match '\S' -and $_ -notmatch 'System audit policy' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } }
    $d = Compare-Object (& $norm (Get-Content $hostFull)) (& $norm $vmAudit)
    if ($d) { Say "DIFF vs host_auditpol_full.txt (<= host only, => VM only):"; $d | ForEach-Object { Say ("  " + $_.SideIndicator + " " + $_.InputObject) } }
    else    { Say "AUDIT POLICY IDENTICAL TO HOST (all categories)." }
}

# --- 2. command-line capture --------------------------------------------------
Hdr "2. COMMAND-LINE CAPTURE (must be absent or 0)"
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$v = (Get-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
if ($null -eq $v) { Say "ProcessCreationIncludeCmdLine_Enabled = (not set -> disabled, correct)" } else { Say "ProcessCreationIncludeCmdLine_Enabled = $v  <-- MUST BE 0" }

# --- 3. Sysmon -----------------------------------------------------------------
Hdr "3. SYSMON (same binary + config as host)"
$sd = "C:\Tools\Sysmon"
New-Item -ItemType Directory -Force -Path $sd | Out-Null
Copy-Item "$repo\tools\sysmon\Sysmon64.exe", "$repo\tools\sysmon\sysmonconfig-export.xml", "$repo\tools\sysmon\Eula.txt" $sd -Force
Get-FileHash "$sd\Sysmon64.exe", "$sd\sysmonconfig-export.xml" -Algorithm SHA256 | ForEach-Object { Say ("{0}  {1}" -f $_.Hash, (Split-Path $_.Path -Leaf)) }
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    Say "Sysmon64 already installed -> reloading config only"
    $r = & "$sd\Sysmon64.exe" -accepteula -c "$sd\sysmonconfig-export.xml" 2>&1
} else {
    $r = & "$sd\Sysmon64.exe" -accepteula -i "$sd\sysmonconfig-export.xml" 2>&1
}
Say ("sysmon exit=$LASTEXITCODE"); $r | Select-Object -Last 6 | ForEach-Object { Say "  $_" }
Get-Service Sysmon64 | ForEach-Object { Say ("service: {0} {1} {2}" -f $_.Name, $_.Status, $_.StartType) }
(& "$sd\Sysmon64.exe" -c 2>&1) | Select-Object -First 12 | ForEach-Object { Say "  $_" }

# --- 4. Defender ---------------------------------------------------------------
Hdr "4. DEFENDER (on + exclusion C:\AtomicRedTeam)"
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction Continue
Say ("ExclusionPath: " + ((Get-MpPreference).ExclusionPath -join '; '))
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
    IsTamperProtected, AMProductVersion, AntivirusSignatureVersion | Format-List | Out-String | ForEach-Object { Say $_.Trim() }
Say ("MAPSReporting (cloud): " + (Get-MpPreference).MAPSReporting + "   SubmitSamplesConsent: " + (Get-MpPreference).SubmitSamplesConsent)

# --- 5. firewall isolation -----------------------------------------------------
Hdr "5. OUTBOUND FIREWALL ISOLATION (group CASIEM-VM-Isolation)"
# Windows Firewall: BLOCK beats ALLOW, so the allowed holes are carved out of the
# block ranges instead of being separate allow rules.
#   10.0.2.2 = NAT gateway = host loopback -> only TCP 1514/1515 (manager) and UDP 67 (DHCP)
#   10.0.2.3 = NAT DNS -> left fully open (blocking it kills DNS and Windows Update)
#   fd17:625c:f037:2::3 = the same NAT DNS relay over IPv6 -> left open too
#   Requires VBoxManage modifyvm --natdnsproxy1 on, otherwise the guest is handed the
#   HOST's router as its DNS server (192.168.x.x), which the 192.168/16 rule blocks.
$g = "CASIEM-VM-Isolation"
Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$rules = @(
  @{N="Block 10/8 except NAT gw+DNS"; R=@("10.0.0.0-10.0.2.1","10.0.2.4-10.255.255.255"); P="Any"},
  @{N="Block NAT gw TCP except 1514-1515"; R=@("10.0.2.2"); P="TCP"; Port=@("1-1513","1516-65535")},
  @{N="Block NAT gw UDP except 67";        R=@("10.0.2.2"); P="UDP"; Port=@("1-66","68-65535")},
  @{N="Block 172.16/12";  R=@("172.16.0.0/12");  P="Any"},
  @{N="Block 192.168/16"; R=@("192.168.0.0/16"); P="Any"},
  @{N="Block 169.254/16"; R=@("169.254.0.0/16"); P="Any"},
  @{N="Block 100.64/10 CGNAT"; R=@("100.64.0.0/10"); P="Any"},
  @{N="Block IPv6 ULA fc00::/7 except NAT DNS"; R=@("fc00::-fd17:625c:f037:2::2","fd17:625c:f037:2::4-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); P="Any"}
)
foreach ($x in $rules) {
  $a = @{ DisplayName = "$g - " + $x.N; Group = $g; Direction = "Outbound"; Action = "Block"; Profile = "Any"; RemoteAddress = $x.R; Protocol = $x.P }
  if ($x.Port) { $a.RemotePort = $x.Port }
  New-NetFirewallRule @a | Out-Null
}
Get-NetFirewallRule -Group $g | ForEach-Object {
  $af = $_ | Get-NetFirewallAddressFilter; $pf = $_ | Get-NetFirewallPortFilter
  Say ("{0} | {1} {2} | remote {3} | ports {4}" -f $_.DisplayName, $_.Action, $pf.Protocol, ($af.RemoteAddress -join ","), ($pf.RemotePort -join ","))
}
# Guest DNS pinned to the NAT relay. VirtualBox 7.2's DHCP hands out the HOST's
# router (192.168.x.x) even with --natdnsproxy1 on, and the 192.168/16 rule blocks it.
$nic = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceAlias $nic.Name -ServerAddresses 10.0.2.3
Clear-DnsClientCache
Say ("guest IPv4 DNS pinned: " + $nic.Name + " -> 10.0.2.3")
Say "-- reachability after rules --"
foreach ($t in @(@("10.0.2.2",1514), @("10.0.2.2",1515), @("10.0.2.2",443), @("10.0.2.2",9200), @("10.0.2.2",55000))) {
  $ok = (Test-NetConnection $t[0] -Port $t[1] -WarningAction SilentlyContinue).TcpTestSucceeded
  Say ("  {0}:{1} -> {2}" -f $t[0], $t[1], $ok)
}
Get-DnsClientServerAddress | Where-Object ServerAddresses | ForEach-Object { Say ("  DNS servers {0} af={1}: {2}" -f $_.InterfaceAlias, $_.AddressFamily, ($_.ServerAddresses -join ",")) }
$dns = Resolve-DnsName www.microsoft.com -ErrorAction SilentlyContinue | Select-Object -First 1
Say ("  DNS www.microsoft.com -> " + $(if ($dns) { "OK" } else { "FAILED" }))
$web = (Test-NetConnection www.microsoft.com -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
Say ("  www.microsoft.com:443 -> $web")

Hdr "END"
Say "Expected: 1514 True, 1515 True, 443/9200/55000 False, DNS OK, internet True."
Write-Host "`nReport written to $report" -ForegroundColor Green
if ($out -like "C:\*") {
    Get-Content $report -Raw | Set-Clipboard
    Write-Host "Report also copied to the clipboard (paste it on the host)." -ForegroundColor Green
}
