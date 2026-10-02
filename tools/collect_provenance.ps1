# Environment provenance snapshot -- ENDPOINT SIDE (Windows 11 host).
# Run in PowerShell AS ADMINISTRATOR, from the project root:
#     .\tools\collect_provenance.ps1 -Label T0
#
# Three times: T0 (right after the audit-policy change), mid (any config
# change), T1 (baseline freeze). Output: provenance\raw\<label>_endpoint_<ts>.txt
#
# Everything captured here is something you cannot reconstruct in November.

# Inside the baseline VM (Part G), run it from the media CD with:
#     .\tools\collect_provenance.ps1 -Label VM_T0 -SysmonDir C:\Tools\Sysmon -OutDir C:\Tools\vm_out
# (defaults are unchanged for the host)

param([string]$Label = "adhoc",
      [string]$SysmonDir = "C:\Personal\UniStuff\Project\ContextAwareSIEM\tools\sysmon",
      [string]$OutDir = "")

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$dir  = if ($OutDir) { $OutDir } else { Join-Path $root "provenance\raw" }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$out  = Join-Path $dir ("{0}_endpoint_{1}.txt" -f $Label, (Get-Date -Format "yyyyMMddTHHmmss"))

function S($t) { "`n==================== $t ====================" }

$agentDir = "C:\Program Files (x86)\ossec-agent"
$sysmonDir = $SysmonDir

$(
S "SNAPSHOT"
"label            $Label"
"captured_at      " + (Get-Date -Format "o")
"captured_at_utc  " + ((Get-Date).ToUniversalTime().ToString("o"))
"timezone         " + (Get-TimeZone).Id
"utc_offset_h     " + (Get-TimeZone).BaseUtcOffset.TotalHours + "  <- MUST match SITE_UTC_OFFSET_H in tools/window_builder.py"
"computer         $env:COMPUTERNAME"
"os               " + (Get-CimInstance Win32_OperatingSystem).Caption
"build            " + (Get-CimInstance Win32_OperatingSystem).Version + " / " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

S "AUDIT POLICY  <- the single most important thing in this file"
"--- Logon/Logoff ---"
auditpol /get /category:"Logon/Logoff"
"--- Detailed Tracking (Process Creation) ---"
auditpol /get /subcategory:"Process Creation"
"--- command line capture (MUST be 0 for this project; see protocol 7.2) ---"
$cl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
if ($null -eq $cl) { "ProcessCreationIncludeCmdLine_Enabled  = (not set -> disabled, correct)" }
else { "ProcessCreationIncludeCmdLine_Enabled  = " + $cl.ProcessCreationIncludeCmdLine_Enabled }

S "SECURITY LOG SIZING  <- an undersized log silently drops events"
wevtutil gl Security
"Sysmon channel:"
wevtutil gl "Microsoft-Windows-Sysmon/Operational"

S "WAZUH AGENT"
Get-Service WazuhSvc | Format-List Name,Status,StartType | Out-String
if (Test-Path "$agentDir\VERSION") { "version file: " + (Get-Content "$agentDir\VERSION" -Raw).Trim() }
(Get-Item "$agentDir\wazuh-agent.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
"--- ossec.conf hash (change = segment boundary) ---"
Get-FileHash "$agentDir\ossec.conf" -Algorithm SHA256 | Format-List | Out-String
"--- eventchannel locations being collected ---"
Select-String -Path "$agentDir\ossec.conf" -Pattern "location|log_format" | ForEach-Object { $_.Line.Trim() }
"--- last 25 agent log lines (look for: Analyzing event log: 'Security') ---"
Get-Content "$agentDir\ossec.log" -Tail 25

S "SYSMON  <- do NOT reinstall or reconfigure during collection"
Get-Service *Sysmon* | Format-List Name,Status,StartType | Out-String
if (Test-Path "$sysmonDir\Sysmon64.exe") {
  (Get-Item "$sysmonDir\Sysmon64.exe").VersionInfo.ProductVersion
  "--- active config, as Sysmon reports it ---"
  & "$sysmonDir\Sysmon64.exe" -c 2>&1 | Select-Object -First 25
  "--- config file hashes ---"
  Get-ChildItem "$sysmonDir\*.xml" | Get-FileHash -Algorithm SHA256 |
    Select-Object Hash,Path | Format-Table -AutoSize | Out-String
} else { "Sysmon dir not found at $sysmonDir" }

S "POWER  <- sleep is fine and handled; hibernate/shutdown are not"
powercfg /getactivescheme
"standby (AC/DC minutes):"
powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Select-String "Current AC|Current DC"
"hibernate after:"
powercfg /query SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE | Select-String "Current AC|Current DC"
"hybrid sleep:"
powercfg /query SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP | Select-String "Current AC|Current DC"
"fast startup (HiberbootEnabled, 0 = off, preferred):"
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled

S "WSL AUTOSTART TASK  (systemctl enable is not sufficient)"
Get-ScheduledTask -TaskName "Start WSL Ubuntu" -ErrorAction SilentlyContinue |
  Format-List TaskName,State | Out-String
if (-not (Get-ScheduledTask -TaskName "Start WSL Ubuntu" -ErrorAction SilentlyContinue)) {
  "MISSING -- WazuhStartup.md section 5. Without it the manager does not come up at logon."
}

S "RECENT UNEXPECTED SHUTDOWNS  (explains gaps in the baseline)"
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1074,6008} -MaxEvents 15 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,Id,@{n='Msg';e={$_.Message.Split("`n")[0]}} | Format-Table -AutoSize | Out-String

S "DISK"
Get-PSDrive -PSProvider FileSystem | Select-Object Name,
  @{n='UsedGB';e={[math]::Round($_.Used/1GB,1)}},
  @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize | Out-String

S "END"
) | Out-File -FilePath $out -Encoding utf8

Write-Host "Written: $out"
Write-Host ""
Write-Host "CHECK NOW: (1) utc_offset_h matches window_builder.py"
Write-Host "           (2) ProcessCreationIncludeCmdLine_Enabled is 0 or unset"
Write-Host "           (3) agent log contains: Analyzing event log: 'Security'"
Write-Host "Then paste the headline values into COLLECTION_RECORD.md."
