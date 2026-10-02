# Benign workload for the baseline VM -- RUNS INSIDE THE VM (vm-win11-target).
# COLLECTION_RECORD.md Part G; handoff section 6. Its SHA-256 is recorded in G.2.
# Changing it after VM T0 is a G.4 segment boundary, and the SAME version must run
# as the benign background during emulation Sessions A and B.
#
# Why these actions: the mix reproduces the KINDS of benign-but-alert-looking
# activity measured on the host's own benign baseline (COLLECTION_RECORD D, 30 Sep):
# account discovery (92031), PowerShell (92066), cmd from an unusual parent (92052),
# file downloads (92213/92205), service creation by installers (92307), file
# deletion (92021), special logon (67028), logon/logoff and the odd failed logon.
# Account split (measured 2026-10-02): wluser's activity is cmd/console only (see
# Act-UserShell); PowerShell activity is the admin's.
# Literature precedent for scripted benign activity alongside emulation:
# refs [1] Roy & Balde, [11] Pomsathit, [13] Chamkar et al., [17] Alboushy et al.
#
# Modes (run in an ELEVATED PowerShell as the VM admin account):
#   -Setup              create local user 'wluser' (standard user, random password),
#                       store its credential DPAPI-encrypted for THIS admin account,
#                       grant wluser "Log on as a batch job", register the three
#                       wluser console tasks and the startup task (asks for the
#                       admin's own password).
#   -Test               run every action once, now, and print what happened.
#   -Once -Action <n>   run one action now.
#   (no switch)         the loop the startup task runs: one user session 1-3 min
#                       after start, then wait 20-40 min, act, repeat.
#
# Log: C:\ProgramData\CASIEM\workload\workload_log.csv (one line per action).

param(
    [switch]$Setup,
    [switch]$Test,
    [switch]$Once,
    [string]$Action = "",
    [ValidateSet("credential","task")][string]$UserMode = "task",
    [int]$MinWaitMin = 20,
    [int]$MaxWaitMin = 40
)

$ErrorActionPreference = "Continue"
$Base     = "C:\ProgramData\CASIEM\workload"
$Log      = Join-Path $Base "workload_log.csv"
$CredFile = Join-Path $Base "wluser.cred.xml"
$State    = Join-Path $Base "state.json"
$WlUser   = "wluser"
$TaskName = "CASIEM Benign Workload"
$UserTaskPrefix = "CASIEM wluser shell"
$Version  = "1.5"
New-Item -ItemType Directory -Force -Path $Base | Out-Null

# wluser's console activity. In "task" mode each variant is a fixed scheduled task
# running as wluser (registered by -Setup), so nothing is modified at run time.
$UserVariants = @(
    '/c dir %USERPROFILE% >nul & ipconfig >nul & echo draft> %TEMP%\memo.txt & copy %TEMP%\memo.txt %TEMP%\memo2.txt >nul & del %TEMP%\memo.txt %TEMP%\memo2.txt',
    '/c whoami >nul & tasklist >nul & dir %USERPROFILE%\Documents >nul & echo list> %TEMP%\todo.txt & type %TEMP%\todo.txt >nul & del %TEMP%\todo.txt',
    '/c hostname >nul & ipconfig /all >nul & dir %SystemRoot% >nul & set >nul'
)

function Write-Log($act, $detail, $result) {
    if (-not (Test-Path $Log)) { "timestamp,version,action,detail,result" | Out-File -Encoding utf8 $Log }
    $clean = { param($x) ("$x" -replace '[\r\n,]', ' ').Trim() }
    "{0},{1},{2},{3},{4}" -f (Get-Date -Format "o"), $Version, $act, (& $clean $detail), (& $clean $result) |
        Out-File -Append -Encoding utf8 $Log
    Write-Host ("[{0}] {1}: {2} -> {3}" -f (Get-Date -Format "HH:mm:ss"), $act, $detail, $result)
}

function Get-State { if (Test-Path $State) { Get-Content $State -Raw | ConvertFrom-Json } else { [pscustomobject]@{ last_install_day = ""; sevenzip_installed = $false } } }
function Save-State($s) { $s | ConvertTo-Json | Out-File -Encoding utf8 $State }

function Get-WlCred { Import-Clixml $CredFile }

# ---- user-context execution ---------------------------------------------------
# "task" (default, the only mode that works from the background): start the fixed
#        scheduled task that runs variant $i as wluser -> batch logon (type 4).
# "credential": Start-Process -Credential -> interactive logon (type 2). MEASURED
#        2026-10-02: from the background task every program started this way dies at
#        start-up with 0xC0000142 (no usable desktop), cmd.exe included, and leaves an
#        application-error event behind. Kept only for interactive testing.
function Invoke-AsUser([int]$i, [int]$timeoutSec = 120) {
    if ($UserMode -eq "credential") {
        $p = Start-Process -FilePath "cmd.exe" -ArgumentList $UserVariants[$i] -Credential (Get-WlCred) -LoadUserProfile `
             -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -PassThru -ErrorAction Stop
        $null = $p.Handle   # keep the handle, or ExitCode comes back empty for -Credential processes
        if (-not $p.WaitForExit($timeoutSec * 1000)) { $p | Stop-Process -Force; return "timeout" }
        return "exit=" + $p.ExitCode
    }
    $tn = "$UserTaskPrefix $i"
    $t0 = Get-Date
    Start-ScheduledTask -TaskName $tn
    # Wait until THIS run has started (LastRunTime moves past $t0) and finished.
    # Task Scheduler can take several seconds to launch a task as another account,
    # longer the first time while it builds the profile.
    do {
        Start-Sleep 3
        $info = Get-ScheduledTaskInfo -TaskName $tn
        $st = (Get-ScheduledTask -TaskName $tn).State
        $ran = $info.LastRunTime -ge $t0.AddSeconds(-1)
    } while ((-not $ran -or $st -eq "Running") -and ((Get-Date) - $t0).TotalSeconds -lt $timeoutSec)
    if (-not $ran) { return "task_not_started_within_${timeoutSec}s" }
    return "task_result=" + $info.LastTaskResult
}

# ---- actions -------------------------------------------------------------------
function Act-UserShell {
    # A user poking around in a console: listing files, processes, network config,
    # copying and deleting a scratch file. cmd and console tools only.
    $i = Get-Random -Maximum $UserVariants.Count
    $r = Invoke-AsUser $i
    Write-Log "user_shell" "cmd variant $i as $WlUser ($UserMode)" $r
}

function Act-AdminShell {
    # Routine admin checks: who am I, local accounts and groups, services. Each runs
    # as a NEW child process (cmd or powershell) so it appears as process creation.
    $choice = Get-Random -Maximum 3
    switch ($choice) {
        0 { $p = Start-Process cmd.exe -ArgumentList '/c whoami /groups >nul & net user >nul' -WindowStyle Hidden -PassThru -Wait; $d = "cmd: whoami /groups, net user" }
        1 { $p = Start-Process powershell.exe -ArgumentList '-NoProfile -Command "Get-LocalGroupMember -Group Administrators | Out-Null; Get-Service | Where-Object Status -eq Running | Out-Null"' -WindowStyle Hidden -PassThru -Wait; $d = "powershell: Get-LocalGroupMember, Get-Service" }
        2 { $p = Start-Process cmd.exe -ArgumentList '/c whoami & hostname & net localgroup' -WindowStyle Hidden -PassThru -Wait; $d = "cmd: whoami, hostname, net localgroup" }
    }
    Write-Log "admin_shell" $d ("exit=" + $p.ExitCode)
}

function Act-App {
    # classic Win32 apps only: Store apps (Paint, Calculator) do not start without a desktop,
    # and WordPad (write.exe) is gone from Windows 11 24H2+
    $apps = @("notepad.exe", "explorer.exe", "msinfo32.exe", "charmap.exe")
    $app = $apps | Get-Random
    $p = Start-Process $app -PassThru -ErrorAction SilentlyContinue
    $secs = Get-Random -Minimum 20 -Maximum 121
    Start-Sleep -Seconds $secs
    if ($app -eq "explorer.exe") { Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq 0 } | Stop-Process -Force -ErrorAction SilentlyContinue }
    elseif ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    Get-Process msinfo32, charmap, notepad -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq 0 } | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Log "app" "$app for ${secs}s" "done"
}

function Act-Web {
    $urls = @("https://example.com/", "https://www.wikipedia.org/", "https://learn.microsoft.com/")
    $u = $urls | Get-Random
    $edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    if ((Test-Path $edge) -and ((Get-Random -Maximum 2) -eq 0)) {
        $tmp = Join-Path $env:TEMP ("edge_" + (Get-Random))
        $p = Start-Process $edge -ArgumentList "--headless=new --disable-gpu --user-data-dir=`"$tmp`" --dump-dom $u" -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $env:TEMP "edge_out.txt")
        if (-not $p.WaitForExit(90000)) { $p | Stop-Process -Force }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "web" "edge headless $u" "done"
    } else {
        try { $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 60; Write-Log "web" "Invoke-WebRequest $u" ("status=" + $r.StatusCode) }
        catch { Write-Log "web" "Invoke-WebRequest $u" ("error=" + $_.Exception.Message) }
    }
}

function Act-FailedLogon {
    # A mistyped password: one failed interactive logon for wluser (4625).
    $bad = New-Object System.Management.Automation.PSCredential($WlUser, (ConvertTo-SecureString ("wrong" + (Get-Random)) -AsPlainText -Force))
    try { Start-Process cmd.exe -ArgumentList "/c exit" -Credential $bad -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -ErrorAction Stop | Out-Null; $r = "unexpectedly succeeded" }
    catch { $r = "failed as intended" }
    Write-Log "failed_logon" "bad password for $WlUser" $r
}

function Act-Install {
    # At most once per calendar day: install 7-Zip, next time uninstall it.
    $s = Get-State
    $today = (Get-Date).ToString("yyyy-MM-dd")
    if ($s.last_install_day -eq $today) { Write-Log "install" "already ran today" "skipped"; return }
    $winget = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
    if (-not $winget) { Write-Log "install" "winget not found in this context" "skipped"; return }
    if ($s.sevenzip_installed) {
        $out = & $winget uninstall --id 7zip.7zip --silent --accept-source-agreements --disable-interactivity 2>&1 | Out-String
        $s.sevenzip_installed = $false; $d = "winget uninstall 7zip.7zip"
    } else {
        $out = & $winget install --id 7zip.7zip --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String
        $s.sevenzip_installed = $true; $d = "winget install 7zip.7zip"
    }
    $s.last_install_day = $today; Save-State $s
    Write-Log "install" $d ("exit=$LASTEXITCODE")
}

function Act-Idle { Write-Log "idle" "no action this round" "done" }

# Weights sum to 100. Install is attempted often but runs at most once a day.
$Mix = @(
    @{ N = "user_shell";   W = 30; F = ${function:Act-UserShell} },
    @{ N = "admin_shell";  W = 15; F = ${function:Act-AdminShell} },
    @{ N = "app";          W = 14; F = ${function:Act-App} },
    @{ N = "web";          W = 14; F = ${function:Act-Web} },
    @{ N = "failed_logon"; W = 3;  F = ${function:Act-FailedLogon} },
    @{ N = "install";      W = 6;  F = ${function:Act-Install} },
    @{ N = "idle";         W = 18; F = ${function:Act-Idle} }
)
function Pick-Action { $r = Get-Random -Minimum 0 -Maximum 100; $acc = 0; foreach ($m in $Mix) { $acc += $m.W; if ($r -lt $acc) { return $m } }; return $Mix[-1] }
function Run-Action($m) { try { & $m.F } catch { Write-Log $m.N "exception" $_.Exception.Message } }

# ---- modes -----------------------------------------------------------------------
if ($Setup) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { Write-Host "Run -Setup in an ELEVATED PowerShell." -ForegroundColor Red; exit 1 }
    # 1. workload user: standard user, random 24-char password nobody needs to know
    $chars = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+="
    $pw = -join (1..24 | ForEach-Object { $chars | Get-Random })
    $sec = ConvertTo-SecureString $pw -AsPlainText -Force
    if (Get-LocalUser -Name $WlUser -ErrorAction SilentlyContinue) { Set-LocalUser -Name $WlUser -Password $sec; Write-Host "wluser existed: password reset" }
    else { New-LocalUser -Name $WlUser -Password $sec -FullName "Workload User" -Description "CASIEM benign workload account" -PasswordNeverExpires | Out-Null; Add-LocalGroupMember -Group Users -Member $WlUser -ErrorAction SilentlyContinue; Write-Host "wluser created" }
    New-Object System.Management.Automation.PSCredential($WlUser, $sec) | Export-Clixml $CredFile
    Write-Host "credential stored (DPAPI, readable only by $env:USERNAME on this VM): $CredFile"
    # 2. "Log on as a batch job" for wluser. Windows grants it only to Administrators,
    #    Backup Operators and Performance Log Users by default, and Task Scheduler then
    #    refuses the task with 0x80070569 (logon type not granted) WITHOUT writing a
    #    4625 (measured 2026-10-02). Local security policy inside the VM only.
    $sid = (Get-LocalUser -Name $WlUser).SID.Value
    $inf = Join-Path $Base "user_rights.inf"; $sdb = Join-Path $Base "user_rights.sdb"
    secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
    $lines = Get-Content $inf
    if (($lines | Where-Object { $_ -match '^SeBatchLogonRight' }) -match [regex]::Escape("*$sid")) {
        Write-Host "wluser already has SeBatchLogonRight"
    } else {
        if ($lines -match '^SeBatchLogonRight') { $lines = $lines -replace '^(SeBatchLogonRight = .*)$', "`$1,*$sid" }
        else { $lines = $lines -replace '^(\[Privilege Rights\])$', "`$1`r`nSeBatchLogonRight = *$sid" }
        $lines | Set-Content $inf -Encoding Unicode
        secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
        Write-Host "granted SeBatchLogonRight to wluser ($sid)"
    }
    secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
    Write-Host ("now: " + ((Get-Content $inf) -match '^SeBatchLogonRight'))
    Remove-Item $inf, $sdb -ErrorAction SilentlyContinue

    # 3. one fixed task per console variant, running as wluser (batch logon, type 4)
    Get-ScheduledTask -TaskName "CASIEM wluser shell" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
    for ($i = 0; $i -lt $UserVariants.Count; $i++) {
        $ua = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $UserVariants[$i] -WorkingDirectory "C:\Users\Public"
        $us = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        Register-ScheduledTask -TaskName "$UserTaskPrefix $i" -Action $ua -Settings $us -User $WlUser -Password $pw -RunLevel Limited -Force | Out-Null
    }
    Write-Host ("registered {0} wluser tasks" -f $UserVariants.Count)
    # 4. the workload loop: at startup, as THIS admin, whether or not anyone is signed in
    Write-Host "Enter the password of THIS admin account ($env:USERNAME) so the task can run at startup:" -ForegroundColor Yellow
    $me = Get-Credential -UserName "$env:COMPUTERNAME\$env:USERNAME" -Message "Admin account for the workload task"
    $script = $MyInvocation.MyCommand.Path
    $dest = Join-Path $Base "vm_benign_workload.ps1"
    if ($script -ne $dest) { Copy-Item $script $dest -Force }
    $la = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`" -UserMode $UserMode"
    $tr = New-ScheduledTaskTrigger -AtStartup; $tr.Delay = "PT3M"
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $la -Trigger $tr -Settings $set -User $me.UserName -Password $me.GetNetworkCredential().Password -RunLevel Highest -Force | Out-Null
    Write-Host ("Registered '{0}' -> {1} (UserMode {2}). SHA-256 of installed copy: {3}" -f $TaskName, $dest, $UserMode, (Get-FileHash $dest -Algorithm SHA256).Hash) -ForegroundColor Green
    Write-Host "Next: run -Test, then reboot the VM; the loop starts 3 minutes after boot."
    exit 0
}

if ($Test) {
    foreach ($m in $Mix) { Write-Host "`n--- $($m.N) ---"; Run-Action $m }
    Write-Host "`nLog: $Log"; exit 0
}

if ($Once) {
    $m = $Mix | Where-Object { $_.N -eq $Action }
    if (-not $m) { Write-Host ("Unknown action. One of: " + (($Mix | ForEach-Object N) -join ", ")); exit 1 }
    Run-Action $m; exit 0
}

# ---- the loop (started by the task at boot) ---------------------------------------
Write-Log "loop_start" ("pid=$PID usermode=$UserMode wait=$MinWaitMin-$MaxWaitMin min") "started"
# Like a person sitting down after switching the machine on: one user session 1-3
# minutes after the loop starts, then the random schedule. This also proves daily
# that the user-context mechanism works from the background task.
Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 181)
Run-Action ($Mix | Where-Object { $_.N -eq "user_shell" })
while ($true) {
    $wait = Get-Random -Minimum ($MinWaitMin * 60) -Maximum ($MaxWaitMin * 60 + 1)
    Start-Sleep -Seconds $wait
    Run-Action (Pick-Action)
}
