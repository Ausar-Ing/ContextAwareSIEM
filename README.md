# Context Aware SIEM Lab Operations

This project currently uses Wazuh running in Ubuntu WSL2 as the SIEM backend, with the native Windows Wazuh agent and Sysmon running on the Windows 11 host.

## Components

- WSL2 Ubuntu 24.04:
  - `wazuh-indexer`
  - `wazuh-manager`
  - `wazuh-dashboard`
- Windows 11:
  - `WazuhSvc`
  - `Sysmon64`

## Open The Wazuh Dashboard

Open this in a Windows browser:

```text
https://localhost
```

The browser may warn about a self-signed certificate. That is expected for this local lab.

If you need the Wazuh password again, run this in Ubuntu WSL from the folder where the installer was run:

```bash
cd ~/ContextAwareSIEM
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

## Start The Lab

### 1. Open Ubuntu WSL

From PowerShell:

```powershell
wsl -d Ubuntu
```

Or open the Ubuntu terminal directly.

### 2. Set The Wazuh Indexer Kernel Requirement

Run this in Ubuntu WSL after a full WSL restart or Windows reboot:

```bash
sudo sysctl -w vm.max_map_count=262144
```

### 3. Start Wazuh Backend Services

Run this in Ubuntu WSL:

```bash
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-dashboard
```

Check status:

```bash
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager
```

### 4. Start The Windows Wazuh Agent

Run this in PowerShell as Administrator:

```powershell
Start-Service WazuhSvc
```

Check status:

```powershell
Get-Service WazuhSvc
```

### 5. Start Or Verify Sysmon

Sysmon normally starts automatically after installation and after Windows boots.

Run this in PowerShell as Administrator:

```powershell
Get-Service *Sysmon*
```

If the service exists but is stopped, try:

```powershell
Start-Service Sysmon64
```

If Sysmon was uninstalled, reinstall it from the project tools folder:

```powershell
cd "C:\Personal\UniStuff\Project\ContextAwareSIEM\tools\sysmon"
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

## Stop The Lab

### 1. Stop The Windows Wazuh Agent

Run this in PowerShell as Administrator:

```powershell
Stop-Service WazuhSvc
```

This stops Windows logs from being forwarded to Wazuh.

### 2. Stop Wazuh Backend Services

Run this in Ubuntu WSL:

```bash
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
```

Check status:

```bash
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager
```

### 3. Sysmon Shutdown Options

`Stop-Service Sysmon64` may fail. That is expected on some systems because Sysmon is installed as a service/driver and is designed to keep running.

Recommended lab option:

```powershell
Stop-Service WazuhSvc
```

This keeps Sysmon collecting locally but stops forwarding events into Wazuh.

To fully remove Sysmon, run this in PowerShell as Administrator:

```powershell
cd "C:\Personal\UniStuff\Project\ContextAwareSIEM\tools\sysmon"
.\Sysmon64.exe -u
```

If normal uninstall fails:

```powershell
.\Sysmon64.exe -u force
```

Reinstall later with:

```powershell
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

## Restart Everything

Ubuntu WSL:

```bash
sudo sysctl -w vm.max_map_count=262144
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-dashboard
```

PowerShell as Administrator:

```powershell
Restart-Service WazuhSvc
Get-Service *Sysmon*
```

## Disable Auto-Start

Use this only if you do not want Wazuh to start automatically.

PowerShell as Administrator:

```powershell
Set-Service WazuhSvc -StartupType Manual
```

Ubuntu WSL:

```bash
sudo systemctl disable wazuh-dashboard
sudo systemctl disable wazuh-manager
sudo systemctl disable wazuh-indexer
```

Re-enable later:

```bash
sudo systemctl enable wazuh-indexer
sudo systemctl enable wazuh-manager
sudo systemctl enable wazuh-dashboard
```

```powershell
Set-Service WazuhSvc -StartupType Automatic
```

## Quick Verification

PowerShell:

```powershell
Get-Service WazuhSvc
Get-Service *Sysmon*
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 40
```

Ubuntu WSL:

```bash
sudo /var/ossec/bin/manage_agents -l
sudo tail -n 80 /var/ossec/logs/ossec.log
```

Expected healthy Windows agent log lines:

```text
Connected to the server ([127.0.0.1]:1514/tcp).
Agent is now online.
Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.
```

## Generate Test Events

Run these in PowerShell:

```powershell
notepad.exe
ping 8.8.8.8
whoami
```

Then check the Wazuh dashboard for Windows and Sysmon events.
