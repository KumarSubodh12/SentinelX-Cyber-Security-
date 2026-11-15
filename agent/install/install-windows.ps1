# Installs the SentinelX agent on Windows as a scheduled task that runs at startup as SYSTEM.
# Run in an elevated (Administrator) PowerShell from the agent folder:
#   .\install\install-windows.ps1 -Url https://sentinelx.example.com -ApiKey sx_your_agent_key
#
# Requires Python 3.9+ on PATH (https://www.python.org/downloads/windows/).

param(
  [Parameter(Mandatory = $true)][string]$Url,
  [Parameter(Mandatory = $true)][string]$ApiKey
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Please run this script from an elevated (Administrator) PowerShell window."
}

$Source  = Split-Path -Parent $PSScriptRoot
$AppDir  = "C:\Program Files\SentinelXAgent"
$DataDir = "C:\ProgramData\SentinelXAgent"
$Conf    = Join-Path $DataDir "agent.env"

New-Item -ItemType Directory -Force -Path $AppDir, $DataDir | Out-Null
Copy-Item -Recurse -Force (Join-Path $Source "sentinelx_agent") $AppDir
Copy-Item -Force (Join-Path $Source "requirements.txt") $AppDir

python -m venv (Join-Path $AppDir "venv")
& (Join-Path $AppDir "venv\Scripts\pip.exe") install --quiet -r (Join-Path $AppDir "requirements.txt")

if (-not (Test-Path $Conf)) { Copy-Item (Join-Path $Source "agent.env.example") $Conf }
$text = Get-Content $Conf -Raw
$text = $text -replace "(?m)^SENTINELX_URL=.*",     "SENTINELX_URL=$Url"
$text = $text -replace "(?m)^SENTINELX_API_KEY=.*", "SENTINELX_API_KEY=$ApiKey"
$text = $text -replace "(?m)^STATE_DIR=.*",         "STATE_DIR=$($DataDir -replace '\\','/')/state"
Set-Content -Path $Conf -Value $text -Encoding UTF8

# Only SYSTEM and Administrators may read the file that holds the API key.
icacls $Conf /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(F)" | Out-Null

$Python = Join-Path $AppDir "venv\Scripts\python.exe"
Write-Host "Testing connection..."
Push-Location $AppDir
& $Python -m sentinelx_agent --config $Conf --check
Pop-Location

$Action    = New-ScheduledTaskAction -Execute $Python -Argument "-m sentinelx_agent --config `"$Conf`"" -WorkingDirectory $AppDir
$Trigger   = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName "SentinelX Agent" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "SentinelX Agent"

Write-Host ""
Write-Host "Done. The agent is running as the scheduled task 'SentinelX Agent'."
Write-Host "Configuration: $Conf"
