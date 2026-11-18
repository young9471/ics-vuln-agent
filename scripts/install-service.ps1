param(
  [string]$PlatformPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "platform\platform.exe"),
  [string]$Address = ":8787",
  [string]$ServiceName = "ProtocolAgent",
  [string]$PgServiceName = "ProtocolAgentPostgres",
  [string]$PgCtl = "E:\tools\pgsql\bin\pg_ctl.exe",
  [string]$PgData = "E:\pgdata",
  [switch]$SkipPostgres,
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run from an elevated PowerShell (Run as Administrator)."
  }
}

Assert-Admin

if ($Uninstall) {
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Write-Host "[service] removed $ServiceName"
  }
  if (-not $SkipPostgres -and (Test-Path $PgCtl)) {
    & $PgCtl unregister -N $PgServiceName 2>$null
  }
  return
}

if (-not (Test-Path $PlatformPath)) { throw "platform.exe not found: $PlatformPath" }
$bin = "`"$PlatformPath`" -addr $Address"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  sc.exe config $ServiceName binPath= $bin start= auto | Out-Null
  Write-Host "[service] updated $ServiceName"
} else {
  New-Service -Name $ServiceName -BinaryPathName $bin -DisplayName "Protocol Agent" -StartupType Automatic | Out-Null
  Write-Host "[service] installed $ServiceName"
}

if (-not $SkipPostgres) {
  if (-not (Test-Path $PgCtl)) { throw "pg_ctl not found: $PgCtl (use -SkipPostgres or -PgCtl)" }
  if (-not (Test-Path $PgData)) { throw "PostgreSQL data dir not found: $PgData" }
  $existing = Get-Service -Name $PgServiceName -ErrorAction SilentlyContinue
  if (-not $existing) {
    & $PgCtl register -N $PgServiceName -D $PgData -S auto
    if ($LASTEXITCODE -ne 0) { throw "pg_ctl register failed: $LASTEXITCODE" }
    Write-Host "[service] registered $PgServiceName"
  }
  Start-Service -Name $PgServiceName
}

Start-Service -Name $ServiceName
Write-Host "[service] started $ServiceName; health: http://localhost$Address/api/health"
