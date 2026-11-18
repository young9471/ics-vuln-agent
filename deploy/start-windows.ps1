param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot),
  [string]$Address = ":8787",
  [int]$DbPort = 5432,
  [switch]$NoBrowser
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path $Root).Path
$PlatformDir = Join-Path $Root "platform"
$Platform = Join-Path $PlatformDir "platform.exe"
$Config = Join-Path $PlatformDir "config.json"
$Example = Join-Path $PlatformDir "config.example.json"
$PgBin = Join-Path $Root "runtime\pgsql\bin"
$PgData = Join-Path $Root "runtime\pgdata"
$RuntimePython = Join-Path $Root "runtime\python"
$RuntimeTshark = Join-Path $Root "runtime\wireshark"
$startedPg = $false

# The dependency installer places portable Python in runtime\python. Prefer it
# over a system interpreter so the analysis scripts have a reproducible runtime.
if (Test-Path (Join-Path $RuntimePython "python.exe")) {
  $env:PATH = "$RuntimePython;$env:PATH"
  $env:PROTOCOL_AGENT_PYTHON = Join-Path $RuntimePython "python.exe"
  $env:PYTHONNOUSERSITE = "1"
}
if (Test-Path (Join-Path $RuntimeTshark "tshark.exe")) {
  $env:PATH = "$RuntimeTshark;$env:PATH"
  $env:PROTOCOL_AGENT_TSHARK = Join-Path $RuntimeTshark "tshark.exe"
} else {
  $systemTshark = "C:\Program Files\Wireshark\tshark.exe"
  if (Test-Path $systemTshark) {
    $env:PATH = "C:\Program Files\Wireshark;$env:PATH"
    $env:PROTOCOL_AGENT_TSHARK = $systemTshark
  }
}
trap {
  $originalError = $_
  if ($startedPg) { & $pgCtl -D $PgData stop -m fast | Out-Null }
  throw $originalError
}

if (-not (Test-Path $Platform)) { throw "platform.exe not found: $Platform" }
if (-not (Test-Path $PgData)) { New-Item -ItemType Directory -Force -Path $PgData | Out-Null }

if (Test-Path (Join-Path $PgBin "pg_ctl.exe")) {
  $pgCtl = Join-Path $PgBin "pg_ctl.exe"
  $initdb = Join-Path $PgBin "initdb.exe"
  $createdb = Join-Path $PgBin "createdb.exe"
  $psql = Join-Path $PgBin "psql.exe"
} else {
  $pgCtl = (Get-Command pg_ctl.exe -ErrorAction SilentlyContinue).Source
  $initdb = (Get-Command initdb.exe -ErrorAction SilentlyContinue).Source
  $createdb = (Get-Command createdb.exe -ErrorAction SilentlyContinue).Source
  $psql = (Get-Command psql.exe -ErrorAction SilentlyContinue).Source
}
if (-not $pgCtl -or -not $initdb) {
  throw "PostgreSQL not found. Use the full package with runtime\pgsql, or install PostgreSQL and add its bin to PATH."
}

$pgRunning = $false
if (Test-Path (Join-Path $PgData "PG_VERSION")) {
  & $pgCtl -D $PgData status *> $null
  if ($LASTEXITCODE -eq 0) { $pgRunning = $true }
}
if (-not $pgRunning) {
  if (-not (Test-Path (Join-Path $PgData "PG_VERSION"))) {
    Write-Host "[deploy] initializing PostgreSQL at $PgData"
    & $initdb -D $PgData -U pagent -A trust --encoding=UTF8
    if ($LASTEXITCODE -ne 0) { throw "initdb failed: $LASTEXITCODE" }
    Add-Content -Path (Join-Path $PgData "postgresql.conf") -Value "`nport = $DbPort" -Encoding UTF8
  }
  Write-Host "[deploy] starting PostgreSQL on port $DbPort"
  & $pgCtl -D $PgData -l (Join-Path $PgData "postgres.log") -w start
  if ($LASTEXITCODE -ne 0) { throw "pg_ctl start failed: $LASTEXITCODE" }
  $startedPg = $true
} else {
  Write-Host "[deploy] PostgreSQL already running; reusing $PgData"
}

$env:PGPASSWORD = ""
$dbExists = (& $psql -h 127.0.0.1 -p $DbPort -U pagent -d postgres -Atc "select 1 from pg_database where datname='protocol_platform'" 2>$null | Out-String).Trim()
if ($dbExists -ne "1") {
  & $createdb -h 127.0.0.1 -p $DbPort -U pagent protocol_platform
  if ($LASTEXITCODE -ne 0) { throw "createdb failed: $LASTEXITCODE" }
}

if (-not (Test-Path $Config)) {
  $cfg = Get-Content $Example -Raw -Encoding UTF8 | ConvertFrom-Json
  $cfg.database.host = "127.0.0.1"
  $cfg.database.port = $DbPort
  $cfg.database.user = "pagent"
  $cfg.database.password = ""
  $cfg.database.dbname = "protocol_platform"
  $cfg.database.sslmode = "disable"
  $json = $cfg | ConvertTo-Json -Depth 12
  [IO.File]::WriteAllText($Config, $json, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "[deploy] wrote $Config"
}

if (Test-Path (Join-Path $Root "offline\analyzers-win-x64\activate.ps1")) {
  . (Join-Path $Root "offline\analyzers-win-x64\activate.ps1")
}
if (Test-Path (Join-Path $Root "runtime\analyzers-env.ps1")) {
  . (Join-Path $Root "runtime\analyzers-env.ps1")
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Warning "Python 3.10+ not found on PATH; P1/P3/P4 scripts will be unavailable."
}
if (-not (Get-Command tshark -ErrorAction SilentlyContinue) -and -not (Test-Path "C:\Program Files\Wireshark\tshark.exe")) {
  Write-Warning "tshark not found; P2 live capture will be unavailable."
}
if (-not $NoBrowser) { Start-Process "http://localhost:8787" | Out-Null }
Write-Host "[deploy] starting Protocol Agent; press Ctrl+C to stop."
try {
  & $Platform @("-addr", $Address)
} finally {
  if ($startedPg) { & $pgCtl -D $PgData stop -m fast | Out-Null }
}
