param(
  [string]$Output = ""
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $Output) {
  $Output = Join-Path $Root "backups\protocol-agent-$stamp.zip"
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null

$cfgPath = Join-Path $Root "platform\config.json"
if (-not (Test-Path $cfgPath)) { throw "config.json not found: $cfgPath" }
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$db = $cfg.database
$pgDump = (Get-Command pg_dump -ErrorAction SilentlyContinue)
if (-not $pgDump) { throw "pg_dump not found on PATH; install PostgreSQL client tools first" }

$stage = Join-Path $env:TEMP "protocol-agent-backup-$stamp"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  $env:PGPASSWORD = [string]$db.password
  & $pgDump.Source -h $db.host -p ([string]$db.port) -U $db.user -d $db.dbname `
    -Fc -f (Join-Path $stage "postgres.dump")
  if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE" }

  $dataDir = Join-Path $Root "platform\data"
  if (Test-Path $dataDir) { Copy-Item $dataDir (Join-Path $stage "data") -Recurse -Force }
  if (Test-Path $cfgPath) { Copy-Item $cfgPath (Join-Path $stage "config.json") -Force }
  foreach ($f in @("secret.key", "jwt.key")) {
    $p = Join-Path $Root "platform\$f"
    if (Test-Path $p) { Copy-Item $p (Join-Path $stage $f) -Force }
  }
  $skills = Join-Path $Root "platform\skills"
  if (Test-Path $skills) { Copy-Item $skills (Join-Path $stage "skills") -Recurse -Force }

  @"
Protocol Agent backup
created: $stamp
database: $($db.dbname) @ $($db.host):$($db.port)
contents: postgres.dump, data/, skills/, config.json, secret.key, jwt.key
Restore outline:
  1. createdb / restore with pg_restore -d <db> postgres.dump
  2. copy data/ back to platform/data
  3. copy secret.key and jwt.key to platform/
  4. start platform and verify /api/health
"@ | Set-Content -Path (Join-Path $stage "README.txt") -Encoding UTF8

  if (Test-Path $Output) { Remove-Item $Output -Force }
  Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $Output
  Write-Host "[backup] $Output"
} finally {
  Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
  Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}