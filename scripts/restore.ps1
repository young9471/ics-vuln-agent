param(
  [Parameter(Mandatory = $true)][string]$Backup,
  [string]$PgBin = "",
  [string]$DbHost = "127.0.0.1",
  [int]$Port = 5432,
  [string]$User = "pagent",
  [string]$Password = "",
  [string]$TargetDb = "",
  [switch]$VerifyOnly,
  [switch]$KeepDb
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Backup)) { throw "backup not found: $Backup" }

function Resolve-PgTool([string]$name) {
  if ($PgBin) {
    $p = Join-Path $PgBin $name
    if (Test-Path $p) { return $p }
  }
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  throw "$name not found; pass -PgBin <PostgreSQL bin directory>"
}

$pgRestore = Resolve-PgTool "pg_restore.exe"
$psql = Resolve-PgTool "psql.exe"
$createdb = Resolve-PgTool "createdb.exe"
$dropdb = Resolve-PgTool "dropdb.exe"

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$stage = Join-Path $env:TEMP "protocol-agent-restore-$stamp"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  Expand-Archive -Path $Backup -DestinationPath $stage -Force
  $dump = Join-Path $stage "postgres.dump"
  if (-not (Test-Path $dump)) { throw "postgres.dump missing from backup" }
  if (-not $TargetDb) { $TargetDb = "protocol_agent_restore_$stamp" }
  if ($Password) { $env:PGPASSWORD = $Password }

  Write-Host "[restore] verifying archive: $dump"
  & $pgRestore --list $dump | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "pg_restore --list failed: $LASTEXITCODE" }
  if ($VerifyOnly) {
    Write-Host "[restore] archive verified (no database restored)"
    return
  }

  Write-Host "[restore] creating temporary database: $TargetDb"
  & $createdb -h $DbHost -p $Port -U $User $TargetDb
  if ($LASTEXITCODE -ne 0) { throw "createdb failed: $LASTEXITCODE" }
  try {
    & $pgRestore -h $DbHost -p $Port -U $User -d $TargetDb --clean --if-exists $dump
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed: $LASTEXITCODE" }
    & $psql -h $DbHost -p $Port -U $User -d $TargetDb -Atc "select count(*) from agents"
    if ($LASTEXITCODE -ne 0) { throw "post-restore query failed: $LASTEXITCODE" }
    Write-Host "[restore] drill succeeded for $TargetDb"
  } finally {
    if (-not $KeepDb) {
      & $dropdb -h $DbHost -p $Port -U $User $TargetDb
    }
  }
} finally {
  Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
  Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
