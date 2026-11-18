param(
  [string]$Version = "0.13.7",
  [switch]$Full,
  [switch]$NoZip
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Edition = if ($Full) { "windows-x64-full" } else { "slim" }
$Name = "protocol-agent-$Version-$Edition"
$Dist = Join-Path $Root "dist"
$Stage = Join-Path $Dist $Name
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

function Copy-Tree([string]$Source, [string]$Dest, [string[]]$ExcludeDirs = @(), [string[]]$ExcludeFiles = @()) {
  $args = @($Source, $Dest, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP")
  if ($ExcludeDirs.Count) { $args += "/XD"; $args += $ExcludeDirs }
  if ($ExcludeFiles.Count) { $args += "/XF"; $args += $ExcludeFiles }
  & robocopy @args | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE): $Source -> $Dest" }
}

# Source + prebuilt binary + embedded UI. Runtime data and secrets are excluded.
Copy-Tree (Join-Path $Root "platform") (Join-Path $Stage "platform") `
  @("data", "node_modules", ".next", "out", ".git", "backups") `
  @("config.json", "secret.key", "jwt.key", "platform.exe~", "platform.exe.orig-*", "platform.exe.prev", "platform.exe.new", "*.pyc")
$newBin = Join-Path $Root "platform\platform.exe.new"
if (Test-Path $newBin) {
  Copy-Item $newBin (Join-Path $Stage "platform\platform.exe") -Force
}
Copy-Tree (Join-Path $Root "tools") (Join-Path $Stage "tools") @("__pycache__", "tests\__pycache__") @("*.pyc")
Copy-Tree (Join-Path $Root "scripts") (Join-Path $Stage "scripts") @() @()
Copy-Tree (Join-Path $Root "examples") (Join-Path $Stage "examples") @() @()
Copy-Tree (Join-Path $Root "deploy") (Join-Path $Stage "deploy") @() @()
Copy-Item (Join-Path $Root "README.md") (Join-Path $Stage "README.md") -Force
if (Test-Path (Join-Path $Root "LICENSE")) { Copy-Item (Join-Path $Root "LICENSE") (Join-Path $Stage "LICENSE") -Force }

# Initialized data tree: empty, no cases/sessions/transcripts/usage.
$data = Join-Path $Stage "platform\data"
if (Test-Path $data) { Remove-Item $data -Recurse -Force }
foreach ($d in @("protocol_cases", "sessions", "transcripts", "cmd-output")) {
  New-Item -ItemType Directory -Force -Path (Join-Path $data $d) | Out-Null
}
@"
Runtime data directory.

This release package is initialized and intentionally contains no cases,
sessions, transcripts, LLM records, logs, database dumps, secret.key or jwt.key.
The platform creates runtime files here on first use.
"@ | Set-Content -Path (Join-Path $data "README.txt") -Encoding UTF8

if ($Full) {
  Copy-Tree (Join-Path $Root "offline\analyzers-win-x64") (Join-Path $Stage "offline\analyzers-win-x64") @("__pycache__") @("*.pyc")
  $pg = Join-Path $Root "runtime\pgsql"
  if (-not (Test-Path (Join-Path $pg "bin\pg_ctl.exe"))) {
    $pg = "E:\tools\pgsql"
  }
  if (-not (Test-Path (Join-Path $pg "bin\pg_ctl.exe"))) { throw "portable PostgreSQL not found at $pg" }
  foreach ($sub in @("bin", "lib", "share")) {
    Copy-Tree (Join-Path $pg $sub) (Join-Path $Stage "runtime\pgsql\$sub") @() @()
  }
  foreach ($rt in @("python", "wireshark")) {
    $src = Join-Path $Root "runtime\$rt"
    if (-not (Test-Path $src)) { throw "portable runtime not found: $src" }
    Copy-Tree $src (Join-Path $Stage "runtime\$rt") @("__pycache__") @("*.pyc")
  }
  New-Item -ItemType Directory -Force -Path (Join-Path $Stage "runtime\pgdata") | Out-Null
  @"
Portable Windows runtime
========================
python/     Python 3.10 embeddable + pefile + capstone
wireshark/  tshark/dumpcap for pcap parsing and live capture
pgsql/      Portable PostgreSQL server

Live capture on a fresh machine additionally needs the Npcap driver.
The Wireshark bundle contains npcap-*.exe; install it with administrator
rights, then restart the platform. Reading existing .pcap files does not
require Npcap.
"@ | Set-Content -Path (Join-Path $Stage "runtime\README.txt") -Encoding UTF8
}

# Hard check: the shipped binary must embed the web UI (built with -tags embedui).
$bin = Join-Path $Stage "platform\platform.exe"
$favicon = Join-Path $Stage "platform\server\webui\dist\favicon.ico"
$latin1 = [Text.Encoding]::GetEncoding("ISO-8859-1")
$marker = [IO.File]::ReadAllBytes($favicon)
if ($marker.Length -gt 1024) { $marker = $marker[0..1023] }
$markerText = $latin1.GetString($marker)
$binText = [IO.File]::ReadAllText($bin, $latin1)
if (-not $binText.Contains($markerText)) {
  throw "platform.exe does not embed the web UI; rebuild with: go build -tags embedui"
}

# Hard checks: release must not carry runtime secrets or case data.
foreach ($p in @("platform\config.json", "platform\secret.key", "platform\jwt.key")) {
  if (Test-Path (Join-Path $Stage $p)) { throw "release contains runtime secret: $p" }
}
$caseFiles = Get-ChildItem (Join-Path $Stage "platform\data") -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -ne "README.txt" }
if ($caseFiles) { throw "release data directory is not empty: $($caseFiles[0].FullName)" }

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
if (-not $NoZip) {
  if ($Full) {
    $archive = Join-Path $Dist "$Name.tar.gz"
    if (Test-Path $archive) { Remove-Item $archive -Force }
    $tar = Join-Path $env:SystemRoot "System32/tar.exe"
    & $tar -czf $archive -C $Dist $Name
    if ($LASTEXITCODE -ne 0) { throw "tar failed: $LASTEXITCODE" }
  } else {
    $archive = Join-Path $Dist "$Name.zip"
    if (Test-Path $archive) { Remove-Item $archive -Force }
    Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $archive -CompressionLevel Optimal
  }
  Write-Host "[package] $archive"
} else {
  Write-Host "[package] prepared $Stage"
}
