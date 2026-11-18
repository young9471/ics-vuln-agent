param(
  [switch]$WithAnalyzers,
  [switch]$SkipWireshark,
  [switch]$CheckOnly,
  [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Runtime = Join-Path $Root "runtime"
New-Item -ItemType Directory -Force -Path $Runtime | Out-Null

# Keep the portable interpreter isolated from %APPDATA%\Python user packages.
$env:PYTHONNOUSERSITE = "1"

$PgUrl = "https://get.enterprisedb.com/postgresql/postgresql-17.6-1-windows-x64-binaries.zip"
$PyUrls = @(
  "https://mirrors.huaweicloud.com/python/3.10.11/python-3.10.11-embed-amd64.zip",
  "https://mirrors.aliyun.com/python-release/windows/python-3.10.11-embed-amd64.zip",
  "https://www.python.org/ftp/python/3.10.11/python-3.10.11-embed-amd64.zip"
)

function Have([string]$Name) {
  $c = Get-Command $Name -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  return $null
}

function Download([string]$Url, [string]$OutFile) {
  Write-Host "[deps] downloading $Url"
  & curl.exe -L --fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 900 -o $OutFile $Url
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -eq 0) {
    throw "download failed: $Url"
  }
}

function Refresh-Path {
  $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $user = [Environment]::GetEnvironmentVariable("Path", "User")
  $env:PATH = @($machine, $user, $env:PATH) -join ";"
}

function Test-PyPackages([string]$Exe) {
  $old = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $out = & $Exe -c "import pefile, capstone; print('ok')" 2>$null
    return ($LASTEXITCODE -eq 0 -and (($out | Out-String).Trim() -eq "ok"))
  } finally {
    $ErrorActionPreference = $old
  }
}

Write-Host "[deps] Protocol Agent dependency installer"
Write-Host "[deps] root: $Root"

# ---------- PostgreSQL ----------
$pgCtl = Join-Path $Runtime "pgsql\bin\pg_ctl.exe"
if (Test-Path $pgCtl) {
  Write-Host "[ok] PostgreSQL portable runtime: $pgCtl"
} elseif ($CheckOnly) {
  Write-Host "[missing] PostgreSQL portable runtime: $pgCtl"
} else {
  $zip = Join-Path $env:TEMP "protocol-agent-postgresql17.zip"
  Download $PgUrl $zip
  Write-Host "[deps] extracting PostgreSQL ..."
  Expand-Archive -Path $zip -DestinationPath $Runtime -Force
  Remove-Item $zip -Force
  if (-not (Test-Path $pgCtl)) {
    $found = Get-ChildItem $Runtime -Recurse -Filter pg_ctl.exe -ErrorAction SilentlyContinue |
      Where-Object { $_.DirectoryName -like "*\bin" } | Select-Object -First 1
    if ($found) {
      $pgRoot = Split-Path (Split-Path $found.DirectoryName -Parent) -Parent
      if ($pgRoot -and $pgRoot -ne (Join-Path $Runtime "pgsql")) {
        Move-Item $pgRoot (Join-Path $Runtime "pgsql") -Force
      }
    }
  }
  if (-not (Test-Path $pgCtl)) { throw "PostgreSQL extraction failed: $pgCtl not found" }
  Write-Host "[ok] PostgreSQL installed: $pgCtl"
}

# ---------- Python + pefile/capstone ----------
$py = Join-Path $Runtime "python\python.exe"
if (-not (Test-Path $py)) {
  if ($CheckOnly) {
    Write-Host "[missing] portable Python: $py"
  } else {
    $zip = Join-Path $env:TEMP "protocol-agent-python310.zip"
    $ok = $false
    foreach ($url in $PyUrls) {
      try {
        Download $url $zip
        $ok = $true
        break
      } catch {
        Write-Warning "Python download failed from $url"
      }
    }
    if (-not $ok) { throw "could not download Python 3.10 embeddable" }
    New-Item -ItemType Directory -Force -Path (Join-Path $Runtime "python") | Out-Null
    Expand-Archive -Path $zip -DestinationPath (Join-Path $Runtime "python") -Force
    Remove-Item $zip -Force
    $pth = Join-Path $Runtime "python\python310._pth"
    @("python310.zip", ".", "Lib\site-packages", "import site") |
      Set-Content -Path $pth -Encoding ASCII
    New-Item -ItemType Directory -Force -Path (Join-Path $Runtime "python\Lib\site-packages") | Out-Null
    Write-Host "[ok] Python extracted: $py"
  }
} else {
  Write-Host "[ok] portable Python: $py"
}

if (Test-Path $py) {
  if (-not (Test-PyPackages $py)) {
    if ($CheckOnly) {
      Write-Host "[missing] Python packages: pefile/capstone"
    } else {
      $getPip = Join-Path $env:TEMP "protocol-agent-get-pip.py"
      Download "https://bootstrap.pypa.io/get-pip.py" $getPip
      & $py $getPip --no-warn-script-location
      if ($LASTEXITCODE -ne 0) { throw "get-pip failed" }
      & $py -m pip install --no-warn-script-location --disable-pip-version-check pefile capstone
      if ($LASTEXITCODE -ne 0) { throw "pip install pefile/capstone failed" }
      Remove-Item $getPip -Force -ErrorAction SilentlyContinue
      if (-not (Test-PyPackages $py)) { throw "pefile/capstone import failed after install" }
      Write-Host "[ok] pefile/capstone installed into portable Python"
    }
  } else {
    Write-Host "[ok] pefile/capstone already available"
  }
}

# ---------- Wireshark / tshark ----------
$tshark = Have "tshark"
$wiresharkDefault = "C:\Program Files\Wireshark\tshark.exe"
if (-not $tshark -and (Test-Path $wiresharkDefault)) { $tshark = $wiresharkDefault }
if ($tshark) {
  Write-Host "[ok] tshark: $tshark"
} elseif ($CheckOnly -or $SkipWireshark) {
  Write-Host "[missing] tshark (P2 live capture and pcap parsing)"
} else {
  $winget = Have "winget"
  if (-not $winget) {
    Write-Warning "tshark not found and winget unavailable; install Wireshark manually from https://www.wireshark.org/"
  } else {
    Write-Host "[deps] installing Wireshark via winget (may require UAC) ..."
    & winget install --id WiresharkFoundation.Wireshark -e --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "winget Wireshark install failed; install manually and ensure tshark.exe is on PATH"
    } else {
      if (-not $tshark -and (Test-Path $wiresharkDefault)) { $tshark = $wiresharkDefault }
      if (-not $tshark) { $tshark = Have "tshark" }
    }
  }
}

# ---------- Optional advanced analyzers ----------
if ($WithAnalyzers) {
  if ($CheckOnly) {
    if (-not (Have "java")) { Write-Host "[missing] JDK 25 (Ghidra)" }
    if (-not (Have "dotnet")) { Write-Host "[missing] .NET SDK 10 (ILSpyCmd)" }
    Write-Host "[info] Ghidra/ILSpy are installed by tools\install-analyzers.ps1 -DownloadGhidra"
  } else {
    $winget = Have "winget"
    if (-not (Have "java") -and $winget) {
      Write-Host "[deps] installing Microsoft OpenJDK 25 ..."
      & winget install --id Microsoft.OpenJDK.25 -e --silent --accept-package-agreements --accept-source-agreements
    }
    if (-not (Have "dotnet") -and $winget) {
      Write-Host "[deps] installing .NET SDK 10 ..."
      & winget install --id Microsoft.DotNet.SDK.10 -e --silent --accept-package-agreements --accept-source-agreements
    }
    Refresh-Path
    & (Join-Path $Root "tools\install-analyzers.ps1") -DownloadGhidra

    # Persist analyzer paths for start-windows.ps1. The analyzer installer runs
    # in a child scope, so without this file a later shell would not see Ghidra.
    $analyzersDir = Join-Path $Runtime "analyzers-env.ps1"
    $toolBin = Join-Path $Root "tools\bin"
    $ghidra = Get-ChildItem (Join-Path $Root "tools") -Directory -Filter "ghidra_*_PUBLIC" -ErrorAction SilentlyContinue |
      Select-Object -First 1
    $java = Have "java"
    $dotnet = Have "dotnet"
    $lines = @(
      "# Generated by install-deps-windows.ps1",
      "`$env:PATH = @('$toolBin', `$env:PATH) -join ';'"
    )
    if ($ghidra) { $lines += "`$env:GHIDRA_HOME = '$($ghidra.FullName)'" }
    if ($java) { $lines += "`$env:JAVA_HOME = '$(Split-Path (Split-Path $java -Parent) -Parent)'" }
    if ($dotnet) { $lines += "`$env:DOTNET_ROOT = '$(Split-Path $dotnet -Parent)'" }
    $lines | Set-Content -Path $analyzersDir -Encoding UTF8
    Write-Host "[ok] analyzer environment: $analyzersDir"
    Write-Host "[i] If Ghidra/ILSpy are not auto-detected, open a new PowerShell window so PATH is refreshed."
  }
}

# ---------- Summary ----------
Write-Host ""
Write-Host "[deps] summary"
Write-Host "  PostgreSQL: $(if (Test-Path $pgCtl) { 'runtime\pgsql' } else { 'missing' })"
Write-Host "  Python:     $(if (Test-Path $py) { 'runtime\python' } else { 'missing' })"
Write-Host "  tshark:     $(if ($tshark) { $tshark } else { 'missing (live capture disabled)' })"
Write-Host "  analyzers:  $(if ($WithAnalyzers) { 'requested (see tools\install-analyzers.ps1 output)' } else { 'optional; rerun with -WithAnalyzers' })"
Write-Host ""
Write-Host "Next: powershell -ExecutionPolicy Bypass -File deploy\start-windows.ps1"