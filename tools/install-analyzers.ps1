# Install optional reverse-engineering backends used by P3/P4.
# Ghidra and IDA are NOT redistributed:
#   - Ghidra: use -DownloadGhidra, or set GHIDRA_HOME.
#   - IDA: commercial license required; install it yourself and add idat64/idat to PATH.
param(
  [switch]$DownloadGhidra,
  [string]$GhidraVersion = "11.3.2"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin = Join-Path $root "bin"
New-Item -ItemType Directory -Force -Path $bin | Out-Null

function Have($name) {
  $c = Get-Command $name -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  return $null
}

$dotnet = Have "dotnet"
if ($dotnet) {
  if (Have "ilspycmd") {
    Write-Host "[ok] ilspycmd already on PATH"
  } else {
    Write-Host "[*] installing ILSpyCmd into $bin ..."
    & $dotnet tool install --tool-path $bin ilspycmd
    if ($LASTEXITCODE -eq 0) {
      Write-Host "[ok] add $bin to PATH, or invoke tools/bin/ilspycmd.exe"
    } else {
      Write-Host "[!] ILSpyCmd install failed (requires .NET SDK, not just runtime)"
    }
  }
} else {
  Write-Host "[!] dotnet not found; .NET decompilation will fall back to strings/CLR survey"
}

$ghidraHome = $env:GHIDRA_HOME
if ($ghidraHome) {
  $headless = Join-Path $ghidraHome "support/analyzeHeadless.bat"
  if (Test-Path $headless) { Write-Host "[ok] Ghidra: $headless" }
  else { Write-Host "[!] GHIDRA_HOME set but support/analyzeHeadless.bat missing" }
} elseif ($DownloadGhidra) {
  $zip = Join-Path $root "ghidra-$GhidraVersion.zip"
  $url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_$($GhidraVersion)_build/ghidra_$($GhidraVersion)_PUBLIC.zip"
  Write-Host "[*] downloading $url"
  Invoke-WebRequest -Uri $url -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath $root -Force
  Remove-Item $zip
  $dir = Get-ChildItem $root -Directory | Where-Object { $_.Name -like "ghidra_*_PUBLIC" } | Select-Object -First 1
  if ($dir) {
    $env:GHIDRA_HOME = $dir.FullName
    Write-Host "[ok] Ghidra extracted to $($dir.FullName); set GHIDRA_HOME to this path"
  }
} else {
  Write-Host "[!] Ghidra not configured. Set GHIDRA_HOME or rerun with -DownloadGhidra"
}

foreach ($c in @("idat64", "idat", "readelf", "objdump", "rabin2", "r2")) {
  $p = Have $c
  if ($p) { Write-Host "[ok] $c = $p" } else { Write-Host "[--] $c not found" }
}
Write-Host "[i] IDA cannot be redistributed; a valid IDA installation is required."
