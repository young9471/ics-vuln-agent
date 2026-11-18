param(
  [string]$Go = $env:PROTOCOL_AGENT_GO
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Go) {
  $cmd = Get-Command go -ErrorAction SilentlyContinue
  if ($cmd) { $Go = $cmd.Source }
}
if (-not $Go) { throw "go not found on PATH; set PROTOCOL_AGENT_GO or pass -Go C:\path\go.exe" }

Write-Host "=== Python analyzer tests ==="
Push-Location (Join-Path $Root "tools")
try { python -m unittest discover -s tests -p "test_*.py" } finally { Pop-Location }

Write-Host "=== Go tests ==="
Push-Location (Join-Path $Root "platform")
try {
  & $Go test ./...
  if ($env:PROTOCOL_AGENT_PG_DSN) {
    & $Go test -tags integration ./db -run Integration
  } else {
    Write-Host "[skip] Postgres integration tests (set PROTOCOL_AGENT_PG_DSN)"
  }
} finally { Pop-Location }

Write-Host "=== Frontend typecheck / unit ==="
Push-Location (Join-Path $Root "platform\web")
try {
  npx tsc --noEmit
  if (Test-Path "node_modules") {
    npm test
    npm run e2e:list
  } else { Write-Host "[skip] npm test / e2e:list (node_modules missing)" }
} finally { Pop-Location }

Write-Host "=== all checks passed ==="