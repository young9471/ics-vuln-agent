#!/usr/bin/env bash
# Optional reverse-engineering backends. Ghidra/IDA are not bundled.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin
if command -v dotnet >/dev/null 2>&1; then
  if command -v ilspycmd >/dev/null 2>&1; then
    echo "[ok] ilspycmd already on PATH"
  else
    if dotnet tool install --tool-path "$PWD/bin" ilspycmd; then
      echo "[ok] add $PWD/bin to PATH"
    else
      echo "[!] ILSpyCmd install failed (requires .NET SDK, not just runtime)"
    fi
  fi
else
  echo "[!] dotnet not found; .NET decompilation falls back to strings/CLR survey"
fi
if [ -n "${GHIDRA_HOME:-}" ] && [ -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
  echo "[ok] Ghidra $GHIDRA_HOME"
else
  echo "[!] set GHIDRA_HOME (Ghidra is not redistributed)"
fi
for c in idat64 idat readelf objdump rabin2 r2; do
  if command -v "$c" >/dev/null 2>&1; then echo "[ok] $c"; else echo "[--] $c not found"; fi
done
echo "[i] IDA is commercial; install it separately and add idat64/idat to PATH."
