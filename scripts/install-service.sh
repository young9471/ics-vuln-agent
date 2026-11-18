#!/usr/bin/env bash
# Install/uninstall a systemd unit for Protocol Agent. Run as root.
set -euo pipefail
ACTION="${1:-install}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/platform/platform.exe}"
WORKDIR="${WORKDIR:-$ROOT/platform}"
ADDR="${ADDR:-:8787}"
USER_NAME="${USER_NAME:-protocol-agent}"
UNIT=/etc/systemd/system/protocol-agent.service

if [[ "$ACTION" == "uninstall" ]]; then
  systemctl disable --now protocol-agent 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  echo "[service] removed protocol-agent"
  exit 0
fi

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "platform binary not found: $BIN" >&2; exit 1; }
id "$USER_NAME" >/dev/null 2>&1 || useradd --system --home "$WORKDIR" --shell /usr/sbin/nologin "$USER_NAME"
sed -e "s#__WORKDIR__#$WORKDIR#g" -e "s#__BIN__#$BIN#g" \
    -e "s#__ADDR__#$ADDR#g" -e "s#__USER__#$USER_NAME#g" \
    "$ROOT/scripts/protocol-agent.service" > "$UNIT"
systemctl daemon-reload
systemctl enable --now protocol-agent
echo "[service] installed protocol-agent; health: http://localhost${ADDR}/api/health"
