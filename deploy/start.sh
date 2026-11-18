#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLATFORM="$ROOT/platform/platform"
CONFIG="$ROOT/platform/config.json"
EXAMPLE="$ROOT/platform/config.example.json"
if [[ ! -x "$PLATFORM" ]]; then
  echo "platform binary not found: $PLATFORM" >&2
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  cp "$EXAMPLE" "$CONFIG"
  python3 - "$CONFIG" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p,encoding='utf-8'))
d.setdefault('database',{}).update(host='127.0.0.1',port=5432,user='pagent',password='',dbname='protocol_platform',sslmode='disable')
json.dump(d,open(p,'w',encoding='utf-8'),ensure_ascii=False,indent=2)
PY
fi
cd "$ROOT/platform"
exec "$PLATFORM" -addr "${ADDR:-:8787}"
