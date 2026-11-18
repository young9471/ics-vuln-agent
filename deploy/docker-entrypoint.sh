#!/usr/bin/env sh
set -eu
# PostgreSQL readiness is normally handled by compose's healthcheck; this loop
# also makes `docker run` with an explicit DSN behave predictably.
if [ -n "${PROTOCOL_AGENT_PG_DSN:-}" ]; then
  python3 - <<'PY'
import os, socket, time
from urllib.parse import urlparse
u = urlparse(os.environ["PROTOCOL_AGENT_PG_DSN"])
host, port = u.hostname or "127.0.0.1", u.port or 5432
for _ in range(60):
    try:
        with socket.create_connection((host, port), timeout=1):
            break
    except OSError:
        time.sleep(1)
else:
    raise SystemExit(f"PostgreSQL not reachable at {host}:{port}")
PY
fi
exec /app/platform/protocol-agent -addr "${PROTOCOL_AGENT_LISTEN:-:8787}"
