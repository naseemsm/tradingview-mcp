#!/bin/bash
# Supervise the TradingView MCP server (127.0.0.1:8000, never published) and the relay
# ($PORT, the only published port). Exit non-zero if either dies, so the platform restart
# policy restarts the container instead of an in-container respawn loop hiding a problem.
set -euo pipefail

for v in RELAY_PUBLIC_URL OAUTH_SIGNING_KEY RELAY_ADMIN_PASSWORD_HASH; do
  if [ -z "${!v:-}" ]; then echo "entrypoint: $v is not set" >&2; exit 64; fi
done
: "${PORT:=8080}"
: "${RELAY_DATA_DIR:=/data}"
: "${MCP_PORT:=8000}"

mkdir -p "$RELAY_DATA_DIR"
chown -R mcpuser:mcpuser "$RELAY_DATA_DIR"

run_as() { setpriv --reuid=mcpuser --regid=mcpuser --init-groups "$@"; }

cd /app
# Loopback only: the relay is the sole route to /mcp from outside the container.
run_as env HOST=127.0.0.1 PORT="$MCP_PORT" tradingview-mcp streamable-http --host 127.0.0.1 --port "$MCP_PORT" &
MCP_PID=$!

run_as env PORT="$PORT" UPSTREAM_URL="http://127.0.0.1:$MCP_PORT" python -m relay &
RELAY_PID=$!

trap 'kill -TERM $MCP_PID $RELAY_PID 2>/dev/null || true' TERM INT
set +e
wait -n $MCP_PID $RELAY_PID
code=$?
set -e
if kill -0 "$MCP_PID" 2>/dev/null; then
  echo "entrypoint: relay exited ($code); stopping MCP server" >&2
else
  echo "entrypoint: MCP server exited ($code); stopping relay" >&2
fi
kill -TERM "$MCP_PID" "$RELAY_PID" 2>/dev/null || true
wait || true
exit "${code:-1}"
