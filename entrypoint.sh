#!/bin/bash
# Container entrypoint. Runs as root.
#
#   1. start the privileged grader daemon (root) in the background,
#   2. wait for its socket to appear,
#   3. drop to the unprivileged `mcp` user and exec the MCP server on stdio,
#      so an external MCP client speaks to it over the container's stdin/stdout.
#
# The model never gets root: `bash` runs as `model`, this server runs as `mcp`,
# and only the grader daemon is root.
set -euo pipefail

SOCKET=/run/grader/grader.sock

# --- 1. privileged grader daemon ------------------------------------------
mkdir -p /run/grader
chmod 755 /run/grader
python3 /app/grader/grader.py --daemon &
DAEMON_PID=$!

# --- 2. wait for the socket -----------------------------------------------
for _ in $(seq 1 50); do
    if [ -S "$SOCKET" ]; then break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "grader daemon died during startup" >&2
        exit 1
    fi
    sleep 0.1
done
if [ ! -S "$SOCKET" ]; then
    echo "grader daemon socket never appeared" >&2
    exit 1
fi

# --- 3. drop to `mcp` and run the MCP server on stdio ---------------------
# runuser keeps our stdin/stdout wired to the MCP client.
exec runuser -u mcp -- /opt/venv/bin/python /app/mcp_server/server.py
