#!/usr/bin/env bash
# Install the OSINT Graph Mapper: the desktop launcher onto PATH + the graph
# tools into the osint-mcp server (that wiring lives in the server itself, but
# this confirms and reports it). Idempotent — safe to re-run.
set -uo pipefail

SELF="$(readlink -f "$0")"
ROOT="$(cd "$(dirname "$SELF")" && pwd)"          # project root (osint-map/)
BIN="${HOME}/.local/bin"
MCP_TOOLS="${HOME}/tools/osint-mcp"

mkdir -p "$BIN"

# 1. launcher on PATH (symlink so edits in the repo are live immediately)
if [ -e "$BIN/osint-map" ] && [ ! -L "$BIN/osint-map" ]; then
  echo "osint-map: $BIN/osint-map exists and is not our symlink — replacing it (backup: osint-map.bak)"
  mv "$BIN/osint-map" "$BIN/osint-map.bak"
fi
ln -sfn "$ROOT/desktop/osint-map" "$BIN/osint-map"
echo "installed: $BIN/osint-map -> desktop/osint-map"

# 2. server wiring — graph_tools is imported by server.py from its own dir;
#    verify rather than copy, so the single source of truth stays here.
if [ -f "$MCP_TOOLS/server.py" ] && grep -q "graph_tools.register" "$MCP_TOOLS/server.py"; then
  echo "installed: graph tools wired into $MCP_TOOLS/server.py (verified)"
else
  echo "WARNING: $MCP_TOOLS/server.py does not import graph_tools." \
       "Copy graph_tools.py next to it and add the shim by hand —" \
       "see README.md 'Server wiring'." >&2
fi

# 3. import check (spaces-in-path means no pip editable install; sys.path shim
#    in server.py is the mechanism and needs to work as-is)
if python3 -c "import sys; sys.path.insert(0, '$ROOT'); import osint_map" 2>/dev/null; then
  echo "ok: python3 imports osint_map from '$ROOT'"
else
  echo "ERROR: import osint_map failed from '$ROOT' — check path/spaces" >&2
  exit 1
fi

echo "done. Try: osint-map"