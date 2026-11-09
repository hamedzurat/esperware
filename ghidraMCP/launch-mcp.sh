#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "$script_dir/.local/jdk25/bin/java" ]]; then
  export JAVA_HOME="$script_dir/.local/jdk25"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
  echo 'Set GHIDRA_INSTALL_DIR to the Ghidra installation directory.' >&2
  exit 2
fi

launcher="$GHIDRA_INSTALL_DIR/support/launch.sh"
if [[ ! -x "$launcher" ]]; then
  echo "Ghidra launcher not found: $launcher" >&2
  exit 2
fi

# Keep Ghidra in the MCP host's process tree so stdio remains connected.
# Route Ghidra logs to stderr; stdout belongs exclusively to MCP's JSON-RPC stream.
vmargs="${GHIDRA_JAVA_OPTIONS:-} ${GHIDRA_GUI_JAVA_OPTIONS:-} -Dlog4j.configurationFile=$script_dir/log4j-mcp.xml"
exec "$launcher" fg jdk Ghidra "${GHIDRA_GUI_MAXMEM:-}" "$vmargs" ghidra.GhidraRun "$@"
