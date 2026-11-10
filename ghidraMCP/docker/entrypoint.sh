#!/bin/sh
set -eu

Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp &
export DISPLAY=:99
sleep 1
exec /opt/ghidraMCP/launch-mcp.sh "$@"
