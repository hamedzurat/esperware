#!/usr/bin/env bash
# Create a Pi workspace under .runs/ for one running esperware container.
# Usage: scaffold.sh '<ready.json line>' <state-dir>
# Called by `just run`/`just resume`. Prints the run directory on stdout.
set -euo pipefail

ready="${1:?ready json}"
state_dir="${2:?state dir}"
agentic="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$agentic")"

command -v jq > /dev/null || { echo "jq is required" >&2; exit 2; }
command -v envsubst > /dev/null || { echo "envsubst (gettext) is required" >&2; exit 2; }
pi_bin="${PI_BIN:-$(command -v pi || true)}"
[ -n "$pi_bin" ] || { echo "pi not found on PATH (set PI_BIN)" >&2; exit 2; }

env_file="$agentic/.env"
[ -f "$env_file" ] || cp "$agentic/.env.example" "$env_file"

binary_name="$(jq -r '.binary_name // "binary"' <<< "$ready")"
port="$(jq -r '.api_url' <<< "$ready" | sed -E 's#^https?://[^:/]+:([0-9]+)/.*#\1#')"
slug="$(sed -E 's/\.(stripped|unstripped)?\.?elf$//; s/[^A-Za-z0-9._-]+/_/g' <<< "$binary_name")"
id="$(date +%Y%m%d-%H%M%S)-${slug}-p${port}"
run="$root/.runs/$id"

mkdir -p "$run/agent" "$run/work" "$run/sessions" "$run/template"
cp "$agentic"/template/{models.json,mcp.json,settings.json} "$run/template/"
cp "$agentic/template/SYSTEM.md" "$run/agent/SYSTEM.md"
cp "$agentic"/template/{pi,export-html} "$run/"
chmod +x "$run/pi" "$run/export-html"

jq -n \
    --arg id "$id" \
    --arg created_at "$(date -Is)" \
    --arg state_dir "$state_dir" \
    --arg container "ghidra-mcp-$port" \
    --arg pi_bin "$pi_bin" \
    --arg env_file "$env_file" \
    --argjson ready "$ready" \
    '{id: $id, created_at: $created_at, port: ($ready.api_url | capture(":(?<p>[0-9]+)/") | .p | tonumber),
      binary_name: $ready.binary_name, binary_sha256: $ready.binary_sha256,
      launch_id: $ready.launch_id, state_dir: $state_dir, container: $container,
      mcp_rw_url: $ready.mcp_rw_url, mcp_ro_url: $ready.mcp_ro_url, api_url: $ready.api_url,
      pi_bin: $pi_bin, env_file: $env_file}' > "$run/run.json"

echo "Pi workspace: $run  (cd there, then ./pi)" >&2
printf '%s\n' "$run"
