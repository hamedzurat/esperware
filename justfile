set shell := ["bash", "-euo", "pipefail", "-c"]

engine := env_var_or_default("CONTAINER_ENGINE", "podman")
image := env_var_or_default("MCP_IMAGE", "ghidra-mcp:local")

default:
    @just --list

# Start one headless Ghidra MCP container: just run <binary> [dir]
run binary dir="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{invocation_directory()}}"
    bin_abs="$(realpath "{{binary}}")"
    [ -f "$bin_abs" ] || { echo "Binary not found: $bin_abs" >&2; exit 2; }
    bin_name="$(basename "$bin_abs")"
    dir_arg="{{dir}}"
    if [ -z "$dir_arg" ]; then dir_arg="/tmp/esperware-$(date +%s%N)-${bin_name%.*}"; fi
    dir_abs="$(realpath -m "$dir_arg")"
    case "/$dir_abs" in */.*) echo "State dir cannot contain '.'-prefixed segments: $dir_abs" >&2; exit 2 ;; esac
    mkdir -p "$dir_abs/run" "$dir_abs/cache"
    rm -f "$dir_abs/run/ready.json"
    port="$(python3 -c $'import socket\nfor port in range(32001, 65536):\n    with socket.socket() as s:\n        try:\n            s.bind(("127.0.0.1", port))\n            print(port)\n            break\n        except OSError:\n            pass\nelse:\n    raise SystemExit("No free port above 32000")')"
    cname="ghidra-mcp-$port"
    {{engine}} run --rm -d --name "$cname" \
      -p "127.0.0.1:$port:8765" \
      -e "GHIDRA_MCP_PUBLIC_URL=http://127.0.0.1:$port" \
      -e GHIDRA_MCP_CORS_ORIGIN \
      -v "$bin_abs:/input/$bin_name:ro" \
      -v "$dir_abs:/data" \
      {{image}} \
      --binary "/input/$bin_name" --work-dir /data/run --cache-dir /data/cache >/dev/null
    for _ in $(seq 1 240); do
      if [ -f "$dir_abs/run/ready.json" ]; then
        echo "Started on port $port (state: $dir_abs)" >&2
        cat "$dir_abs/run/ready.json"
        exit 0
      fi
      if ! {{engine}} container inspect "$cname" >/dev/null 2>&1; then
        echo "Container $cname exited before becoming ready" >&2
        exit 1
      fi
      sleep 0.25
    done
    echo "Timed out waiting for $dir_abs/run/ready.json; check: just logs $port" >&2
    exit 1

# Resume an existing state directory without re-importing a binary
resume dir port="8765":
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{invocation_directory()}}"
    dir_abs="$(realpath "{{dir}}")"
    [ -f "$dir_abs/run/ghidra-project/workspace.gpr" ] || { echo "No existing workspace in $dir_abs/run" >&2; exit 2; }
    rm -f "$dir_abs/run/ready.json"
    cname="ghidra-mcp-{{port}}"
    {{engine}} run --rm -d --name "$cname" \
      -p "127.0.0.1:{{port}}:8765" \
      -e "GHIDRA_MCP_PUBLIC_URL=http://127.0.0.1:{{port}}" \
      -e GHIDRA_MCP_CORS_ORIGIN \
      -v "$dir_abs:/data" \
      {{image}} \
      --work-dir /data/run --cache-dir /data/cache >/dev/null
    for _ in $(seq 1 240); do
      if [ -f "$dir_abs/run/ready.json" ]; then
        cat "$dir_abs/run/ready.json"
        exit 0
      fi
      if ! {{engine}} container inspect "$cname" >/dev/null 2>&1; then
        echo "Container $cname exited before becoming ready" >&2
        exit 1
      fi
      sleep 0.25
    done
    echo "Timed out waiting for $dir_abs/run/ready.json" >&2
    exit 1

# One-shot export of pseudocode and metadata into <dir>/run/code/v0: just dump <binary> [dir]
dump binary dir="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{invocation_directory()}}"
    bin_abs="$(realpath "{{binary}}")"
    [ -f "$bin_abs" ] || { echo "Binary not found: $bin_abs" >&2; exit 2; }
    bin_name="$(basename "$bin_abs")"
    dir_arg="{{dir}}"
    if [ -z "$dir_arg" ]; then dir_arg="/tmp/esperware-$(date +%s%N)-${bin_name%.*}"; fi
    dir_abs="$(realpath -m "$dir_arg")"
    case "/$dir_abs" in */.*) echo "State dir cannot contain '.'-prefixed segments: $dir_abs" >&2; exit 2 ;; esac
    mkdir -p "$dir_abs/run"
    {{engine}} run --rm \
      -v "$bin_abs:/input/$bin_name:ro" \
      -v "$dir_abs:/data" \
      {{image}} \
      --binary "/input/$bin_name" --work-dir /data/run --no-cache --dump
    echo "Dumped to $dir_abs/run/code (state: $dir_abs)" >&2

# Stop a running container and wait for its name to become reusable
stop port="8765":
    #!/usr/bin/env bash
    set -euo pipefail
    cname="ghidra-mcp-{{port}}"
    if ! curl -fsS --max-time 5 -X POST "http://127.0.0.1:{{port}}/api/v1/shutdown" >/dev/null 2>&1; then
      if {{engine}} container inspect "$cname" >/dev/null 2>&1; then
        {{engine}} stop "$cname" >/dev/null
      fi
    fi
    for _ in $(seq 1 80); do
      if ! {{engine}} container inspect "$cname" >/dev/null 2>&1; then exit 0; fi
      sleep 0.25
    done
    echo "Timed out waiting for $cname to stop" >&2
    exit 1

# Show live server status
status port="8765":
    @curl -fsS "http://127.0.0.1:{{port}}/api/v1/status" | jq

# List running ghidra-mcp containers
ps:
    @{{engine}} ps --filter "name=ghidra-mcp-"

# Tail container logs
logs port="8765":
    @{{engine}} logs "ghidra-mcp-{{port}}"

# Open standalone WebUI pointed at port
wui port:
    @xdg-open "file://{{justfile_directory()}}/wui/index.html?port={{port}}" >/dev/null 2>&1 &

# Build all C test binaries in artifacts/
artifacts:
    @just -f artifacts/justfile build

# Build ghidra-mcp:local container image
image:
    @just -f ghidraMCP/justfile image

# Run fast JUnit unit tests
test:
    @just -f ghidraMCP/justfile test

# Run container E2E test suite
e2e:
    @just -f ghidraMCP/justfile e2e

# Run unit tests and container E2E suite
check:
    @just -f ghidraMCP/justfile check
