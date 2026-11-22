set shell := ["bash", "-euo", "pipefail", "-c"]

engine := env_var_or_default("CONTAINER_ENGINE", "podman")
image := env_var_or_default("MCP_IMAGE", "ghidra-mcp:local")
cors_origin := env_var_or_default("GHIDRA_MCP_CORS_ORIGIN", "loopback")

default:
    @just --list

# Start one headless Ghidra MCP container: just run <binary> [dir]
run binary dir="": (_launch "run" binary dir)

# Resume an existing state directory without re-importing a binary
resume dir port="8765": (_launch "resume" "" dir port)

[private]
[positional-arguments]
_launch mode binary dir fixed_port="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{invocation_directory()}}"
    mode="$1"
    dir_arg="$3"
    fixed_port="$4"
    workspace=(--work-dir /data/run)
    if [ "$mode" = resume ]; then
        dir_abs="$(realpath -- "$dir_arg")"
        [ -f "$dir_abs/run/ghidra-project/workspace.gpr" ] || { echo "No existing workspace in $dir_abs/run" >&2; exit 2; }
        mounts=(-v "$dir_abs:/data")
    else
        bin_abs="$(realpath -- "$2")"
        [ -f "$bin_abs" ] || { echo "Binary not found: $bin_abs" >&2; exit 2; }
        bin_name="$(basename "$bin_abs")"
        if [ -z "$dir_arg" ]; then dir_arg="/tmp/esperware-$(date +%s%N)-${bin_name%.*}"; fi
        dir_abs="$(realpath -m -- "$dir_arg")"
        case "/$dir_abs" in */.*) echo "State dir cannot contain '.'-prefixed segments: $dir_abs" >&2; exit 2 ;; esac
        mkdir -p "$dir_abs/run"
        mounts=(-v "$bin_abs:/input/$bin_name:ro" -v "$dir_abs:/data")
        workspace+=(--binary "/input/$bin_name")
    fi

    if [ "$mode" = dump ]; then
        {{engine}} run --rm "${mounts[@]}" {{image}} "${workspace[@]}" --no-cache --dump
        echo "Dumped to $dir_abs/run/code (state: $dir_abs)" >&2
        exit 0
    fi

    command -v jq >/dev/null || { echo "jq is required to check server readiness" >&2; exit 2; }
    mkdir -p "$dir_abs/cache"
    launch_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    launch_container() {
        {{engine}} run --rm -d --name "ghidra-mcp-$port" \
            -p "127.0.0.1:$port:8765" \
            -e "GHIDRA_MCP_PUBLIC_URL=http://127.0.0.1:$port" \
            -e "GHIDRA_MCP_LAUNCH_ID=$launch_id" \
            -e "GHIDRA_MCP_CORS_ORIGIN={{cors_origin}}" \
            "${mounts[@]}" {{image}} "${workspace[@]}" --cache-dir /data/cache
    }
    find_port() {
        python3 - "$1" "$2" <<'PY'
    import socket
    import sys

    for port in range(int(sys.argv[1]), int(sys.argv[2]) + 1):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
        print(port)
        break
    else:
        sys.exit(1)
    PY
    }

    if [ "$mode" = resume ]; then
        port="$fixed_port"
        launch_container >/dev/null
    else
        # Randomize the first candidate to spread concurrent launches across ports.
        first_port=$((32001 + RANDOM))
        next_port=$first_port
        last_port=65535
        while true; do
            if ! port="$(find_port "$next_port" "$last_port")"; then
                if [ "$last_port" -lt 65535 ]; then
                    echo "No free port above 32000" >&2
                    exit 1
                fi
                next_port=32001
                last_port=$((first_port - 1))
                continue
            fi
            if launch_output=$(launch_container 2>&1); then
                break
            else
                launch_status=$?
            fi

            cname="ghidra-mcp-$port"
            if ! {{engine}} container inspect "$cname" >/dev/null 2>&1 &&
                find_port "$port" "$port" >/dev/null &&
                [[ "$launch_output" != *"address already in use"* &&
                    "$launch_output" != *"port is already allocated"* &&
                    "$launch_output" != *"$cname"*"already in use"* ]]; then
                printf '%s\n' "$launch_output" >&2
                exit "$launch_status"
            fi
            next_port=$((port + 1))
        done
    fi

    cname="ghidra-mcp-$port"
    base_url="http://127.0.0.1:$port"
    ready_file="$dir_abs/run/ready.json"
    for _ in $(seq 1 240); do
        if ! {{engine}} container inspect "$cname" >/dev/null 2>&1; then
            echo "Container $cname exited before becoming ready" >&2
            exit 1
        fi
        if ready=$(cat -- "$ready_file" 2>/dev/null) &&
            jq -e --arg launch_id "$launch_id" --arg api_url "$base_url/api/v1" \
                '.status == "ready" and .launch_id == $launch_id and .api_url == $api_url' \
                >/dev/null 2>&1 <<<"$ready"; then
            echo "Started on port $port (state: $dir_abs)" >&2
            printf '%s\n' "$ready"
            exit 0
        fi
        sleep 0.25
    done
    echo "Timed out waiting for $ready_file; check: just logs $port" >&2
    exit 1

# Export pseudocode and metadata into <dir>/run/code/v<N>
dump binary dir="": (_launch "dump" binary dir)

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

# Build (if needed) and serve the WebUI, optionally printing a URL for <port>
wui port="" ui_port="4173":
    #!/usr/bin/env bash
    set -euo pipefail
    wui_dir="{{justfile_directory()}}/wui"
    server_port="{{port}}"
    ui_port="{{ui_port}}"
    url="http://127.0.0.1:$ui_port"
    if [ -n "$server_port" ]; then
        url="$url/?port=$server_port"
    fi
    if curl -fsS --max-time 1 "http://127.0.0.1:$ui_port/" >/dev/null 2>&1; then
        echo "WebUI already running: $url"
        exit 0
    fi
    cd "$wui_dir"
    [ -d node_modules ] || bun install
    [ -f build/index.html ] || bun run build
    echo "Serving WebUI at $url"
    exec bun run preview -- --host 127.0.0.1 --port "$ui_port" --strictPort

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
