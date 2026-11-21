# Esperware

Headless Ghidra 12.2 MCP server with versioned edits, read-only subagent endpoints, and a standalone diff viewer.

## Repository layout

- `ghidraMCP/`: headless Java Ghidra server, container build, and JUnit 5 test suite. See [the architecture notes](ghidraMCP/README.md) for internals.
- `wui/`: standalone browser page that connects to a running server port to inspect versions, unified diffs, and functions.
- `artifacts/`: C test sources and a `justfile` that builds stripped ELF binaries into `artifacts/build/`.

## Build test binaries

Run `just` inside `artifacts/` to compile every `.c` file into a stripped ELF under `artifacts/build/`:

```sh
cd artifacts
just
```

Run `just one readability-fixture` to build one file, or `just clean` to remove `artifacts/build/`.

## Run the MCP server in a container

One container runs one binary at a time. Build the image from the repository root:

```sh
podman build -t ghidra-mcp:local -f ghidraMCP/Dockerfile .
```

Start a container and mount a host directory at `/data` for your binary, work directory, and SHA-256 analysis cache:

```sh
podman run --rm -d \
	-p 127.0.0.1:8765:8765 \
	-v /path/to/data:/data \
	ghidra-mcp:local \
	--binary /data/target.elf \
	--work-dir /data/run-01 \
	--cache-dir /data/cache
```

Check `/path/to/data/run-01/ready.json` or `GET http://127.0.0.1:8765/api/v1/status` to confirm readiness. The server prints one JSON line to standard output when ready and exposes these routes:

- Main agent (read-write, 13 tools): `http://127.0.0.1:8765/mcp/rw`
- Subagents (read-only, 9 tools): `http://127.0.0.1:8765/mcp/ro`
- REST and SSE API: `http://127.0.0.1:8765/api/v1`

Restarting the container with the same `--work-dir` and omitting `--binary` resumes from the existing Ghidra project and SQLite version history. Send `SIGTERM` or `POST http://127.0.0.1:8765/api/v1/shutdown` to stop the server cleanly.

## Open the WebUI

Open [the WebUI page](wui/index.html) directly in a browser, enter the Ghidra server port (default `8765`) or full base URL in **Port / URL**, and select **Connect**. You can also pass `?port=8765` in the URL query string.

## Run locally without a container

Requires JDK 25 and Ghidra 12.2 (`GHIDRA_INSTALL_DIR` or `ghidraMCP/.local/ghidra_12.2_PUBLIC`):

```sh
cd ghidraMCP
./gradlew stageServer
./bin/ghidra-mcp \
	--binary ../artifacts/build/readability-fixture.elf \
	--work-dir /tmp/run-01 \
	--cache-dir /tmp/ghidra-cache \
	--port 0
```

Passing `--port 0` binds a free ephemeral port and writes the chosen port into `ready.json`. Do not use directory names starting with `.` inside `--work-dir`, because Ghidra rejects dot-prefixed project paths.

## Server options

| Flag | Environment variable | Purpose |
|---|---|---|
| `--binary <path>` | — | Target binary to import on first run. |
| `--work-dir <path>` | — | Run directory for `ghidra-project/`, `history.sqlite`, and `ready.json`. |
| `--cache-dir <path>` | `GHIDRA_MCP_CACHE_DIR` | Directory for analyzed `.gpr` templates keyed by binary SHA-256. |
| `--no-cache` | — | Disable the SHA-256 project cache. |
| `--host <addr>` | `GHIDRA_MCP_HOST` | Bind address (default `127.0.0.1`; `0.0.0.0` in container). |
| `--port <num>` | `GHIDRA_MCP_PORT` | HTTP port (`0` for ephemeral, default `8765`). |
| `--public-url <url>` | `GHIDRA_MCP_PUBLIC_URL` | Base URL advertised in `ready.json` and `/api/v1/status`. |
| `--decompiler-pool <n>` | — | Concurrent `DecompInterface` worker count (default `2`). |
| `--cors-origin <origin>` | `GHIDRA_MCP_CORS_ORIGIN` | `Access-Control-Allow-Origin` header value (default `*`). |
| `--rw-token <token>` | `GHIDRA_MCP_RW_TOKEN` | Bearer token required on `/mcp/rw` and `POST /api/v1/shutdown`. |
| `--ro-token <token>` | `GHIDRA_MCP_RO_TOKEN` | Bearer token required on `/mcp/ro` (`--rw-token` also accepted). |

## MCP tools

Read-only tools on `/mcp/ro` and `/mcp/rw`: `program_info`, `list_functions`, `list_symbols`, `decompile`, `disassemble`, `get_xrefs`, `read_memory`, `search_code`, and `get_type`.

Write tools on `/mcp/rw` only: `apply_edits`, `define_type`, `revert`, and `save_checkpoint`.

## Build and test shortcuts (`ghidraMCP/justfile`)

Run `just` commands from `ghidraMCP/`:

```sh
cd ghidraMCP
just --list     # Show available recipes
just build      # Stage server jars locally
just test       # Fast JUnit unit tests
just image      # Build ghidra-mcp:local container image
just e2e        # Run container E2E suite (Podman by default)
just e2e-local  # Run local headless E2E suite
just check      # Run unit tests and container E2E suite
```

All tests use Java and JUnit 5. Pass `CONTAINER_ENGINE=docker` to run `image`, `e2e`, or `check` with Docker instead of Podman.
