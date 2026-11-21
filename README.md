# Esperware

Headless Ghidra 12.2 MCP server with versioned edits, read-only subagent endpoints, and a standalone diff viewer.

## Repository layout

- `justfile`: shortcut commands to start, inspect, and stop a binary container.
- `ghidraMCP/`: headless Java Ghidra server, container build, and JUnit 5 test suite. See [the architecture notes](ghidraMCP/README.md) for internals.
- `wui/`: standalone browser page that connects to a running server port to inspect versions, unified diffs, and functions.
- `artifacts/`: C test sources and a `justfile` that builds `-O1` stripped and unstripped ELF binaries into `artifacts/build/`.

## Build test binaries

Run `just` inside `artifacts/` to compile every `.c` file at `-O1` (`-fno-inline`) into both `build/<name>.unstripped.elf` (with DWARF) and `build/<name>.stripped.elf`:

```sh
just artifacts
```

Or run `cd artifacts && just one <name>` for one C file, or `cd artifacts && just clean` to remove `artifacts/build/`.

## Quickstart with containers

Build the container image once:

```sh
just image
```

Start the server by pointing at a binary, port (default `8765`), and state directory (default `/tmp/esperware-<port>`):

```sh
just run ./artifacts/build/readability-fixture.stripped.elf 8765 /tmp/my-run
```

`just run` creates `/tmp/my-run/run` (project and SQLite history) and `/tmp/my-run/cache` (SHA-256 baseline cache), starts the container, waits until ready, and prints the endpoints:

- Main agent (read-write, 13 tools): `http://127.0.0.1:8765/mcp/rw`
- Subagents (read-only, 9 tools): `http://127.0.0.1:8765/mcp/ro`
- REST and SSE API: `http://127.0.0.1:8765/api/v1`

Open [the WebUI page](wui/index.html) directly (or run `just wui 8765`) to view versions, unified diffs, and functions.

Manage running containers with:

```sh
just status 8765              # Query live binary metadata and current version
just ps                       # List running ghidra-mcp containers
just logs 8765                # View container logs
just stop 8765                # Graceful shutdown
just resume /tmp/my-run 8765  # Reopen existing project and version history
```

Pass `CONTAINER_ENGINE=docker` before any `just` command to use Docker instead of Podman.

## Run locally without a container

Requires JDK 25 and Ghidra 12.2 (`GHIDRA_INSTALL_DIR` or `ghidraMCP/.local/ghidra_12.2_PUBLIC`):

```sh
cd ghidraMCP
just build
./bin/ghidra-mcp \
	--binary ../artifacts/build/readability-fixture.stripped.elf \
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

## Build and test commands

All tests use Java and JUnit 5:

```sh
just --list     # List top-level run and test commands
just test       # Fast unit tests (VersionStore and access control)
just e2e        # Container E2E suite using Podman
just check      # Unit tests and container E2E suite
```

Inside `ghidraMCP/`, `just e2e-local` runs the same E2E suite against the local headless launcher without containers.
