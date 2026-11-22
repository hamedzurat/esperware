# Esperware

Headless Ghidra 12.2 MCP server with versioned edits, read-only subagent endpoints, and a standalone diff viewer.

## Repository layout

- `justfile`: shortcut commands to start, inspect, and stop a binary container.
- `ghidraMCP/`: headless Java Ghidra server, container build, and JUnit 5 test suite. See [the architecture notes](ghidraMCP/README.md) for internals.
- `wui/`: standalone browser viewer for versions, unified diffs, and functions.
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

Start a server with a binary. The recipe chooses a free port above `32000` and prints it when the server is ready:

```sh
just run ./artifacts/build/readability-fixture.stripped.elf
```

By default, `just run` stores the project and SQLite history in `/tmp/esperware-<time>-readability-fixture.stripped/run`. It stores the SHA-256 baseline cache in the matching `cache` directory. Pass a directory as the second argument to choose a different state directory:

```sh
just run ./artifacts/build/readability-fixture.stripped.elf /tmp/my-run
```

The readiness output contains the server endpoints. Each run gets its own port and container name, so you can run multiple binaries at once. Use the reported port with the management commands:

```sh
just status <port>             # Query live binary metadata and current version
just ps                        # List running ghidra-mcp containers
just logs <port>               # View container logs
just stop <port>               # Graceful shutdown
just resume /tmp/my-run <port> # Reopen existing project and version history
just wui <port>                # Open the standalone viewer for this server
```

The [standalone WUI](wui/index.html) reads the server's REST and event APIs. To open it from disk, set `GHIDRA_MCP_CORS_ORIGIN=null` when you start the container with `just run` or `just resume`. If you host the WUI separately over HTTP, set the server's allowed origin to the WUI's scheme, hostname, and port. Enter the target server's port, base URL, or MCP endpoint URL in the WUI. If you configured tokens, enter the read token there.

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
| `--binary <path>` | — | Target binary. If the work directory already contains a project, the binary must match it. |
| `--work-dir <path>` | — | Run directory for `ghidra-project/`, `history.sqlite`, and `ready.json`. |
| `--cache-dir <path>` | `GHIDRA_MCP_CACHE_DIR` | Directory for analyzed `.gpr` templates keyed by binary SHA-256. |
| `--no-cache` | — | Disable the SHA-256 project cache. |
| `--host <addr>` | `GHIDRA_MCP_HOST` | Bind address (default `127.0.0.1`; `0.0.0.0` in container). |
| `--port <num>` | `GHIDRA_MCP_PORT` | HTTP port (`0` for ephemeral, default `8765`). |
| `--public-url <url>` | `GHIDRA_MCP_PUBLIC_URL` | Base URL advertised in `ready.json` and `/api/v1/status`. |
| `--decompiler-pool <n>` | — | Concurrent `DecompInterface` worker count (default `2`). |
| `--cors-origin <origin>` | `GHIDRA_MCP_CORS_ORIGIN` | Adds one allowed browser origin. Use `null` if you deliberately open the viewer as a local file. |
| `--rw-token <token>` | `GHIDRA_MCP_RW_TOKEN` | Bearer token for write endpoints, shutdown, and read endpoints. |
| `--ro-token <token>` | `GHIDRA_MCP_RO_TOKEN` | Bearer token for `/mcp/ro` and the REST inspection and event endpoints. |

When either token is configured, inspection routes require a bearer token and write routes require the write token. You can leave both unset for trusted local use. The standalone WUI requires an allowed browser origin.

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
