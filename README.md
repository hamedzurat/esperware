# Esperware

Headless Ghidra 12.2 MCP server with versioned edits, read-only subagent endpoints, and a SvelteKit WebUI.

## Repository layout

- `justfile`: shortcut commands to run, inspect, and stop binary containers and serve the WebUI.
- `ghidraMCP/`: headless Java Ghidra server, container build, and JUnit 5 test suite. See [the architecture notes](ghidraMCP/README.md) for internals.
- `wui/`: SvelteKit static WebUI for version scrubbing, unified diffs, function inspection, symbol and type lookup, code search, and memory dumps.
- `artifacts/`: C/C++ sources under `codes/` and a `justfile` that builds them with several compiler profiles into stripped and unstripped ELF binaries under `artifacts/build/dataset/`.

## Build test binaries

Put each program's `.c`/`.cpp` files in `artifacts/codes/<name>/`; all files in one directory are linked into one binary. Then build:

```sh
just artifacts
```

Each program is built into `artifacts/build/dataset/<name>/<profile>.unstripped.elf` (with DWARF) and `<profile>.stripped.elf`, and recorded in `build/dataset/manifest.jsonl`. Compiler profiles live in `artifacts/profiles.toml`; `artifacts/dataset.toml` sets which profiles each program gets.

Inside `artifacts/`, `just dataset --all` builds every profile, `just dataset <profile>...` builds named ones, `-p <glob>` limits the programs, and `just clean` removes `artifacts/build/`.

## Quickstart with containers

Build the container image once:

```sh
just image
```

The build runs the unit and end-to-end tests. If any test fails, it produces no new image.

Start a server with a binary. Install Python 3 and `jq` to use `just run` and `just resume`. `just run` tries ports above `32000` and prints the port when the server is ready. Use a different state directory for each running server.

```sh
just run ./artifacts/build/dataset/test/gcc-O1-noinline.stripped.elf
```

By default, `just run` stores the project and SQLite history in `/tmp/esperware-<time>-readability-fixture.stripped/run`. It stores the SHA-256 baseline cache in the matching `cache` directory. Pass a directory as the second argument to choose a different state directory:

```sh
just run ./artifacts/build/dataset/test/gcc-O1-noinline.stripped.elf /tmp/my-run
```

The readiness output contains the server endpoints. Each run gets its own port and container name, so you can run multiple binaries at once. Use the reported port with the management commands:

```sh
just status <port>             # Query live binary metadata and current version
just ps                        # List running ghidra-mcp containers
just logs <port>               # View container logs
just stop <port>               # Graceful shutdown
just resume /tmp/my-run <port> # Reopen existing project and version history
just wui [port] [ui_port]      # Serve the WebUI and print its URL for <port>, default UI port 4173
just dump test                 # Export every built binary for the test program
just dump ./artifacts/build/dataset/test/gcc-O1-noinline.unstripped.elf  # Export one binary
```

`just dump` writes each initial snapshot to `.tmp/<program>/<profile>/<stripped|unstripped>/`, with combined container output in the matching `.txt` file. It includes both variants when a program name is given, runs up to 16 binaries in parallel, and prints progress as jobs finish. A unique binary filename also works. Existing output or log files are not overwritten; move them elsewhere before dumping that binary again.

To export from a running server, send `POST /api/v1/export`. The server writes to `<work-dir>/code/v<current_version>/`. If tokens are configured, use the write token.

Install Bun to run `just wui`. The [WebUI](wui/) is a SvelteKit static app that connects directly to the server's REST and SSE endpoints. Run `just wui [port] [ui_port]` to build `wui/` if needed, serve it at `http://127.0.0.1:4173`, and print the URL. If that UI port is already serving, `just wui <port>` prints the URL for that server so you can open it in another tab.

Each tab stores its server target and view state in URL query parameters such as `port`, `api`, `tab`, and `fn`. Reloading restores the active view. Use the footer server switcher to change targets or open another server in a new tab. Because `just run` and `just resume` default `GHIDRA_MCP_CORS_ORIGIN` to `loopback`, the local WebUI connects without extra flags. If you host the WebUI on a different origin, set `GHIDRA_MCP_CORS_ORIGIN` when you start the container. Enter a server port, base URL, or MCP URL in the UI. Add a read or write bearer token if the server requires tokens.

Pass `CONTAINER_ENGINE=docker` before any `just` command to use Docker instead of Podman.

## Run locally without a container

Requires JDK 25 and Ghidra 12.2 (`GHIDRA_INSTALL_DIR` or `ghidraMCP/.local/ghidra_12.2_PUBLIC`):

```sh
cd ghidraMCP
just build
./bin/ghidra-mcp \
	--binary ../artifacts/build/dataset/test/gcc-O1-noinline.stripped.elf \
	--work-dir /tmp/run-01 \
	--cache-dir /tmp/ghidra-cache \
	--port 0
```

Passing `--port 0` binds a free ephemeral port and writes the chosen port into `ready.json`. Do not use directory names starting with `.` inside `--work-dir`, because Ghidra rejects dot-prefixed project paths.

## Server options

| Flag | Environment variable | Purpose |
|---|---|---|
| `--binary <path>` | — | Target binary. If the work directory already contains a project, the binary must match it. |
| `--work-dir <path>` | — | Run directory for `ghidra-project/`, `history.sqlite`, `ready.json`, and `code/v<N>/`. |
| `--dump` | — | Export `<work-dir>/code/v<N>/` pseudocode and metadata once, print JSON summary, and exit without starting HTTP/MCP. |
| `--cache-dir <path>` | `GHIDRA_MCP_CACHE_DIR` | Directory for analyzed `.gpr` templates keyed by binary SHA-256. |
| `--no-cache` | — | Disable the SHA-256 project cache. |
| `--host <addr>` | `GHIDRA_MCP_HOST` | Bind address (default `127.0.0.1`; `0.0.0.0` in container). |
| `--port <num>` | `GHIDRA_MCP_PORT` | HTTP port (`0` for ephemeral, default `8765`). |
| `--public-url <url>` | `GHIDRA_MCP_PUBLIC_URL` | Base URL advertised in `ready.json` and `/api/v1/status`. |
| `--decompiler-pool <n>` | — | Concurrent `DecompInterface` worker count (default `2`). |
| `--cors-origin <origin>` | `GHIDRA_MCP_CORS_ORIGIN` | Sets allowed browser origins. Accepts one exact origin, `loopback` for any HTTP or HTTPS origin on `127.0.0.1`, `localhost`, or `[::1]`, or `null`. Rejects `*`. Unset by default in `ghidra-mcp`, and defaults to `loopback` in `just run` and `just resume`. |
| `--rw-token <token>` | `GHIDRA_MCP_RW_TOKEN` | Bearer token for write endpoints, shutdown, and read endpoints. |
| `--ro-token <token>` | `GHIDRA_MCP_RO_TOKEN` | Bearer token for `/mcp/ro` and the REST inspection and event endpoints. |

When either token is configured, inspection routes require a bearer token and write routes require the write token. You can leave both unset for trusted local use. The WebUI requires an allowed browser origin.

## MCP tools

Read-only tools on `/mcp/ro` and `/mcp/rw`: `program_info`, `list_functions`, `list_symbols`, `decompile`, `disassemble`, `get_xrefs`, `read_memory`, `search_code`, and `get_type`.

Write tools on `/mcp/rw` only: `apply_edits`, `define_type`, `revert`, and `save_checkpoint`.

## Build and test commands

Server unit and end-to-end tests use Java and JUnit 5:

```sh
just --list     # List top-level run and test commands
just test       # Fast Java unit tests for VersionStore and access control
just e2e        # Container E2E suite using Podman
just check      # Java unit tests and container E2E suite
```

Inside `ghidraMCP/`, run `just e2e-local` to execute the E2E suite against the local headless launcher without containers.

Run WebUI tests, checks, and builds inside `wui/` with Bun:

```sh
cd wui
bun test        # Unit tests for API, SSE, address, and URL helpers
bun run check   # ESLint and svelte-check type checking
bun run build   # Build the static bundle into wui/build/
bun run dev     # Start the Vite dev server with hot reload
```
