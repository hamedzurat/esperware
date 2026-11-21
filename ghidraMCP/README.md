# ghidraMCP

Standalone **headless** Ghidra 12.2 MCP server (no Swing GUI, no `Xvfb`). One container/process owns one binary and serves:

- `/mcp/rw` — Streamable HTTP MCP for the primary read-write agent (**13 tools**: 9 read + 4 write)
- `/mcp/ro` — Streamable HTTP MCP for read-only subagents (**9 read tools only**; writes hidden and blocked in service layer)
- `/api/v1/*` — Simple REST + SSE API for version history and diffs
- `/` — Simple WebUI served from [`../wui/index.html`](../wui/index.html)

## Run with Docker / Podman (Recommended)

Build the container image from the repository root:

```sh
podman build -t ghidra-mcp:local -f ghidraMCP/Dockerfile .
```

Start one server on a target binary and mount a data directory for persistent project state, SQLite version history, and SHA-256 analysis cache:

```sh
podman run --rm -d \
  -p 127.0.0.1:8765:8765 \
  -v /path/to/data:/data \
  ghidra-mcp:local \
  --binary /data/target.elf \
  --work-dir /data/run-01 \
  --cache-dir /data/cache
```

Check `/path/to/data/run-01/ready.json` (or `GET http://127.0.0.1:8765/api/v1/status`):

- WebUI: `http://127.0.0.1:8765/`
- Main agent (RW): `http://127.0.0.1:8765/mcp/rw`
- Subagents (RO): `http://127.0.0.1:8765/mcp/ro`

Restarting on `--work-dir /data/run-01` resumes from the existing project and SQLite version history. Stop cleanly with `SIGTERM` or `POST /api/v1/shutdown`.

## Local Build & Run

Requires JDK 25 and Ghidra 12.2 (`GHIDRA_INSTALL_DIR`, or `.local/ghidra_12.2_PUBLIC`):

```sh
./gradlew stageServer
./bin/ghidra-mcp --binary /path/to/target.elf --work-dir /tmp/run-01 --cache-dir /tmp/ghidra-cache --port 0
```

Optional flags/env: `--host` (`GHIDRA_MCP_HOST`), `--port` (`GHIDRA_MCP_PORT`, default `8765`), `--public-url` (`GHIDRA_MCP_PUBLIC_URL`), `--no-cache`, `--decompiler-pool <n>`, `--webui-dir` (`GHIDRA_MCP_WEBUI_DIR`), `--cors-origin` (`GHIDRA_MCP_CORS_ORIGIN`), `--rw-token` (`GHIDRA_MCP_RW_TOKEN`), `--ro-token` (`GHIDRA_MCP_RO_TOKEN`).

## Tests (Pure Java JUnit 5)

```sh
./gradlew test                        # Fast unit tests (VersionStore + access control)
./gradlew e2eTest                     # Full container E2E test (Podman by default)
./gradlew e2eTest -De2e.engine=docker # Same E2E test with Docker
./gradlew e2eTest -De2e.mode=local    # Local headless binary E2E test
```

## MCP Tools

**Read-only (9 — `/mcp/ro` and `/mcp/rw`):**
`program_info`, `list_functions`, `list_symbols`, `decompile`, `disassemble`, `get_xrefs`, `read_memory`, `search_code`, `get_type`

**Write (4 — `/mcp/rw` only):**
`apply_edits` (atomic batch of renames/types/signatures/comments with `expected_version`), `define_type` (C declaration parser), `revert` (multi-step rollback via stored inverse ops), `save_checkpoint`

## WebUI & REST API

- `GET /api/v1/health` — `analyzing | ready | error`
- `GET /api/v1/status` — binary metadata, `version`, MCP URLs
- `GET /api/v1/versions` — lightweight step timeline (`v0..vN`)
- `GET /api/v1/versions/{v}` — step ops, before/after pseudocode, unified diffs
- `GET /api/v1/diff?from=0&to=N[&function=...]` — cumulative diff across stages
- `GET /api/v1/functions` & `GET /api/v1/functions/{addr}` — live function list and decompiled C
- `GET /api/v1/events` — SSE stream (`status`, `version_created`, `checkpoint_saved`)
- `POST /api/v1/shutdown` — graceful shutdown
