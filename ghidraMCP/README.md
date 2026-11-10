# ghidraMCP

A Java Ghidra extension that exposes the approved contract v1 over MCP stdio. The MCP process is the Ghidra process: one running Ghidra instance owns one selected project program and its persistent decompiler. It does not reimport a binary for each call.

## Build

Use Ghidra 12.2 and Java 25. Ghidra 12.2 requires JDK 25. The project compiles against the Ghidra API installed at `GHIDRA_INSTALL_DIR`.

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew extensionZip
```

The output is `build/distributions/ghidraMCP-0.1.0.zip`. Install it through **File → Install Extensions**, restart Ghidra, and enable the `GhidraMCPPlugin` in the CodeBrowser tool configuration. Then configure the MCP client to launch Ghidra through `launch-mcp.sh`; do not connect a second stdio server to an already-running GUI process.

Set `GHIDRA_INSTALL_DIR` before starting the MCP client. `program_session(open)` takes the project-relative program path.

## Docker

Build from the repository root and run the image as an MCP stdio process:

```sh
docker build -t ghidra-mcp:local -f ghidraMCP/Dockerfile .
docker run --rm -i -v ghidra-mcp-data:/data ghidra-mcp:local \
  /data/projects/MyProject.gpr:/program/path
```

The image builds the MCP extension from this source tree. It downloads the official Ghidra 12.2 runtime during the image build and verifies its SHA-256 checksum; it does not download a prebuilt MCP extension. The Dockerfile pins the runtime release and checksum. Ghidra itself can be built from source, but that requires its full Gradle source-build toolchain and substantially increases build time and complexity.

The image enables `GhidraMCPPlugin` in its CodeBrowser tool configuration. Pass Ghidra 12.2's `project.gpr:/project/path` argument so it opens the CodeBrowser tool and starts MCP. Mount persistent project storage at `/data`. The container uses Xvfb for Ghidra's UI runtime and keeps MCP JSON-RPC on stdin/stdout; logs go to stderr. Each container owns one Ghidra process and one stdio MCP connection.

Run the Docker integration test with `python3 -m unittest discover -s tests -v`. It builds `fixtures/readability-fixture.c`, imports it into a disposable container project, then initializes MCP over stdio and exercises all seven tools, including edit, save, revert, and close. Set `CONTAINER_ENGINE=docker` to use Docker instead of the default Podman engine.

## Contract

The server exposes seven MCP tools: `program_session`, `inspect_function`, `search_pseudocode`, `search_types`, `edit_function`, `save_program`, and `revert_last_edit`.

All requests use `contract_version: 1`. Open-program operations carry the session id, generation, and expected revision. Function addresses are entry addresses. Variable references are valid only at the inspection revision that created them. After mutation, inspect again before using variable references.

`inspect_function` includes referenced globals as well as local variables. Both expose revision-bound references: pass `variable_ref` or `global_ref` with the function entry address to `edit_function`. `search_pseudocode` searches function names, signatures, or decompiled text in bounded pages. `search_types` finds existing types by name or category path; structures and unions include field names, offsets, and field types. To apply a type, pass its Ghidra data type path (for example, `/mytypes/Player`) as the `type` change value. Global type changes update Ghidra's data-type listing and preserve comments; they do not write raw bytes, and are limited to fixed-size types no larger than the existing defined data.

To annotate pseudocode, call `edit_function` with target `{"kind":"function","function_address":"<entry>"}` and change `{"kind":"comment","value":"<your note>"}`. The comment replaces the existing function comment and appears above the function in refreshed pseudocode. Save the program to persist it. Variable and global comments are also supported on their respective targets.

An edit commits in one Ghidra transaction before cache flush and decompilation. The response separates `edit_status` from `decompile_status`; never repeat a committed edit because the decompilation timed out. Save does not advance revision. Revert is limited to the latest eligible edit.

## Local probes

The real-runtime fixture workflow is documented in `docs/runtime-probes.md`. The supported Ghidra version, save/reopen, analysis stability, GUI concurrency, and project portability are not considered accepted until those probes pass on the target installation.

## MCP client configuration

Configure your MCP host to run `launch-mcp.sh` with `GHIDRA_INSTALL_DIR` set to the extracted Ghidra 12.2 directory. The host owns the launched process and its stdio connection. Ghidra opens its project UI; use that same instance for the selected project. A second MCP process cannot attach to an already-running Ghidra GUI process.

## Edit history API

The running plugin records each committed MCP edit and revert in SQLite and serves
read-only JSON on `http://127.0.0.1:8765`. Each record contains the project and
program, session and revision, edit ID, operation, target/change (for edits), and
full before/after pseudocode. `before_status` and `after_status` identify failed
or timed-out decompilation; the corresponding code is absent when unavailable.
The database records changes from the time this version is installed. GUI edits,
analysis changes, and earlier edits are not recorded. A global edit can affect
other functions; the captured pseudocode is for the function supplied to MCP.

- `GET /api/v1/edits?after=0&limit=50` lists entries in ascending ID order.
  `after` is an exclusive ID cursor and `limit` is 1–100. Optional exact-match
  `project`, `program`, and `function_address` query parameters filter results.
  The response contains `edits` and `next_after`.
- `GET /api/v1/edits/{id}` returns one entry, or 404.

Set `GHIDRA_MCP_HISTORY_DB` to choose the database path (default:
`~/.ghidra/ghidraMCP/history.sqlite`; container default: `/data/history.sqlite`).
Set `GHIDRA_MCP_HISTORY_PORT` to change port 8765. The server binds to loopback
unless `GHIDRA_MCP_HISTORY_HOST` is set. For a container, publish a host-local
port and bind inside the container, for example add
`-e GHIDRA_MCP_HISTORY_HOST=0.0.0.0 -p 127.0.0.1:8765:8765` to `docker run`.
Persist `/data` to retain history. The API has no authentication; do not expose
it to untrusted networks. A browser UI on another origin needs a same-origin
backend proxy; the API does not grant cross-origin access.

Edit and revert responses include `history_status`. If it is `failed`, the Ghidra
edit still committed; do not retry the edit. Ghidra transactions and SQLite writes
are separate, so a crash between them can also leave a gap in history. Saving the
Ghidra project remains separate from recording history.
