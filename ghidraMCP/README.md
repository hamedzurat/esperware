# ghidraMCP

A Java Ghidra extension that exposes the approved contract v1 over MCP stdio. The MCP process is the Ghidra process: one running Ghidra instance owns one selected project program and its persistent decompiler. It does not reimport a binary for each call.

## Build

Use Ghidra 12.2 and Java 25. Ghidra 12.2 requires JDK 25. The project compiles against the Ghidra API installed at `GHIDRA_INSTALL_DIR`.

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew extensionZip
```

The output is `build/distributions/ghidraMCP-0.1.0.zip`. Install it through **File → Install Extensions**, restart Ghidra, and enable the `GhidraMCPPlugin` in the CodeBrowser tool configuration. Then configure the MCP client to launch Ghidra through `launch-mcp.sh`; do not connect a second stdio server to an already-running GUI process.

Set `GHIDRA_INSTALL_DIR` before starting the MCP client. `program_session(open)` takes the project-relative program path. Hypothesis events are stored in `~/.ghidra/ghidraMCP/hypotheses.sqlite` by default; `GHIDRA_MCP_STORE` overrides that path.

## Contract

The server exposes exactly five MCP tools: `program_session`, `inspect_function`, `edit_function`, `save_program`, and `revert_last_edit`. Hypothesis events are an internal Java store interface for the trusted harness; there are no student-callable hypothesis tools.

All requests use `contract_version: 1`. Open-program operations carry the session id, generation, and expected revision. Function addresses are entry addresses. Variable references are valid only at the inspection revision that created them. After mutation, inspect again before using variable references.

An edit commits in one Ghidra transaction before cache flush and decompilation. The response separates `edit_status` from `decompile_status`; never repeat a committed edit because the decompilation timed out. Save does not advance revision. Revert is limited to the latest eligible edit.

## Local probes

The real-runtime fixture workflow is documented in `docs/runtime-probes.md`. The supported Ghidra version, save/reopen, analysis stability, GUI concurrency, and project portability are not considered accepted until those probes pass on the target installation.

## MCP client configuration

Configure your MCP host to run `launch-mcp.sh` with `GHIDRA_INSTALL_DIR` set to the extracted Ghidra 12.2 directory. The host owns the launched process and its stdio connection. Ghidra opens its project UI; use that same instance for the selected project. A second MCP process cannot attach to an already-running Ghidra GUI process.
