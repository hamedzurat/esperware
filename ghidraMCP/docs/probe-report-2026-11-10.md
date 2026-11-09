# Runtime probe report — 2026-11-10

Environment: Ghidra 12.2 PUBLIC, Temurin 25.0.5+8, Linux x86-64.

## Completed

- Built the stripped fixture with `fixtures/build-fixture.sh`.
- Imported the fixture into a local Ghidra project and completed Ghidra analysis.
- Ran `fixtures/RuntimeProbe.java` against the analyzed project. `DecompInterface`
  opened the live program and decompiled `_DT_INIT` at `00401000`; the result
  contained 144 pseudocode characters.
- Ran `RuntimeEditProbe.java` in an isolated project. Ghidra committed a
  function rename, local-variable rename, function and variable comments, and a
  local type change to `uint`; the modification number advanced and the edited
  function decompiled to 462 characters.
- Reopened that project in a second headless Ghidra process. The function name,
  variable name, and type survived Ghidra's save and reopen.
- Started the foreground Ghidra launcher. Captured stdout was empty, leaving it
  available for MCP JSON-RPC; Ghidra startup logs went to stderr.
- Ran an isolated `gpt-6-luna` Codex CLI session with `--ignore-user-config`,
  ephemeral command-line MCP overrides, and a headless Ghidra stdio bridge. The
  agent discovered exactly five MCP tools: `program_session`,
  `inspect_function`, `edit_function`, `save_program`, and `revert_last_edit`.
  It opened the fixture, inspected `00401020`, renamed the function and its
  local variable, and reinspected the pseudocode. No system or project Codex
  settings were changed.

The MCP session opened `mcp_probe_function` at revision 3. Its initial
pseudocode included a `uint mcp_probe_variable` local. The function rename to
`transform_for_agent` committed as edit `e-ecab8058-ecce-456f-ae94-522b62b883bf`
at revision 4. Reinspection returned fresh variable reference `v:50:4`. The
variable rename to `input_state` committed as edit
`e-438eefd7-3a72-49e2-88c7-7d8116caa8ff` at revision 6, with decompilation
complete. Final pseudocode retained the body and showed the renamed function
and local. The MCP session did not save the program.
- `./gradlew clean test extensionZip` passed, including hypothesis event-store
  history/withdrawal tests and extension packaging.

## Still required

The following have not yet been verified through MCP calls: paging, stale
revision/reference rejection, revert eligibility, GUI concurrency, forced
decompile timeout recovery, project portability, and internal hypothesis
events through the Ghidra service.

Do not treat Ghidra 12.2 as fully contract-accepted until those probes pass.
