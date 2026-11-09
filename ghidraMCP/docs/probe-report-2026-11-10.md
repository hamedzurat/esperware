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
- `./gradlew clean test extensionZip` passed, including hypothesis event-store
  history/withdrawal tests and extension packaging.

## Still required

These are direct Ghidra runtime checks, not MCP protocol calls. The following
have not yet been verified through the public MCP interface: exact tool
listing, inspection and paging, stale revision/reference rejection, edit and
revert eligibility, GUI concurrency, forced decompile timeout recovery,
project portability, and internal hypothesis events through the Ghidra service.

Do not treat Ghidra 12.2 as fully contract-accepted until those probes pass.
