# Runtime probe report — 2026-11-10

Environment: Ghidra 12.2 PUBLIC, Temurin 25.0.5+8, Linux x86-64.

## Pseudocode tool handler probe

- Rebuilt `readability-fixture.elf` with a referenced two-field global state and created `/Probe/ProbeState` on that global in a disposable Ghidra project.
- Ran `RuntimeMcpToolsProbe.java` against the current extension JAR and a real headless Ghidra program. Pseudocode search found the function using `probe_state`; type search returned both struct fields at offsets 0 and 4; inspection returned the global reference and `/Probe/ProbeState` path.
- Renamed the global, verified the name in the refreshed inspection/pseudocode, and reverted it. Changed its type from the 8-byte struct to `uint`, then reverted it. Changed and reverted its comment. All edits committed and decompilation completed; the final inspection restored the original name, struct type, and comment.
- The type-revert probe exposed a bug: the revert compared the original struct size to the scalar's smaller current size. The implementation now records the original data extent and uses it when restoring the type. The probe passes with this fix.
- This probe invokes the Ghidra service handlers directly. It does not verify MCP JSON-RPC tool discovery/calls over stdio; that transport probe remains open.

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
That first MCP pass hit the fixture's startup stub. A second pass targeted the
actual C `transform` function at `0040116d`. Initial pseudocode was:

```c
void FUN_0040116d(uint param_1,int param_2)
{
  uint local_c;

  local_c = FUN_00401129(param_1,param_2);
  if ((local_c & 3) == 0) {
    local_c = local_c + param_2;
  }
  else {
    local_c = local_c ^ param_1 >> 3;
  }
  FUN_00401129(local_c,param_1);
  return;
}
```

The function rename to `transform_for_agent` committed as edit
`e-d4ca9bfa-7ab8-4bd5-a0d6-9fd924bcba05` (revision 3 → 4; decompilation
complete). Reinspection returned the fresh variable ref `v:49:4`. The local
rename to `transformed_state` committed as edit
`e-30c41dd7-282f-40ec-afc4-c53607615c75` (revision 4 → 6; decompilation
complete). Final pseudocode was:

```c
void transform_for_agent(uint param_1,int param_2)
{
  uint transformed_state;

  transformed_state = FUN_00401129(param_1,param_2);
  if ((transformed_state & 3) == 0) {
    transformed_state = transformed_state + param_2;
  }
  else {
    transformed_state = transformed_state ^ param_1 >> 3;
  }
  FUN_00401129(transformed_state,param_1);
  return;
}
```

The MCP session did not save this program.

- `./gradlew clean test extensionZip` passed, including hypothesis event-store
  history/withdrawal tests and extension packaging.

## Still required

The following have not yet been verified through MCP calls: paging, stale
revision/reference rejection, revert eligibility, GUI concurrency, forced
decompile timeout recovery, project portability, and internal hypothesis
events through the Ghidra service.

Do not treat Ghidra 12.2 as fully contract-accepted until those probes pass.
