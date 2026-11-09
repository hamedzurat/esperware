# Runtime probes

These checks must run against the installed Ghidra runtime and a real project. API compilation is not evidence that the Ghidra behavior is accepted.

## Fixture

Build a source-blind Linux x86-64 fixture:

```sh
./fixtures/build-fixture.sh
```

Run Ghidra's real analysis and decompiler against the fixture:

```sh
GHIDRA_INSTALL_DIR="$PWD/.local/ghidra_12.2_PUBLIC"
JAVA_HOME="$PWD/.local/jdk25" PATH="$PWD/.local/jdk25/bin:$PATH" \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PWD/build/ghidra-projects" FixtureProbe \
  -import "$PWD/build/fixtures/readability-fixture.elf" -overwrite \
  -scriptPath "$PWD/fixtures" -postScript RuntimeProbe.java
```

Exercise Ghidra's function/variable rename, comment, type, decompile, save, and
reopen behavior in a separate project:

```sh
GHIDRA_INSTALL_DIR="$PWD/.local/ghidra_12.2_PUBLIC"
JAVA_HOME="$PWD/.local/jdk25" PATH="$PWD/.local/jdk25/bin:$PATH" \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PWD/build/ghidra-edit-probe" EditProbe \
  -import "$PWD/build/fixtures/readability-fixture.elf" -overwrite \
  -scriptPath "$PWD/fixtures" -postScript RuntimeEditProbe.java
JAVA_HOME="$PWD/.local/jdk25" PATH="$PWD/.local/jdk25/bin:$PATH" \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PWD/build/ghidra-edit-probe" EditProbe \
  -process readability-fixture.elf -noanalysis \
  -scriptPath "$PWD/fixtures" -postScript RuntimeReopenProbe.java
```

Import `build/fixtures/readability-fixture.elf` into a fresh local Ghidra project, run analysis to completion, and open it in CodeBrowser. Keep the source file outside the project and use the stripped ELF for all MCP calls.

## Required probes

1. Confirm the MCP tool list contains exactly the five contract-v1 tools. Open the fixture by its project-relative path and inspect one function. Record the active caps, Ghidra version, JDK version, and decompilation outcome.
2. Rename a variable, then verify the returned edit is committed before decompilation status is reported. Reuse the prior variable reference and prior revision; both calls must be rejected without changing the program. Reinspect and verify the reference is revision-bound.
3. Exercise navigation and pseudocode cursors, save without a revision change, close/reopen the MCP session, then save/reopen the Ghidra project. Confirm a new generation/session is issued and old references fail.
4. Verify reverting the latest edit succeeds after save, while a later edit, GUI edit, undo, or redo invalidates eligibility. Confirm MCP edits and GUI edits serialize against the same program.
5. Force one decompilation timeout after a committed edit. Confirm the edit is not repeated, and a fresh inspection can recover. Copy the saved project to a second directory and reopen it to test project portability.
6. Through the internal `HypothesisEventStore` boundary, create and support a claim, link an edit, withdraw the claim, verify the dependent edit is flagged, restart the runtime, and verify history/snapshot reconstruction. Clear the flag only with independent evidence or explicit correction.

Record each result in a dated probe report before claiming a Ghidra version supported. A failed probe is a contract failure to fix, not a reason to silently change the cap or behavior.
