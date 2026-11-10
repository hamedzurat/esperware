# Ghidra Readability Training Pipeline

Terms for the persistent Ghidra MCP and its source-aware training workflow.

## Language

**Ghidra session**:
A live MCP-owned runtime bound to an open Ghidra project and program. The session is the scope for object references and revision checks.

**Program revision**:
A session-local version of a live Ghidra program that changes after committed edits, undo, or redo. A revision is used to reject operations based on stale program state and is not a durable identifier across reconnects.

**Edit experiment**:
A committed program mutation made to test a proposed interpretation. Under the agreed contract, explicit revert is limited to a safe last-in-first-out case.

**Hypothesis**:
An uncertain interpretation of a program's behavior or meaning. A hypothesis is distinct from established knowledge and should be supported by evidence that can be revisited.
