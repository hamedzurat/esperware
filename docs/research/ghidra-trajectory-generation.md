# Token-efficient Ghidra trajectory generation

**Purpose.** Research background for issue #6, under the project map and decisions in [#1](https://github.com/hamedzurat/esperware/issues/1), [#3](https://github.com/hamedzurat/esperware/issues/3#issuecomment-6740152954), and [#5](https://github.com/hamedzurat/esperware/issues/5#issuecomment-6740897052). The later resolution in #6 supersedes this report's tentative source-aware-actor recommendation; the sources below are methodological precedents, not evidence that this exact workflow is optimal.

## Final decision recorded in issue #6

Use a **source-blind actor plus a private source-aware oracle**. The actor's Ghidra workspace comes from a stripped, no-DWARF binary and exposes the same binary-derived MCP context/results as the student. The oracle uses matching source, mapping, and debug artifacts privately. The harness runs the actor's real calls and returns actual Ghidra results. Keep the whole program open; the user chooses scope and the harness splits broad requests into linked focused tasks. Train only on accepted binary-visible traces, with execution validity, semantic correctness, and evidence support reported separately.

Each user-launched batch has a configurable total-token ceiling; tasks have no fixed token cap. Checkpoint at the ceiling and continue in a later batch. Preserve informative evidence-backed recovery and safe partial/abstention outcomes; reject unsupported edits and regenerate traces with pointless repeats. The complete operational contract, hypothesis-event envelope, replay state, serialized examples, and sample report are in [issue #6](https://github.com/hamedzurat/esperware/issues/6).

## Earlier research recommendation (superseded where it conflicts)

Keep one complete program/build variant open, but do not serialize every source file or decompilation into each turn. Prepare the binary-derived program index for deployment-equivalent task splitting. The source-blind actor chooses calls through the shared MCP, observes actual results, and decides whether to continue, repair, or stop. The private source-aware oracle checks the finished trajectory. Keep the full trace and provenance for audit, then emit only the accepted binary-visible SFT projection.

Use a staged corpus plan: begin with diverse projects, languages/toolchains, optimization classes, and binary task types; validate; expand where accepted, nonredundant examples add coverage. Each user-launched batch has a configurable total-token ceiling; tasks have no fixed token ceiling. Checkpoint at the batch ceiling and continue in a later batch. Stop a task when complete, evidence cannot support a safe action, state recovery fails, a repeated state cycle appears, or no useful next step remains.

This mix is an inference from the map’s requirements and cited methods: interactive trajectories teach the actual MCP protocol, while scripted references, selective verification, and staged sampling reduce teacher-generated volume and repeated context. No published result establishes an optimal recipe for this exact Ghidra task; report measured tradeoffs on this corpus.

## Strategy comparison

| Strategy | Teacher-token cost | Strength | Main failure mode / role here |
|---|---:|---|---|
| Teacher live-tool trajectories | Highest per accepted episode: repeated model turns plus tool feedback | Real action-observation sequences teach when/how to inspect, edit, recover, and stop; matches the approved MCP contract. ReAct is a relevant precedent. | Repeated large context and tool outputs; teacher errors remain possible. Use for diverse seed coverage and uncertain/high-value cases. |
| Scripted/reference trajectories | Low teacher cost; mostly deterministic harness/storage cost | Cheaply cover canonical API mechanics, revision errors, pagination, timeout recovery, save/revert, and stable transformations. | A fixed call list cannot react to live results and may teach brittle or unjustified actions. Use as protocol references and prompts, not as teacher-chosen interactive episodes. |
| Teacher critique/repair | Moderate added cost on flagged candidates | Can reject source-only claims and repair grounded conclusions; Self-Refine studies iterative feedback in other tasks. | Extra inference may repeat context; critic can share generator blind spots. Use narrow, evidence-packed review on suspicious/high-impact samples and preserve both versions. |
| Student/cheap-model proposals + teacher verification | Low proposal cost; bounded teacher verification cost | Pilot uncertainty, failure, or disagreement can nominate likely gaps; teacher verifies/corrects selectively. | Self-selection bias misses gaps the student does not detect; cheap proposals may be noisy. Retain random coverage and held-out audits. |
| Active/selective sampling | Saves teacher tokens by targeting undercovered or uncertain strata | Select by project/language/compiler/optimization/mapping status, task/tool path, novelty, and pilot-model failure. Targeted data selection is a precedent, not a validated score for this task. | Poorly calibrated uncertainty/novelty can over-sample odd cases and under-sample routine correctness. Preserve stratified random samples. |
| Staged corpus and variant coverage | Avoids full-matrix generation before quality is known | Build a broad, small first tranche; assess accepted-token yield and coverage; expand selected strata. Issue #5 retains useful build variants and project-grouped splits. | Early stopping can leave rare strata thin. Track uncovered cells; keep all variants of a project in one split. |

Primary method references: [ReAct](https://arxiv.org/abs/2210.03629) studies interleaved reasoning and actions; [Toolformer](https://arxiv.org/abs/2302.04761) studies generated API selection/timing/arguments and filtering; [Self-Instruct](https://arxiv.org/abs/2212.10560) filters invalid and similar synthetic examples; [Self-Refine](https://arxiv.org/abs/2303.17651) uses iterative feedback/refinement; [LESS](https://arxiv.org/abs/2402.04333) selects data for target capabilities. These are methodological precedents, not direct evidence that a particular Ghidra workflow wins.

## Proposed pipeline

1. **Build a program-level manifest once.** Key the run by project/revision, build-variant ID, binary/source hashes, compiler/toolchain/settings, Ghidra version/configuration, and persistent project/session. Store artifacts by content hash and provenance in PostgreSQL, per issue #5.

2. **Prepare privileged mapping and a compact index.** Use build metadata and external DWARF where available to map source function IDs/ranges/inline relationships to analyzed function entry addresses. Record mapped, ambiguous, unmapped, and transformed/many-to-many outcomes with confidence and evidence. Do not force one-to-one matches when optimization inlines, splits, merges, or removes functions. Ghidra documents external DWARF for ELF binaries; source identity remains a build-sidecar/oracle relation, not student evidence. See [Ghidra DWARFProgram](https://ghidra.re/ghidra_docs/api/ghidra/app/util/bin/format/dwarf/DWARFProgram.html) and [Ghidra external DWARF package](https://ghidra.re/ghidra_docs/api/ghidra/app/util/bin/format/dwarf/external/package-summary.html).

3. **Select a program-wide coverage plan.** Select candidates by strata, not raw function count. Link repeated instances of the same source-function identity. Deduplicate exact identical binaries/initial evidence/targets before spending teacher tokens; retain nonidentical compiler/optimization variants only when they add meaningful binary or trajectory evidence. Do not use pseudocode similarity alone to delete examples. Keep all variants of a project in a single project-level split, following #5.

4. **Pack context once, retrieve incrementally.** Give the actor a compact binary-derived program map and task goal. Keep source/mapping/debug artifacts in the separate oracle workspace, inaccessible to the actor. Start with relevant pseudocode/signature and deployment-available task context; retrieve additional callers/callees/xrefs through MCP only as needed. Cache immutable build metadata and unchanged Ghidra outputs by revision; after mutation, invalidate affected evidence and refresh references because #3 makes variable references revision-bound. The actor can navigate the whole persistent program.

5. **Run actual interaction, not a guessed call list.** Teacher chooses a real MCP call; harness executes it and returns actual output before the next choice. Keep messages faithful to the student interface. Stop when complete or when a justified blocker remains; allow useful correction/revert sequences. Record usage at program, batch, and corpus level. No fixed per-example token/call/time allowance is needed.

6. **Apply cheap deterministic checks to every episode.** Validate schema/version; session/generation/revision sequencing; actual call/result correspondence; stale-reference handling; edit/decompile status separation; save/revert legality; absence of source/debug/mapping fields in student data; and evidence-reference validity. Reject fabricated calls/results, malformed sequences, unsupported claims, or corrupted checkpoints. Resume from durable checkpoints without replaying committed edits.

7. **Review selectively.** Deterministic checks handle protocol/state validity. At task end, a private source-aware oracle checks semantic truth and a separate source-blind reviewer checks support using only the student projection. Review flagged cases such as ambiguous mappings, optimized-away functions, unsupported type/signature claims, contradictory evidence, unusual recovery chains, and repetitive traces. Human review samples accepted episodes and inspects unresolved/high-impact disagreements, not every item. Model critique alone cannot prove semantic correctness.

8. **Project student-visible SFT data.** Persist linked records: (A) privileged generation/audit record; (B) derived student transcript. Exclude source, DWARF/debug artifacts, mapping IDs/confidence, oracle verdicts, selection scores, private critique, and source-dependent names/explanations from (B). Include only a binary-only task prompt, permitted pseudocode/signature/callers/callees/xrefs, actual MCP calls/results and revision-safe recovery, and final claims/actions supported by visible observations. Include failed attempts only when their failure is visible and teaches safe recovery; exclude unobservable teacher deliberation. Descriptive names are acceptable if binary context supports them; exact source-name imitation is not the objective, per #1.

9. **Expand by accepted yield and coverage.** After the first tranche, prioritize undercovered strata and pilot-student failures while reserving random exploration. Add build variants when mapping or trajectories change meaningfully; otherwise retain provenance without adding duplicate SFT weight. Spend remaining global teacher tokens on underrepresented strata or verification before near-duplicates. This is a corpus-level allocation rule, not a preset episode budget.

## What to measure

Report by project, language, compiler/toolchain, optimization, and mapping status:

- **Teacher budget:** provider-reported input/output tokens cumulatively; tokens per raw episode, accepted episode, accepted SFT token, and distinct covered source-function/variant stratum. Do not invent prices; report actual billing only if available.
- **Yield:** raw, mechanically valid, reviewed, accepted, repaired, rejected, unresolved counts; rejection reason; accepted student-visible tokens per teacher token.
- **Trajectory efficiency:** MCP calls, unique functions inspected, output size/tokens, repeated-context fraction, cache hit rate, truncation/pagination, edits, redecompiles, recovery attempts, and stop reason.
- **Evidence quality:** fraction of claims/actions supported by student-visible evidence; source/oracle leakage rate (target zero); mapping coverage/ambiguity by optimization/compiler; reviewer agreement and sampled false-accept/false-reject estimates.
- **Redundancy and coverage:** exact duplicate rate; near-duplicate rate for review (not automatic deletion); distinct project/function/variant strata; useful accepted examples per stratum; project isolation across train/validation/holdout.
- **Outcome:** later, on project-disjoint evaluation, task success/correctness, unsupported-action/error rates, safe recovery, and performance per matched student-visible context/tool budget against base model and teacher. Report correctness separately from readability.

These metrics distinguish savings from improved accepted-evidence yield versus merely fewer examples, without assuming a token price.

## Limits

Source mapping is not semantic proof, teacher self-critique is not independent ground truth, and model uncertainty/novelty may be miscalibrated. Use build/source sidecars to check identity and behavior, but accept student targets only when support is recoverable from binary-visible evidence. The strategy and stopping rule are design inferences; test them on a deliberately diverse pilot before committing the global teacher-token budget.
