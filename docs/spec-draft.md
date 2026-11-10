## Problem Statement

Hard-to-read Ghidra pseudocode requires repeated inspection, annotation, type/signature experiments, and redecompilation. Users need a tool-using student that improves readability without introducing unsupported interpretations or changing the meaning represented by the analysis. Building this student requires reproducible live demonstrations, private correctness checks, durable evidence, and affordable local training rather than static source/pseudocode pairs alone.

## Solution

Keep a whole program open in a persistent Ghidra session. Let users request improvements to one function or a whole program; decompose broad requests into linked focused tasks. Execute the actor's real MCP calls, preserve their actual results, and retain only demonstrations that pass execution, semantic, and evidence-support checks. Train a student through QLoRA using deployment-equivalent binary-visible context. Begin locally on an RTX 5060 mobile with 8 GB VRAM, measure feasibility, and later compare the student with its base and a teacher using blinded readability judgments constrained by correctness.

## User Stories

1. As a user, I want clearer pseudocode, so that I can understand program behavior.
2. As a user, I want correctness to override readability, so that fluent annotations do not mislead me.
3. As a user, I want function-to-program scope, so that I can choose the size of a request.
4. As a user, I want persistent analysis, so that each call builds on previous work.
5. As an actor, I want actual tool results, so that my next action reflects the live program.
6. As a student, I want the same binary-visible interface used in generation, so that training transfers to deployment.
7. As a user, I want uncertain hypotheses identified explicitly, so that speculation remains distinguishable from evidence.
8. As a user, I want provenance and retained history, so that I can revisit interpretations.
9. As an actor, I want caller, callee, and reference inspection, so that I can investigate beyond the current function.
10. As an actor, I want bounded paginated responses, so that inspection fits available context.
11. As an actor, I want rename, comment, type, and signature edits, so that I can improve the analysis.
12. As an actor, I want separate edit and decompilation outcomes, so that I do not repeat committed mutations after a timeout.
13. As an actor, I want stale-state rejection, so that outdated references cannot silently target the wrong object.
14. As an actor, I want explicit last-edit revert, so that I can recover from a recent experiment.
15. As a user, I want dependent edits flagged after contradictions, so that cascading errors receive review.
16. As an operator, I want context resets reconstructed from durable state, so that long tasks retain evidence.
17. As an operator, I want saved accepted checkpoints, so that interrupted batches resume safely.
18. As an operator, I want a configurable batch token ceiling, so that I control generation expenditure.
19. As an operator, I want targeted and random review, so that automation reduces curation without hiding systematic errors.
20. As a corpus contributor, I want reproducible build provenance, so that binaries can be matched to private ground truth.
21. As a corpus maintainer, I want ambiguous mappings preserved as ambiguous, so that optimization does not create false labels.
22. As a researcher, I want project-separated splits, so that related builds do not contaminate evaluation.
23. As a trainer, I want faithful tool serialization and loss masking, so that the student learns actions rather than predicting tool replies.
24. As a trainer, I want informative recovery and safe abstention examples, so that the student learns when to correct or stop.
25. As an operator, I want measured local resource use, so that model and hardware choices follow evidence.
26. As a reviewer, I want blinded comparisons and separate human/LLM reports, so that readability evidence remains interpretable.

## Implementation Decisions

- Contract v1 has five tools: program_session (open/status/close), inspect_function, edit_function, save_program, and revert_last_edit. Do not expand illustrative ticket calls into new approved APIs.
- One persistent runtime owns an open program. Serialize mutations. Reconnection requires the runtime to remain alive; restart requires opening a new session and refreshing references.
- Requests include contract_version 1; open-program operations include session_id, generation, and expected_revision, with lifecycle exceptions. Revisions track live modification numbers, not durable snapshot identity. Reject stale revisions without mutation and report the current revision.
- Functions use entry addresses; variable references are revision-bound and must be resolved again after mutation. Reject ambiguous/stale references.
- Each edit is one transaction and one change. Commit independently of decompilation, flush the cache, and redecompile. Report committed edit identity/revision separately from complete/timed_out/failed decompilation. Never retry a committed edit merely because decompilation failed.
- Initial caps: one function per inspection, 50 navigation results per page, 16,000 pseudocode characters, and a 30-second decompilation timeout. Expose active caps and truncation/cursors. No project-wide MCP search is approved. Runtime probes may tune caps.
- Save committed changes without advancing revision; failed saves preserve live changes for retry. Revert only the latest eligible edit, as a new transaction/revision. Saving does not invalidate eligibility; intervening edits/undo/redo do.
- Record uncertain interpretations as Ghidra function comments through `edit_function`; preserve supporting evidence in the comment and distinguish uncertainty from established facts.
- Corpus: owned/buildable Linux x86-64 projects in C/C++/Rust/Odin/Zig. Use GCC and Clang where both build the source; record actual supported compiler/optimization settings elsewhere. Cover supported equivalents of optimization 0–3 through a bounded matrix, with no invented corpus count.
- Record project/revision, build variant, source-function, binary, analyzed-function identities; toolchains/settings, hashes, Ghidra version/configuration, initial pseudocode/references, project location, failures, and resumability. Store provenance in PostgreSQL and content-addressed artifacts separately.
- Retain private source/build/debug mapping with ranges, inline relationships, confidence and ambiguous/unmapped/transformed cases. Optimization may inline/split/merge/remove functions; never force one-to-one alignment.
- Actor projects come from stripped no-DWARF binaries. Source, mapping, debug artifacts and oracle feedback never enter actor/student prompts, results, or SFT targets. Deployment task decomposition/ranking must be reproducible without source.
- Keep useful distinct build variants linked to source-function identity; deduplicate byte-identical examples and control repeated-variant sampling. Pseudocode similarity alone cannot justify deletion. Keep every variant/version of a project in one split; generate training/validation trajectories only from their respective projects, never holdout projects.
- Start tasks from the latest accepted saved project snapshot. Record snapshot hash, committed edit IDs in order, project identity, contract version, and initial program revision. Restore creates fresh session/generation/references. Rejecting a parent invalidates descendants.
- Give the actor task scope, binary-derived index, initial pseudocode and Ghidra comments; retrieve additional evidence through real calls. Preserve exact call/result correspondence rather than fabricated or scripted teacher actions.
- Separate private audit records from student projections. Private records retain oracle checks, mapping/confidence, transcript, dependencies, lineage, retries and usage. Student projections contain deployment-visible context, assistant calls/events, actual results and completion/partial/abstention responses; exclude oracle verdicts, selection scores, privileged hints and private deliberation.
- Check protocol/state after every call. At task end independently report execution validity, private semantic correctness, and source-blind evidence support. Review all changed decompilations; use deterministic checks where possible and private adjudication where interpretation is needed. Select the independent evidence review model/provider during implementation/pilot.
- Reject unsupported or incorrect retained edits. Keep intact evidence-explained recovery traces only when their final state passes. Reject pointless repetitive traces wholesale; regenerate from accepted state without oracle-derived hints rather than deleting individual turns. Label supported partial and abstaining outcomes separately; quarantine uncertain matches/disagreements.
- Batches have configurable total teacher-token ceilings with input/output usage recorded. No fixed per-task call/time/token cap. At the ceiling finish/checkpoint the current real result, persist resumable state, and continue only in a later user-launched batch. Stop tasks at completion, insufficient evidence, repeated state cycles, failed recovery or no supported improvement.
- Reports include completed/accepted/rejected/flagged/failed counts; full/partial/abstention outcomes; independent gate statuses/reasons; attempts and tokens per accepted unique trajectory; retries/timeouts; coverage/gaps by project/language/compiler/optimization/task; duplicates, mapping ambiguity, provenance-linked review queue and next tranche. Review random accepted items plus suspicious edits and disagreements; report sampled false acceptance/rejection rather than claiming automated proof.
- Local candidate ladder: Qwen3.5-4B, then 2B, then 0.8B if necessary. Final selection remains empirical. Larger discussed models are not selected or assumed to fit.
- Starting QLoRA recipe: 4-bit NF4, gradient checkpointing, micro-batch 1, rank 16, alpha 32, dropout 0.05, supported attention/MLP projections with exact targets recorded. Preserve native tokenizer/chat template/tool interface. Measure stable context, VRAM and throughput.
- Train assistant-authored calls/events/final responses; tool results/errors are context with no loss. Include valid visible recovery, exclude malformed/unrecoverable targets. Segment at focused-task checkpoints carrying state; do not pack unrelated tasks/projects.
- Pin model revision, tokenizer/template, dataset/split snapshot, training code/libraries, configuration, seed, adapter and resource/quality reports. Verify checkpoint/resume and serialization in a short real-format smoke test.
- Consider a rented RTX 5090 32 GB only after measured local capacity/throughput or promising quality justifies it; compare generation on identical tasks. Provider, current prices and spending cap must be settled before rental.
- Later evaluation uses held-out projects, identical initial states, matched student/base tool/time budgets, and a separate generous teacher ceiling. Randomize/anonymize pairwise results, allow ties/cannot-determine, and enforce semantic correctness. Keep human and LLM judgments separate. Retain traces without requiring an exact action sequence or source spelling.

## Testing Decisions

- User-approved: test the public MCP contract against small real Ghidra fixtures, then use the task-to-accepted-checkpoint/SFT-export workflow as the main integration seam. No existing implementation or test suite supplies prior art in this checkout.
- Assert external behavior: persistent edits, revision rejection, refreshed references, pagination/truncation, timeout versus committed mutation, save failure/retry, last-edit eligibility, restart/reopen and serial mutation behavior. Avoid assertions about internal class structure or exact model call sequences.
- Check source/debug/oracle leakage, independent acceptance gates, actual call/result matching, ambiguous mapping quarantine, intact recovery, partial/abstention safety, rejected-parent invalidation and resumability at token ceilings.
- Validate split isolation, deduplication/provenance, loss masks, native tool serialization, checkpoint/resume and real-format local training feasibility. These are future implementation checks; this planning task runs no training or benchmark.
- Runtime probes must establish supported Ghidra versions, project portability, save/reopen behavior, analysis stability and GUI concurrency before claiming integration readiness.

## Out of Scope

- Binary patching, permanently.
- Implementation, production data generation, training runs, rentals and benchmark execution during this planning task.
- Initial support for arbitrary architectures, obfuscation, malware-specific workflows or unrestricted languages.
- Exact source-name reconstruction, unsupported source-derived student targets, arbitrary historical selective rollback, or assumed dataset/model readiness.

## Further Notes

- This specification synthesizes [map #1](https://github.com/hamedzurat/esperware/issues/1) and all bodies/resolution comments on issues #2–#8. The original tickets retain detailed contract examples, hypothesis lifecycle examples, serialized generation illustrations and the illustrative batch report: [runtime research #2](https://github.com/hamedzurat/esperware/issues/2), [MCP contract #3](https://github.com/hamedzurat/esperware/issues/3), [hypotheses #4](https://github.com/hamedzurat/esperware/issues/4), [corpus #5](https://github.com/hamedzurat/esperware/issues/5), [generation #6](https://github.com/hamedzurat/esperware/issues/6), [training #7](https://github.com/hamedzurat/esperware/issues/7), and [evaluation #8](https://github.com/hamedzurat/esperware/issues/8). These examples are supporting detail; illustrative payloads do not override the approved v1 contract. Explicit actor/oracle clarifications supersede earlier source-aware generator wording. PFTN has no supplied expansion.
- Ghidra APIs support a persistent integration but are not an official MCP. Separate headless invocations do not preserve the live runtime. API research is not installed-runtime validation.
- Ghidra-100K contains text pairs without reusable program artifacts. Decompile-Bench table/binary alignment, build provenance and per-origin rights remain unverified; its separate binary archive is substantial (advertised approximately 140 GB compressed/500 GB expanded). Dataset-card licenses do not clear upstream source rights. ExeBench preserves source licenses; AnghaBench licensing remains unresolved. No surveyed dataset supplies this MCP's executed trajectories.
- Open evaluation decisions: sampling, review unit/rubric, Elo calculation/uncertainty, disagreement and contaminated/ambiguous-case handling, numerical success targets and the meaning of approaching the teacher. Corpus sufficiency, runtime/version acceptance and detailed implementation slicing/launch order remain open.
- User-confirmed hardware progression: try trajectory generation and QLoRA on the RTX 5060 mobile 8 GB first, and extend only if measured results go well. Actor denotes a role, not a mandatory larger model: the initial actor may be a small local model. A larger teacher is an optional later progression and evaluation comparator.
- The user approved both testing boundaries after clarification. This specification records planning decisions; its ready-for-agent label does not authorize spending, production generation, training or benchmark execution. Explicitly deferred choices above must be resolved when their dependent implementation work is scoped.
