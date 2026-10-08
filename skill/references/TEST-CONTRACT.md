# Plans, real invocations, and evidence

This page describes the implemented schema-1 workflow and versioned evidence
gates. Outcome, recovery, cancellation, scoring and comparison contracts are in
[EVALUATION-CONTRACT.md](EVALUATION-CONTRACT.md). Qualification and exact observed
scope are recorded separately in [VALIDATION.md](../VALIDATION.md).

## Plan schema 1

A reviewed JSON object accepts `schema`, `name`, `required_paths`, `protected_paths`,
`setup`, `agents`, and `checks`. At least one agent and one independent check are
mandatory. Up to eight agents and twenty checks are allowed. Unknown fields fail
validation. Relative paths may not escape via `..`, an absolute path, or backslash.

An agent stage accepts:

```json
{
  "name": "implementer",
  "cwd": ".",
  "prompt": "Read SPEC.md, implement the change, and run the real tests.",
  "tools": ["read", "bash", "edit", "write"],
  "require_tools": ["read", "bash"],
  "access": "rw",
  "timeout_seconds": 900,
  "max_turns": 24,
  "max_total_tokens": 500000
}
```

Use exactly one of `prompt` or `prompt_file`; the latter resolves relative to the
plan file, on the trusted parent. `access` is `ro` or `rw`. Allowed built-in tools
are `read`, `write`, `edit`, `bash`, `grep`, `find`, `ls`. A required tool must be in
the allowlist and must complete successfully at least once. Limits cannot be zero;
wall time is at most 3,600 seconds per agent, turns at most 100, and reported tokens
at most 10,000,000. Token accounting depends on provider reports; it is not a
billing guarantee. Wall-time/log/turn caps remain independent.

Setup and check stages accept `name`, `cwd`, `argv`, `timeout_seconds`, and
`network`. Use an argv array, not a shell string. An explicitly reviewed
`["bash", "-lc", "..."]` is possible but invokes a shell; do not interpolate
untrusted prompt text into it. `network` is `none` or `inherit`, with the latter
also requiring command-line parent consent. Commands are limited to 3,600 seconds.
The `.pi-lab` directory is reserved for runtime state.

`validate-plan` validates structure only; `run` additionally checks required paths
and starting directories in the staged project. Schema validity is not proof that
a test exists, discovers cases, asserts behavior, or uses the correct language
runtime. The parent must inspect those conditions.

## What a verified agent invocation requires

Pi runs in one-shot JSON mode as an actual process, with a single configured local
provider (`local-lab`) and exact model ID. No fallback provider is injected. The
host continuously drains stdout/stderr and stores them outside the workspace.
Raw supplied key occurrences are redacted from captured logs.

The structural analyzer requires:
- valid LF-delimited JSON records and complete agent/message/tool lifecycles;
- assistant messages with the configured model and provider, no error/abort/pending/deferred terminal state;
- at least one nonempty final assistant text with `stopReason: stop`;
- every required tool paired by ID with a successful completion;
- no exhausted retries, pending tool calls, or nonzero process exit;
- `agent_settled` under the default completion contract.

Explicit `--event-contract process-exit` supports an audited earlier one-shot Pi
schema that has no `agent_settled`. It still requires an ended lifecycle, final
assistant response, matching identity, completed tools, no pending retry, and exit
0. Missing events never cause an automatic relaxation. Context overflow/length
termination is not successful completion. Zero/missing usage is reported, not
invented and not proof by itself that no model call occurred.

This is evidence of the Pi process's observed run, not cryptographic proof that a
particular set of weights served the answer. Correlate server access logs/response
IDs when server identity or model provenance is part of acceptance.

## Independent acceptance

The smoke's random nonce/arithmetic challenge is verified by an immutable helper
in a fresh key-free container. Repository plans run their own independent check
commands after agent work. Parent control/evidence stays outside `/workspace`.
Tests/specifications in `protected_paths` are hashed before and after; changes fail
the run. More rigorous workflows should keep acceptance oracles and input data
outside the writable project too, because final hashing does not prevent all
adversarial temporary edits or runtime test manipulation.

A command exiting 0 is necessary but not automatically a meaningful test.
`verify-unittest.py` rejects zero discovered tests. For other frameworks, explicitly
verify test counts and skip statuses. If test authoring is the task, authorize new
tests but keep an independent parent-approved oracle or hidden fixtures. Do not
let an agent redefine what PASS means.

A read-only reviewer is an independently invoked agent, not an automatic semantic
approval engine. The runner verifies it executed and completed; the parent reads
its findings. A negative review can coexist with a mechanical PASS. Report and
resolve the discrepancy instead of claiming a clean approval.

## Status and stored artifacts

`PASS`: planned agent invocations structurally verified; checks exited 0; protected
hashes unchanged. `FAIL`: executed work failed one of those mechanical gates.
`ASSISTED`: otherwise mechanically successful work had accepted parent steering,
patches or budget changes (exit 1). Summary document type `run_summary` is schema
2 with assistance and legacy mechanical fields; sealed schema-2 run_result
records carry separated invocation, task, infrastructure and assistance outcomes.
RECOVERED is successful authorized segmented recovery (exit 1).
`BLOCKED`: infrastructure/configuration/preflight/setup prevented the intended
flow. `INTERRUPTED`: user interruption. Exit mapping: PASS=0, FAIL/ASSISTED/RECOVERED=1,
BLOCKED/INTERRUPTED=2. Process-level timeouts are recorded as 124.

Typical run output includes `summary.json`, `plan.json`, controls, snapshot
workspace, per-stage commands/process results, per-agent events/evidence/final
text, before/after file hashes, `protected-before.json`, `protected-after.json`,
and `changes.json`. Requested/effective resource policies and image capabilities
are in the host/image receipt. Observed OOM/HostConfig values are in process logs
when inspection succeeds. Missing observations are not filled with fake values.

Maintainer tests in the source repository deliberately use synthetic protocol fixtures and mocked
Docker calls. They validate runner logic only. They are never described as a real
LLM, browser, Docker, or model-tool acceptance run. Preparation-stage validation
coverage and omissions are documented in `VALIDATION.md`.

Protocol reference:
[Pi 0.87.1 JSON specification](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/docs/json.md).
The release-specific state-machine requirements, example shapes and dated
qualification scope are in [PI-COMPATIBILITY.md](PI-COMPATIBILITY.md).

## Durable outcomes

Run/smoke allocate UUID run and attempt IDs and write an initial record before
endpoint, secret, host/image, plan or admission prerequisites. Result.json is a
sealed schema-2 run_result with independent infrastructure, invocation, termination,
scoring, task_result, assistance and protected_inputs dimensions; summary.json is
the progress/compatibility view. Unknown workspace, score and counts stay null.
Finalization cannot overwrite a sealed failed result with a later success. Unsafe/
unavailable evidence storage emits sanitized structured stderr with the attempt
ID and no fallback project write. Run/smoke missing secrets return BLOCKED/2;
doctor/secrets still use their specific exit-3 diagnostic convention. Full scorer
and segment behavior is implemented; exact historical/native scope and current
hardening gates are recorded separately in VALIDATION.md.

## Ordered protocol evidence

The analyzer enforces session/run/turn/message/tool/retry/compaction settlement
ordering, declared tool IDs, matching provider/model identity and a final stop
response/process exit. Required tools need paired successful completions. Metadata
cannot settle execution; custom observation messages may pair outside a turn.
The isolated one-prompt segment profile rejects execution after final settlement;
separate continued prompts are separate process segments. RPC-only execution is not
implicitly accepted by this JSON adapter. Source references remain pinned in
PI-COMPATIBILITY.md; synthetic fixtures never qualify a release live.

Protocol validity, final completion and clean invocation are separate evidence
fields. Default retries/compaction are disallowed; explicitly enabled diagnostic
retry fixtures may complete with invocation_status=recovered, retaining earlier
errors and never agent_invocation_verified=true. Explicit process-exit legacy
ordering remains available without auto-downgrade, but rejects Pi 0.87.1 when its
version is observed. Actual release/event support requires matching live traces.

## Independent scorer schema 1

Schema-1 plan checks may add `scorer` with schema, id/version, 1..32 explicit
source/target assets, score_domain (finite min/max, higher/lower direction and
pass_threshold), required_assertions, explicit zero_test_policy/all_skipped_policy
(fail/allow), optional allow_partial and test_counts_required booleans. Assets are
copied/hashes retained before children run and mounted only at /opt/pi-scorer,
read-only, without a writable subject alias. Structured scorers get a read-only
subject, independent runtime, finite bounds and no forwarded key. Legacy command
checks preserve writable subject compatibility and have null score/test counts.
Networking remains none unless the existing reviewed check/network opt-in allows it.

The scorer emits exactly one JSON object on stdout with schema=1, scorer_id,
scorer_version, run_id, attempt_id, task_status (pass/fail/partial), score,
test_counts (null or discovered/passed/failed/skipped) and assertions (id, passed,
optional skipped). Run/attempt IDs come from PI_LAB_RUN_ID/PI_LAB_ATTEMPT_ID.
Exit 0 means measurement completed, including measured task failure. Nonzero
exit, missing/malformed output, wrong identity/domain or asset mutation is scorer
error with null score/counts; no score is invented. Required assertions cannot
change; omission requires declared partial policy and cannot yield pass. Zero/all
skipped outcomes obey the fixed parent policy. Numeric results from unrelated
scorers are not averaged; every per-check result remains visible.

See [artifact-scorer.plan.json](../assets/artifact-scorer.plan.json) and its
[example scorer](../examples/scorers/artifact.py). Frozen asset receipts and each
check's score.json record code/fixture/command hashes independently of subject
changes. Actual read-only mount enforcement requires runtime observations; offline tests exercise
real subprocess output, immutable copies, mutation detection and argv construction.

## Linked process segments

Each Pi process has its own parent-generated segment UUID, ordinal, trace/process
files and exact session ID. The parent consumes accepted directives and records
predecessor/intervention links; no concatenated trace is treated as a clean run.
The worker executes one Pi process. Ordinary steering waits for process completion.
Interrupt steering is applied by the host supervisor via SIGUSR1 to the worker,
which forwards one SIGINT to Pi. Parent signal receipts, not child ack files,
establish that an authorized interruption was requested through the trusted path.

A successor uses a parent-frozen regular session file and --session, never latest
--continue lookup, in fresh runtime state. Header/cwd/model and session hash are
validated; missing/ambiguous/linked sessions reject. Stage wall-time/deadline revision
continues unchanged; prior turn/reported-token consumption carries forward. Unknown
usage remains unknown and finite wall/turn bounds remain independent. Multiple
accepted directives are retained and consumed once. Explicit user cancellation
launches no successor. Required successful tool pairs may span only the same
authorized session chain; aborted/pending calls cannot count as successful.

The final segment must complete cleanly. Earlier aborts and partial EOF traces
remain visible and can yield RECOVERED/assisted only with a parent interruption
receipt and valid linked successor. Wrong identity, unrelated sessions, malformed
middle events and forged acks cannot authorize recovery. Actual Pi signal/session
durability and Docker cleanup require runtime observations; process/trace fixtures
are offline only.

## Scoring surviving artifacts

Dependent agents stop after invocation failure or uncertain cleanup. Approved
independent scorers still run after timeout, reported-token cutoff, nonzero exit
or invalid evidence only when every attempted writer is confirmed stopped and
the workspace is available. The parent freezes an artifact snapshot and gives
each scorer its own copy; generated Linux dependencies and symlink text are
preserved without following links on the host. Immutable scorer assets stay
separate. Protected input changes remain diagnostic failures, never clean PASS.

All per-scorer completed/error/skipped/cancelled results are retained. A scorer
error with confirmed cleanup does not hide later independent results; uncertain
cleanup stops further runtime launches and records skipped outcomes. No workspace
inspection or snapshot is attempted while an agent writer may still be active.
Passing artifact scores coexist with invalid invocations and FAIL/exit 1.

Explicit cancellation launches neither agents nor new scorers by default.
--score-after-cancel is explicit active-task authorization for independent scoring
when cancellation happened before scoring started and cleanup is confirmed. It
does not restart an interrupted scorer; cancelled results stay visible. The run
remains INTERRUPTED/exit 2 even when that authorized diagnostic scoring passes.
Missing workspaces, unconfirmed cleanup and snapshot failure give explicit skipped
reasons and null scores rather than fabricated failures or successes.
