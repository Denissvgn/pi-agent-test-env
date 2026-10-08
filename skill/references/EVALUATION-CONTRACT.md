# Evaluation contract

The runner evaluates frozen application cases with independent scoring and
explicit ownership of evidence. [TEST-CONTRACT.md](TEST-CONTRACT.md) describes
the coding workflow; [PROJECTS.md](PROJECTS.md) describes project discovery
and isolation.

## Scope

The runner evaluates a small application through reviewed CLI/API commands, with
fresh snapshots, serial Pi trials, an independent key-free deterministic scorer,
fixed finite budgets and the exact selected model. Start with the bundled Python
slug task, immutable input cases and a parent-held scorer. Collect task success,
assertion score, invocation validity, elapsed time and reported usage; unknown
usage remains null. Experiments freeze the intended case/variant/repetition matrix.
No scheduler, dashboard, server management, automatic retries or model fallback.

The separate optional integration track uses one reviewed Pi extension providing
a `fixture_lookup` tool. It reads a fixed, read-only fixture table and returns a
structured value; it has no shell, network or write capability. Compare it with
a built-in `read` baseline on the same lookup/application cases and budgets. A
load receipt alone is insufficient: traces must show its registered tool name,
arguments, paired successful result and independent assertion of the resulting
artifact. Application baselines do not
depend on this track. No child-discovered assets or nested agents are enabled.

## Identities, ownership and versions

Identifiers are parent-generated opaque UUID strings, never user paths or child
values. Names are display labels. The containment relationships are:

- `experiment_id` → `trial_id`: one intended case/variant/repetition cell, including
  cells never executed. Store `case_id`, `variant_id`, zero-based `repetition` and
  the immutable `configuration_digest` in the matrix.
- `trial_id` → `attempt_id`: `attempt_index` starts at 1. The first attempt is
  primary; an explicitly authorized fresh retry has `retry_of_attempt_id`, index
  2 or higher and a new snapshot/session. It never replaces attempt 1. Standalone
  schema-1 execution has null experiment/trial fields, not fabricated trial data.
  Authorizing a fresh retry alone does not mark it assisted; changed prompts,
  steering, patches or budget changes do. A configuration change requires a new
  trial/configuration instead of pretending it is the same retry.
- `attempt_id` ↔ `run_id`: one run executes one attempt, possibly multiple planned
  stages. Each stage has its own `stage_id`; each actual Pi process has its own
  `segment_id`, ordinal, session identity and trace/process artifact references.
  An authorized continuation links `continues_segment_id` in that stage. A scorer
  is a separate stage and never supplies missing agent evidence.

Run-result schema 2, stage-record schema 2, control-command schema 2 and
acknowledgement schema 2 are separate from experiment and scorer-result schema 1
in distinct document types. Readers dispatch by document type and schema, reject
unknown major schemas for execution, and may expose raw unsupported records for
inspection. Optional additive fields cannot change enum/ownership semantics.
These version numbers do not bump schema-1 plans or endpoint files.

A parent-owned stage descriptor outside every child-writable mount fixes the
run/attempt/stage IDs, workspace path/mode, control sources, writable outbox,
stage kind, access and original limits. Lifecycle updates are separate revisions:
`pending → running → stopping → stopped → finalized`, or
`pending → stopped → finalized` if never launched. `stopped` requires a cleanup
observation; uncertain cleanup is recorded explicitly and forbids scoring.
Finalized stages reject execution controls. Parent metadata, not child heartbeat,
selects paths, limits, stage routing and lifecycle state. The filesystem and
mount requirements are described in [SECURITY.md](SECURITY.md); this contract
alone provides no write-confinement proof.

Control commands contain schema, command ID, run/attempt/stage/segment target,
kind (`steer`, `patch`, `extend_budget`, `continue`), creation time, expected
stage/budget revision and payload digest. Reject missing/ambiguous/wrong targets,
stale revisions, malformed/nonfinite limits and stopped/finalized mutations.
Continuation is allowed only through the recovery transition described below.
Budget changes preserve original/effective limits, use a host-owned elapsed-time
deadline and record finite before/after values; cleanup grace is separate.
No comparison of host and Docker-VM monotonic clock origins is permitted.

Append-only parent intervention records contain `intervention_id`, command ID,
IDs/revisions, UTC timestamps, requested/accepted/rejected/applied transitions,
reason, authorization source and patch hashes or before/after limits. Child
acknowledgements echo IDs/revision with observed status/time and remain untrusted
observations: they cannot grant authority or establish host patch application.
An accepted execution-affecting intervention marks the attempt `assisted`, even
when delivery/application is unverified. Rejected requests and read-only status
inspection do not. Scorer/oracle changes require a new configuration and trial;
they cannot be accepted as patches to an existing trial's acceptance contract.
No secrets, raw keys or private endpoint URLs belong in intervention history.

## Outcomes and exit mapping

Each attempt has independent fields. Never infer one from another:

| Field | Values and meaning |
|---|---|
| `infrastructure.status` | `ready`, `failed`, `not_started`; failures carry reason and phase |
| `invocation.status` | `not_started`, `verified`, `invalid`, `recovered`; verified requires all planned Pi stages cleanly validated |
| `termination.reason` | `not_started`, `completed`, `process_error`, `timeout`, `turn_limit`, `token_limit`, `log_limit`, `oom`, `interrupted`, `cancelled`, `cleanup_error`; interrupted is an authorized steering/recovery stop, cancelled is explicit user cancellation; preserve per-segment reasons and actual process exit codes separately |
| `scoring.status` | `not_started`, `completed`, `error`, `skipped`, `cancelled`; use reason codes for skipped/error/cancelled |
| `task_result.status` | `pass`, `fail`, `partial`, `unknown`; unknown when no valid scorer result exists |
| `assistance.status` | `autonomous`, `assisted`; list authorized intervention IDs |
| `protected_inputs.status` | `unchanged`, `changed`, `unknown`; changed/unknown disqualify a clean result |

`recovered` means the final continuation completed under the recovery rule; it
does not turn earlier invalid/aborted segments into verified ones. Cleanup error
takes precedence as the attempt-level termination reason; retain the originating
timeout/error/cancellation in segment records and `termination.trigger`. Explicit
user cancellation takes precedence over ordinary process-error classification.
Successful cleanup after a timeout does not change `timeout` to `completed`.

Result `status` and CLI exit are derived in this order at finalization:

| Condition | Status | Exit |
|---|---|---|
| Explicit user cancellation (including during scoring) | `INTERRUPTED` | 2 |
| Infrastructure/preparation prevents any planned agent launch | `BLOCKED` | 2 |
| Infrastructure fails after launch; termination other than completed; invocation invalid/not_started; protected inputs changed/unknown; scoring other than completed; task fail/partial/unknown | `FAIL` | 1 |
| All remaining gates pass, invocation recovered | `RECOVERED` | 1 |
| All remaining gates pass, assistance assisted | `ASSISTED` | 1 |
| Infrastructure ready, every planned invocation verified, completed normally, autonomous, inputs unchanged, scoring completed and task pass | `PASS` | 0 |

`RECOVERED`/`ASSISTED` deliberately return 1 so consumers treating zero as a clean
autonomous success cannot accidentally accept assisted results. A retry may earn
its own PASS/0 but cannot change the primary outcome or denominator. Worker
timeout 124 and Pi's actual exits belong in segment/process records, not in place
of the orchestration exit. A command-only check can satisfy mechanical schema-1
acceptance with exit 0 under a declared scorer adapter, but has null score/test
counts and cannot supply numeric quality or test-discovery claims.

## Scoring and finalization

The immutable scorer contract fixes ID/version, code and input hashes, argv,
network policy (none by default), finite limits, output schema, score domain,
direction, pass threshold, required assertions, zero-test and all-skipped policy.
Scorer-result schema 1 contains `scorer_id`, `scorer_version`, subject run/attempt
IDs, assertion results, test counts (`discovered`, `passed`, `failed`, `skipped`),
task status and score (null for a command-only adapter). Partial results must be
declared by that scorer; an omitted assertion cannot be silently counted passed.
The MVP uses score [0, 1], higher is better, 1 required to pass, equal weighted
assertions, zero discovered/all skipped = task failure. Scorer error is distinct
from task failure. Malformed/missing output, wrong identity/domain, nonzero scorer
exit or scorer timeout is `scoring.error`, task unknown, score null; retain raw
output as evidence. Even an emitted passing JSON with nonzero exit is an error.

After any attempted agent, stop and confirm all writers terminated, freeze/copy
the scoreable workspace and check protected inputs, then run the independent
scorer even after timeout, budget cutoff, invalid trace or nonzero Pi exit.
Scoring a protected-input violation can be retained diagnostically but is excluded
from attributable comparisons. Missing workspace or uncertain cleanup gives
`scoring.skipped` with `workspace_missing` or `cleanup_unconfirmed` and null score.
Infrastructure blocking all agents gives skipped `agent_not_started`.

Explicit user cancellation stops agents and any active scorer, performs bounded
cleanup and durably writes the available evidence. It never launches another
agent, continuation or scorer by default. If scoring was active, use
`scoring.cancelled`; if it had not started, use `scoring.skipped/user_cancelled`;
if already complete, preserve it. Only an explicit instruction in the active task
authorizing post-cancellation scoring permits a new scorer; record that authority
and keep INTERRUPTED/2. Existing authorization to run a trial is insufficient.

Finalization writes a result even if preparation, launch, scoring, hashing or
cleanup fails. Persist records as each phase completes; seal a final result only
once with finish time and artifact hashes. Unavailable observations remain null
with reasons. Interruption cannot erase prior completed stages. If durable output
itself fails, return nonzero and report its last safe location; never invent a
saved receipt. A sealed run is immutable; later analysis uses a linked record.

Recovery requires parent authorization recorded before a continuation launches.
While unfinalized, a stopped stage may enter a new running revision with a fresh
segment linked to the exact persisted session and prior segment. Validate each
segment independently, including identity and ordering. Earlier completed,
successful required-tool pairs may count toward recovered completion only within
this same stage/session chain; aborted/pending tool calls never count. Every
completed assistant message must retain the selected model/provider identity.
The final segment needs clean lifecycle completion, final stop text, exit 0 and
no pending retry/tool/message. Retain earlier aborts/errors; mark recovered and
assisted. Never validate arbitrary concatenated traces as a clean invocation.
After sealing, any continuation requires a new linked assisted attempt/run.

## Provenance and comparison

Retain source revision plus dirty-tree/snapshot digest and exclusions; original
and normalized plan/configuration hashes; effective prompt/capabilities manifest;
selected integration assets/hashes; scorer code/inputs; runner revision; Pi
package/version/artifact; image reference, immutable ID and architecture; resource
policy and effective limits; sessions, segment traces and process/cleanup logs.
Endpoint identity is a redacted logical identifier. Model ID is exact. Record
server revision/weights digest and response IDs when available, otherwise null.

For each reasoning/sampling/seed/token setting store requested value, effective
observed value (nullable), evidence reference and enforcement state
`verified`, `unverified` or `unsupported`. An unsupported requested setting fails
admission, rather than being discarded. A stored seed is not deterministic replay.
Pi identity is process evidence, not proof of served weights; artifact correctness
does not establish that the selected model created it.

Keep every intended matrix cell, including missing, blocked, cancelled, failed
and unscorable trials. Publish counts and these separate quantities:

- Primary autonomous success: clean primary PASS count / all intended cells.
  Nonexecution, assistance and retries never shrink that denominator.
- Artifact task success/score: completed valid scores, including invalid-invocation
  and timeout artifacts, with scored / intended counts and missing reasons. Label
  this diagnostic metric as artifact-only; it cannot establish model success.
- Attributable task scores: only verified primary autonomous invocations with
  unchanged inputs, valid comparable scorer and matching declared configuration;
  report eligible / intended and score coverage. Do not silently condition away
  failures. Compare numeric scores only for the same scorer/version/hash/domain,
  cases and acceptance inputs; incompatible contracts require separate reports.
- Recovery, assisted and retry results: separate cohorts, still linked to their
  primary cells. Timing/usage statistics state their observed denominator; never
  turn unknown usage or missing time into zero.

## Compatibility and reviewed examples

Schema-1 plans/endpoints stay readable with their exact selected version/model.
Existing summaries remain schema-1/legacy observations; do not synthesize a
verified schema-2 invocation or experimental provenance from them. Inspectable
legacy controls lacking unambiguous parent-owned routing reject mutations with
an explicit unsupported-legacy-control reason. No automatic completion downgrade.
The exact source-inspected candidate and its release-specific limits are in
[PI-COMPATIBILITY.md](PI-COMPATIBILITY.md); no runtime qualification is implied.

[outcome-examples.json](outcome-examples.json) contains normative projections of
final results. They omit artifact/UUID details for readability; they are neither
full stored records nor executable schema-1 plans. Each projection must obey the
field semantics and exit precedence above. They cover clean success, prelaunch
failure, timeout with task pass, scorer error, authorized recovery, fresh retry
(both original and retry), cancellation before/during scoring and assisted success.
