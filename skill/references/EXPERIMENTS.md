# Application experiment schema 1

`validate-experiment --definition FILE [--endpoint FILE]` validates offline.
`experiment-prepare --definition FILE --experiment-dir OUT [--endpoint FILE]`
freezes inputs and publishes the full intended matrix before any trial executes.
Without an explicit endpoint, it reads the saved endpoint offline; this is not
session confirmation or endpoint health qualification. Execution must still pass
the environment gate. These commands do not launch Docker or invoke a model.

Required fields: `schema: 1`, slug `name`, `baseline` (a declared variant name),
`repetitions` (1..10), `cases` (1..8), `variants` (2..8), `budgets`, `execution`,
and `policies`. The total matrix is capped at 64 cells. Unknown fields reject.
Case and variant names are display labels; stored case/variant/trial IDs are
parent-derived UUIDs within a new UUID experiment. Repetition is zero-based.
Trial IDs remain stable; fresh attempt IDs are separate.

Each distinct case/variant pair owns one flat `inputs/plans/<UUID>.json` file;
repetitions share that pair's file. The UUID is version 5 with the experiment UUID
as namespace and `"plan:" + json.dumps([case_name, variant_name], ensure_ascii=False,
separators=(",", ":"))` as its name. Preparation computes and collision-checks the
whole map before plan writes, preserving labels with consecutive hyphens and
existing `../scorers/...` asset paths.

Each case has `name`, `project`, `plan`, and optional `budgets`. Paths resolve
relative to the definition. A schema-1 plan declares real agents and exactly one
structured independent scorer with immutable assets/domain/assertions and
zero/all-skipped policies. Command-only checks cannot supply numeric experiment
scores. A variant has `name`, optional explicit `endpoint`, and optional
`prompt_suffix` (at most 8 KiB), appended to each planned agent prompt. Otherwise
all variants share the case's plan, source, scorer and budgets; variant-specific
oracles, undeclared integrations and arbitrary runner flags reject. Different
cases may have distinct scorers and are compared separately.

`budgets` declares positive integer `timeout_seconds` (≤3600), `max_turns` (≤100),
and `max_total_tokens` (≤10000000) for each agent stage of that trial. Setup/scorer
timeouts are capped to the case timeout and use network none. Stage counts are
bounded by the existing plan schema; these are stage limits, not an invented
whole-experiment token ceiling. Execution is serial and each trial will receive
a fresh snapshot; stages within a trial may share that snapshot.

`execution` declares a trusted, already qualified immutable `image` (`sha256:…`),
explicit native `platform`, and `resources` JSON path. Optional `environment`
JSON supplies image capability probes; `network` defaults to bridge. Image trust
and actual architecture/limits remain execution checks, not schema claims. There
is no image build or alternate model/server fallback in an experiment.

`policies` requires `primary_attempt: first`, `assistance: exclude`,
`on_failure: continue|stop`, and `max_attempts: 1..3`. Automatic retry and best-result
selection are unsupported. A successful authorized retry cannot replace the
primary result or its planned denominator. Preparation alone does not collect a baseline. Explicit retry and resume
semantics are described below; comparisons remain a separate reporting step.

The output directory must be new and outside all case projects. It contains
`experiment.json`, `matrix.json` with every initially planned cell, `integrity.json`,
`state.json` and parent-held `inputs/` (sources, normalized per-variant plans,
endpoints, resource/capability JSON and scorer assets). Source changes during
freezing reject publication; scorer hashes are checked again during copying.
Ignored dependencies/credentials/links follow existing snapshot exclusions,
which are not a complete secret scanner. Review the project and keep the secret
store outside it. Credentials are never literal endpoint fields and are excluded
from configuration identity; key variable names may remain in frozen endpoints.

Frozen inputs retain hashes and are never exposed through a writable trial mount.
`verify` checks their exact file set, modes/content and no-follow paths before use.
It also checks pair ownership, consistent repetition paths and normalized plan
hashes; cross-pair aliases and missing/escaping references reject even when the
inventory hashes match. User-plan `prompt_file` inputs are materialized as inline
prompts during preparation; frozen verification rejects prompt-file references
and never loads the original host prompt file. Valid unambiguous legacy `<case>--<variant>.json` archives
remain readable/reportable without rewriting frozen bytes; ambiguous legacy
archives reject. Archive inspection uses the recorded preparation root for
normalized identity, while execution still rejects changed runners or moved
preparation roots and requires a newly prepared experiment.
The integrity inventory detects changes; it is not a publisher signature. The
matrix accounts for cells that never execute. Default profile scope is built-in
only. Optional variant `agent_profile` selects the one reviewed fixture_lookup
contract; its assets/identity and expected tools are frozen explicitly. See
[AGENT-PROFILES.md](AGENT-PROFILES.md). Application baselines require no integration.

## Serial execution

`experiment-run --experiment OUT --session ID` executes the prepared matrix once.
It reserves UUID attempt/run identity before entering the existing `run_suite`,
which still acquires its usual host admission lease, checks image architecture,
preflights the exact endpoint and independently scores eligible stopped failures.
Each attempt snapshots the frozen source into its own run directory. Original
source changes during collection cannot enter later trials. Stages of one trial
share that trial's workspace, not another trial's edits or dependencies.

An experiment controller lease rejects a second controller. Saved-environment
variants require session readiness and exact agreement with the frozen endpoint;
explicit endpoint variants remain explicitly selected files. No fallback or build
is attempted. Inputs are rechecked before each cell; sealed results retain IDs and
hashes. Existing attempts reject a repeated `experiment-run`; use `experiment-resume` for crash reconciliation and explicit retries.

`on_failure: continue` retains setup/invocation/scorer failures and runs later
planned cells after known cleanup. `stop` halts at the first non-clean outcome,
retaining all remaining cells as planned. Uncertain cleanup blocks collection
regardless of policy. Cancellation stops collection and launches no later trial.
Collection exit 0 means the matrix finished, not that every trial passed; per-trial
statuses, scoring and comparison denominators remain independent.

After reconciliation and cleanup verification, stop policy is reconstructed from
all validated sealed attempts. Any outcome other than PASS permanently halts
pending cells, including when a later retry passes or the mutable controller view
says prepared, running, blocked, interrupted or completed. A halted view without
supporting non-PASS history, or a halted view under continue policy, is an
inconsistent-state error; missing/malformed evidence also rejects before any new
reservation. Cleanup recovery establishes quiescence, not permission to erase a
stop condition.

## Resume, explicit retries and export

`experiment-resume --experiment OUT --session ID` reconciles abandoned attempts
and runs only cells with no prior attempt. Add `--retry-trial TRIAL_UUID` to request
one fresh linked attempt for a failed/interrupted cell, within `max_attempts`;
completed clean cells reject retry. Remaining pending cells may then run under
continue policy. A stop-policy collection stays halted; a diagnostic retry does
not reopen its pending cells. No result is selected by its observed score.
That retry returns halted/1 even on PASS; retry cancellation returns interrupted/2
and uncertain cleanup returns blocked/2. Explicit cancellation stops the current
collection call. A later explicit continue-policy resume may run pending cells
after known cleanup; a sealed cancelled attempt establishes stop-policy halt.
Cancellation before reservation creates no failed attempt, and cancellation after
a sealed PASS never rewrites that result.

Every reservation is fsynced before runtime admission. A second controller rejects.
Frozen inputs must match on restart. Already sealed attempts are read/hashed and
never rewritten or repeated; missing/corrupted sealed results reject. An incomplete
unsealed final write is preserved as an artifact before sealing the available
observations. Known user cancellation remains INTERRUPTED/cancelled. Controller
loss records a separate `controller_interruption` with `controller_lost` and
retains observed dimensions; it does not invent user cancellation, Pi completion,
score or a passing invocation. Recovery starts no scorer for that abandoned run.

Cleanup first acquires the same global host lease. Only parent-registered stage
or image-probe containers with matching exact image and read-only control-source
mount may be removed; uncertain inspection/cleanup blocks pending work. Probe
identity is persisted before launch and cleanup survives graceful interruption.
Unregistered legacy runtime ownership cannot be guessed. Additional independent
cleanup observations may permit a fresh retry but never alter the sealed original
outcome or its primary eligibility. The controller and runtime leases have distinct
roles; neither bypasses the other.

`experiment-export --experiment OUT` writes deterministic `trials.jsonl`, ordered
by the fixed matrix and attempt index. Every planned cell appears, even without an
attempt/result. Primary attempt remains index 1; retries link to the previous
attempt and retain new run/attempt IDs. Same unchanged records produce identical
bytes/hash. Reports are derived from these retained records, not overwritten
"latest" results. The exported rows dispatch by schema/document type and retain
null observations rather than coercing missing measurements to zero.

## Comparisons with accountable denominators

`experiment-report --experiment OUT` emits `trials.jsonl`, `comparison.json` and
`comparison.md`. The output is deterministic for unchanged retained records.
Counts are primary-only: planned = started + not_started; started = completed +
incomplete; planned = scorable + unscorable; completed = scorable +
completed_unscorable. Started means an attempt was reserved, not proven Pi launch;
completed means a terminal sealed primary record, including blocked/cancelled
ones. Blocked/cancelled/assisted are subsets, not additive partitions. Every
planned cell and every retry remains linked to evidence. Missing results link to
the intent record rather than a nonexistent result file.

A scorable artifact has a completed compatible structured scorer, finite declared
score/domain and known task status. Artifact-correct/scored is a conditional
**diagnostic** rate, separate from clean primary success/all-planned. Numeric
primary eligibility additionally needs verified invocation, autonomous assistance,
unchanged protected inputs and matching source/plan/model configuration/image/
runner identities. Cancellation and uncertain cleanup exclude primary eligibility.
A correct artifact after invalid invocation/timeout is still diagnostic, not a
verified model success. Zero/all-skipped policies remain scorer-declared failures;
unknown measurements are not coerced to failures or zeros.

Reports retain per-case baseline/candidate pairs by repetition. Only mutually
eligible pairs with the same oracle/source/runner produce a score difference.
Different case oracles are not averaged together. Score spread uses observed min,
max and sample standard deviation; tiny samples imply no significance. Measured
usage categories and agent end-to-end intervals show observed/missing counts;
inference seconds stay unknown. Assisted and retry cohorts are separate and can
overlap; neither changes primary denominators or replaces a failed primary.

Preparation records the runner content identity and expected normalized plan
hashes. Execution/resume refuse changed runner content or a moved execution
root; prepare a new experiment rather than mixing executor versions. Reporting
uses the recorded expected identities and does not require the original runner
to remain current. The inventory is change detection, not a signature.

## Runnable application baseline

[The Python slug walkthrough](../examples/application-baseline/README.md) renders
fixed baseline/candidate definitions from a reviewed ARM64 Pi 0.87.1 or 1.2.0 image receipt.
It uses an external eight-group oracle, two fresh repetitions and a bounded
cutoff/resume demonstration. The candidate differs only in its predeclared prompt
instruction; it is not assumed to improve results. No integration profile is
needed. Offline fixtures establish schema/reset/oracle behavior; real numbers
require retained real execution and independent scoring evidence.
