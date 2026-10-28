# ENV-ADMISSION-002 implementation and verification plan

Status: implementation and correctness/safety review verified on
`codex/env-admission-002`. Four confirmed review findings are fixed and covered by
regression tests. PR 9 is merged and the verified 4.6.1 prerelease is published under an explicit
one-release Copilot waiver. The subsequent owner-proof contract implementation is
locally verified on `codex/pi-owner-proof-001`: 2,741 tests pass, with package and
standalone checks. Real owner migration, native integration qualification and
promotion remain deferred. The original exceptional-exit lifecycle behavior is
unchanged. The subsequent local safety review fixes seven findings and passes
2,757 tests. Review and exact candidate evidence are recorded below.
Created: 27 October 2026. Updated: 27 October 2026.

Affected release: `4.6.0`, tag `v4.6.0`, source commit
`925deb0cad3b3b986f66e8fe6ef33a1dfa7873f5`.

The required outcome is actionable, sanitized host-registry admission diagnostics
and a supported recovery outcome that preserves ownership, termination, sensitive
cleanup and durability checks. The original denial is confirmed; its failing
phase and underlying cause remain unknown. The first implementation must improve
diagnostics without changing which executions are admitted.

This is maintainer planning history, outside the installable skill. Saving this
plan does not resume the downstream campaign, operate on the shared registry,
restart the inference service, publish a release or change installed packages.

## Evidence and provenance

| Reference | Location or identity |
| --- | --- |
| Downstream issue | [Original issue](/Users/bramen/Projects/WorkChord/docs/plans/autonomous-agentic/reports/upstream/pi-agent-test-env/ENV-ADMISSION-002/issue.md) |
| Sanitized source bundle | [Original ZIP](/Users/bramen/Projects/WorkChord/docs/plans/autonomous-agentic/reports/upstream/pi-agent-test-env/ENV-ADMISSION-002/pi-agent-test-env-admission-triage.zip) |
| Bundle SHA-256 | `02afe5526437a47bba162706115a78de3519be736f2014952ef04b2a46cfa8e7` |
| Verification and source hashes | [verification.json](env-admission-002-evidence/verification.json) |
| Focused synthetic reproducer | [reproduce.py](env-admission-002-evidence/reproduce.py) |
| Observed synthetic results | [results.json](env-admission-002-evidence/results.json) |
| Contribution and publication rules | [CONTRIBUTING.md](../../CONTRIBUTING.md) and [PULL-REQUESTS.md](../../skill/references/PULL-REQUESTS.md) |

All 16 bundle payload hashes and the five reported source hashes were verified.
The local source files used for analysis matched the pinned release. The retained
analysis artifacts were copied byte-for-byte from the original temporary output;
`verification.json` contains the reproducer and results hashes.

The original issue and ZIP links identify local downstream evidence. The ZIP is
a sanitized observation bundle, not an executable registry fixture. It excludes
the complete registry, private cleanup receipts, credentials and full run state.

The retained reproducer is an analysis artifact. It uses the original absolute
repository path and writes `results.json` beside itself. For a future rerun, copy
it to a fresh output directory first, select and record the implementation under
test, and retain new results separately. Do not overwrite these baseline results
or treat a changed source checkout as the original release.

## Findings that govern implementation

1. The predecessor failed on API connection refusal with a sealed `BLOCKED`
   result, zero attempted Pi stages and confirmed physical container cleanup.
   A subsequent standalone preflight failed at admission with
   `host-registry-unsafe`. The two failures require separate treatment.
2. The three `absent` records are consistent with the released exception path.
   Container cleanup persists `absent`; the run controller raises on preflight
   failure; an exception thrown through `admission_lock()` skips the
   `registry.close()` statement after `yield`. The next admission must reconcile
   the records. This behavior alone does not establish corruption or a defect.
3. Synthetic execution of that lifecycle produced exactly three `absent` records.
   The next admission released all three and preserved the predecessor's sealed
   blocked result byte-for-byte.
4. When pending records exist, reconciliation checks older ordinary application
   helpers, including `released` records. Missing retained cleanup proof can deny
   admission before Docker observation. With no pending records, an earlier
   return skips this ordinary-helper check. This sequence was reproduced
   synthetically; its presence in the downstream registry is unestablished.
5. Later record-shape checks and validation of 66 qualification cleanup receipts
   do not exercise all ordinary-helper checks, record writes, sensitive recovery
   or durable release. Later successful daemon/container observations also do
   not prove what was observable during the original denial.
6. Nine distinct synthetic denial conditions produced identical public fields
   apart from `error_digest`. This confirms the diagnostic visibility gap. Do not
   infer the original cause by matching or guessing that digest.
7. Normal recovery worked with 6,777 and 8,192 synthetic records. Native temporary
   filesystem operations worked on macOS 26.6.2, ARM64, Python 3.14.5. This does
   not establish access or durability behavior at the real registry path.

No new container or Docker probe does not imply that reconciliation made no
Docker CLI observations: it can call `docker info` and exact container inspection
before dispatching preflight.

## Source boundaries

Line references are for the pinned release and may move during implementation.

| File and boundary | Responsibility |
| --- | --- |
| [resources.py](../../skill/scripts/resources.py), `admission_lock`, lines 332–346 | Constructor/reconciliation/close error translation; close occurs only after a normal body exit |
| [ownership_registry.py](../../skill/scripts/ownership_registry.py), `reconcile`, lines 644–719 | Historical proof checks, daemon and writer observations, absent commits, sensitive recovery, release commits |
| [ownership_registry.py](../../skill/scripts/ownership_registry.py), `_application_stage_pending`, lines 490–575 | Required ordinary application-helper cleanup evidence |
| [ownership_registry.py](../../skill/scripts/ownership_registry.py), `write`, lines 630–642 | Existing-record checks, atomic replacement and directory fsync |
| [stage_control.py](../../skill/scripts/stage_control.py), `atomic`, lines 22–33 | Temporary record creation, serialization, file fsync, replacement and temporary cleanup |
| [application_credentials.py](../../skill/scripts/application_credentials.py), `recover`, lines 226–242 | Sensitive descriptor validation, stage purge, snapshot discard and receipt update |
| [pi_lab.py](../../skill/scripts/pi_lab.py), `_execute_suite`, lines 1319–1328 | Preflight failure raises before participant dispatch |
| [pi_lab.py](../../skill/scripts/pi_lab.py), `main` and `cli_failure`, lines 2182–2184 and 2257–2263 | Admission before standalone dispatch and public failure JSON |
| [outcomes.py](../../skill/scripts/outcomes.py), `Attempt.fail`, lines 130–142 | Sanitized diagnostics in sealed run/smoke results |

## Scope and invariants

- Preserve the existing shared lease, its identity and legacy default-path
  selection. No alternate lock, lock deletion or lock replacement is a recovery.
- Preserve the closed public `host-registry-unsafe` category, `BLOCKED` status
  and exit code 2. Keep capacity and lock-contention failures distinct.
- Require positive ownership and termination evidence before admission. A live
  abandoned writer may be stopped through the existing proven-ownership path;
  no new execution is admitted while it remains live. A mismatched writer must
  never be removed as part of this recovery.
- Preserve daemon, immutable identity, mount, inference, sensitive cleanup and
  historical receipt predicates. Absence, PID liveness or a `released` label
  alone cannot establish all prerequisites.
- Preserve record bounds, old identities, unrelated records, failure history and
  sealed results. Do not raise the cap or introduce automatic archival/deletion.
- Do not fabricate receipts, flip statuses manually, purge private state to
  bypass a gate, silently retry, or switch endpoint/model/image.
- Keep diagnostics bounded and credential-free. Raw exceptions, tracebacks,
  command stderr, private paths, prompts and credential payloads are not public
  diagnostic authority. Owner-private storage is not permission to log secrets.
- Maintain Python 3.10+ and the standard-library-only host contract.
- For any later native Docker qualification on this workstation, explicitly use
  `linux/arm64` and verify image architecture before launch.

## Implementation sequence and tracking

Use the task IDs below in implementation notes, tests, review dispositions and
verification receipts. Status values are `planned`, `in_progress`, `verified`,
`blocked` or `deferred`. Change status to `verified` only with an evidence link.

| ID | Deliverable | Depends on | Status |
| --- | --- | --- | --- |
| E002-01 | Freeze diagnostic schema and failure taxonomy | Analysis | verified |
| E002-02 | Preserve typed phase/condition information at failure boundaries | E002-01 | verified |
| E002-03 | Propagate sanitized diagnostics to CLI and sealed outcomes | E002-02 | verified |
| E002-04 | Integrate focused lifecycle, history and persistence regressions | E002-01; final verification after E002-03 | verified |
| E002-05 | Specify and implement bounded read-only registry inspection | E002-01, E002-04 | verified |
| E002-06 | Specify and implement reconciliation-only recovery reporting | E002-03, E002-04, E002-05 | verified |
| E002-07 | Identify the downstream failing prerequisite with narrow evidence | E002-03; E002-05/E002-06 as needed | verified for the subsequently reported owner-proof block; original denial remains unattributed |
| E002-08 | Decide whether exceptional-exit cleanup needs a separate change | E002-04, E002-07 | deferred |
| E002-09 | Complete qualification, review and corrective-release preparation | Applicable implementation tasks | verified |
| E002-10 | Perform authorized downstream recovery and fresh preflight | E002-07, reviewed qualified implementation | deferred |

### E002-01 Diagnostic contract

Keep the existing outer admission category. Introduce an additive, versioned
nested registry diagnostic so that the existing run-level
`infrastructure.phase = admission` is not overloaded.

Freeze exact names and bounds before runtime edits. The proposed shape is:

```json
{
  "reason": "host-registry-unsafe",
  "registry_diagnostic": {
    "schema": 1,
    "phase": "persist_absent",
    "condition": "filesystem_operation_failed",
    "operation": "directory_fsync",
    "os_error": "io_error",
    "effects": "may_have_occurred"
  }
}
```

This schema is implemented in [registry_diagnostics.py](../../skill/scripts/registry_diagnostics.py);
this example is not an observed downstream diagnosis. All values must originate from trusted, closed catalogs. Do not classify
arbitrary exception messages, digest values or spoofable object attributes.

Cover registry initialization/inventory, historical qualification replay,
ordinary application cleanup, daemon observation, inference termination, writer
inspection/termination, absent persistence, network cleanup, sensitive recovery,
private-store cleanup and release persistence. Filesystem operations must
distinguish create/open, read, file fsync, replacement, directory fsync and purge
where relevant. Use bounded OS-error categories; exclude path-bearing messages.

Completion: schema examples, compatibility expectations, redaction rules and
static remedies are reviewed; unknown/untrusted values fail safely; no admission
predicate is relaxed. Record optional correlation identifiers and their audience
explicitly before exposing them.

### E002-02 and E002-03 Failure context and reporting

Attach typed context where a predicate fails or an OS/daemon operation is
performed. Preserve it through inner validators that currently replace errors
with generic messages. Cover constructor and terminal-close failures as well as
reconciliation. Audit control-record exceptions and bounded subprocess timeouts
so they cannot accidentally fall through to raw diagnostics.

Propagate only allowlisted fields through `admission_diagnostic()`, the standalone
CLI and `Attempt.fail()`. Preserve sealed outcome accounting and existing error
categories. Retain `error_digest` for correlation without using it for diagnosis
or promising that its value remains stable across implementation changes.

Provide useful structured stderr before the requested results directory exists.
If optional private diagnostic storage is added, use a separate owner-only
location, bounded no-follow writes and a safe reporting-failure fallback. Never
put diagnostic files inside the launch-registry directory. Failure to write a
diagnostic must not turn a safety block into admission or erase the primary cause.

Completion: each failure phase has distinguishable sanitized evidence in both
standalone and sealed-result routes; secret canaries, hostile messages and forged
diagnostic attributes cannot escape the public boundary. Persistence diagnostics
accurately allow for partial effects, including replacement before fsync failure.

### E002-04 Regression suite

Port the relevant standalone scenarios into maintainable tests using the real
lease, constructor, reconciliation and filesystem boundaries, with synthetic
Docker observations and disposable registries. Do not turn these tests into
native Docker/model qualification claims.

Required cases:

- Failed run preflight leaves three `absent` records, zero participant stages and
  a sealed blocked result; a healthy next admission safely releases them without
  rewriting the original result or counting a participant invocation.
- A registry with only released ordinary helpers, followed by an ordinary failed
  preflight, reaches the historical cleanup guard on the next admission. Test
  both complete proof and missing/tampered/unavailable proof.
- Historical qualification service and preworker receipt replay, mixed with
  ordinary pending records, preserves every original ownership and cleanup gate.
  Include reused historical numeric PIDs without substituting PID checks for the
  approved replay contract.
- Exact writer absence, live positively owned orphan termination, mismatched
  ownership/mounts, changed or unavailable daemon, unresolved inference, pending
  application authority, and unsafe path/mode/symlink conditions.
- Each persistence operation fails independently: temporary creation, write/file
  fsync, replacement, directory fsync and final release. Cover interruption after
  replacement, between absent commits, during sensitive recovery and after a
  partial release. A subsequent attempt must revalidate required proofs.
- Sensitive cleanup succeeds only with its required descriptors and ownership;
  invalid identity or incomplete cleanup denies. Preserve all safety checks for
  helpers that generic recovery cannot handle.
- Mixed histories at the observed size and the existing capacity boundary.
  Existing cleanup updates remain possible at capacity; new intents are denied;
  unrelated committed bytes and old receipts remain unchanged.
- Diagnostics remain bounded, typed and nonsecret before output-directory
  creation and across both reviewed Pi release routes.

Completion: each required case has an implementation test and recorded outcome;
new regressions include the failure phase/subreason, not merely an asserted block.

### E002-05 Read-only inspection

Define a supported inspection contract before choosing CLI names. It must use
the original existing lease with bounded waiting and exclusion against mutating
controllers, without replacing it, changing its mode or rewriting its header.
Avoid the normal admission wrapper because it performs reconciliation effects.
Do not expose construction through `Registry.__new__` as the supported interface.
Factor bounded pure observation/validation primitives instead.

Inspection must neither dispatch workers nor stop containers, purge state,
rewrite records or fabricate cleanup evidence. Specify whether bounded read-only
Docker observations are included. Identify historical helper classifications and
missing prerequisites with safe references. Explicitly report write/fsync and
mutation-dependent prerequisites as untested, rather than calling the registry
recoverable merely because passive checks passed.

Completion: tests prove no mutation, no changed lease inode/header, no native
dispatch, and precise outcomes for unreadable or missing evidence. Inspection
does not mint a proof that later recovery can use without revalidation.

### E002-06 Reconciliation-only recovery

Define an explicit recovery entry point that retains the original lease and uses
the existing ownership/termination/cleanup rules. It must not launch a fresh
probe or participant after reconciliation. There is no forced-release option.
Application helpers still requiring their owning cleanup workflow remain blocked.

Retain a separate bounded recovery receipt with invocation identity, source
version, changed record references, verified transitions, outcome and safe failure
context. Never overwrite old results, old receipts or failure classifications.
Record partially completed effects; do not treat a failed call as a transaction
that necessarily left all bytes unchanged. No automatic retry follows a failure.

Completion: safe release and precise denial are demonstrated under the real
temporary lease; original failure evidence stays unchanged; recovery receipts
cannot authorize bypassing subsequent admission checks.

### E002-07 Downstream attribution

Begin with the smallest relevant nonsecret evidence. In particular, determine
whether historical ordinary application-helper records exist beyond the 66
validated qualification receipts, and whether their retained proof is available.
Separate permission/durability failures from missing cleanup prerequisites and
transient Docker observation failures.

Use already retained contemporaneous private diagnostics only within an approved
narrow scope. If they do not exist, a new diagnostic observation identifies the
new attempt; it does not retroactively prove the exact cause of the original
denial. Keep that uncertainty explicit and document the corroboration needed to
associate a persistent condition with the original attempt. A digest match alone
is insufficient. Do not import the shared registry or secret stores wholesale.

Completion: record either an evidence-backed unmet prerequisite or confirmed
implementation defect, the supported next action and any remaining limit on
retrospective attribution. A safe, actionable block is an acceptable recovery
outcome when proof is missing.

### E002-08 Exceptional-exit cleanup decision

Keep this separate from the diagnostic-only change. Do not move `Registry.close()`
into `finally` as a one-line fix: its present checks are not a complete abandoned
execution recovery procedure.

If a change is warranted, design explicit current-generation finalization that
requires physical writer termination, inference termination, sensitive cleanup
and durable release. Preserve unresolved records and both the primary execution
failure and any secondary cleanup failure. Exercise exceptions, cancellation,
partial cleanup and interruption. Otherwise mark this task `deferred` with the
reason and retain supported next-admission reconciliation.

Completion: an explicit reviewed decision, with a separate implementation and
qualification receipt if behavior changes. This task cannot substitute for
diagnosing the reported admission failure.

### E002-09 and E002-10 Qualification and downstream return

Keep the diagnostic-only patch reviewable independently of recovery interfaces
and any lifecycle behavior change. Record the implementation base and head SHAs.
If creating a branch, use `git switch --no-track -c` from the reviewed base and
verify no inherited upstream; follow the shared explicit same-name push rule.
Preserve unrelated local changes.

Run targeted tests as each relevant boundary changes. Before promotion, complete
the repository checks required by `CONTRIBUTING.md`, then satisfy the configured
review gate on the final head. Preparing a corrective release must preserve the
published 4.6.0 tag/assets and produce fresh versioned artifacts and verification
evidence. Do not relabel old qualification as evidence for changed runner bytes.

After the actual prerequisite is identified and supported recovery is separately
authorized, retain the original lease and run the qualified recovery path. Then
perform one fresh ordinary preflight using the exact selected endpoint/model,
resource policy and verified native ARM64 image. Resolve the inference listener
through its authorized environment procedure. If still unavailable, retain its
own preflight failure with zero participant stages and stop dependent execution.

Completion: original failure, assistance/recovery, new attempt and cleanup are
separately traceable. The paused campaign and heartbeat are not implicitly resumed
by a successful registry recovery or standalone preflight.

## Acceptance traceability

| Original criterion | Implementation tasks | Required closure evidence | Current state |
| --- | --- | --- | --- |
| AC1 Diagnose the observed denial | E002-02, E002-03, E002-05, E002-07 | Failing phase/category and supported cause or explicit retrospective evidence limit | Unresolved |
| AC2 Reproduce failed-preflight lifecycle under a real disposable lease | E002-04 | Integrated fixture and preserved predecessor accounting | Integrated lifecycle regression passed; original result preserved |
| AC3 Release only with complete required proof; deny precisely otherwise | E002-04, E002-06 | Positive and negative proof matrix with recovery receipts | Synthetic recovery and denial matrix passed; live recovery excluded |
| AC4 Preserve writer, ownership, inference, authority and cleanup denials | E002-02, E002-04, E002-06 | Safety regression matrix | Focused safety regressions and full maintainer suite passed |
| AC5 Historical replay and mixed near-capacity histories | E002-04 | Combined heterogeneous fixtures; unchanged unrelated bytes and receipts | Combined full-capacity qualification/ordinary history passed |
| AC6 macOS write/replace/fsync and failure behavior | E002-02, E002-04, E002-09 | Native filesystem tests and injected failures; real-path limits recorded | Native temporary-filesystem and injected-failure regressions passed |
| AC7 Actionable sanitized diagnostics | E002-01, E002-02, E002-03 | Phase/subreason assertions, canary and spoofing tests, both output routes | Typed phase/condition/operation and redaction regressions passed |
| AC8 Fresh ordinary preflight after authorized recovery | E002-07, E002-10 | Exact environment/lease identities and new preflight result | Not performed |
| AC9 Preserve original failure and separate recovery/attempt accounting | E002-03, E002-04, E002-06, E002-10 | Original hashes unchanged; distinct recovery and attempt identities | Separate recovery receipts and sealed-result preservation tested; live closure excluded |

## Baseline verification

Observed on macOS 26.6.2, ARM64, Python 3.14.5 against the pinned source:

- 55 existing ownership-registry tests passed.
- 66 existing admission-diagnostic, qualification-historical-admission and
  resource tests passed.
- 13 focused synthetic scenarios passed, including the failed-preflight
  lifecycle, historical-helper guard, nine denial conditions in total, valid
  sensitive recovery, and histories of 6,777 and 8,192 records.

The leases and filesystem operations were real; Docker observations and
preflight failures were synthetic. No live registry recovery, native Docker/model
qualification or downstream retry was performed. The large histories contained
ordinary synthetic records and did not reconstruct the 66 private qualification
receipts. See the retained JSON artifacts for exact commands, scope and outcomes.

## Implementation ledger

Append one row per meaningful implementation or verification event. Preserve
earlier observations and record amendments explicitly; do not rewrite a failed
attempt as successful after a later retry.

| Date | Task or evidence ID | Change or observation | Commit / evidence | Outcome and remaining work |
| --- | --- | --- | --- | --- |
| 2026-10-27 | BASELINE-01 | Bundle/source verification and offline analysis | [Verification](env-admission-002-evidence/verification.json) | Diagnostic gap confirmed; original cause unresolved |
| 2026-10-27 | BASELINE-02 | 121 existing tests and 13 focused synthetic scenarios | [Results](env-admission-002-evidence/results.json) | Baseline behavior established within documented scope |
| 2026-10-27 | PLAN-01 | Fix plan saved; baseline artifacts retained outside `/tmp` | This file and `env-admission-002-evidence/` | All implementation tasks remain planned |

For each task completion, record the implementation head, changed boundaries,
tests and exact outcome, new evidence paths, original evidence hashes preserved,
review dispositions and remaining limitations. For any live action, also record
the authorized scope, actual lease identity, environment identity, new attempt
identity, assistance classification and confirmed cleanup outcome.

## Initial implementation authorization checkpoint

The user authorized implementation on a separate branch and explicitly required
that the live registry and downstream campaign remain untouched. The branch was
created with `git switch --no-track -c codex/env-admission-002 HEAD` from
`8f42f86e6077307e98869ba33298c8086abdc752`; it had no upstream at that checkpoint.
Push, release preparation, installed downstream package updates and native recovery
were outside that initial implementation scope. Later push/PR/release-preparation
authorization is recorded below.

The diagnostic contract is implemented in `registry_diagnostics.py` and documented
in [REGISTRY-RECOVERY.md](../../skill/references/REGISTRY-RECOVERY.md). The public
schema uses `none_observed` and `may_have_occurred` effects. No record identity is
added to the nested diagnostic; maintenance reports expose only validated launch
UUID references and lease/registry identities, never raw paths or private payloads.

`registry-inspect` performs offline passive validation under the existing lease;
it explicitly reports untested mutation and live-observation prerequisites.
`registry-recover --output-dir NEW_DIRECTORY` records an intent before effects,
uses existing reconciliation and records a separate terminal/partial receipt.
Neither command authorizes subsequent dispatch. Both are tested only on synthetic
state in temporary directories.

Tasks E002-07 and E002-10 are deferred under the user's live-state constraint. The
original denial remains unattributed. E002-08's runtime behavior change is also
deferred: the demonstrated exception lifecycle already supports safe next-owner
reconciliation, and no observed cause justifies changing terminal close now.
E002-09 tracks local checks here; native qualification, external review and release
promotion remain separate work. No gate is marked passed by analogy to baseline
or synthetic evidence.

## Verified implementation evidence

The task statuses above refer to local implementation and synthetic verification,
not deployment, native Docker/model qualification or diagnosis of the original
live denial.

| Tasks | Implementation | Verification |
| --- | --- | --- |
| E002-01 | Closed schema in [registry_diagnostics.py](../../skill/scripts/registry_diagnostics.py) and [public contract](../../skill/references/REGISTRY-RECOVERY.md) | Catalog, spoofing, redaction, operation and capacity-condition tests |
| E002-02 | Phases/operations in registry, control-record and sensitive-cleanup boundaries; possible effects remain monotonic after quarantine | [Registry tests](env-admission-002-evidence/implementation/registry-tests.log), 147 passed |
| E002-03 | Both CLI admission failures and sealed outcomes retain the same sanitized nested diagnostic | CLI-before-output and both reviewed-release metadata routes tested without model execution |
| E002-04 | [Reconciliation diagnostics tests](../../tests/test_registry_reconciliation_diagnostics.py) plus existing ownership/history/admission suites | Failed preflight, complete/incomplete historical helper proof, full-capacity mixed qualification history, persistence failures, partial release and interrupted sensitive purge |
| E002-05 | [registry_maintenance.py](../../skill/scripts/registry_maintenance.py), `registry-inspect` | [Maintenance tests](../../tests/test_registry_maintenance.py): no record/header/inode mutation, no dispatch, missing/busy/replaced lease denial |
| E002-06 | `registry-recover`, initial durable intent and separate terminal/partial receipt | New output directory required; no dispatch; interrupted recovery and secondary receipt failure retain distinct outcomes |

The helper's explicit frozen bundle now includes `scripts/registry_diagnostics.py`.
Current bootstraps require its exact identity; historical registry metadata still
accepts the two previously reviewed bundle shapes. Historical receipt hashes and
approved campaign code revisions were not rewritten. The old credential-validator
whole-file hash remains retained; the unchanged `CredentialError` and `validate`
subset is independently pinned by its original normalized AST, and a new negative
test rejects changes to that validator.

| Date | Task or evidence ID | Change or observation | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| 2026-10-27 | VALIDATION-01 | Full suite encountered sandbox denial of temporary loopback servers and was interrupted | [Sandbox run](env-admission-002-evidence/implementation/unit-tests.sandbox-interrupted.log) | Retained; not a passing run |
| 2026-10-27 | VALIDATION-02 | Full suite exposed missing diagnostics dependency in isolated helper bundle and was interrupted | [Bundle regression run](env-admission-002-evidence/implementation/unit-tests.bundle-regression-interrupted.log) | Corrected explicit allowlist; added isolated copied-Python-bundle regression |
| 2026-10-27 | VALIDATION-03 | 172 integration tests exposed two historical whole-file pin failures | [Integration run](env-admission-002-evidence/implementation/integration-tests.log) | Retained; not a passing run; unchanged validator AST verified against pinned release |
| 2026-10-27 | VALIDATION-04 | SDK suite after preserving original validator semantics | [SDK regressions](env-admission-002-evidence/implementation/sdk-regressions.log) | 97 tests passed |
| 2026-10-27 | E002-01–E002-06 | Focused registry and maintenance verification on current implementation | [Registry regressions](env-admission-002-evidence/implementation/registry-tests.log) | 147 tests passed |

## Final local verification

Implementation commit: `b537b1942e7095f31a4c9b89a14ce2e56f17edad` on `codex/env-admission-002`.
At this verification checkpoint the branch had no upstream and had not been
pushed. The separate
tracking commit retains this plan and evidence without changing tested runtime
bytes. Unrelated `docs/design/application-agent-enhancements/` content remains
outside this change.

- Full maintainer suite: **2,671 tests passed**, no failures or skips, 581.908 s.
- Focused registry/admission/history/resource suite: **147 tests passed**.
- Historical SDK regressions after the validator pin update: **97 tests passed**.
- Offline skill-validator self-test: **passed**.
- Package/manifest validation: **passed**, 185 files.
- Patch whitespace check and original analysis-artifact hashes: **passed**.

The [implementation verification receipt](env-admission-002-evidence/implementation/verification.json)
records exact source-file hashes, the implementation commit, environment, commands,
log hashes and deferred work. The [full-suite log](env-admission-002-evidence/implementation/unit-tests.log)
supersedes earlier interrupted/failing runs without deleting them. The package
and validator outputs are retained as [package-check.json](env-admission-002-evidence/implementation/package-check.json)
and [standard-validation.json](env-admission-002-evidence/implementation/standard-validation.json).

| Date | Task or evidence ID | Change or observation | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| 2026-10-27 | VALIDATION-05 | Final full maintainer suite after bundle and historical-pin corrections | Full-suite log and implementation verification receipt | 2,671 passed; no skips |
| 2026-10-27 | E002-09 local checks | Package manifest and offline validator verified | Package/validator JSON receipts | Passed locally; native qualification, external review and release remain deferred |
| 2026-10-27 | IMPLEMENTATION-01 | Source, tests and public documentation committed | `b537b1942e7095f31a4c9b89a14ce2e56f17edad` | E002-01–E002-06 verified; live registry and downstream campaign untouched |

Captured terminal logs are retained byte-for-byte, including trailing whitespace.
The tracking commit marks these log files `-text -whitespace` in `.gitattributes`
to preserve their bytes; this metadata change does not alter tested runtime or
test sources. The verification receipt separately records this tracking metadata.

## Correctness and safety review

Review baseline: `4335f4b`, with runtime implementation `b537b1942e7095f31a4c9b89a14ce2e56f17edad`.
The review compares the branch with base `8f42f86e6077307e98869ba33298c8086abdc752`.
The user explicitly excluded operations on the live registry and downstream
campaign. All reproductions use temporary leases, registries and files with
Docker/model effects forbidden or mocked.

| Finding | Priority | Confirmed behavior before the fix | Correction | State |
| --- | --- | --- | --- | --- |
| E002-R1 | P1 | Replacing the receipt directory or its parent with a symlink could redirect terminal publication and overwrite foreign evidence before a later no-follow check failed; replacement during temporary creation also reproduced the overwrite | Hold original parent/directory FDs through recovery; use FD-relative temporary creation, rename and cleanup; revalidate namespace, modes and the prior receipt identity/content; bound receipt size | Verified fixed |
| E002-R2 | P2 | An interruption during the post-reconciliation registry observation skipped terminal receipt publication and left only `RUNNING`, despite a controlled exit 130 | Retain interruption phase and attempt one terminal receipt under the held lease; never retry reconciliation or interrupted publication | Verified fixed |
| E002-R3 | P2 | `existing_lease()` caught body `OSError` and relabeled it as an admission-lock access failure | Restrict lock-error translation to acquisition/validation; propagate body exceptions unchanged while releasing the lease | Verified fixed |
| E002-R4 | P2 | Reusing an exception object in a later operation replayed its earlier diagnostic phase and operation | Bind observation metadata to a particular nested operation invocation; preserve inner causes within that operation and refresh later occurrences | Verified fixed |

Six focused reproductions failed on the reviewed baseline (five assertions and
one error), retained in [findings-before-fixes.log](env-admission-002-evidence/review/findings-before-fixes.log).
They establish these branch findings; none attributes the original downstream
admission denial to a newly introduced maintenance command.

The first post-fix focused pass completed 32 tests successfully. Expanded tests
then exposed a test-fixture setup mistake: its failure subcase reused a registry
that the success subcase had already released. The fixture now creates fresh
pending records before injecting the daemon failure. That intermediate result is
retained in [focused-fixture-correction.log](env-admission-002-evidence/review/focused-fixture-correction.log).
Additional cases cover initial-publication replacement, late replacement,
non-symlink directory replacement, receipt tampering/links/modes, descriptor
closure, bounded output and publication interruption without retry.

The earlier implementation evidence and original analysis artifacts remain
unchanged. Review verification is retained separately under
`env-admission-002-evidence/review/`. No historical receipt, campaign result or
approved code revision is rewritten to satisfy the new tests.

## Review completion

Review fixes committed as `208121a86bec8beb4803f0cae84c7f2e502de195` against reviewed head
`4335f4b3f81994fe9afb5c5ad2d927ee7dcf835a`. No unresolved findings remain from this local review.
The original downstream denial is still not attributed; none of these findings
is presented as evidence of its original cause.

- Full maintainer suite: **2,685 tests passed**, no failures or skips, 557.823 s.
- Focused registry/history/resource/maintenance suite: **160 tests passed**.
- Final lease/queue suite including callback propagation: **34 tests passed**.
- Package/manifest check and offline validator self-test: **passed**.
- Original analysis artifacts and initial implementation evidence: preserved.

The [review verification receipt](env-admission-002-evidence/review/verification.json)
binds each finding to the reviewed/fixed commits, exact source hashes, commands,
log hashes and scope. The [full review test log](env-admission-002-evidence/review/unit-tests.log)
retains the complete final run. Focused results are in
[focused-final.log](env-admission-002-evidence/review/focused-final.log) and
[lease-final.log](env-admission-002-evidence/review/lease-final.log); package and
validator results are in [package-check.json](env-admission-002-evidence/review/package-check.json)
and [standard-validation.json](env-admission-002-evidence/review/standard-validation.json).

| Date | Task or evidence ID | Change or observation | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| 2026-10-27 | E002-R1 | FD-bound receipt publication, namespace and prior-content checks, bounded output | Replacement/tampering/link/mode/descriptor regressions | Verified fixed; no foreign evidence overwrite in reproduced cases |
| 2026-10-27 | E002-R2 | Terminal interruption receipt stays under the existing lease | Post-observation and terminal-publication interruption regressions | Verified fixed; no automatic retry |
| 2026-10-27 | E002-R3 | Lease acquisition errors separated from body and outer-timer failures | Body-error identity and queue-callback regressions | Verified fixed |
| 2026-10-27 | E002-R4 | Diagnostic origin tied to the active nested operation | Reused-error and nested-wrapper regressions | Verified fixed; inner origin preserved without stale replay |
| 2026-10-27 | REVIEW-VERIFY | Final full suite and package checks on review fixes | Review verification receipt | 2,685 passed; live registry and downstream campaign untouched |

## Release preparation and PR

The user authorized pushing the branch, opening a PR with Actions CI skipped due
to exhausted limits, and preparing the next project release. Native operations
on the live registry and downstream campaign remain excluded.

The branch was pushed with the explicit same-name refspec
`codex/env-admission-002:refs/heads/codex/env-admission-002` and now tracks
`origin/codex/env-admission-002` (`branch.remote = origin`,
`branch.merge = refs/heads/codex/env-admission-002`).
[Draft PR 9](https://github.com/Denissvgn/pi-agent-test-env/pull/9) targets `main`.
Its initial head is `56d35bada04c655ef8fcf45175a090c5edb349b7`, whose commit message
contains `[skip ci]`. Repository Actions inspection found only the managed
Copilot reviewer and no checked-in CI workflow; the first post-creation query
reported zero Actions runs and no check rollup for this head. No workflow or
branch-protection policy was disabled. The configured review remains a later
merge gate.

The latest published release is the experimental `v4.6.0` prerelease. The new
candidate is **4.6.1**, with updated package/version/archive documentation,
changelog, registry-maintenance command metadata and CLI interruption exit code.
Historical qualification text and evidence keep their original versions.

Candidate output: `dist/pi-agent-test-env-4.6.1-candidate/` (ignored build output).
The build produced five skill archive layouts, one source archive and SHA256SUMS,
with 185 package files and 392 allowlisted source files. Internal planning,
retained reports and unrelated untracked application-agent-enhancement work were
excluded. A changed-file credential-literal scan found no candidate literals.

Artifact verification was started through the repository's normal verifier,
including standards validation of all five extracted skill layouts, the complete
maintainer suite from extracted source bytes, example checks, checksums and
before/after input inventories. Build output and release notes are retained in
[the release evidence folder](env-admission-002-evidence/release-4.6.1/RELEASE-NOTES.md).
This is candidate preparation. Final configured review, merge, immutable tag,
verified uploads and release publication remain subsequent steps.

### Release verifier timeout and fresh candidate

The first archive-verification attempt exceeded the existing 600-second
extracted-source test deadline. It did not produce a passing artifact receipt;
[verification-timeout-600.json](env-admission-002-evidence/release-4.6.1/verification-timeout-600.json)
retains that outcome. The first artifact directory and build receipt are
preserved. No orphaned process for the temporary verification tree was found.

The maintainer verifier now records a finite extracted-test budget, defaults to
900 seconds and accepts an explicit integer in 60..1800 seconds. Timeout failures
retain captured stdout/stderr with exit 124 instead of losing the partial output.
This applies only to release-verification tests; runner, registry, inference and
container budgets are unchanged. A timeout is still a failed verification and
never skips tests. The publishing regressions passed 11 tests, including actual
partial-output timeout capture and invalid-budget rejection before input access.

Fix/candidate source commit: `bd0958cb8ab9c7e8c40d193300ae34ff4e954d08`.
A fresh candidate was built in `dist/pi-agent-test-env-4.6.1-candidate-r2/`.
Verification of the fresh candidate used an explicit 900-second test deadline; all first-attempt
artifacts and outcomes remain separate. [source-r2.json](env-admission-002-evidence/release-4.6.1/source-r2.json)
records the candidate identity and budget.

### Verified release candidate

The rebuilt **4.6.1** candidate passed the complete release verifier: five skill
layouts, 185 package files, 392 allowlisted source files, all checksums and file
modes, standards validation, **2,687 extracted-source tests with zero skips**,
examples, and unchanged before/after source/archive inventories. The suite ran
598.691 seconds under the explicit 900-second budget. Temporary extractions were
removed. A direct comparison also confirmed that all 392 published source files
still match the archive after updating only excluded planning/evidence files.

- Candidate source: `bd0958cb8ab9c7e8c40d193300ae34ff4e954d08`.
- Artifacts: `dist/pi-agent-test-env-4.6.1-candidate-r2/`.
- [Candidate summary and checksums](env-admission-002-evidence/release-4.6.1/candidate-verification.json).
- [Complete artifact verification](env-admission-002-evidence/release-4.6.1/artifact-verification.json).
- [Release notes](env-admission-002-evidence/release-4.6.1/RELEASE-NOTES.md).

The authorized push/PR/release-preparation scope is complete. E002-09 remains
`in_progress` only for later configured review, authorized merge, immutable tag
and publication gates. The candidate is not claimed as a final reviewed/merged
release. The live registry and downstream campaign remain untouched; E002-07,
E002-08 and E002-10 retain their earlier limits.

| Date | Task or evidence ID | Change or observation | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| 2026-10-27 | RELEASE-01 | Branch pushed with explicit same-name refspec; draft PR 9 opened | PR URL and source.json | Upstream verified as origin/codex/env-admission-002; initial Actions runs zero |
| 2026-10-27 | RELEASE-02 | First artifact verification reached the old 600-second test cutoff | verification-timeout-600.json and first candidate | Failed attempt preserved; no passing artifact claim |
| 2026-10-27 | RELEASE-03 | Bounded configurable verification deadline and retained timeout output | bd0958c; publishing-tests.log | 11 publishing regressions passed; runner/registry budgets unchanged |
| 2026-10-27 | RELEASE-04 | Rebuilt candidate verified against extracted bytes | artifact-verification.json and candidate-verification.json | 2,687 passed; five layouts verified; no tag/publication or live recovery |

## Published 4.6.1 prerelease

The owner explicitly authorized: "Waive Copilot for this release; merge and publish
using the recorded local review and verified artifacts." This is a one-release
exception to the Copilot requirement, not a change to the package's future review
policy. The retained promotion gate still says `BLOCKED` for missing completed
Copilot review; no passed hosted review was fabricated. Copilot subsequently
posted a quota refusal, which was not counted as a review. There were no unresolved
review threads or other final gate blockers.

[PR 9](https://github.com/Denissvgn/pi-agent-test-env/pull/9) was merged with an
exact-head guard on `9bcf9f90d57ba05a1e48315173104d62051629f3` and no admin bypass.
The merge commit is `cf90d19a8db094c6a6bce9eaac708efead3ef45b`; its complete tree
`33d4e0c240bc8399cf44a1ec71b6344a73892e31` matches the verified PR head. The
annotated `v4.6.1` tag points to that merge commit. Its tag object is
`dc6246ce7c6d0924cc6e0dd79168202e90af440f`.

The [4.6.1 prerelease](https://github.com/Denissvgn/pi-agent-test-env/releases/tag/v4.6.1)
was published at `2026-10-27T15:38:37Z`, release ID `425648753`. It was staged as a
draft, and all seven uploaded assets were downloaded and hashed before publishing.
Every downloaded hash and GitHub server digest matched the verified candidate.
The public release retained those same asset IDs, sizes and digests. `v4.5.0`
remains the latest stable release; no existing release/tag/assets were rewritten.

CI stayed skipped: both the verified PR head and merge commit have zero Actions
runs, and the merge/tag messages retain `[skip ci]`. The live registry and
downstream campaign were not operated on. No new native Docker/model
qualification is claimed. E002-09 is complete for this authorized prerelease
promotion; E002-07, E002-08 and E002-10 remain deferred. Earlier candidate and gate
receipts remain historical evidence rather than being rewritten as successful
hosted review or original-environment recovery.

The [publication receipt](env-admission-002-evidence/publication-4.6.1/publication.json),
[explicit authorization](env-admission-002-evidence/publication-4.6.1/authorization.json),
[unchanged blocked review gate](env-admission-002-evidence/publication-4.6.1/review-gate.json)
and [uploaded-byte verification](env-admission-002-evidence/publication-4.6.1/upload-verification.json)
retain the exact identities and checksums. This post-publication audit changes
only excluded planning/evidence files on the existing feature branch; it does not
alter the immutable merge/tag or any published asset.

| Date | Task or evidence ID | Change or observation | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| 2026-10-27 | RELEASE-05 | Owner waived Copilot only for this prerelease | authorization.json; retained BLOCKED gate | Explicit exception recorded; future policy unchanged |
| 2026-10-27 | RELEASE-06 | PR 9 merged with exact-head guard; complete tree matched candidate | cf90d19; v4.6.1 | Verified immutable release target; CI skipped |
| 2026-10-27 | RELEASE-07 | Seven uploaded assets downloaded and SHA-256 checked before publication | upload-verification.json | All bytes/server digests matched |
| 2026-10-27 | E002-09 / RELEASE-08 | Published 4.6.1 as a prerelease | Public release and publication.json | Complete within stated qualification scope; live registry/campaign untouched |

## Owner-proof follow-up review: PI-OWNER-PROOF-001

Reviewed on 27 October 2026. This section records the analysis before the
implementation tracked below; its observations are not permission to operate on
live state. The published 4.6.1 release, downstream installation, live registry,
owner evidence and downstream campaign remain unchanged.

The [new downstream issue](/Users/bramen/Projects/WorkChord/docs/plans/autonomous-agentic/reports/upstream/pi-agent-test-env/ENV-ADMISSION-002/owner-proof-gap/issue.md)
reports six blocking released records among 31 ordinary application helpers.
All four payload hashes in its manifest verified. The reported registry source
hash matches the reviewed local 4.6.1 source exactly:
`a01599004d80e75b9ca93f8730ea8672a73936f5ef0eb7afc054c2cf66c91401`.
The report's private proof graph and live observations were not independently
re-executed here. A bounded downstream wiki query was unavailable with
`InvalidRequestError`; this review uses the supplied report and targeted upstream
source, without interpreting unavailable wiki results as a negative fact.

This provides the current failing prerequisite that the original report lacked:
`application_cleanup / application_cleanup_pending / validate / none /
none_observed`. It does not retrospectively prove that the original 4.6.0 denial
had the same cause. The diagnostics added in 4.6.1 are working as intended; that
release deliberately preserved the existing admission predicates.

### Confirmed contract behavior

The [offline fixture](env-admission-002-evidence/owner-proof-gap/reproduce.py) and
[observations](env-admission-002-evidence/owner-proof-gap/results.json) reproduce
three generic execution shapes in temporary registries. External subprocesses
and PID observations are forbidden in the fixture. Each shape returns pending,
and each produces the reported closed diagnostic when a dependent pending record
exists. The fixture also confirms the existing all-released early return and the
different ordinary-release predicate. The [existing registry suite](env-admission-002-evidence/owner-proof-gap/ownership-tests.log)
passed **55 tests**, no failures or skips, in 2.181 seconds with mocked Docker.
These are source-contract observations, not native cleanup or qualification.

| Finding | Evidence and implication |
| --- | --- |
| P1: Missing bridge from genuine later owner cleanup to ordinary admission | `_application_stage_pending()` requires an agent descriptor, a removed credential receipt, finalized cleanup-confirmed state, a cleanup-confirmed process/helper receipt, and absent contexts. Zero agents returns pending. Failed sealed accounting cannot be cleared by this route without changing historical files. |
| P1: An absent name is insufficient for the interrupted no-CID shape | The report's six physical observations include one Docker name rather than an immutable CID. `confirm_absent()` intentionally requires a real 64-hex CID for application helpers. This path needs evidence of the actual launch lifecycle; it cannot inherit the five CID-backed observations. |
| P2: Release and later historical validation express different scopes | `OwnedHelper.cleanup()` can release the helper before coordinator context purge and final stage/credential accounting. `Registry.release()` accepts the ordinary caller's `sensitive_clean=True`; it does not establish the later stage predicate. `validate_history()` skips ordinary history when nothing is pending. A later unrelated pending record exposes the unresolved proof obligation. |
| P2: Existing owner-side overlays are disconnected from installed ordinary admission | There is already an exact-ID diagnostic overlay validator and narrower later physical-absence replay. They preserve failures, but are maintainer-only and do not supply the installed ordinary-helper receipt. They must not be imported into the skill through an implicit source-checkout dependency. |

The guard is correct to deny incomplete proof. The repair is a supported proof
and lifecycle contract, not weakening that guard, deleting the pending records,
selecting another lease, or treating `released` as comprehensive cleanup proof.
The P1 classification is justified by blocked integration work; this report does
not demonstrate a credential disclosure or an admission bypass.

### Per-shape owner evidence

The following are report observations, augmented by exact matches found in
maintainer source. They do not attest that those validators currently pass.

| Launch | Retained shape | Existing source clue and required follow-up |
| --- | --- | --- |
| `03c973f8-72c0-4c85-8244-396f5cde932b` | Failed agent, recorded CID | Listed by `application_operational_replay.RETAINED_UNCERTAIN_ROWS`, origin 12. Its later physical-absence adapter is narrower than a complete credential/context cleanup receipt. |
| `f0751c6c-3bf7-45ec-b7ee-601a0f9d1bdb` | Helper-only, recorded CID | No exact-ID adapter found in the targeted source search. Establish the actual owner, terminal command, bootstrap/authority scope and cleanup closure. |
| `f707c0df-3517-4d80-8e9c-cede2eaa8696` | Failed agent, recorded CID | Listed by the same retained replay, origin 10. Retain its raw uncertain accounting; audit private-state coverage separately. |
| `7640af6b-d857-49c6-9e12-a5c168abf405` | Failed agent metadata, no recorded CID | Establish whether a real CID survives in original owner evidence. Otherwise a reviewed interrupted-intent contract must prove launcher termination, source ordering, owned-target absence and sensitive cleanup without inventing a CID. |
| `eb0c56da-b04a-4ae1-9261-d01cec7a12c8` | Helper-only, recorded CID, workspace absent | Workspace absence alone does not close parent/bootstrap, controls, runtime or retained evidence scope. Missing historical workspace identity remains an explicit gap if it cannot be established. |
| `e049b004-7407-4e08-9f4a-a928856d0685` | Helper-only, recorded CID | `application_diagnostic_cleanup.py` names this exact launch/CID and validates a failed-diagnostic hygiene overlay. It returns carry with `driver_status=BLOCKED`, `cleanup_accounting=FAILED`, zero native rows and `native_success_attested=False`. Reuse its real proof graph after auditing scope; ordinary admission currently has no bridge to it. |

At least three records have exact upstream qualification/diagnostic source
lineage. The owner responsible for those executions must establish their proof;
WorkChord should not fabricate an upstream-owner attestation. Five reported
workspaces still exist and were not scanned or purged. The original lease inode
is reported as `284885578`; retain its actual identity and namespace.

The existing `qualification_preworker_cleanup` contract remains narrowly bound
to two roots, 7+12 launches, zero participant segments, an exact failed stage and
controller, real CID, service receipts and specific private-state evidence.
Do not broaden its name or accept arbitrary qualification-looking records.

### Recommended shared cleanup contract

Introduce a versioned **ordinary application-helper admission-cleanup receipt**
and one shared verifier used by supported owner recovery, historical admission,
inspection and future normal finalization. The name is a design proposal, not an
existing CLI or schema. Existing valid legacy evidence remains valid; a selected
malformed, mismatched or stale new proof must fail rather than silently falling
back to a weaker branch. Qualification service/preworker subtypes retain their
existing exact validators and cannot change subtype through this mechanism.

Keep four meanings separate: the original task outcome; the original cleanup
accounting; the later cleanup observation; and permission for a fresh host
admission. Later hygiene can make the last one true while the first two remain
failed. An old `safe_to_continue=False` may concern the discarded task workspace
or frozen campaign; it cannot simply be negated or reused as a fresh admission
decision. No new proof establishes native task success, qualification success,
business completion, or permission to resume the old campaign.

The contract must establish all of the following:

1. **Exact subject and authority.** Bind the original lease/registry identity,
   generation and launch UUID, canonical immutable intent, daemon, image,
   mounts, private root, run/attempt/stage/segment bindings where they actually
   exist, and original code identity. Specify immutable-field normalization and
   separately bind real CID provenance. Inventory hashes detect changes; they
   are not signatures or owner authorization. The same-user ownership model and
   approved proof producer remain explicit.
2. **Actual execution shape.** Represent agent-backed, helper-only and
   interrupted-intent histories as distinct checked variants. An empty stage
   list needs a positive, bounded no-agent/worker/issued-context proof from the
   original controller and source order; it is not permission to omit sensitive
   state. Prepared stage metadata is not proof a participant ran. Do not add
   synthetic stages, use a zero CID or substitute an unrelated helper.
3. **Writer and request closure.** Resolve the parent, helper, participant and
   relevant Docker client capabilities for the selected file/authority scope.
   Require exact original terminal/ownership evidence; a numeric PID alone is
   insufficient. For a missing CID, either recover an actual bound CID from
   retained evidence or prove the reviewed interrupted-launch case, including
   no delayed creation and no remaining positively owned target. Name absence
   alone, an expired deadline or lease availability cannot establish this. If
   the evidence cannot close the case, leave that record blocked. Unresolved
   inference or other resource ownership remains a separate prerequisite.
4. **Complete sensitive file scope.** Account for the owned workspace, helper
   private store, parent envelopes, application/native-budget contexts,
   sessions/child state, controls/outboxes and retained helper evidence that
   actually existed for that shape. Bind retained directories by descriptor/
   FD identity and validate current no-follow absence or exact retained clean
   inventory. Scanning with a partial or unavailable secret set is not a
   cleanup proof. A separately authorized discard may cover an owned disposable
   workspace; it is not permission to delete unrelated paths. No key value,
   reusable capability or secret-value digest belongs in a public receipt.
5. **Honest scope.** Historical physical-absence and task-scoped file proofs
   cannot be promoted into global actor termination, a complete holder census,
   credential memory erasure or all application authorities being revoked.
   Preserve any known `PENDING`/unknown fields. A reviewed source-specific
   capability exclusion can be accepted only for its existing file boundary
   when that is sufficient for the documented admission contract. If admission
   requires more, obtain additional proof rather than upgrading its claim.
6. **Durable acceptance and replay.** Store new evidence outside sealed runs and
   registry record files, in an owner-only store bound to the original lease.
   Use explicit proof selection and an accepted per-launch index; do not search
   arbitrary directories or run callbacks supplied by a receipt. Bound the
   transitive read closure, schema, bytes, count, path modes and no-follow FD
   identities. Commit the receipt before its accepted index or any release
   transition, with durable intent and terminal/partial-effect reporting.
   Already released original records need no status flip. Crash recovery must
   revalidate proof and current ownership before adopting incomplete publication.
   Revalidate paths and retained hashes on replay without treating later PID
   reuse as a new historical writer. An old inspection/recovery report alone
   is not an accepted cleanup proof.

Owner tools may have adapters for genuinely different historical evidence
formats. All adapters must produce the same semantic contract, with closed
reviewed provenance and no project IDs or fixed launch counts in the generic
runtime. Preserve existing exact owner validators as authoritative inputs where
compatible. Never accept an arbitrary external `PASS` report or human-entered
cleanup boolean as an equivalent adapter. Keep the full owner evidence private;
the installable package must not depend on this checkout's `tools/qualification`
or embed a workstation's reports and absolute paths.

### Lifecycle and integration changes to implement

Future normal execution should persist enough custody before dispatch to explain
interruptions: intent, launch attempt, actual CID capture, bootstrap send, authority
and context issuance, worker launch, writer closure, physical cleanup and private
cleanup. Preserve the existing order that persists CID before sending bootstrap.
Close the gap between helper cleanup and subsequent coordinator/context/stage
finalization by producing the common durable receipt at the final applicable
boundary. Requiring a finalized stage inside the current early helper cleanup
would create an ordering cycle; refactor the finalizer explicitly. A discarded
workspace may justify a fresh-host cleanup receipt while the task stays failed.

The supported owner-cleanup command should first inspect exact selected subjects
without effects, then perform only authorized owned cleanup under the original
lease. It must never start a probe, Pi participant, application workflow or model
request, manufacture historical metadata, or call `application_credentials.recover`
as an unguarded shortcut. That existing function changes credential receipt files
and does not resolve the complete historical proof gap. Generic `registry-recover`
continues to refuse unresolved application helpers and only handles its existing
dependent ordinary resources after accepted owner proof.

Update every actual consumer of the new contract: ordinary history validation,
inspection, recovery, finalization, runtime/package manifests and any helper
trusted-code closure that gains a dependency. Review the SDK admission kernel's
closed record shapes, subtype rules, read authority and source pins. A separate
proof store avoids injecting a new field into frozen records, but its new read
authority still needs explicit integration. Do not silently reinterpret frozen
qualification kernels or make their all-released shortcut a recovery path.
Decide and test any change to that shortcut as an explicit compatibility policy.

Improve read-only inspection to report all affected launch UUIDs with closed,
bounded failure shapes such as no-agent evidence, pending credentials, incomplete
stage/process cleanup, missing CID and insufficient owner coverage. Keep private
paths, raw exception messages and credentials outside public diagnostics. A
diagnostic summary does not become cleanup authority.

### Follow-up work and acceptance

| ID | Deliverable | State |
| --- | --- | --- |
| OP-01 | Verify sanitized report and reproduce the three contract shapes without live effects | verified: four hashes, three cases, 55 existing registry tests; implementation regressions retained below |
| OP-02 | Owner-side audit of all six proof graphs, including existing exact adapters and remaining workspace/authority scope | static source/shape audit complete; private/live owner proof audit deferred under the user's exclusion |
| OP-03 | Freeze shared receipt variants, proof authority/read closure, replay and admission-scope semantics | verified locally: [final evidence](env-admission-002-evidence/owner-proof-gap/implementation/verification.json) |
| OP-04 | Implement explicit owner inspection/cleanup and durable proof publication under the original lease | verified locally for released ordinary histories with complete original custody; missing actual CID, unrecognized scope and pending helpers stay blocked |
| OP-05 | Produce the same proof through normal lifecycle finalization without rewriting failed accounting | verified locally, including actual process/CID/wait witness production |
| OP-06 | Integrate registry, SDK/kernel, packaging and diagnostics compatibility | verified locally; record format 3 fences older readers; frozen SDK proof-read extension explicitly required |
| OP-07 | Complete regressions, applicable native ARM64 qualification, review and a new corrective release | local regressions/package verified; native qualification/promotion/release deferred; 4.6.1 stays immutable |
| OP-08 | Separately authorized owner cleanup, accepted proof, one fresh generic recovery, then fresh downstream gates | deferred; no current authorization to operate on live state |

Start implementation with negative regressions for all three shapes and with
preserved byte hashes of original released registry records and sealed run,
process, stage, credential and result metadata. Separately authorized sensitive
file cleanup may remove the exact proven-owned private material; it must not
rewrite failed accounting. Add positives only for genuinely complete proof. Cover:

- Valid agent-backed and helper-only closure; helper-only with any undisclosed
  context/writer must deny. No-CID with proven original launch closure may be
  supported, while absent-name-only, pending Docker launch and borrowed CID deny.
- Wrong lease, daemon, registry, generation, UUID, code identity, intent, mounts,
  descriptor/workspace identity or secret/authority scope; missing, stale or
  rehashed false evidence; sibling records sharing a runroot; all helpers must
  be independently covered, without a count/ID allowlist.
- Existing diagnostic overlay and narrower physical replay preserve `FAIL`,
  `BLOCKED`, cleanup uncertainty and qualification ineligibility. A file-only
  proof cannot satisfy a broader authority requirement. A failed explicit new
  proof never falls back to treating old history as clean.
- Successful physical/helper cleanup followed by coordinator/context purge,
  credential finish or terminal metadata failure. Normal success and fresh
  admission use the same scoped evidence semantics, without reopening old work.
- No-follow ancestors, symlinks, hardlinks, changed directory/receipt identity,
  insecure modes, duplicate/unknown JSON fields, boolean/integer aliases, byte/
  count bounds and exact allowed transitive reads; no raw secret or exception
  leakage.
- Interruptions at every receipt/index/release write and fsync boundary;
  replacement before failed fsync; owner death and PID reuse; one record proved
  while another remains blocked; current paths recreated after cleanup. Retain
  partial evidence and never dispatch or automatically retry.
- Legacy valid cleanup, exact qualification service/preworker replay, both
  reviewed Pi routes and affected SDK/kernel/runtime consumers; applicable local
  Docker checks on an inspected native ARM64 image before any future PR push.

The owner audit must name unsupported cases honestly. If one record cannot be
proven, do not claim the environment is cleared even if five are accepted. After
all required owner proofs are accepted and an independently authorized generic
recovery completes, run separate fresh image/browser/inference/smoke gates and a
new canonical WorkChord pilot. The old API refusal remains a separate issue.
Historical campaign flags, frozen runner identities and resume authorization
remain unchanged.

## Owner-proof implementation tracking

Implementation branch: `codex/pi-owner-proof-001`, created without tracking from
`cb370043e28439927a44c117a025a9b246c909d9`. Verified no upstream and no branch
remote/merge configuration. The earlier uncommitted review addendum and evidence
were carried into the requested branch. Unrelated untracked
`docs/design/application-agent-enhancements/` content remains untouched.

The user authorized implementation and regression tests while explicitly
excluding the live registry and downstream campaign. All owner requests,
terminals, snapshots, files, leases, registries and Docker observations used by
the new regressions are disposable synthetic fixtures. No real owner proof is
imported, no installed package is replaced and no integration is dispatched.

### Completed implementation boundaries

- `application_owner_cleanup.py` defines the closed subject/request, original
  process invocation/terminal and snapshot witnesses, retained-terminal and
  runtime-finalization receipt variants, explicit selection and create-only
  acceptance index. All use the original lease; evidence is bounded and read
  through no-follow descriptors. Public CLI output omits private evidence paths.
- `application-owner-inspect` observes all ordinary helper shapes offline;
  `registry-inspect` includes the same per-helper observations.
  `application-owner-recover` requires explicit discard authorization, exact
  retained custody, PID absence at initial acceptance, matching daemon and exact
  container/name plus launch-label absence. It only discards the bound disposable
  host-file scope; it neither launches nor removes containers. Already released
  records and failed run/process/stage/credential metadata remain unchanged.
- Initial receipt and parent-directory persistence precede cleanup. Terminal
  receipt publication precedes the acceptance index. Separate selection witnesses
  make missing indexes fail closed. Interruptions/late failures retain partial
  outcomes without automatic continuation or overwriting an accepted index.
- New normal intents carry `owner_cleanup_contract: 1`. Host custody records
  precede launch, persist CID binding before bootstrap, and retain helper cleanup.
  Normal final close produces the common receipt only after the existing complete
  stage cleanup predicate, or an actually completed helper-only lifecycle with no
  context tree. Failed stage accounting is not regraded. Retained clean workspaces
  get identity plus bounded inventory checks. Deleting custody does not remove
  the new intent's proof obligation.
- Ordinary history validates explicitly selected proof even when all records
  are released, preserving legacy semantics when no new contract/proof was
  selected. Qualification service/preworker validators remain separate. Original
  historical records are not rewritten to add a contract marker; their complete
  independent selection/index/receipt store must be retained.
- The frozen SDK policy refuses the new store with
  `owner_cleanup_policy_extension_required`: its old closed read authority is not
  enlarged implicitly. This is an explicit compatibility stop, not qualification
  of a new policy or a way to resume an old campaign. New native qualification
  must select and review an appropriate proof read scope first.
- Public references, CLI discovery metadata, unreleased change notes and the
  package manifest are updated. This is an unreleased branch; versioned 4.6.1
  assets, tags and installation evidence remain immutable. The new module is a
  host dependency; no helper-service trusted-code list is broadened. Existing
  frozen helper boot tests exercise that dependency boundary.

### Evidence and intermediate outcomes

All logs are under `env-admission-002-evidence/owner-proof-gap/implementation/`.
Failed/intermediate attempts are retained instead of being replaced by passing
results.

| Evidence | Actual outcome |
| --- | --- |
| `regressions-before.log` | 15 new cases fail on the baseline because the proposed owner interface does not exist |
| `focused-first.log` | Initial 15 owner-proof cases pass after the first implementation |
| `integration-attempt-1.log` | 180 cases; 22 local-service errors in the restricted sandbox; a representative failed case passes unchanged with loopback access |
| `expanded-first.log` | Two test expectation errors: scoped OS failures correctly become RegistryError; assertions corrected to preserve that diagnostic contract |
| `integration-attempt-2.log` | 293 cases; two stale source-test expectations: the closed catalog gained one denial, and unrelated lifecycle instrumentation changed the whole-file authority-source pin |
| `expanded-second.log` | New negative test mutation did not match the actual method text; corrected the fixture mutation; no product behavior changed for that correction |
| `focused-finalization.log` | 35 cases pass, including 33 owner cleanup cases and exact authority-projection checks |
| `source-before-suite.json` | Exact hashes of 395 allowlisted candidate source files before the full maintainer suite |
| `unit-tests-attempt-1.log` | Intermediate candidate: 2,722 passed; see suite-attempt-1.json |

The historical application authority whole-file pin remains unchanged. A separately
pinned exact `Authority.launch_spec` AST from the baseline permits unrelated host
cleanup instrumentation, while a negative test rejects changed actor projection.
The existing credential validator subset pin remains intact. The new SDK denial
is explicitly included in its closed 154-code catalog.

### Deliberate remaining boundaries

The current report does not contain enough raw owner evidence to accept the six
real records here. In particular, external `PASS` hygiene reports and narrow
physical-absence replays are not automatically converted into terminal/snapshot
witnesses. Their owners must audit real coverage and adapt genuine retained facts;
missing waits, original snapshot identity, or broader authority closure cannot be
fabricated. Unknown external parent scope is rejected. The recognized original
private-envelope binding must already be absent; this interface does not purge
an external parent authority directory. Initial PID reuse without compatible
identity evidence stays blocked; accepted historical replay never probes old PIDs.

OP-02's private audit, a qualified SDK read-scope extension, real ARM64
Docker/browser/inference/application qualification, real cleanup, downstream
rebinding and release promotion remain deferred. They are not passed gates or
implicit consequences of the unit results. No live registry, downstream campaign,
owner proof or original failure artifact was operated on in this implementation.

### Full-suite and namespace review follow-up

The first complete candidate passed **2,722 tests**, no failures or skips, in
543.211 seconds. Its 395-file allowlisted source inventory remained unchanged;
`suite-attempt-1.json` records the result. A second hardened candidate passed
**2,727 tests**, no failures or skips, in 500.579 seconds, again with the complete
source inventory unchanged (`suite-attempt-2.json`, historical log named
`unit-tests-final.log`). These are intermediate coherent candidates, not the
final namespace fix verification.

Additional review then reproduced two unsafe omissions: helper-only proof could
leave an orphan control tree, and retained-terminal proof did not require coverage
of an unexpected retained raw file. The synthetic observation is preserved in
`orphan-control-before.json`; `scope-regressions-before.log` retains two failed
assertions. Three corresponding regression assertions, including changed normal
retained-run output, fail before correction in `namespace-before.log`.

The correction derives control scope from every real stage descriptor, including
non-agent kinds, and refuses unexplained control trees. It discards only bound
segments/inboxes/outboxes/child state, preserving original metadata. Retained
terminal acceptance now requires a recognized retained namespace; uninspected raw
logs, runtime copies and unknown artifacts are rejected before effects and are
not deleted as a workaround. Their actual owner needs an adapter with reviewed
hygiene coverage. Normal finalization, whose original complete cleanup gate has
passed, additionally binds the entire remaining retained-run inventory and helper
evidence. Changing those bytes invalidates replay.

Private receipt directory modes are rechecked on replay, source/stage bindings
are checked before effects, proof-store mutations are reflected in effects, and
the custody directory chain is synced before dispatch. A real local helper
process test under a temporary lease confirms CID custody precedes bootstrap and
that proof files contain none of its disposable fixture key values. Docker is
emulated; this is not native container or application qualification.

`namespace-after.log` passes all **42** owner cases after the namespace correction.
Final full-suite verification against the resulting candidate is pending. No
source from the earlier published release, live registry or downstream campaign
was changed by these observations.

### Proof-store publication review

The namespace candidate passed **2,732 tests**, no failures or skips, in 498.212
seconds, with its complete 395-file source inventory unchanged. The result is
retained in `suite-attempt-3.json` and `unit-tests-scope-final.log`.

Subsequent publication review reproduced regular-directory replacement of the
companion proof store. The earlier companion writer could append a new acceptance
index into the replacement directory. This was a new, unreleased implementation
finding, not the original downstream cause. `store-replacement-before.log` and
`store-regressions-before.log` retain the failing reproduction and three failed
regressions for index, custody and selection publication.

The store identity is now bound to the held registry operation. Selection writes
use an already-open directory descriptor, custody/finalization creation duplicates
a retained parent FD, and the shared receipt helper accepts that internal bound
parent capability. Normal custody also retains its actual directory identity.
Namespace replacement or disappearance blocks without writing into a foreign
directory or automatically rebuilding a lost bound store. Acceptance is rechecked
after publication. Existing default receipt callers retain their behavior.

Owner CLI Docker observations now use the existing reviewed Docker-environment
allowlist, excluding unrelated exported application/inference keys. No key value
is resolved or copied to proof files. This does not attest global holder or memory
cleanup.

`store-regressions-after.log` passes 68 owner/receipt cases. The final affected
lease/registry/diagnostics/SDK set passes **277 tests** in 20.421 seconds in
`store-affected-final.log`. New owner cases explicitly forbid external subprocesses
except the separate local helper integration fixture; Docker/model boundaries
remain emulated. Final full-suite verification of this hardened candidate is the
remaining local gate. Native owner migration and release gates remain deferred.

### Immutable identity and original witness refinement

The store candidate passed **2,737 tests**, no failures or skips, in 535.673
seconds, with the 395-file source inventory unchanged (`suite-attempt-4.json`).
Further contract review retained the original strict application CID requirement:
a completed Docker CLI and absent name/label set cannot by themselves exclude a
delayed create. `immutable-identity-before.log` reproduces this missing guard and
an unreviewed launcher authority environment as two failing assertions.

An interrupted record without its own CID now requires a genuine original
`owned_container_identity` witness binding a real CID to its exact launcher,
intent, daemon, generation, labels/mounts/image identity. Physical observation
uses that immutable ID without changing the historical record. Missing, zero,
borrowed or mismatched identity stays blocked (`owner_identity_required`). Helper
launcher environment values are restricted to the reviewed helper forms.

Normal execution now emits original snapshot and launcher-invocation witnesses,
persists the actual observed CID independently before the primary registry CID
update and private bootstrap, and records a launcher terminal only after a real
wait produced its return code. The identity deadline is rechecked; no time budget
is reset or extended. A local real-process test verifies this ordering and actual
wait identity. Original controller terminal evidence still belongs to the actual
outer owner; this module never invents it. Existing historical formats still
need their owning reviewed adapter rather than retrospective fabrication.

New ordinary helper intents use schema 3 with contract 1, so older readers fail
closed at the record parser instead of ignoring the proof obligation. Historical
schema-1/2 records remain byte-for-byte unchanged. New-schema qualification
reclassification and malformed contract aliases reject. Frozen SDK policies
still require a separately qualified proof-read extension. Historical sidecar
migration requires a compatible controller cohort; older clients do not consume
those receipts and are unsupported for it.

Receipts retain current runner content identity for tracing. The original
helper-code identity remains bound through the immutable intent. Neither hash is
a signature or qualification claim. `identity-affected-final.log` passes 280
affected cases before the witness-producer integration; `witness-producer-first.log`
retains one actual launcher-form parser mismatch, corrected to recognize the
helper's fixed `--workdir=/pi-client/state` form. `witness-affected-final.log` then
passes 325 affected owner/helper/registry/SDK cases. The final full candidate will
include these refinements and the tracing metadata field.

## Owner-proof local implementation completion

The final candidate passed **2,741 tests**, no failures, errors or skips, in
**536.741 seconds** on native macOS ARM64 with Python 3.14.5. All **395**
allowlisted source file hashes match the inventory recorded before the suite;
the tested runtime/test/package bytes did not change during verification.

- [Final verification receipt](env-admission-002-evidence/owner-proof-gap/implementation/verification.json).
- [Complete final test log](env-admission-002-evidence/owner-proof-gap/implementation/unit-tests-complete.log).
- [Exact tested source hashes](env-admission-002-evidence/owner-proof-gap/implementation/source-before-complete-suite.json).
- [Package/manifest verification](env-admission-002-evidence/owner-proof-gap/implementation/package-check-complete.json): 187 files, complete manifest coverage.
- [Fresh extracted package verification](env-admission-002-evidence/owner-proof-gap/implementation/standalone-package-complete.json): isolated import origin, both CLI help routes, seven offline standard checks, unchanged source/extraction, Python 3.10 syntax checks. Execution used Python 3.14.5; this is not Python 3.10 execution qualification.
- [Retained verification procedure](env-admission-002-evidence/owner-proof-gap/implementation/verify_package.py).
- [Prior release artifact integrity](env-admission-002-evidence/owner-proof-gap/implementation/previous-release-unchanged.json): all seven 4.6.1 candidate assets retain their recorded hashes; the local release tag still points to `cf90d19a8db094c6a6bce9eaac708efead3ef45b`.

There are **52** owner-specific tests, including a genuine local helper process
under a temporary lease with Docker emulated. Existing helper, historical
qualification, resource, SDK, outcome and publishing regressions are included in
the full suite. The final 325-case affected suite also passed. Failed and
intermediate attempts above remain retained; none was relabeled as native
integration evidence.

The implementation scope is complete locally: shared versioned proof, explicit
offline inspection and bounded owner cleanup, durable original witness capture,
finalization/replay, namespace/persistence guards, record-version fencing,
sanitized diagnostics and self-contained package documentation. Generic recovery
still refuses unresolved application helpers. New owner cleanup only accepts
already released ordinary histories with complete recognized original custody.
It never fabricates a CID, wait, agent stage, private cleanup fact or successful
old outcome. An interrupted history with no actual original CID remains blocked.

The private proof audit/adaptation for the six real records, qualification of a
new SDK read scope, native Docker/browser/inference/application checks, actual
owner recovery and downstream activation remain deferred. The user explicitly
excluded live registry/campaign operations. No installed downstream package,
live record, owner proof, campaign flag or historical result was changed; no
real container/model/WorkChord workflow was dispatched. The independent API
refusal remains untested. No push, PR, tag, release or change to hosted CI is
authorized by this implementation completion.

Implementation committed locally as
`6d6067854e313fdc8cc4c8001352d18c3dd8bda6`. A read-only `git archive` comparison
confirmed that all 395 committed source files exactly match the tested candidate.
The verification receipt includes that commit identity. Plan and evidence are
retained in a separate local tracking commit for reviewability.

The branch remains `codex/pi-owner-proof-001`, with **no upstream configured**.
Only the requested source/tests/reference/plan/evidence files are committed;
unrelated untracked work remains untouched. No branch publication is performed.

## Owner-proof correctness and safety review

Review started on 28 October 2026 against branch head
`ec1848b0ab685c1116a355962de33e43f5864aca`, with implementation
`6d6067854e313fdc8cc4c8001352d18c3dd8bda6`. The comparison base remains
`cb370043e28439927a44c117a025a9b246c909d9`. The user explicitly excluded live
registry and downstream campaign operations. All reproductions below use
temporary leases/registries, synthetic owner evidence and mocked Docker/model
boundaries. No real owner proof is imported or changed.

| Finding | Priority | Confirmed behavior | Correction | State |
| --- | --- | --- | --- | --- |
| OPR-01 | P1 | After owner proof was accepted, generic recovery of an ordinary record from the same run called legacy credential recovery, rewriting the original failed credential receipt and invalidating the new proof. Losing both selected index/witness mid-operation could also restore that raw-repair path. | Revalidate current history after writer/status transitions and skip legacy sensitive repair for a run with accepted owner cleanup; retain selected identities for the held operation so disappearance denies. Unproven runs keep legacy recovery. | Verified fixed; final evidence below |
| OPR-02 | P2 | Reversing valid registry iteration order invalidated an otherwise unchanged retained proof. | Sort related records canonically; validate/compare saved subject sets independently of order, retaining duplicate/missing checks. | Verified fixed; final evidence below |
| OPR-03 | P2 | Runner identity I/O failure after receipt allocation leaked the directory and parent descriptors. | Observe runner identity before allocating receipt resources. | Verified fixed; final evidence below |
| OPR-04 | P2 | Nested replay readers separately passed budgets even when the transitive graph exceeded the aggregate cap. The CLI request was outside that graph and could be deleted with its workspace. | Share one reader across replay/runtime validators, repeated recovery validation and selected CLI input. Count the complete graph and reject discarded input references. | Verified fixed; final evidence below |
| OPR-05 | P2 | Reusing a private reference through the default reader permitted weaker file/directory privacy after a mode change. | Keep the strongest observed privacy requirement for each path. | Verified fixed; final evidence below |
| OPR-06 | P1 | The proof stage catalog used `browser-check`, while the actual runner emits `browser`; healthy browser/native-helper runs could fail finalization and future admission. | Match the actual worker stage kind and exercise finalization with browser plus complete agent cleanup metadata. | Verified fixed; final evidence below |

Reproductions are retained under
`env-admission-002-evidence/owner-proof-gap/review/`. `findings-before-final.log`
contains seven failing cases (six failures and one error) for the first five
findings. `proof-loss-before.log` separately reproduces selected-proof loss during
generic recovery; `browser-kind-before.log` reproduces the browser catalog error.
Earlier focused runs remain unchanged.

The first corrections pass all seven initial cases in `findings-after-first.log`.
Expanded tests also verify legacy recovery without new proof, canonical saved
subject order with duplicate rejection, loss of selected proof, and browser
finalization. The final affected set passes **336 tests**, no failures, errors or
skips, in **56.548 seconds** (`affected-final.log`). Final full-suite and package
verification is in progress. Original implementation evidence remains historical;
its 2,741-test result is not substituted for this changed candidate.

The schema versions, original ownership/daemon/CID/inference predicates, capacity
limits and qualification-subtype checks remain enforced. No thresholds or proof
requirements are relaxed. Existing valid unordered subject lists retain their
meaning; a duplicate or omitted subject does not become equivalent. The separate
read-only SDK policy still requires its explicitly qualified owner-proof scope.
Native owner audit, Docker/browser/inference/application qualification, actual
recovery, downstream activation and publication remain deferred.

### Review overlap follow-up

The six-finding candidate passed **2,752 tests**, no failures or skips, in
535.416 seconds, with all 396 allowlisted source hashes unchanged. That coherent
intermediate result is retained in `review/first-full-suite.json` and
`review/unit-tests.log`; it is not reused as verification of the later overlap fix.

One additional safety finding was confirmed:

| Finding | Priority | Confirmed behavior | Correction | State |
| --- | --- | --- | --- | --- |
| OPR-07 | P1 | Owner cleanup ignored a pending registered container from a different run that mounted the selected workspace. It could delete shared files while that known holder remained unproven. Aliased run roots and read-only overlapping mounts had the same coverage gap. | Check pending external owners' canonical mount/run-root footprints against the selected run, discard scopes and proof inputs before cleanup and before acceptance. Overlap blocks; no unrelated container is stopped. Historical replay remains passive so subsequent ordinary reconciliation can resolve pending writers safely. | Verified fixed; final evidence below |

`review/overlap-before.log` retains the first reproduction;
`review/overlap-cases-before.log` contains three failing assertions. The expanded
16-case review suite passes in `review/overlap-after.log`, including positive
disjoint-owner and later generic-reconciliation cases. The original live registry
and downstream campaign remain untouched. Final full-suite verification of all
seven corrections is in progress.

### Owner-proof review completion

All seven findings OPR-01–OPR-07 are fixed and verified locally. The final suite
passes **2,757 tests**, no failures, errors or skips, in **511.273 seconds** on
native macOS ARM64 with Python 3.14.5. All **396** allowlisted candidate source
hashes match the inventory saved before execution. The **16** new review
regressions include negative proof-loss/overlap/budget/privacy cases and positive
legacy-recovery, unordered-subject, browser-finalization and disjoint-owner cases.

- [Review verification receipt](env-admission-002-evidence/owner-proof-gap/review/verification.json).
- [Final complete test log](env-admission-002-evidence/owner-proof-gap/review/unit-tests-final.log).
- [Exact tested candidate hashes](env-admission-002-evidence/owner-proof-gap/review/source-before-final-suite.json).
- [Final package verification](env-admission-002-evidence/owner-proof-gap/review/package-check-final.json): 187 files with complete manifest coverage.
- [Extracted standalone verification](env-admission-002-evidence/owner-proof-gap/review/standalone-package-final.json): four offline import/help/standard commands, seven standards checks, unchanged source/extraction and Python 3.10 syntax checks. Execution used Python 3.14.5.

Earlier failing and intermediate review attempts remain unchanged. The initial
six-finding full run and the implementation's older 2,741-test result are not
substituted for the final candidate. Raw terminal logs retain their original
bytes through scoped Git attributes; this does not relax source checks or runtime
ownership predicates.

No unresolved findings remain from this local review. Real owner-proof migration,
native integration qualification and SDK proof-scope qualification remain the
explicit deferred gates documented above. The live registry, original owner
proofs, downstream installation/campaign and published release are untouched.
No real containers, model requests or WorkChord workflows ran. The review fixes
and plan/evidence are committed separately on `codex/pi-owner-proof-001`, which
remains unpushed with **no upstream configured**.

Review fixes committed as `59479eca953d4411a087a8d7f728606ca3cdec12`. A read-only Git archive comparison
confirmed all 396 committed source files match the final tested candidate.

## Owner-proof PR publication and 4.7.0 prerelease preparation

On 28 October 2026 the user authorized pushing `codex/pi-owner-proof-001` and
opening a PR with hosted CI skipped **after local ARM64 Docker CI passes**.
This supersedes the earlier publication deferral for this branch. It does not
authorize merge, tagging, publishing a release, live owner recovery, downstream
installation or campaign activation. The live registry and downstream campaign
remain untouched.

The next experimental prerelease candidate is **4.7.0**, reflecting the new
schema-3 / owner-contract-1 compatibility boundary. Version metadata, manifest
and changelog are prepared in `47437aa3402bd85e04ada659648301e2b787298b`.
The final code candidate is
`26d3e4aba43a64ef074ac59a83cff2df4c9a94c8`; subsequent plan/evidence commits must
keep all **398** published-source files identical to that tested candidate.

### Local CI attempts and corrections

All containers explicitly selected `linux/arm64`; image inspection verified
native ARM64 before launch. The CI image derives from the existing package-owned
native image, adding only `procps`. It uses Python 3.11.2, Node 24.21.0, Git 2.39.5
and Bash 5.2.15. CI runs non-root with two CPUs, 4 GiB memory, 1,024 processes,
bounded commands, a read-only root, no external network and only a fresh volume
plus a read-only public candidate seed. Neither the live registry, downstream
workspace, host home, Docker socket nor credentials are mounted.

| Attempt | Actual result | Resolution |
| --- | --- | --- |
| CI image build 1 | BuildKit treated the raw local image ID as a remote repository; access failed. | Use the inspected local image tag with pulling disabled, then verify the derivative's ARM64 architecture and base layers. Build 2 passed. |
| Container CI 1 | Origin, runtimes and package passed; standards failed because the temporary venv could not execute on a no-exec tmpfs. | Permit executable temporary test files within the isolated container's bounded tmpfs; keep the root read-only and all other isolation. |
| Container CI 2 | Full discovery ran 2,757 tests: 14 failures, 298 errors and one native-filesystem skip. No OOM occurred. | Fix macOS-only test temp paths, Python-version-dependent AST rendering and a request-ceiling test racing its separate handler ceiling. Preserve this failed output. |
| Native portability check 1 | 313 affected tests ran with 50 failures and 117 errors because macOS's default temp path contains an alias. | Resolve temporary fixture roots before passing them to production no-follow checks. Do not relax those checks. |
| Native portability check 2 | All 313 affected tests passed in 18.109 seconds. | Retain the corrected native result separately from the failed attempt. |
| Native pinned-source check | All 191 tests passed in 32.714 seconds. | Original pin constants remain unchanged. |
| Native filesystem/serializer checks | Four tests passed, including the exact case-alias test inapplicable on Linux. | Retain native ARM64 evidence; do not infer this outcome from Docker. |
| Container CI 3, final | All CI jobs passed. Full extracted-source discovery ran 2,760 tests in 383.890 seconds: 2,759 passed, one Linux-inapplicable case-alias test skipped, zero unexpected skips. | Its exact native counterpart passed above. All package/archive/source checks passed and candidate bytes remained unchanged. |

Portability corrections are committed in the final code candidate. The AST
adapter normalizes only empty-list rendering in a detached AST to Python 3.14's
existing format; no historical hash constant changes. Regression tests check
semantic changes and input preservation. The retained-check normalization accepts
only the exact stronger compatibility serialization at the known pin guard.
The request test still exhausts the same request limit and waits for prior
independent handlers to settle; runtime request/concurrency ceilings are unchanged.

### Completed preparation and remaining promotion work

- [x] Run actual local native ARM64 Docker CI against a clean extraction of the
  exact candidate, including complete maintainer tests, package checks, pinned
  standards checks and full release verification for five skill layouts.
- [x] Verify image architecture, extracted code origin, all 398 source hashes,
  permissions, seven asset hashes and before/after byte identity. A read-only
  `git archive HEAD` comparison also matches all 398 tested files.
- [x] Preserve failed attempts, CI drivers, image/container isolation facts,
  native counterparts and final results in
  `env-admission-002-evidence/owner-proof-gap/release-4.7.0/`.
- [x] Prepare seven verified assets in
  `dist/pi-agent-test-env-4.7.0-candidate-r2/`, checksums and separate release
  notes. No release/tag is created; published 4.6.1 remains unchanged.
- [x] Write the separate downstream handoff
  `env-admission-002-evidence/owner-proof-gap/downstream-4.7.0-instructions.md`.
  Its shell examples are syntax-checked only. No downstream command is executed.
- [x] Push with an explicit same-name refspec and verify upstream is
  `origin/codex/pi-owner-proof-001`; do not target the base/default branch.
- [x] Open a draft PR with `[skip ci]`, verify hosted Actions observations and
  attach the PR to this chat. No workflow configuration is disabled or added.
- [ ] Complete the configured exact-head review before any later authorized
  merge/publication. The earlier Copilot waiver applied only to 4.6.1.
- [ ] Upon separate merge/publication authorization, rebuild/verify from the
  final reviewed tree and publish a new immutable experimental prerelease.

The candidate ZIP SHA-256 is
`7e64444f30975232eb656aae871af6359e53faac682fa2ca8144d2f9bd7f9318`;
the `SHA256SUMS` SHA-256 is
`42abe41cc1416d53af0c0a9357efb46bb3e471a425fc6ab9fe17aaa8ac7f7567`.
The detailed receipt is `release-4.7.0/candidate-verification.json`; raw CI/native
outputs and their integrity inventory are retained separately there.

The real six-owner audit/adapters, native Docker/browser/inference/application
qualification, extended frozen-SDK proof-read scope and original API refusal
remain independent unresolved integration gates. Package CI does not qualify
them. No real Pi/model request or downstream application workflow is dispatched.

### PR publication receipt

[PR #10](https://github.com/Denissvgn/pi-agent-test-env/pull/10) is open as a
draft from `codex/pi-owner-proof-001` to `main` and is attached to this chat.
Initial published head was `81296703a8f95198cd2830cbfa6bcb9d10356b51`; its complete
398-file published-source inventory matches tested code candidate
`26d3e4aba43a64ef074ac59a83cff2df4c9a94c8`. Additional tracking updates change only
export-excluded plan/evidence files and require the same inventory comparison
before their push.

The push used
`git push --set-upstream origin codex/pi-owner-proof-001:refs/heads/codex/pi-owner-proof-001`.
Verified upstream: `origin/codex/pi-owner-proof-001`; configured remote `origin`,
merge ref `refs/heads/codex/pi-owner-proof-001`. Remote main remains
`cf90d19a8db094c6a6bce9eaac708efead3ef45b`. The PR is mergeable/clean; the initial
head has zero GitHub Actions runs and an empty check rollup. Hosted CI remains
skipped, with no workflow configuration changes. A final post-tracking-push
observation is required before handoff.

The GitHub connector returned permission error 403 for PR creation; authenticated
`gh pr create --draft` completed the authorized request. The published 4.6.1
prerelease still has its original seven assets and publication timestamp; no
4.7.0 release was created. See `release-4.7.0/publication.json` for the bounded
observation. Merge, exact-head review and release publication remain pending.
