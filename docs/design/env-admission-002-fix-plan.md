# ENV-ADMISSION-002 implementation and verification plan

Status: local implementation verified on `codex/env-admission-002`. Tasks
E002-01 through E002-06 are complete within the documented synthetic-test scope.
Live-state actions, lifecycle changes and release gates remain deferred.
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
| E002-07 | Identify the downstream failing prerequisite with narrow evidence | E002-03; E002-05/E002-06 as needed | deferred |
| E002-08 | Decide whether exceptional-exit cleanup needs a separate change | E002-04, E002-07 | deferred |
| E002-09 | Complete qualification, review and corrective-release preparation | Applicable implementation tasks | deferred |
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

## Current implementation scope

The user authorized implementation on a separate branch and explicitly required
that the live registry and downstream campaign remain untouched. The branch was
created with `git switch --no-track -c codex/env-admission-002 HEAD` from
`8f42f86e6077307e98869ba33298c8086abdc752`; no upstream is configured. No push,
release, installed downstream package update or native recovery is part of this
implementation session.

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
The branch has no configured upstream and has not been pushed. The separate
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
