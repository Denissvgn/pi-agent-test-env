# Retained application ownership cleanup

Application-helper cleanup is distinct from task success. A later cleanup proof
can permit a fresh host admission while an original result remains failed,
blocked, cleanup-unconfirmed or ineligible for qualification. It never resumes a
campaign, repairs a participant report or certifies business completion.

These operations hold the original existing host lease. Do not select another
lock to bypass admission. Use the owning project's Python environment. The
package remains self-contained; maintainer source-checkout tools are not loaded
by an installed skill.

## Inspect first

```bash
"$PROJECT_PYTHON" "$SKILL_DIR/scripts/pi_lab.py" application-owner-inspect \
  --lock-file "$ORIGINAL_LOCK" --lock-wait-seconds 30
```

Inspection is offline and read-only. It lists ordinary helper launch UUIDs,
agent/helper-only/interrupted shapes, recorded CID availability and the closed
conditions `cleanup_observed`, `owner_proof_required`, `owner_proof_accepted` or
`cleanup_proof_invalid`. `proof_status` distinguishes `not_selected`, `accepted`
and `invalid`. Accepted means the stored graph passed passive verification;
it is separate from admission permission. Execution shape can remain `unknown`
when the older shape reader does not recognize an otherwise valid proof format.
It does not query Docker, read keys, purge files, create missing leases or
registry directories, or dispatch an agent. `OBSERVED`/0 means inspection
completed; individual helpers can still require proof. Every report retains
`admission_authorized: false`.

For a summary without launch identifiers, use the same command with `--summary`.
The `summary` object contains helper totals, accepted-proof, required-proof,
invalid-proof and metadata-only counts, plus sorted inspection conditions.
`OBSERVED`/0 still means the observation completed. `cleanup_completed` remains
false because inspection performs no cleanup, even when stored proof is accepted.

`registry-inspect` also includes these per-helper observations, before applying
the ordinary history gates. An old `released` label or an absent container does
not replace sensitive cleanup evidence.

## Retained-terminal cleanup

The explicit owner path accepts only **already released ordinary helpers** with
complete retained parent custody. Pending/quarantined helpers still require
their original owning cleanup procedure. Qualification service and preworker
subtypes retain their separate exact proof contracts.

```bash
"$PROJECT_PYTHON" "$SKILL_DIR/scripts/pi_lab.py" application-owner-recover \
  --lock-file "$ORIGINAL_LOCK" --lock-wait-seconds 30 \
  --request /owner/private/original-custody-request.json \
  --output-dir /owner/private/new-cleanup-receipt \
  --discard-workspace
```

The request must be owner-only and the output directory must be new, outside the
registry and all retained run/mount/private scopes. `--discard-workspace`
explicitly authorizes discarding the exact proven-owned disposable workspace and
private scopes described below. Inspection does not authorize that discard.

The command requires matching original controller and launcher terminal
witnesses, the original snapshot identity, all retained agent-stage identities
where they exist, the matching daemon, exact helper absence and an empty
launch/registry-label container query. It refuses present or uncertain writers.
It never launches or removes a container, makes an application/model request,
retrieves a key, or fabricates missing stage/CID fields. A no-CID history needs
an actual immutable CID retained by the original launch guard, bound to that
launcher and exact intent. It does not write that CID into the historical record.
A completed CLI, name/label absence, a PID observation or an expired deadline
alone cannot exclude a delayed create and is insufficient. Missing original CID
evidence remains blocked.

Before discarding files, cleanup checks pending registered owners outside the
selected run too. An overlapping mount or run root, including a read-only holder
or path alias, blocks with `owner_writer_pending`; the command does not stop or
repair that other owner. Resolve it through its supported cleanup procedure first.
Disjoint pending owners do not expand the selected cleanup scope. Historical
proof replay stays passive so ordinary reconciliation can stop later pending
writers before a fresh dispatch.

The recognized private scope consists of the owned workspace, the exact helper
private root and helper evidence root, stage segment/inbox/outbox directories and the
owned child-state tree. Original stage, process, credential and result metadata
remain byte-for-byte unchanged. Parent private-envelope scope can be recognized
from the original `--private-envelope .../pi-qualification-cell-*/initial.json`
invocation and must already be absent; this command does not delete external
parent directories. Other external authority shapes require a reviewed owning
adapter and remain blocked by this interface.

The retained-terminal variant requires a completely recognized retained
namespace: the bound original metadata and known control metadata, plus empty
parent lock files. Orphan controls without an original descriptor, unexpected
control entries, uninspected raw logs, runtime copies or other retained artifacts
return `owner_scope_unsupported` before cleanup. This command does not delete or
declare those files key-free to clear the guard. Their owner needs a reviewed
adapter establishing the actual sensitive scope and retained-file hygiene.
Non-agent control scopes are handled as their actual stage kind; no synthetic
agent is created. A helper-only history is not evidence that controls never existed.

## Request and witness contract

The schema is closed: unknown fields, duplicate JSON keys, nonfinite numbers,
insecure modes, links, changed hashes or identities, unbounded inventories and
mismatched ownership reject. Every evidence reference has exactly `path` and
`sha256`, naming original parent-owned metadata outside discarded scopes.

The request has exactly these fields:

| Field | Required value |
| --- | --- |
| `schema`, `document_type` | Integer `1`, `application_owner_cleanup_request` |
| `subject` | Registry, generation, launch UUID, canonical immutable-intent hash and actual nullable CID, as returned by the installed module's `subject(record)` |
| `shape` | `agent`, `helper_only`, or `interrupted` |
| `controller` | `invocation` and `terminal` references |
| `launchers` | One launch UUID with invocation/terminal references for every related container record in the exact run/generation; an application helper missing its recorded CID additionally requires an original `identity` reference |
| `snapshot` | Original owned snapshot reference |
| `stages` | Sorted actual retained agent-stage UUIDs; empty only when no agent descriptor exists |
| `extra_private_roots` | Empty, or the exact recognized already-absent parent-envelope path with `origin` equal to the controller invocation reference |

An invocation witness has exactly `schema: 1`,
`document_type: owned_process_invocation`, `pid`, `argv`, `cwd`, `runroot`,
`registry`, `generation`, and sorted `launch_ids`. A terminal witness has exactly
`schema: 1`, `document_type: owned_process_terminal`, the exact `invocation`
reference, matching `pid`, `argv`, `cwd`, and integer `actual_exit`. It must
represent a real completed original process, not an inferred wait or a new
synthetic terminal. The first acceptance also requires PID absence; ambiguous
PID reuse remains blocked. Accepted historical replay does not probe old PIDs.

Launcher arguments must match the recorded name, immutable image, exact mounts
and launch/registry labels. Only the reviewed Docker-run argument forms are
accepted; host file-output/environment-file/volume options and arbitrary helper
entrypoints reject. The terminal set cannot omit a related launcher, including
one that failed before CID capture.

An `identity` witness has exactly `schema: 1`,
`document_type: owned_container_identity`, `registry`, `generation`, `launch_id`,
`daemon`, `container`, `image`, `mounts`, `container_id`, `intent_sha256`, and the
exact launcher `invocation` reference. The CID must be a real original 64-hex
identity, never a zero placeholder or an ID borrowed from another launch. The
remaining fields bind the original ownership and canonical intent. Unknown
historical formats need a reviewed adapter with real original provenance; a new
name lookup after disappearance cannot manufacture this witness.

The snapshot witness has exactly `schema: 1`,
`document_type: application_owned_snapshot`, `registry`, `generation`, `runroot`,
`binding`, `workspace`, and its original `[device, inode]` `workspace_identity`.
Existing agent descriptors must agree with it. A current path observation cannot
replace missing original ownership. Helper-only history needs genuine original
snapshot custody, without a synthetic agent descriptor.

These are parent custody witnesses within the existing same-user trust model,
not signatures or a defense against a malicious host owner. Do not manufacture
this format from an unrelated external `PASS` report. An unfamiliar historical
format needs a reviewed adapter that establishes the same original facts while
preserving its raw evidence and narrower scope. Missing facts remain missing.
Existing owner qualification validators are not automatically granted broader
ordinary admission authority.

## Persistence, replay and limits

Recovery durably publishes a private intent before cleanup. It uses no-follow
directory descriptors and checks identities before removal. It publishes the
terminal receipt before a create-only per-launch acceptance index in the
owner-only sibling `<original-registry>.owner-proofs` store. It does not change
already released registry records. The receipt and index are proof authority;
stdout is only a sanitized operation report.
A separate per-launch selection witness makes a missing acceptance index fail
closed. Retain the complete proof store and receipts; historical records are not
rewritten to encode an independent backup of that store. New helper intents
carry `owner_cleanup_contract: 1`, so losing their custody/acceptance files still
requires proof instead of enabling the legacy all-released shortcut.
The proof-store identity remains bound during the operation. Custody and
selection creation use retained parent directory descriptors; replacing a store
or subdirectory cannot redirect publication into a foreign directory. Loss of a
bound store blocks rather than recreating it during publication. Docker CLI
observations receive the reviewed Docker environment variables, without unrelated
exported inference/application keys.

`CLEANED`/0 means cleanup and acceptance publication completed. A fresh operation
must still pass ordinary admission and qualification. `BLOCKED`/2 or
`INTERRUPTED`/130 can follow partial file removal. Keep `recovery.json` and
inspect the reported phase/effects. There is no automatic retry, overwrite,
force-release or rollback promise. A hard kill can leave `RUNNING`; an incomplete
or invalid acceptance index blocks instead of falling back to legacy proof.

Replay rechecks the subject, original lease device/inode, all referenced
metadata hashes and current private-path absence. Recreated paths, changed
metadata, missing/tampered proof and cross-record borrowing deny, including an
otherwise all-released registry. Valid legacy cleanup remains available when
no new proof was selected. This does not change the historical qualification
service/preworker rules.
Related launch identities are compared as a complete set, independent of
directory iteration order; duplicates or missing subjects still reject. Once a
proof is selected during a held operation, losing its index and selection witness
cannot restore legacy fallback in that operation.

When generic recovery later reconciles dependent ordinary records from the same
run, it revalidates the accepted owner proof after writer/status transitions.
It preserves the original failed credential accounting instead of invoking the
legacy sensitive-file repair for that proven run. Runs without accepted owner
proof retain the existing recovery requirements.

Normal host helpers record custody before dispatch, CID binding before private
bootstrap, and actual helper cleanup. The final host close publishes the same
versioned receipt only after the existing full stage cleanup gate succeeds, or
for a completed helper-only lifecycle with no context tree. A retained clean
workspace is bound by identity and a bounded file inventory. Failed stage
accounting cannot become a normal success proof. Unfinalized current custody
continues to block admission; it cannot disappear through an all-released shortcut.
Normal proof also binds retained helper evidence and the rest of the retained
run namespace, after the original complete cleanup gate. Changes to any of those
inventories invalidate replay.
The helper retains original snapshot, launcher invocation, observed immutable CID
and completed launcher-wait witnesses under its custody directory. CID evidence
is durable before the primary registry CID update and private bootstrap; the
original identity deadline is rechecked before continuing. These are actual
parent observations, not reconstructed agent execution or synthesized waits.
Receipts include the current runner content hash for tracing, without treating
that hash as approval or qualification.

New helper launch records use schema 3 with `owner_cleanup_contract: 1`, so older
record readers reject them before dispatch. Existing historical schema-1/2
records are unchanged. Use one compatible registry-aware controller cohort;
older clients cannot consume the new historical sidecar proof and are unsupported
during this migration. Never downgrade a record or discard proof to make an old
client accept it.

Evidence JSON is limited to 4 MiB per file, 128 references and 16 MiB in the
aggregate for each complete proof graph, including its index, receipt, selected
CLI request and transitive retained evidence. Nested validators share the same
budget and retain the strongest privacy requirement for a reused path. A request
inside a scope selected for discard rejects before cleanup.
Private cleanup/inventory has 4,096 entries per root; retained
workspace inventory additionally caps each file at 16 MiB and total bytes at
256 MiB. Receipt publication retains its 4 MiB bound. Exceeding a bound rejects;
it does not authorize a higher limit or an omitted scope.

Receipts attest only their owned host-file scope. They do not claim a complete
actor census, global authority revocation or credential memory erasure. An
existing task-scoped file proof cannot satisfy a broader requirement. Frozen SDK
admission policies without authority for this proof store explicitly refuse its
presence; qualify a new policy/read scope before using one with these receipts.
Keep old campaign results, flags and frozen runner identities unchanged.

## Derived legacy requests and operation output

The closed schema-2 request selects `method: legacy_derived_v1`,
`cohort: application_owner_legacy_1` and a declared `variant`:
`standard_workspace_v1` or `diagnostic_disposable_v1`. Its exact fields are
`schema, document_type, method, subject, shape, variant, cohort, evidence, stages,
extra_private_roots`. The document type remains `application_owner_cleanup_request`;
`evidence` is an absolute `{path, sha256}` reference to the private evidence
assembly. The subject preserves the original registry/generation/launch/intent/CID
identity. Do not fabricate original witnesses or copy missing facts into a new
original-looking document. Only installed reviewed source families qualify;
unknown rules or source identities remain unsupported. The
[versioned SDK reader contract](APPLICATION-OWNER-READER.md) and independent
qualification remain separate from a request or release version.

This method uses the existing recover command and explicit discard flag. It
publishes an immutable RUNNING intent, independent anchor and selected-method
witness before any removal, then a create-only CLEANED terminal and acceptance
index. Later failure uses a separate failure record. There is no overwrite,
automatic retry or adoption. A lost/partial selected graph blocks, including after
all primary records are released. Independent-anchor loss detection requires
the new reader; an older binary cannot discover that new namespace after the
entire store is lost. Use a qualified reader/SDK before consuming this method.

New-method cleanup stdout contains closed status, completion, authority, zero
container/participant/model dispatch counters, persistence and effects. It omits
private subject/runner hashes, paths and command bodies. Invalid/unclassified
requests also use a closed diagnostic rather than an exception message/digest.
Original schema-1 compatibility output remains available for that method.

| Result | Exit | Meaning |
| --- | --- | --- |
| OBSERVED | 0 | Offline inspection completed; counts may still show required or invalid proof. No cleanup ran. |
| CLEANED | 0 | The cleanup operation verified the complete durable graph; `cleanup_completed:true`, persistence `confirmed`. |
| BLOCKED | 2 | Cleanup is not confirmed. Persistence is `not_started` before effects, otherwise `unconfirmed`. |
| INTERRUPTED | 130 | The operation was interrupted; completion stays false and possible effects remain visible. |

`effects` is `none_observed` or `may_have_occurred`; metadata publication alone
can make effects possible. A terminal can remain CLEANED after a later index or
close failure while the originating command reports BLOCKED/INTERRUPTED. Inspect
passively to determine which graph survived; never rewrite the terminal. Every
result retains `admission_authorized:false`. Historical nonzero exits and failed
credential/process/result accounting remain unchanged in the private originals.
Neither structural eligibility, stored cleanup proof nor command success alone
qualifies a downstream campaign, model integration or credential-memory erasure.
