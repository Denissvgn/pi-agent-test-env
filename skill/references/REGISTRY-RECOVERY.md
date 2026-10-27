# Registry admission diagnostics and recovery

Host admission reconciles prior owned execution under the same-user lease before
dispatch. A failed prerequisite remains `host-registry-unsafe`, `BLOCKED`, exit 2.
Capacity exhaustion and a busy lease retain their separate reasons. The default
lease selection, including the existing legacy-path compatibility, is unchanged.

## Diagnostic contract

Standalone admission failures and sealed run/smoke infrastructure failures can
include an additive `registry_diagnostic` object with schema 1. It does not replace
the run-level infrastructure phase or change invocation/task scoring.

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

All diagnostic strings come from closed host catalogs. They contain no paths,
keys, command output, prompts, receipt payloads or raw exception messages.
`error_digest` is a correlation value; matching guessed messages or hashes does
not establish a cause. Invalid diagnostic objects cannot supply public fields.

| Field | Meaning |
| --- | --- |
| `phase` | Registry initialization/inventory, qualification service/preworker cleanup, ordinary application cleanup, daemon observation, inference termination, writer inspection/termination, absent persistence, network cleanup, sensitive recovery, private-store cleanup, release persistence, registry write, terminal close, or recovery receipt; `unspecified` is a bounded fallback |
| `condition` | The failed closed prerequisite, such as `application_cleanup_pending`, `owned_application_cleanup_required`, `daemon_changed`, `ownership_mismatch`, `cleanup_proof_invalid`, or `filesystem_operation_failed` |
| `operation` | The enclosing operation: validation, inventory/record/proof read, temporary creation, file write/fsync, atomic replacement, temporary cleanup, directory open/fsync, daemon info, container/network inspection/removal, or purge |
| `os_error` | `none`, `permission_denied`, `read_only`, `storage_exhausted`, `io_error`, `missing`, `unsafe_link`, `invalid_operation`, `unsupported`, `resource_exhausted`, or `other` |
| `effects` | `none_observed` or `may_have_occurred`; an attempted mutation remains visible even if its error is caught and rethrown later |

Atomic replacement may succeed before directory fsync fails. An error does not
mean the registry was unchanged. Diagnostics do not authorize skipping checks on
a later admission, and `none_observed` is scoped to the reported operation rather
than a claim about every other host process.

## Inspect without recovery

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" registry-inspect --lock-wait-seconds 30
```

Inspection opens the existing lease without creating it, changing permissions,
rewriting its header or replacing its inode. It holds exclusive flock while
reading so cooperating mutating controllers cannot overlap. Missing, insecure,
replaced or busy leases deny the operation. `--lock-file` must identify the
original reviewed lease; selecting another lease cannot bypass a safety block.

Inspection performs bounded registry and retained-history validation. It uses no
Docker, model or application requests, does not quarantine records, and does not
purge or update anything. The JSON includes counts and validated launch UUID
references for pending records and released application helpers, never private
paths. Required referenced cleanup evidence is still read.

`OBSERVED` / exit 0 means those passive checks completed. The report always has
`admission_authorized: false` and lists untested daemon/writer observations,
inference termination, sensitive recovery, writes/fsync and durable release.
`BLOCKED` / exit 2 includes the available closed diagnostic. Inspection is not a
qualification receipt or proof that reconciliation will succeed.

## Recover prior ownership without fresh dispatch

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" registry-recover \
  --lock-wait-seconds 30 --output-dir /path/to/new-owner-recovery
```

Explicit recovery uses the original existing lease and the ordinary
reconciliation predicates. It can stop positively owned abandoned containers,
clean dependent resources and sensitive snapshots, and commit record transitions
only as permitted by those predicates. It has no force-release option. It never
launches a new container, probe, participant or inference request and performs no
automatic retry. No model environment is needed for these registry commands.

The output directory must be new and outside the lease, registry and retained
execution/mount/private paths. Recovery creates an owner-only directory and
durably writes `recovery.json` before attempting reconciliation. If this initial
receipt cannot be persisted, reconciliation does not start. Keep recovery
evidence separate from old campaign results and receipts.

The receipt directory and its parent remain bound to open directory descriptors
throughout recovery. Publication and temporary cleanup use those descriptors;
replacing a path with a symlink or another directory cannot redirect a write.
Before each publication, the original namespace, owner-only modes and previous
receipt identity/content are rechecked. Changed, linked or tampered receipts
block publication instead of being overwritten. Receipt size is bounded to 4 MiB.

The report records a new invocation UUID, runner content hash, lease device/inode,
registry identity, before/after counts, changed launch UUID/status transitions
and reconciliation outcome. It is informational, not authority for a later
admission. After-observation or final receipt failures remain explicit; a second
failure cannot replace an already recorded primary denial. A hard process kill
may leave the initial `RUNNING` receipt; it does not establish completed cleanup.
An interruption during the final registry observation still attempts one terminal
receipt under the held lease. An interruption during receipt publication is
reported as unconfirmed and is not retried automatically.

| Outcome | Meaning |
| --- | --- |
| `RECONCILED` / 0 | Existing reconciliation completed; a fresh operation must still pass normal admission |
| `BLOCKED` / 2 | A prerequisite or receipt-persistence requirement failed; inspect phase/condition and possible partial effects |
| `INTERRUPTED` / 130 | Explicit interruption; partial transitions may be recorded, and no automatic continuation follows |

All reports retain `admission_authorized: false`. A final receipt persistence
failure can block the command even when `reconciliation` is `completed`; this
does not imply that successful physical cleanup was rolled back.

## Choosing the next action

- For filesystem errors, inspect the actual host access/storage condition for
  the reported operation. A successful passive read does not prove write/fsync
  access. Preserve the lease and registry while correcting the condition.
- For historical qualification or ordinary application-cleanup failures, use the
  owning cleanup procedure and retained evidence. A `released` label or missing
  container does not replace required proof. Generic recovery does not authorize
  unresolved application helpers.
  [Retained application ownership cleanup](APPLICATION-OWNER-CLEANUP.md) describes
  the explicit inspection, typed terminal/snapshot evidence and separately
  retained ordinary-helper cleanup receipt. Unsupported owner scopes stay blocked.
- For daemon, writer or inference uncertainty, establish the exact required
  identity and termination evidence. Never remove a mismatched writer.
- For capacity failure, preserve history and request reviewed maintenance. This
  interface does not delete records or raise limits.

Run-level preflight exceptions can leave physically absent records for the next
admission because normal terminal close follows a successful context-body exit.
Reconciliation intentionally revalidates those records. When pending records
exist, older released ordinary application helpers may also require retained
cleanup evidence. Changing this lifecycle requires a separate reviewed contract.

A later successful recovery does not change the old campaign's outcome or resume
paused testing. After authorized environment recovery, use a fresh ordinary
preflight with the same exact endpoint/model/image and original lease. An
unavailable API must retain its own failure with zero participant stages.
