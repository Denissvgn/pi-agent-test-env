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

## What one run left behind

A supervisor removes each container it started. When the supervisor itself is
killed, or Docker restarts, a container can stay. The next operation that takes
the lease reconciles it, and so does `registry-recover`. Two commands answer the
question for one run without starting anything.

Every container the runner starts with the worker image carries
`org.pi-agent-test-env.managed=1` and `org.pi-agent-test-env.run=<run id>`. The
value is `none` for a container outside a run: an image probe of `ensure-image`
or `doctor`, or the shared inference gateway of an experiment. Networks the
runner creates carry both labels as well. Application helper containers carry
the run label only, because their cleanup needs the owner's proof. The BuildKit
container of an image build carries no label, because the buildx
`docker-container` driver has no option for one. The run label names a run; the
launch and registry labels and the registry records remain the only ownership
authority.

```bash
docker ps -a --filter label=org.pi-agent-test-env.run=RUN_ID
python3 "$SKILL_DIR/scripts/pi_lab.py" leftovers [--run RUN] [--json]
python3 "$SKILL_DIR/scripts/pi_lab.py" cleanup --run RUN [--yes] [--json]
```

`RUN` is a run id or a run directory. A run id is looked up in `--results-dir`.

`leftovers` reads Docker and the run directories and changes nothing. It lists
each labelled container and network with its name, state, age and run id when
its run is sealed (`result.json` exists) or when no operation holds the lease of
an unsealed run, which means its supervisor is gone. It tests the lease with a
momentary shared probe and never creates or writes the lease file. Resources of
an active run are counted, not listed. Resources labelled `none`, and resources
whose run directory is not in `--results-dir`, appear under `unclassified`.

`cleanup` without `--yes` prints what it would remove and changes nothing: no
lease is taken and the registry is not reconciled. With `--yes` it:

1. takes the host lease without waiting; a busy lease is `host-admission-busy`,
   exit 2, because an operation is active;
2. lets the registry reconcile, exactly as any admission does; a registry that
   refuses is `host-registry-unsafe`, exit 2, and nothing is removed;
3. removes the containers and then the networks that carry both the managed
   label and this run id, by Docker ID and never by a name pattern;
4. confirms their absence with `docker ps -aq` and `docker network ls -q`
   filtered by both labels;
5. seals an unsealed run as a lost controller, with the cleanup recorded in
   `controller_interruption`; such a run never ends as `PASS`;
6. writes `cleanup.json` into the run directory. `reconciled` lists what the
   registry's reconciliation removed and `removed` what the label pass removed.

| Outcome | Meaning |
| --- | --- |
| `DRY_RUN` / 0 | Without `--yes`: the selection is reported and nothing changed |
| `CLEANED` / 0 | Nothing with both labels remains for this run |
| `INCOMPLETE` / 2 | A removal failed, absence was not confirmed, or Docker could not be asked; the run is not sealed by this attempt |
| `INTERRUPTED` / 130 | Explicit interruption; `cleanup.json` records what was removed so far |

Cleanup deletes and edits no registry record. It refuses a run whose stages
recorded another lease (`cleanup-lease-mismatch`) and names the `--lock-file` to
use. A run killed before its first stage records no lease; cleanup then trusts
the selected lease. It leaves alone anything that lacks either label, including
application helper containers; those need
[retained application ownership cleanup](APPLICATION-OWNER-CLEANUP.md). It does
not seal an experiment attempt, which `experiment-resume` reconciles, or a
`preflight` or `browser-check` directory, which has no attempt record.

`status` prints one line with the number of containers and networks that still
carry the run's label, or `unknown` when Docker cannot be asked.

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
