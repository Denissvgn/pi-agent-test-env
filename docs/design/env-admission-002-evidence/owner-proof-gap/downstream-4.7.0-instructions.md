# WorkChord: staged 4.7.0 owner-proof upgrade and integration handoff

Prepared on 28 October 2026. This is a separate downstream handoff, not an
executed installation, cleanup or campaign resume. Keep the original campaign and
heartbeat paused. Use the owning downstream session's existing authorization;
live cleanup, model calls and application mutations need their actual approved
scope. This upstream task leaves them untouched.

## Candidate identity and availability

The **4.7.0 experimental prerelease candidate is prepared locally**. It is not a
published release. Do not assume a `releases/download/v4.7.0` URL exists yet.
The source change is in [draft PR #10](https://github.com/Denissvgn/pi-agent-test-env/pull/10).

- Candidate code commit: `26d3e4aba43a64ef074ac59a83cff2df4c9a94c8`.
- Candidate archives: `/Users/bramen/Projects/pi-agentic-development/dist/pi-agent-test-env-4.7.0-candidate-r2/`.
- Universal ZIP: `pi-agent-test-env-4.7.0.zip`.
- ZIP SHA-256: `7e64444f30975232eb656aae871af6359e53faac682fa2ca8144d2f9bd7f9318`.
- `SHA256SUMS` SHA-256: `42abe41cc1416d53af0c0a9357efb46bb3e471a425fc6ab9fe17aaa8ac7f7567`.
- Local CI/release evidence: sibling `release-4.7.0/` directory. Candidate and
  final publication checksums must be verified separately if review changes code.

The exact extracted candidate passed local native ARM64 Docker CI: 2,760 tests
ran, 2,759 passed and one Linux-inapplicable filesystem alias test passed separately
on macOS ARM64. Package, pinned standards, all five archive layouts, code origin
and unchanged-byte checks passed. These are package checks, not qualification of
the six real owner histories or a new WorkChord environment.

When the reviewed PR is later merged and a release is explicitly published, use
the published immutable tag/assets and their verified hashes. Do not replace
4.6.1 assets or transfer these candidate hashes to different bytes.

Read-only observations on 28 October: WorkChord's installed skill remains
**4.6.0**; campaign metadata records **4.5.0**, Pi **0.87.1**,
`execution_ready=false`, `user_resume_authorized=false`, and
`automatic_resume=false`. The latest owner-proof report identifies a disabled
1.2.7/4.6.0 harness. Determine historical versus active bindings before changing
a new revision. Preserve old provenance instead of editing it to claim readiness.

## 1. Stage the complete candidate beside the old installation

These commands write a new immutable version slot. They do not authorize harness
activation. WorkChord requires its project `.venv/bin/python`; internal WorkChord
documentation must use ignore-verified paths and its repository instructions.
The version store uses `.local/share` so it does not change legacy lease-default
selection through creation of a new `.local/state` tree.

```bash
set -euo pipefail
umask 077
WC_ROOT=/Users/bramen/Projects/WorkChord
WC_PYTHON="$WC_ROOT/.venv/bin/python"
PI_ARCHIVES=/Users/bramen/Projects/pi-agentic-development/dist/pi-agent-test-env-4.7.0-candidate-r2
PI_STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pi-owner-470.XXXXXX")
PI_VERSION_HOME="$HOME/.local/share/pi-agent-test-env/releases/v4.7.0-candidate-26d3e4a"

printf '%s  %s\n' \
  7e64444f30975232eb656aae871af6359e53faac682fa2ca8144d2f9bd7f9318 \
  "$PI_ARCHIVES/pi-agent-test-env-4.7.0.zip" \
  42abe41cc1416d53af0c0a9357efb46bb3e471a425fc6ab9fe17aaa8ac7f7567 \
  "$PI_ARCHIVES/SHA256SUMS" | shasum -a 256 -c -
unzip -q "$PI_ARCHIVES/pi-agent-test-env-4.7.0.zip" -d "$PI_STAGE/unpacked"
(cd "$PI_STAGE/unpacked/pi-agent-test-env" && shasum -a 256 -c MANIFEST.sha256)
if [ -e "$PI_VERSION_HOME" ] || [ -L "$PI_VERSION_HOME" ]; then
  printf 'Version slot exists; verify it before reuse.\n' >&2
  exit 1
fi
mkdir -p "$(dirname "$PI_VERSION_HOME")"
mv "$PI_STAGE/unpacked" "$PI_VERSION_HOME"
PI_NEW_ROOT="$PI_VERSION_HOME/pi-agent-test-env"
"$WC_PYTHON" -B "$PI_NEW_ROOT/scripts/pi_lab.py" application-owner-inspect --help
"$WC_PYTHON" -B "$PI_NEW_ROOT/scripts/pi_lab.py" application-owner-recover --help
```

Record the package version, archive/manifest hashes, runner content hash and exact
CLI path outside the skill root. For an isolated fingerprint calculation, add
the selected package's `scripts` and `runtime` paths explicitly before importing
`provenance.execution({}, {}, root)`. The normal CLI examples use `-B`, without
`-I`, because isolated Python omits sibling script imports by default.

Preserve the existing 4.6.0 path and historical 4.6.1 stage. Do not extract over
either, make a mixed directory, install a pip provider, or switch a catalog link
while the active/frozen harness binding is unqualified. Confirm Docker Desktop
can read the new package location before later native execution; do not broaden
mounts to the whole home directory.

## 2. Keep one original lease and a compatible controller cohort

Derive the exact original lock from retained invocation/descriptor evidence.
This case used the legacy
`$HOME/.local/state/pi-agentic-development/operation.lock`, with reported inode
`284885578`. Verify the actual selected path and inode in the owning session.
An unexpected identity is a stop, not a reason to replace/chmod/unlink the lease.
Pass `--lock-file "$PI_ORIGINAL_LOCK"` on every command. Do not switch to another
default or create a new lock to bypass the shared block.

New ordinary helper intents use **record schema 3 / owner contract 1**. Older
record readers reject them; older clients also cannot consume the new historical
sidecar proof. Use one compatible registry-aware cohort. Do not downgrade raw
schemas, reclassify helpers or discard proof to keep an old client running.

**The frozen SDK admission policy remains a hard gate.** It refuses a new owner
proof store with `owner_cleanup_policy_extension_required`. This candidate does
not supply native qualification of an extended policy. Have the canonical
downstream harness owner review/qualify its proof-read scope and a fresh source
revision. Do not activate the old 1.2.7 harness or bypass that policy.

## 3. Diagnose passively before any owner cleanup

After authorization for read-only diagnostics, establish the variables in one
shell, or restore them from the install receipt in each fresh agent shell:

```bash
: "${PI_ORIGINAL_LOCK:?Select the exact retained original lease}"
PI_DIAG=$(mktemp -d "$HOME/.local/share/pi-agent-test-env/owner-diagnostics.XXXXXX")
if "$WC_PYTHON" -B "$PI_NEW_ROOT/scripts/pi_lab.py" application-owner-inspect \
  --lock-file "$PI_ORIGINAL_LOCK" --lock-wait-seconds 30 \
  > "$PI_DIAG/owner-inspect.json" 2> "$PI_DIAG/owner-inspect.stderr"; then
  PI_INSPECT_EXIT=0
else
  PI_INSPECT_EXIT=$?
fi
printf 'Inspection exit: %s\n' "$PI_INSPECT_EXIT"
```

`OBSERVED`/0 only means passive inspection completed. Inspect each helper's
condition and execution shape; `admission_authorized` remains false. This command
does not probe Docker, retrieve keys, clean files or qualify inference. The full
registry inspection can still return `BLOCKED`/2 when an admission predicate fails.

## 4. Resolve the six historical owners through genuine evidence

The report groups two failed-agent histories with recorded CIDs
(`03c973f8…`, `f707c0df…`), three helper-only diagnostics (`f0751c6c…`,
`eb0c56da…`, `e049b004…`), and one interrupted history whose primary record has
no CID (`7640af6b…`). Resolve full IDs privately through the safe report and
original owner records. At least three map to upstream maintainer qualification
history; WorkChord must not fabricate the upstream owner's attestation.

The reference `references/APPLICATION-OWNER-CLEANUP.md` defines the exact closed
request/witness protocol. Its crucial requirements are:

- Genuine original controller and launcher invocations/actual terminals, every
  related launch, original snapshot device/inode and exact intent/daemon/mount
  binding. Prepared stage metadata is not proof a Pi participant ran.
- An absent name or completed CLI does not prove an interrupted create cannot
  finish later. A missing primary CID needs a real original guard CID bound to
  that exact launch. Without it, keep the record blocked.
- The existing specialized preworker proof remains narrowly scoped. The exact
  `e049b004…` diagnostic validator and physical-absence replay for two other IDs
  may be useful original inputs, but their external `PASS` labels are not generic
  ordinary-helper proof. Unfamiliar retained formats need reviewed owner adapters.
- Five workspaces reportedly remain. No prior read-only observation certified
  their sensitive hygiene. Preserve failed stage/process/credential/result
  accounting. Do not rewrite flags, invent stage/CID data, remove old records,
  or delete retained raw logs/runtime copies to fit the new validator.
- Unknown retained files, external authority scope, overlapping pending holders,
  missing witnesses or incomplete writer/request closure remain blocked. The
  cleanup interface does not take over another owner or attest memory erasure.

Only after complete owner evidence and separately authorized discard scope may
the responsible owner consider this mutating command. It accepts already
released ordinary histories, not a force-release of pending/quarantined helpers:

```bash
"$WC_PYTHON" -B "$PI_NEW_ROOT/scripts/pi_lab.py" application-owner-recover \
  --lock-file "$PI_ORIGINAL_LOCK" --lock-wait-seconds 300 \
  --request /owner/private/validated-original-custody-request.json \
  --output-dir /owner/private/new-cleanup-receipt \
  --discard-workspace
```

The request path and all evidence must remain outside discarded scopes; the
output child must be fresh. Keep the full private receipt/selection/index store.
`CLEANED`/0 is separate cleanup acceptance, not a task pass or resume authority.
`BLOCKED`/2 and `INTERRUPTED`/130 may follow partial removal; preserve receipts
and diagnose effects rather than automatically retrying or assuming rollback.

## 5. Reconcile once, then qualify a fresh downstream revision

After all required real owner proofs are accepted, separately authorized generic
`registry-recover` may reconcile the ordinary pending resources under the same
lease, with a fresh output directory. It revalidates accepted proof before skipping
legacy sensitive repair, preserving original failed credential accounting.
It is not authority to dispatch. Preserve every old failure and owner receipt.

Then prepare a **new canonical WorkChord environment/campaign revision** with the
exact new package path, runner/manifest/archive identities and qualified SDK read
scope. Use WorkChord's existing compiler/admission interface; do not edit frozen
metadata, runner pins, readiness or resume flags to claim compatibility.

Qualify image/native architecture, browser, inference and actual Pi tool use as
separate gates. Preserve Pi **0.87.1**, `linux/arm64`, `chromium-userns`, the trusted
original image and bounded original environment/resources unless a new scope is
explicitly selected. A parent update alone does not authorize a different Pi,
model, route, profile, parallel mode or broader mounts.

- Browser admission needs real sandboxed DOM/JavaScript observations.
- Preflight includes a tiny **real chat request**. The old port-8888 API refusal
  is a separate unresolved issue; verify the selected host/container route, exact
  model and settings without exposing credentials or silently switching servers.
- Smoke needs real paired read/write/bash calls, fresh independent verification
  and the reviewed ordered settlement evidence. Exit zero alone is insufficient.
- Only after those gates and actual downstream resume authorization, run one
  bounded disposable pilot through the new canonical harness with an independent
  root oracle. Historical campaigns remain immutable and are not resume inputs.

Local ARM64 Docker CI verifies source/package behavior with synthetic integration
boundaries. It does not qualify the real six owner graphs, application auth,
WorkChord workflows, native browser/model behavior or an extended SDK policy.

## Copyable downstream-agent handoff

> Stage and fingerprint the verified 4.7.0 candidate beside existing installs using
> WorkChord's project Python. Keep the old campaign/heartbeat disabled and all
> original history unchanged. Use the exact original lease throughout. Start with
> offline owner inspection; resolve the six records through their actual upstream
> owners and genuine original custody, including real immutable identity for the
> interrupted record. Do not fabricate proof, rewrite failed cleanup accounting,
> downgrade schema 3 or bypass the frozen SDK gate. Unknown scope remains blocked.
> Perform no live recovery, model call, application mutation or campaign resume
> without its existing explicit authorization. After supported owner proof and
> authorized generic recovery, prepare a new canonical revision, qualify the SDK
> scope and each native/browser/inference/smoke gate, then one approved disposable
> pilot with an independent oracle. Retain private raw evidence locally; share
> only bounded nonsecret diagnostics and exact candidate identities.
