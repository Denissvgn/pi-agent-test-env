# Trust boundaries and operating rules

## Parent versus child

The parent host process controls Docker, reviewed plans, model credentials, image
selection, and evidence paths. The child Pi process is untrusted with respect to
project changes. It receives no Docker socket, no host home mount, no GPU access,
no privileged mode, no extra capabilities, and no writable root filesystem.

All runtime containers use a non-root UID, `--cap-drop=ALL`,
`no-new-privileges`, `--ipc=none`, finite CPU/RAM/PID budgets, an explicit workspace,
and read-only helper/control mounts. Reused images declaring volumes or obvious
baked credential variables are rejected. A capability probe is not an image
malware audit: use only images whose source/provenance you trust.

BuildKit is separate trusted parent infrastructure. Docker's docker-container
builder may require elevated host-managed privileges to build images; children
cannot address or invoke it. Review the Dockerfile/base image, keep the build
context minimal, and never supply project secrets as build arguments. The builder
has independent CPU/RAM/parallelism limits and is removed after use.

## Files and program execution

The configured OS/mount boundary uses a read-only root, read-only frozen helper/
control/scorer sources and the selected project access. Writable exceptions are
/pi-state runtime, /opt/pi-control/outbox and /workspace when access is rw. The
boundary probe samples write denial at selected root/system paths; it does not
prove every possible operation is confined. Native bind behavior depends on the selected image/daemon; see [QUALIFICATION.md](../QUALIFICATION.md).

workspace-boundary.mjs adds write/edit lexical/realpath checks and a Bash regex
for common attempts to modify protected paths. That regex is not a shell parser
or general confinement mechanism; arbitrary shell/Python/application code can
write any writable mount. Path checks alone are not race-proof host patching.
Prompts are policy guidance, not isolation. Read-only stage workspace facts and
network mode come from effective Docker arguments; PI_OFFLINE disables startup
network activity, not inference or all external routing. No automatic destination
allowlist exists. Child outbox telemetry/acks remain untrusted observations.

A default run mounts a copied project, not the original. Review snapshot omissions.
An explicitly selected in-place run checks the complete mounted tree before any
writable project stage. Metadata inspection rejects symlinks (including dangling
links), multiply linked regular files, and inspection/enumeration failures, even
inside excluded or secret-looking directories. It opens directories without
following links and accepts normal directory link counts. Snapshot exclusions,
user `--exclude` patterns and filtered change-inventory exclusions do not narrow
admission. This checks the admitted tree under the cooperating-writer host lease;
it does not protect against arbitrary concurrent hostile host mutation. File
contents are not read by this scan, so it is not a secret scanner.

Do not add `/`, host home, model-server data volumes, Docker sockets, host PID/IPC,
`SYS_ADMIN`, or `--privileged` to repair a failing test. Do not run the parent as
root; the runner rejects UID 0. Numeric UID/GID must have access to the staged files
on the Docker daemon host. Mac Docker Desktop bind permissions still need testing.

Built-in/discovered extensions, skills, themes, prompt templates, and context files
are disabled in children. Project trust is not itself a filesystem boundary.
Arbitrary Bash and application code still run inside the container; an enabled tool
can modify any writable mounted project file. A read-only reviewer has a read-only
project plus its own fresh writable `/pi-state` mount outside the host project. Read-write agents have the
entire snapshot, not only their `cwd`.

## Credentials and network

The key is taken from the parent environment or the host-side secret store
(`~/.config/pi-agent-test-env/secrets/`, permissions `0600`, directory `0700`, refuses symlinks)
and supplied as `PI_LAB_API_KEY` only to preflight/Pi. Keys are never stored in project checkouts,
plan files, container CLI arguments, or chat transcripts. Status commands display only a truncated
SHA-256 fingerprint (`sha256:xxxxxxxxxx`). A child with Bash can read its own environment: plain
Docker is not a credential-withholding proxy. A short-lived inference-only key is
preferable. Setup/independent checks receive no forwarded model key, but use a
clean image because the runner cannot prove that no secret exists in image files.

Raw keys are redacted from captured stdout/stderr. Encoded/transformed credentials
and arbitrary secrets in source files are not comprehensively scrubbed. Session
files inside the workspace may contain sensitive content. Do not publish logs or
whole workspaces without review. Do not store keys in Git or screenshot them.

Agent containers need the selected model endpoint and retain ordinary network
access; there is no automatic destination allowlist. Setup/check network is off
unless both the plan and parent authorize it. `NO_PROXY=*` avoids routing local
requests through ambient proxies, but is not a firewall. A network-accessible model
server could expose tool execution or filesystem functions outside this container.
Constrain it with server permissions/proxy policy, or use a pure inference endpoint.
Local LLM server CPU/GPU/memory usage is outside the Pi-container quota.

## Acceptance evidence and tampering

Plans and evidence are kept outside the workspace mount. Runtime helpers and the
current stage's task/config are mounted read-only. Protected-path hashes detect
final modifications of tests/specs; they are not immutable mounts during agent
execution and do not protect against all adversarial dynamic code loading.

A sophisticated adversarial implementation can make a visible test pass without
satisfying its spirit. For higher assurance keep acceptance oracles, data, harnesses,
and expected results outside the writable project; validate test counts and review
the actual diff. JSONL is execution evidence from the Pi process, not cryptographic
attestation from the LLM server. No generated claim is an independent verifier.

The runner's PASS does not parse the reviewer's prose as approval. A reviewer can
find a defect while mechanical checks pass. The parent must inspect findings and
report unresolved ones instead of automatically merging.

## Browser exceptions

Default Chromium sandbox remains enabled. Do not automatically add `--no-sandbox`
or unsafe SwiftShader after an error. Explicit opt-ins are only for trusted local
fixtures and weaken the browser's own boundary. Docker isolation remains, but
browser code can access resources available inside that boundary. Never treat
arbitrary websites or unreviewed model-generated HTML as safe merely because it is
served from localhost.

## Recovery and residual limits

Host limits serialize cooperating runs, not other tools/users. Timeouts and log
limits kill/remove child containers; hard-killing the parent can leave an orphan.
Inspect the specific managed container/builder before deleting it. Do not prune
unrelated images, volumes, or model caches. Input snapshot and captured logs are
bounded, but generated disk usage is not quota-controlled. Use a VM/volume quota
for adversarial execution or strict disk isolation. Containers are not a proof
against kernel/runtime vulnerabilities.

Upstream guidance:
- https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/security.md
- https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/containerization.md
- https://docs.docker.com/engine/containers/run/
- https://docs.docker.com/engine/storage/bind-mounts/

## Parent control storage

Every stage uses a fresh UUID control directory under the parent run, outside
the project and every writable runtime source. Task, endpoint, challenge and
inbox are mounted only at `/opt/pi-control` read-only. The outbox leaf is the
only writable submount there; no parent write uses its contents as a destination.
Runtime state is allocated once outside the project and mounted at `/pi-state`.
The parent never reinitializes a previous child's runtime or outbox. Docker argv
construction performs no source creation/chmod. Project `.pi-runtime` and
`.pi-lab` entries cannot redirect these sources; the old workspace aliases are
removed. Parent JSON records use atomic replacement and reject leaf symlinks.
Permission/setup failures stop the flow. Legacy ambiguous control mutation and
unsafe legacy patching fail explicitly rather than using ambiguous old controls.

Offline regressions prove host sentinel preservation and mount construction.
Actual Docker Desktop bind/mount behavior must be checked for the selected runtime.

## Stage routing

Schema-2 descriptors under stages/<UUID> record workspace identity and immutable
control/runtime references. A separate revisioned state file records pending,
running, stopping, stopped and finalized phases. Status and controls accept stage
UUIDs or unique labels; ambiguous legacy mutations fail. Heartbeats and per-command
acks carry stage identity and remain observations. Worker delivery tracking uses
process-local state, never child-writable acknowledgement files as authority.
Steering directives are retained individually, rather than overwritten. Legacy
status records remain inspectable. Process segments retain continuation identity;
run outcomes and parent-applied deadline revisions are recorded separately.

## Workspace patches

Only pending agent stages may be patched. The recorded host admission lease must
be free, launch is serialized by a parent run lock, and all prior managed writers
on that workspace must be finalized with confirmed cleanup. Active patching is
unsupported and rejects; inode checks alone cannot confine concurrent ancestor
renames. Unrelated host processes/users are trusted and must honor the exclusive
lease; it is not an OS lock against arbitrary host actors or alternate lock files.

Under that quiescence precondition, patching pins the workspace root inode, walks
with directory FDs/O_NOFOLLOW, rejects linked/nonregular leaves, creates bounded
temporary regular files and atomically replaces via dir_fd rename. Ancestors are
revalidated before replacement as an additional check. Required POSIX operations
must exist; no unsafe fallback. Protected acceptance inputs require a new trial/
configuration. Rejections produce no success/steering directive. Snapshot and
original-directory pending stages use the same authoritative workspace reference.

## Budget authority

The supervisor owns a fixed host-monotonic start and revisioned deadline. CLI
commands queue requests; only the active supervisor applies them before the
current deadline. Finite integer caps remain 3600 seconds, 100 turns and 10000000
reported tokens. Original/effective budgets are retained; no automatic increase.
Stale, late, reduced, malformed and ineffective requests reject. Status exposes
parent application separately from child observations; --wait-seconds may wait
for a bounded host response. Worker views transmit a remaining duration, never
a host clock timestamp. A revision is applied at most once and rereading it
cannot renew the worker timer. The host independently enforces the actual bound.
Cleanup grace is recorded separately; timeout, log limit, OOM observation and
cleanup failure remain distinct. Actual worker ingestion and resource behavior
require observations from the selected runtime.

## Intervention evidence

Parent interventions are append-only schema-2 JSONL in interventions.jsonl, outside
all child mounts, with separate command/intervention UUIDs, sequence, UTC time,
stage/attempt/run identity, revisions and payload hashes. Appends use no-follow
regular-file checks, an exclusive ledger lock and file/directory fsync; readers
use a shared lock. Requested, queued, accepted, rejected, applied and application
error events retain their distinct history. Patches record content hashes and
budget applications retain numeric before/after limits. Raw steering/source
contents, secrets and private endpoint URLs are excluded from the history.

Acceptance is durably recorded before an effect is attempted. An accepted command
marks assistance even if delivery/application is unverified. A queued budget
request is not accepted until the supervisor processes it. Rejected requests
remain visible without making the run assisted. Child acks can only append
observed/trusted=false events linked to existing parent acceptance; stale/wrong/
unknown targets cannot authorize anything. Observation statuses are sanitized;
symlinked ack directories reject and repeated observations are deduplicated.

Run summaries now explicitly use document_type=run_summary, schema=2 and retain
legacy mechanical fields plus assistance. Mechanical success with accepted
assistance is ASSISTED/exit 1, never clean PASS/0. Schema-1 plans and endpoints
remain readable; legacy summaries stay inspectable. Separated run results preserve
actual process segment identities without synthesizing evidence for old records.
These records are parent provenance, not cryptographic server/model attestation.

Runtime helpers are frozen under the parent run before the
first child starts. In-place evaluation of the skill repository therefore cannot
modify the helper source used by later stages through a writable project alias.
The runtime-snapshot receipt retains hashes; helper sources are never mounted
writable. Low-level argv construction rejects an unisolated helper source.
