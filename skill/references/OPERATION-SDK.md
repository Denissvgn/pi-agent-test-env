# Experimental operation SDK

The SDK offers fixed library operations through a fresh verified worker. It is
experimental source functionality. The first qualification profile is Linux
ARM64 with CPython **3.12.13**, in an immutable read-only container, with caller,
SDK, worker and private objects in the same Linux namespace. Other Python
versions and native macOS/Windows operation execution are unsupported. Existing
Python 3.10+ CLI behavior is unchanged.

Validation success grants no agent execution, project admission, historical
ownership, installation or release approval. No command runner, `run`, `doctor`,
owner-maintenance proxy, whole-store scan or default credential store is exposed.

## Operations and private results

| Operation | Actual implementation | Private result |
| --- | --- | --- |
| `plan_validate_source_v1` | `application_contracts.validate_source` | Unchanged validated typed source and UTF-8 digest |
| `plan_validate_ir_v1` | `application_contracts.validate_ir` | Unchanged validated execution document and UTF-8 digest |
| `plan_validate_legacy_v1` | `pi_lab.validate_plan`, explicit profile loader | Normalized plan including defaults, application references and schema-2 bindings |
| `plan_check_project_v1` | Legacy validation plus `check_project_contract` | Normalized plan and separately observed project metadata gate |
| `redact_bytes_v1` | `application_credentials.Redactor.bytes` | Arbitrary bytes after declared-pattern redaction and a second pattern check |
| `credentials_collect_v1` | Exact version-bound flat references | Participant/stage, application aliases and separate inference value |
| `secret_register_create_only_v1` | Installed native no-replace primitive | Private native observation and independently checked final metadata |
| `resource_read_v1` | Exact approved immutable resource | Bytes and independently checked resource hash |

Plan validation never freezes scorer assets or executes plan commands. Declared
scorer bytes are bounded and hash checked; their paths and contract are
normalized. Prompt/profile assets pass through an explicit bounded reader.
Project metadata is separately declared by exact path, device/inode and expected
file/directory kind. A valid plan alone does not check that metadata.
Overlapping dependency/resource declarations must agree on their content hash;
the narrower dependency and prompt limits remain binding. Resource approval
never widens a separately declared dependency grant.

Redaction accepts arbitrary input bytes, but its **patterns** must be strict
normalized UTF-8 values: 1..4096 characters, at most 16 KiB, no whitespace,
control characters or surrogates. Application credentials require at least 16
characters. Patterns include literal values and three JSON-string escape layers.
Arbitrary byte patterns, transformations beyond those layers and automatic
structured-store discovery are unsupported. A replacement-marker collision
refuses the operation; suppression is never reported as successful redaction.

## Trust and loading

The application must first trust the consumer bootstrap independently. Executing
an unverified bootstrap and subsequently asking it to check its own hash cannot
establish that trust. An approved image or separately verified loader can execute
the pinned `scripts/operation_sdk/__init__.py` bytes under the canonical package
name `operation_sdk`, then call:

```python
client = trusted_package.load_verified(consumer_root, approved_consumer_files)
with client.prepare(policy, request, trusted_policy_sha256=approved_policy_hash) as operation:
    result = operation.execute(private_fd)
    if result.accepted:
        private_output = result.private()
        # Consume private output while namespace/coordination authority is held.
    public_status = result.public_wire()
```

`approved_consumer_files` is the separately approved exact twelve-file SDK
inventory. Ordinary imports, preloaded SDK/provider siblings, cached bytecode,
unexpected code/resource/runtime identities and a writable installation refuse.
Neither a provider manifest nor an environment probe approves an operation.

Policy compilation is pure and precedes provider import, child creation,
coordination lookup and private data reads. Matching a caller-supplied digest
establishes consistency only; the caller still needs independent operation
authority. See `scripts/operation_sdk/policy.py` for exact fields and bounds.

The deployment closes provider files **and sizes**, inventory digest, exact flat
module-to-source paths, independent consumer files, explicitly readable resources,
Python executable hash, runtime file hashes/sizes, actual module descriptors and
mapped file set. Runtime builtins, frozen modules, file modules and the actual
`typing.io`/`typing.re` export aliases have distinct descriptor forms. Lazy
dependencies used by a selected operation belong in the approved graph.

The caller must be able to read and search every directory from `/` to the SDK
and selected namespace. The verified loader opens each ancestor with
`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`; permission to traverse a path and read its
leaf files alone is insufficient. A public ancestor can be root-owned mode 0755
while the selected private store and coordination parent remain owner-only mode
0700. Namespace checks also reject unsafe ancestor ownership and nonowner write
permissions, except for root-owned sticky directories. A layout change needs its
own review and current observation; it does not approve an SDK operation.

`environment_probe_v1` and `compile_discovery` are qualification-only discovery:
they select no private source/store/references and dispatch no handler. Their
output always says approval is false; normal `Client.prepare` rejects this
operation. A maintainer must review a discovered closure before separately
approving a complete operational policy.

## Policy, input ownership and lifetime

The closed policy contains schema/type/IDs, actor/participant/stage, one operation,
deployment, input source, scope and finite limits. Scope declares base/profile,
exact dependency files with role/hash/byte cap, project metadata, resource,
existing store and coordination identities, exact versioned references and any
create-only write leaf/value contract. No field is inferred from HOME, environment,
an installation, a project scan or a previous result.

The request binds policy hash, operation, actor/participant/stage, operation/request/
worker/channel/source UUIDs and a finite monotonic lifetime. These form the
`operation_sdk_context_1` binding. Replay/duplicate IDs and expired requests are
spent, including failed attempts. Process-local tombstones have a finite capacity;
exhaustion refuses instead of evicting old requests for reuse.

The input is one length-prefixed private frame from either an exact read-only
pipe or a sealed Linux memfd. Its selected device/inode and source UUID are
bound before reading. Sealed memfds require mode 0600, zero links, offset zero
and all write/grow/shrink/seal seals. Ordinary disk files are unsupported inputs.
The payload is `{"plan": ...}`, `{"value": ...}` or `{}` for collection;
redaction alone takes raw bytes inside the frame. Resource reads have no input FD.

Input FD ownership transfers only after exact metadata/type/seal validation.
The SDK then spends and closes that owned descriptor once. A mismatched FD was
not transferred and remains the caller's responsibility. Do not close, reuse or
retry a transferred descriptor. A prepared capability executes once; no implicit
retry, adoption or recovery follows a missing/invalid reply.

The selected coordination file must already exist, be owner-only mode 0600,
single linked and have the exact approved identity in an owner-only directory.
The SDK takes a real nonblocking exclusive lock and verifies held/named custody.
It never creates, replaces, chmods or unlinks the coordination file. Store
directories require mode 0700; private leaves require 0600, one link, exact
identity, byte size, mtime and ctime. Symlink ancestors and replacement fail.
All relevant actors must independently agree to honor coordination; a lock does
not prove absence of noncooperating writers.

Linux fork/dup descriptors share flock ownership. The worker borrows store/lock
FDs and never issues `LOCK_UN`; parent authority stays held through child
cleanup, complete receipt and current receiver checks. Keep the `with` context
open while using the private result, then close it. Closing an uncertain native
FD is never retried. An uncertain cleanup can turn context exit into an error
even after an earlier operation result was received.

## Budgets and acceptance

Admission forecasts private/control/result frames, failure reserve, pattern and
regex growth, redaction replacements, normalized plans/defaults/prompts/scorers,
native calls, descriptor depths and explicit verification read multiplicity.
Failed reads spend reservations. Zero-byte grants perform no positive payload
read. Source verification has separate shared parent/worker halves; counters are
reservations and are not a census of CPython, dynamic loader or kernel I/O.

The supported container requires finite measured cgroup CPU, memory and PID
limits. Worker rlimits restrict descriptors, address space and CPU. CPU time uses
whole seconds and policies therefore require exact multiples of 1000 ms;
CPU quota is a separate millicore field. Pipe/frame deadlines and an independent
supervisor bound cooperative processing. Ordinary filesystem/native syscalls
can block in the kernel; this API makes no universal hard wall-clock guarantee
for arbitrary filesystems. Initial integration evidence uses fresh local tmpfs
objects. A deployment on another filesystem requires its own qualification.

Parent owns child creation, immediate pidfd acquisition before poll/wait, held
proc-directory custody, start/executable/maps observation and reaping. Probes
apply only to that own live child; there is no historical PID lookup. The
approved worker graph is measured before protected action and conserved after
it. This constrains reviewed code; it is not a hostile Python/native-code sandbox.

Acceptance requires complete bound frames, empty child stdout/stderr, actual
zero exit/reap, conserved code/runtime, exact private-result shape and receiver
checks. Typed plans must preserve submitted documents; resources must match
the independent hash; credential results must equal all collected bindings.
Registration also checks the complete native trace, final receiver metadata and
actual pending-leaf absence under current custody. A native create observation
alone is insufficient. Lost receipts after a dispatched write remain unknown.
The redaction receiver independently checks the exact replacement relation,
including preservation of every unmatched byte; an empty or altered output is
not accepted merely because it contains no known pattern.

`accepted` and `code` are read-only. `private()`, `bytes()` and `facts()` are
**private** outputs, including normalized plans and alias/inference bundles.
Their snapshots do not change the operation's stored result.

`public_wire()` is exactly twelve raw C0 bytes. The raw frame cannot contain any
strict normalized UTF-8 pattern, including single-character patterns. This
guarantee does not cover arbitrary raw byte patterns or caller-added JSON,
text, base64, repr or transport envelopes. `public_json(value)` scans the entire
encoded caller envelope against known collected patterns and refuses collisions;
before collection, pattern coverage is unavailable and it refuses. No private
exception text, partial response or value fingerprint is a public diagnostic.

## Consumer and release gates

Keep CLI validation, redactor module, secret-store module and browser-resource
roles distinct. Reading the browser policy grants no module or CLI permission;
validation grants no run permission. Unsupported call sites remain disabled.
Use fresh literal fake values and disposable namespaces for integration proof.
Real credential delivery, native-host deployment, actual model/browser execution,
historical owner cleanup/replay and release promotion require their own evidence
and authorization. Source tests do not close those gates.
