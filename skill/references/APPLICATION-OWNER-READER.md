# Application owner proof reader contract

Contract ID: `application_owner_legacy_reader_1`. Contract version: 1.
Machine-readable fields and bounds are in
[the contract descriptor](../assets/application-owner-reader-v1.json).
[Conformance vectors](../assets/application-owner-reader-vectors-v1.json) describe
synthetic algorithm checks. Neither document approves a provider, policy, real
cleanup, model integration or downstream campaign.

## Approve the consumer before importing the provider

A consumer first checks its own trusted admission policy. That policy must
explicitly support this contract, `legacy_derived_v1`, cohort
`application_owner_legacy_1`, the declared variant and `owned_host_files_only`.
It must separately approve the exact immutable provider code/resource identity
and permitted read namespaces. Use a fresh provider process or otherwise prove
loaded code origin; a version string, path label or on-disk hash alone does not
qualify previously loaded code. Compare the observed provider identity against
the consumer's independently approved identity.

If any permission/support is missing, return `extension_required` before importing
new provider code, looking up historical proof or dispatching a native action.
Do not import new product code to decide whether the old policy may import it.
A vector's qualified profile is a test oracle, not authorization. No receipt,
manifest, source hash, PASS label or capability object may approve itself.

Frozen SDK policies stay frozen. Qualify a new policy/read scope explicitly; do
not add an audit/report directory to an old allowlist or reinterpret a task FILE
proof as generic integration qualification. Passing this contract's vectors is
one input to that qualification, never its final result.

## Input and selected graph

Read-only replay receives a privileged current registry observation and holds the
original existing lease without creating, replacing, truncating or chmodding it.
The ordinary helper subject is exactly registry, generation, launch_id,
intent_sha256 and container_id. Preserve historical schema-1/2/3 record bytes and
intent normalization. Qualification service/preworker subtypes use their existing
typed contracts; never turn them into ordinary helpers.

The adjacent original store is `<registry-name>.owner-proofs`. Selection is
`selected/<launch_id>.json`, index is `<launch_id>.json`. The independent anchor
is `<registry-name>.owner-selected/<launch_id>.json`. It survives whole-store
loss as a separate trusted record. Check it before missing-index fallback and
remember observed new-method selection in process, even when the graph is invalid.
Bind private store/anchor namespace identities and reject replacement in the
same consumer. This does not claim protection against a trusted owner deliberately
deleting every independent state copy across fresh processes.

Required graph versions are anchor 1, intent 1, selection 2, index 2, terminal 2,
request 2 and evidence 1. Exact fields are closed by the descriptor. Method/cohort,
subject, original lease, request, variant, protected metadata, related set, runner
identity and pre-effect roots agree across all applicable records. Anchor binds
the immutable intent reference. Index binds the immutable terminal reference;
terminal binds the same intent. No mixed-version or unknown-field fallback exists.
The failure document is informational and never accepted proof.

Only return `not_selected` when index/selection/anchor are absent, no selection
was remembered, and no bound namespace disappeared. Missing or changed selected
state is `invalid_proof`, including all-released primary history. Old readers
reject present schema-2 records, but an old binary cannot discover the new anchor
namespace after whole-store loss. New-cohort consumers must use this qualified
anchor-aware reader; never claim retroactive crash protection for obsolete code.

## Allowed reads and evidence semantics

One bounded Reader covers the complete transitive graph, including publication
records and typed related proofs. Limits: 4 MiB per file, 128 distinct reference
paths, 16 MiB aggregate and 4096 entries per retained/discard namespace root.
Budgets never reset at component or JSON/source boundaries. A repeated path keeps
the strongest privacy and smallest role-specific size ceiling. A zero-byte role
must reject newly nonempty data before reading its payload. A bound failure means
unsupported/invalid evidence, not permission to omit inputs or raise a ceiling.

Refs are absolute canonical paths plus exact SHA-256 bytes. Use stable no-follow
regular single-link reads, owner checks, held/named parent identity and private
0600-class files/0700-class parents by default. Only the exact installed reviewed
catalog may permit public source files or readable metadata parents; it never
permits other-user writes. Reject duplicate JSON keys, nonfinite numbers,
exponent overflow, unknown schemas/rules/versions and changed bytes. Canonical
new JSON uses sorted keys, UTF-8, compact separators and no nonfinite values;
original historical intent encodings remain defined by their reviewed adapter.

Traverse only exact selected typed refs and derived bounded retained namespaces.
Do not recursively allowlist an audit/report tree, inspect unreviewed raw logs,
read application credentials or disposable payload bytes, or execute referenced
source. Sources are data. Fixed installed rules validate their exact code/map
identities and execution-instance bindings; an input cannot install an adapter,
callback, source family, approval flag or new semantic rule.

Require every typed obligation and complete protected closure. Actual original
controller/helper waits and nonzero exits remain unchanged. PID/parent/argv,
real guard CID and original host root custody cannot be supplied by prepared
commands, a current stat, guest inode, missing event, human PASS or another actor.
The qualified diagnostic may retain `cwd:null` only with its installed
`absolute_owned_host_paths_v1` rule; that does not invent an original cwd or wait.
Unknown facts stay unsupported. The standard workspace and diagnostic disposable
variants remain distinct; a campaign parent is never a diagnostic discard root.

Current private scopes must be absent. Preserve pre-effect root observations and
original custody in intent/terminal/evidence; absence is not a substitute original
snapshot. If the original terminal already recorded removal, pre-effect root
observations must also be absent; a later receipt cannot assert recreation even
with the same numeric inode. Recompute canonical related subjects from current typed records, ignoring
only their specified mutable status field. Order is immaterial; duplicates,
missing or extra subjects deny. Revalidate protected original stage/process/
credential/result bytes. Later cleanup never repairs failed accounting.

Replay calls no Docker, model, application, cleanup/publisher or historical PID
probe. It never removes files, adopts partial state, repairs indexes or mutates
primary records. A callback/import selected by evidence is forbidden. The
reference upstream entry is `application_owner_cleanup.validate_accepted` from an
already-qualified exact provider under the original lease. Its boolean result is
not permission to import that provider in the first place.

## Decisions and diagnostics

| Decision | Meaning |
| --- | --- |
| proof_accepted | The complete supported graph passed passive validation for this exact subject and host-file scope. |
| not_selected | No selected state or remembered/bound-state loss exists. No cleanup proof is granted. |
| invalid_proof | Selected state, typed premises, privacy, limits, absence or immutable commitments failed. No fallback. |
| extension_required | The trusted consumer lacks contract/provider/read-scope authority. Stop before provider import/history admission. |

Every decision keeps admission_authorized false. No decision changes task success,
qualification, model capability or campaign readiness. Preserve closed upstream
diagnostic fields `schema, phase, condition, operation, os_error, effects` when
available; do not expose exception bodies, hashes, argv, paths, PIDs or CID values.
`inventory_unbounded`, `owner_legacy_unsupported`, `owner_legacy_incomplete` and
`owner_proof_publication_incomplete` are denial conditions, not extension grants.
An inspection `OBSERVED` result or structural plan is never accepted proof.

## Conformance use

Vector IDs, fixture kinds, mutations and expected decisions are fixed in the
vector descriptor. The upstream source test harness builds every graph in a
TemporaryDirectory using synthetic source-bound standard/diagnostic examples,
then emulates durable bytes and absent private scopes. Its fixture source catalog
is patched only in that test process and restored afterward. Those identities
must never enter a production catalog. No original owner record, lease, session,
protected report, secret or live registry is consulted.

An independent SDK can port these behavioral fixtures to its own approved reader.
It must reproduce coherent hash updates when testing semantic contradictions;
otherwise a hash mismatch can mask an unimplemented predicate. Pre-import denial
vectors must prove the reader factory/import hook was never called. Valid replay
vectors must fail loudly if a native/PID call occurs. Include complete-graph
limits, strongest reused-path privacy/size, selected loss and related-set tests.
Keep provider origin, actual local/native platform qualification and downstream
integration qualification as separate evidence with exact scope.
