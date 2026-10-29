# Indexed inference environments: implementation and qualification plan

Status: fixed-order implementation plan; no indexed runtime feature or native
execution is authorized by this document alone. Date: 14 October 2026.
Baseline: released 4.4.0 at `3664d60370ef48a3b2a696f66c3200618f081487`.
The [impact assessment](indexed-inference-environments.md) supplies the rationale.
Where its open questions differ from decisions below, this plan governs the
initial implementation. Change this plan explicitly before implementing a
different scope; do not improvise acceptance criteria during collection.

## Outcome and first release scope

The existing `pi-agent-test-env` skill will let its root agent discover a private
catalog, select named inference environments, authorize exact identities and
freeze assignments for a single run, serial comparison, two-trial parallel
collection or sequential implementer/reviewer pipeline. Different compatible
services may have different base URLs, exact models, credentials, context/reply
limits, reasoning and bounded sampling settings.

Initial supported wire contract remains OpenAI-compatible Chat Completions.
Preserve exact Pi 0.87.1 and 1.2.0 support, their release-specific events/profiles,
serial defaults and the qualified homogeneous two-trial contract. “API” in the
initial scope means a separately selected compatible service, not permission to
pass arbitrary wire protocols, headers or provider plugins into Pi.

The indexed mode keeps two worker slots, one bounded routing helper and one
**global cooperating inference slot**. New indexed paths, including single and
serial runs, keep original upstream keys outside Pi and supply scoped opaque
authorities. Unchanged legacy direct paths retain their existing documented
credential boundary; do not retroactively claim the stronger indexed guarantee
for historical measurements.

Additional wire APIs, independent group concurrency, more workers, mixed Pi
images/releases within an experiment, OAuth/ambient cloud credentials, arbitrary
extensions, automatic fallback and in-place indexed execution are excluded from
this first delivery. Each requires a separate reviewed contract and qualification.

## Contracts to settle before runtime edits

### Catalog, identity and authorization

- Catalog schema 1: at most 32 entries and 1 MiB of encoded JSON; at most eight
  distinct selected profiles per collection. IDs are lowercase slugs matching
  `[a-z][a-z0-9-]{0,63}`. Existing eight-agent and 64-cell-per-experiment bounds
  remain. The larger native campaign below comprises several bounded experiments.
- Each entry has an immutable incarnation UUID, semantic configuration revision,
  exact adapter contract, normalized endpoint/settings, credential source binding
  and deployment capacity-group ID. Account/rate-limit memberships are separate
  optional metadata; they do not introduce additional slots in this release.
- Use a full internal SHA-256 configuration identity. Normalize parameterized
  routes/models once in the trusted parent; do not re-expand mutable process
  variables during execution or continuation. Endpoint normalization retains the
  current URL/field/settings allowlists for Chat Completions.
- A display index is temporary. Resolving it requires the revision of the
  displayed catalog; the result is a stable ID, incarnation and fingerprint.
  Reordering, deletion or a stale response cannot select another profile.
- Session confirmations are a map of exact configuration/authority identities,
  not one global “all profiles approved” flag. Unrelated catalog edits preserve
  unchanged approvals. A selected semantic change requires fresh authorization
  and a new prepared execution.
- New entries select credential source explicitly: `store`, `env` or `none`.
  No fallback between those sources. Existing saved/explicit endpoints preserve
  legacy exported-variable-before-store resolution. A keyless indexed route has
  no upstream Authorization header; any compatibility placeholder is nonsecret.
- Confirmation binds a random opaque authority generation to the exact selected
  source and value using a parent-only keyed consistency tag in owner-only state.
  Do not expose key hashes, lengths, suffixes or consistency tags in outputs or
  experiment inputs. Admission checks the value privately before new dispatch.
- Changed/missing credentials return `inference-authority-changed` or
  `credential-unavailable`. Reauthorization creates a new prepared execution;
  a begun stage cannot acquire replacement credentials. A newly minted gateway
  token after authorized recovery may change, but its underlying binding cannot.
- Delete/revoke creates a durable tombstone. Check trusted revocation state before
  future attempts, stages and continuation segments, without reselecting endpoint
  fields. Already admitted segments keep their fixed authority; stopping them
  uses explicit cancellation. Recreated IDs get new incarnations and approvals.
- Catalog/state live outside project trees, snapshots, build contexts and child
  mounts. Use secure owner-only directories, no-follow/one-link regular files,
  bounded atomic replacement, exclusive mutation locks and revision checks.

### Selection ownership and schema compatibility

| Input contract | Selection owner and behavior |
|---|---|
| Existing plan schema 1, ordinary CLI | Existing `--endpoint FILE` or saved environment unchanged. A new explicit `--inference-env ID` selects one indexed profile for every agent stage; no competing selector is accepted. |
| Existing experiment schemas 1/2 | Preserve accepted fields, frozen formats and reading/reporting. Schema 2 still requires one identical endpoint and `parallel-trials-v1`; no indexing fields silently enable another mode. |
| New experiment schema 3, initial serial milestone | A variant selects one indexed environment; preparation materializes an exhaustive case → agent-stage → binding map from plan schema 1. Store the resolved map from the first implementation, even when uniform. |
| New standalone plan schema 2 | Owns one exhaustive top-level stage-name → environment-ID map. Every agent stage must have exactly one binding; setup/check stages cannot receive one. CLI overrides and per-agent competing selectors reject. |
| Schema-3 experiment with explicit stage maps | The variant owns the complete case → stage map. A case plan's inline environment map conflicts and rejects; use a plan with external bindings. Do not silently override it. |
| Indexed parallel execution | Explicit successor scheduler, `parallel-trials-v2`, plus reviewed indexed broker/host contracts. Schema-3 parallel admission stays disabled until its phase gate passes. |

Finalize exact JSON field names and examples in phase 1. There must be only one
selection owner for each stage. Missing/extra stages, duplicate names, unsupported
selectors and contradictory defaults reject before any credential resolution or
Docker launch. Catalog `default_id` is a discovery convenience: root resolves it
to an explicit ID. It does not change legacy commands' default saved endpoint.

Do not migrate frozen schema-1/2 evidence. New host code must read predecessor
registry/contract formats while rejecting unknown ones. Introduce an indexed
host generation 2 without changing the meaning of a frozen generation-1 request.
All cooperating hosts used for indexed execution must understand generation 2;
quiesce older installed packages, including original 4.4.0 copies, during rollout.
An old package's flock alone cannot establish post-crash indexed ownership.

### Runtime boundaries

- Freeze an `indexed-inference-v1` helper/execution contract independently of
  parallel concurrency: one worker plus one helper for indexed single/serial;
  two workers plus the same helper for indexed parallel. Setup, preflight, browser
  probes, check/scorer and fixture containers all count toward reservations.
- Resolve all selected inference sources in the trusted parent before probes,
  setup or worker dispatch. Reject application references or values colliding
  with **any** selected inference authority. Preserve shared-actor serialization.
- Pi receives only an opaque capability for its frozen environment/trial/attempt/
  stage/segment. Model names, headers, URLs and body fields cannot choose routes.
  Model-list preflight exposes only the model bound to that capability.
- Preserve current non-root/read-only/capability/IPC/sandbox policies and separate
  snapshots, networks, sessions, controls, caches and stdout. No Docker socket or
  complete catalog/key map enters a worker. No unscoped inference credential lookup.
- One-route serial helpers have immutable configuration; switching serial
  variants requires known cleanup and a fresh authority/helper. Multiroute mode
  also freezes its table; adding or rebinding a route during a run is forbidden.
- Deployment groups and overlapping provider/account constraints stay separate.
  All routes still share one global slot; metadata does not prove independent
  servers, GPU slots, accounts or quotas. Future multiple-group admission must
  satisfy every constraint atomically, not accumulate partial reservations.
- Unknown upstream termination causes durable **global** inference quarantine.
  No new route can evade it. Container absence does not prove remote completion.
  Preserve parent stop/cancel policies, sealed primaries and exact-session recovery.
- Per-stage identity includes environment incarnation/configuration, adapter,
  original authority generation, release/image and stage. A session cannot change
  any of these on continuation. Every stage's source/artifact destination is
  authorized before dispatch; fresh stages may use different environments.

## Fixed implementation order

Finish each phase's gate before its dependent phase. Keep an implementation
ledger outside the installed package with source revision, changed files, checks,
independent findings and unresolved scope. A failed gate stops dependents.

### 0. Preserve the baseline and evidence

Record baseline tree, versions, manifests, released contracts and dated native
identities. Preserve the assessment and 4.4.0 evidence. Create any implementation
branch without tracking its base; publish only an explicitly selected same-name
ref after authorization. Inspect existing work rather than resetting it.

Gate: baseline recorded, worktree changes understood, protected inputs identified,
no endpoint/key/deployment mutation or native dispatch performed.

### 1. Freeze schemas, root workflow and acceptance

Define the contracts above, safe reason-code whitelist, public/private output
views, authority/revocation lifecycle and representative examples. Define schema 3
before the serial milestone and its exhaustive resolved map. Separate adapter
availability, declared capabilities, confirmation, health and live qualification.

Specify proposed CLI names: `env list`, `env inspect --id`, `env register --id`,
`env update --id --expected-revision`, `env revoke/delete --id`, per-ID
`env confirm/check/status`, and mutually exclusive `--inference-env ID` selection.
Preserve current commands and avoid confusing existing `--environment FILE`
(container capability probes) with inference selection.

Gate: strict positive/negative schema fixtures; no ambiguity about binding ownership,
unsupported APIs, default behavior, authority rotation or continued sessions.
Installed documentation must label future commands until their code gate passes.

### 2. Secure catalog, common resolver and per-profile session gate

Implement a focused catalog module and reuse endpoint normalization rather than
duplicating it. Support explicit legacy import into a new named incarnation,
without automatic migration or overwriting the saved environment. Add secure
CRUD/CAS/tombstones and a shared resolver used by all indexed entry points.

Listing is offline and metadata-only: no secret values, model calls, URL probes,
credential commands or login. Availability is `present/missing/insecure/unknown`;
default inspection returns bounded status, IDs and capabilities. Detailed routes,
models, references and semantic fingerprints remain private-only.

Gate: storage races, temporary-file security, stale indexes, concurrent mutation,
unrelated edits, selected changes, delete/recreate, authority changes and legacy
confirmation all have deterministic fixtures. No indexed dispatch yet.
Indexed `confirm` records the explicit selection and private source binding
offline; indexed `status` reports cached state unless live checking is expressly
selected. `check` performs bounded live work only after its runtime gate exists.

### 3. Extract and verify a one-route indexed broker

Factor the existing gateway ownership/admission machinery into a broker contract
usable outside schema-2 parallel collection. Keep the existing gateway transport,
timeouts, response framing, one-slot behavior and disabled retry/compaction/cache
warming. Reserve the helper before launch and persist exact registry intent.

Resolve selected sources explicitly, issue scoped tokens, proxy preflight without
giving upstream credentials to Pi, and scrub every held key/token. Reuse secure
owned cleanup and global uncertainty quarantine. No catalog selector enters an
execution path until this boundary is proven.

Gate: loopback fixtures prove exact route/model/auth, token-scoped model listing,
all denial paths, deadlines, complete/truncated streams, caller cancellation,
owner loss, private purge and reservation release. Legacy broker/direct behavior
remains unchanged. Zero unauthorized upstream requests on rejected bindings.

### 4. Indexed single runs and serial schema-3 experiments

Integrate the resolver/gate/broker with run, smoke, preflight, doctor and experiment
commands while retaining their existing command-specific admission boundaries.
Freeze normalized endpoints, authority references, adapter IDs, settings and
exhaustive stage maps. Execution reads frozen copies and trusted authorization
state, never a mutable catalog default. Reject selector conflicts.

For serial variants, create/clean immutable one-route helpers in frozen order;
do not mutate an active helper's upstream. Materialize a uniform profile into all
agent stages without giving setup/check stages an inference binding.
Indexed live health/check requests also obey the same-user admission lease,
global inference slot and durable quarantine; a root diagnostic cannot bypass an
uncertain broker by contacting its upstream directly. Preserve legacy semantics
while making the new indexed-path guarantee explicit.

Gate: new indexed selectors work through the broker; old saved/explicit callers
and schema-1 serial behavior retain semantics; prepared metadata mutation cannot
reroute execution. Ship the supported root workflow/reference/examples now.

### 5. Immutable multiroute broker and complete credential admission

Generalize the trusted broker to only the selected bounded profile set. Route
from a validated opaque binding, never the worker-supplied model/URL/provider.
Validate per-binding settings and token limits; exact equal model names on two
upstreams must not bypass route isolation. Retain one global slot and quarantine.

Extend parent admission, application-key exclusion, environment stripping,
redaction, contamination scans and cleanup to every selected inference key.
Arbitrary valid key-reference names must be stripped explicitly, not only by
secret-suffix heuristics. No multiroute catalog or original key map reaches Pi.

Gate: two synthetic routes with distinct keys, both distinct and identical model
names, route/body/header spoofing, cross-token use and split/escaped all-key echoes.
Quarantine on one route stops all further inference; private stores and owned
networks clean correctly. Indexed parallel execution remains gated off.

### 6. Indexed two-trial scheduling and durable recovery

Implement `parallel-trials-v2` with schema-3 admission, host generation 2 and frozen
binding/helper/deadline/group metadata. Preserve predecessor readers and the
existing `parallel-trials-v1` homogeneous route. Reuse process-isolated host
controllers, weighted FIFO reservations, trial-local namespaces and same-user
lease custody; do not add a lock bypass or another inference slot.

Update grant validation, registry observations, owner-loss reconciliation,
cancel/stop policy and ledger ordering. Remove no existing endpoint-equality
guard from old schema 2. Its successor explicitly supports trusted heterogeneous
bindings; it must never pick `work[0]`'s key for another profile.

Gate: different profiles overlap in separate worker containers while one inference
slot is enforced; shared aliases, stopped siblings, pending/halted cells, missing
ownership and uncertain upstream state preserve accounting and cleanup. An
older-client negative fixture proves unsupported coexistence after owner death.

### 7. Per-stage assignments and exact-session controls

Add standalone plan schema 2 and schema-3 variant-owned stage maps. Validate exact
case/stage coverage and map ownership; no hidden inheritance/override channel.
Admit all destinations and credentials before dispatch. Generate only the assigned
model/provider configuration for each fresh stage and its exact Pi contract.

Extend stage descriptors, model evidence, session freezing/continuation and
assistance controls with immutable binding identity. Mint new opaque tokens when
needed for authorized recovery without changing the original authority. A caller
cannot steer/patch a stage into another environment or reopen sealed primaries.
Standalone and schema-3 serial role pipelines use one immutable multiroute broker
with the complete frozen selected set and only one active worker. Stage A→B
changes the scoped capability, not the helper's upstream table. Parallel pipelines
use the same table with two worker slots. The phase-4 one-route-per-trial lifecycle
remains for uniform serial bindings; every intent states the chosen broker mode,
and its launch/network derivation counts that lifecycle.

Gate: A→B and B→A role pipelines use fresh sessions and correct routes; same-name
models at different endpoints cannot evade continuation checks; model/API/key/
image/release/stage switches reject before launch. Revocation and credential
rotation races stop future admissions without rewriting completed history.

### 8. Provenance, comparison, privacy export and diagnostics

Bind the complete stage map, adapter/resource policy and authority generation to
configuration and attempt identity. Record requested, observed, missing, assisted,
retry and failed dimensions per stage/profile without replacing old report fields.
Keep provider token categories separate; missing usage stays unknown. Do not infer
price, inference time, model quality or performance from heterogeneous timings.

Add private selected-profile receipts and allowlisted public exports using opaque
per-collection binding labels. Do not export the complete catalog, private IDs,
URLs/model IDs/key references, credential-derived fingerprints or home paths.

Safe reasons include `environment-not-found`, `environment-index-stale`,
`selection-conflict`, `unsupported-api-adapter`, `environment-unconfirmed`,
`environment-configuration-changed`, `inference-authority-changed`,
`environment-revoked`, `credential-unavailable`, `inference-queue-expired`,
`inference-quarantined` and existing ownership/resource failures. Guidance is
bounded and nonsecret; raw provider errors remain redacted/private diagnostic data.

Gate: comparisons reject mismatched bindings/oracles; export/privacy fixtures and
raw exception/redaction negatives pass; old sealed results remain readable and
unchanged. A failed invocation with a correct artifact is still not model success.

### 9. Complete native skill integration and installed-root workflow

Update the existing skill, not a second launcher or skill:

- `SKILL.md`: environment gate, selector ownership, reuse of unchanged approvals,
  explicit egress/budgets, qualification, frozen execution and safe recovery.
- `references/INFERENCE-ENVIRONMENTS.md`: complete CLI/schema/state semantics,
  legacy/indexed differences and current qualified scope.
- `EXPERIMENTS.md`, `PARALLEL-AGENTS.md`, `PI-COMPATIBILITY.md`, `RESOURCES.md`,
  `APPLICATION-CREDENTIALS.md`, `SECURITY.md` and `PROJECTS.md`: consistent limits.
- `assets/` and `examples/`: synthetic indexed single run, serial comparison,
  heterogeneous collection and role pipeline; commands are valid at this phase.
- `skill.json`, manifests, exporter/source allowlists and all five install layouts:
  complete self-contained delivery. Do not add a release-version promise early.

Root must be able to follow **offline list → inspect → explicit selection →
per-profile confirmation → qualification → offline freeze → execution/report**
from the installed entry alone. It never delegates selection to children or
uses a spare profile as automatic fallback. CLI dry-run/inspection is metadata
only; commands that actually perform health or Pi/Docker work say so explicitly.

Gate: executable example/schema checks and a fresh-history independent root review
of extracted installed instructions find no missing hidden dependency or fictional
command. A parent-model/tool invocation is claimed only if actually observed;
standards/package checks alone do not establish parent discovery behavior.

### 10. Implement the native harness and dry execution intent

Use a maintainer-only harness under `tools/qualification/`, with tests before any
live run. Define all tables below, unique trial/stage identities, oracles, fixture
bytes, profile/authority identities, exact images, resources, whole/subcollection
clocks, launch plans and cleanup inventories. Build a dry intent without Docker
or model execution; concrete image/deployment inputs are resolved before approval.

Derive Docker launch ceilings from every planned image/probe/preflight/setup/
agent/scorer/helper/recovery path. Record numeric infrastructure/A/B/whole ceilings
in the concrete manifest; fail freeze if the derivation has omissions or exceeds
the provisional whole hard cap of **1600 container launches** or **256 created
networks**. Derive network creation/removal counts separately. Do not inherit
4.4.0's 900-launch ceiling or invent numbers after seeing the native run. If either
hard cap is insufficient, revise and approve a new intent before dispatch.
Every actual launch consumes its phase and whole counters.

Gate: offline fake-boundary harness tests prove complete cells/segments/launch
accounting, real-versus-scripted separation, strict source/config/oracle freeze,
timed-out/failed/not-run states and independently verified cleanup. Harness
implementation is complete before the final-source verification in phase 11.

### 11. Final offline/package verification, frozen intent and approval

Run the full maintainer suite, including all existing 546 baseline tests plus new
regressions; required tests may not be skipped to produce a pass. Build fresh
archives and run `tools/verify_release.py` against extracted bytes, five layouts,
manifests, examples and pinned official standards. Include final harness/tests
from phase 10. Fix supported findings and rebuild/reverify after executable edits;
no later harness/source change can reuse this gate silently.

Independent forward tests must exercise actual CLI/storage/loopback/subprocess
boundaries and both pinned SDK request shapes, including the native harness dry
paths and installed root instructions. They must not merely repeat implementation
conditions. Audit publication files for credentials/private inventory. Record
fixtures separately from native/model acceptance.

After these checks pass on one exact source, freeze the concrete approved-profile,
image, resource and launch derivation with integrity receipts. Present the execution
intent and obtain explicit approval for the infrastructure and A/B subcollections,
including older-host quiescence, egress, live health calls and model-deployment
known/unknown limits. Passing offline verification does not authorize dispatch.

Gate: suite/package/forward/privacy checks pass on final executable/harness bytes;
immutable intent and exact approved ceilings/identities are recorded. Source or
intent changes return to the affected checks and a fresh approval decision.

### 12. Native ARM64 infrastructure gate

On Apple Silicon, explicitly select and verify `linux/arm64` for every pull/build/
run. Admit core/browser images for exact Pi 0.87.1 and 1.2.0; use the selected
sandbox with no opt-out/emulation. Qualify image builds separately and serially
with a finite BuildKit budget if reuse is unavailable.

Prove two-container physical overlap/applied limits, FIFO third-worker admission,
cancel/owner-loss recovery and both sandboxed DOM gates. Run at most **64 direct
scripted gateway transactions**, adding zero Pi segments, for two-route isolation,
identical model names, scoped lists, all-key/opaque-token redaction, shared aliases,
deadline/cancellation and global uncertainty quarantine. The disposable fixture
authority can serve these routes; no unbudgeted extra helper is allowed.

Gate: all infrastructure oracles and physical/private cleanup checks pass within
the 20-minute gate ceiling, including its own cleanup allowance. A failure stops
both dependent subcollections.

### 13. Ordered native subcollections A then B

Run Collection A completely, verify its physical/private cleanup and retain its
sealed evidence, then start B under the same frozen final source and whole-clock
budget. No source, route/model, key source, oracle, helper or budget adjustment is
allowed between them. Verify exact source identity again at each boundary.

Both releases must pass every positive and fault oracle required below. Actual
positive Pi tool calls, clean release-specific settlement, correct assigned
upstream/model and key-free independent scores are mandatory. Inspect all 36 planned coding
diffs/reviewer reports against protected inputs (24 standalone/serial pipelines
in A and 12 parallel pipelines in B). Reviewer prose is advisory.

Gate: both subcollections complete; all resources/networks/private stores are
independently confirmed absent, known-key scans and public privacy audit pass,
original environments/stores/deployments are unchanged, and observed totals stay
within every cap. Partial/blocked evidence cannot qualify the whole option.

### 14. Promotion and rollout

Document only observed scope and retain original source/image/model/harness
identities. Update installable examples/qualification guidance, rebuild/verify
artifacts and audit Git/PR/release metadata. Prepare a clean PR and finish actual
configured exact-head review, with supported dispositions of all findings.
Previous one-time Copilot exceptions do not authorize another exception.

Merge/release only under the user's applicable authorization with an exact-head
guard, immutable tag/assets and uploaded-hash verification. Roll out the catalog
as explicit opt-in; legacy defaults stay unchanged. Rollback selects legacy/old
homogeneous behavior in a **new** prepared execution and retains all new evidence.
Do not resume a frozen indexed execution under older or changed runner bytes.

## Offline acceptance matrix

| Domain | Required fixtures |
|---|---|
| Catalog/storage | Bounds/unknown fields, insecure ownership/modes, symlink/hardlink/temp-file aliases, atomic replacement/CAS, concurrent CRUD, stale menu revisions, delete/recreate incarnation and durable tombstones. |
| Session/resolution | Selected-only approval invalidation, immutable normalized substitutions, explicit selector conflicts, legacy default untouched, metadata-only list, no automatic login/model requests. |
| Credential source | Exact store/env/none mode, ambient override rejected for store mode, missing/insecure source, arbitrary variable names, rotation between admission and continuation, private authority tag/revocation behavior. |
| Broker/routing | Distinct synthetic routes/keys plus equal model IDs, wrong stage/trial/segment capability, body/header/URL/model spoofing, token-scoped model lists, old-token revocation and zero unauthorized upstream requests. |
| Sensitive boundaries | Every selected inference ref/value excluded from application credentials; all-key/surrogate redaction over every split and JSON escape layer; contaminated snapshot discard; no catalog/key map into child or scorer. |
| Resources/lifecycle | Every helper/stage reservation, exact-fit/oversubscription, FIFO, pending limits, cancellation, queued disconnect, forwarded completion, uncertain-upstream global stop, source-safe lease custody, owner-loss cleanup and predecessor registry reading. |
| HTTP/deadlines | DNS/address/TLS/header/body/chunk/trailer cumulative limits; short/large/truncated replies; 401/429/5xx; no hidden SDK retry/fallback; queue-before-grant expiry and frozen route-aware preflight ceilings. |
| Plan/experiment | Exhaustive case/stage map ownership, duplicate/unknown names, schema/adapter/image/release mismatches, freeze/tamper/catalog changes, matching initial/continued identity, assist/retry/stop primary accounting. |
| Evidence/comparison | Per-stage binding and authority identities; same model name/different route distinction; shared oracle/source/treatment factors; missing usage unknown; public export strips private inventory; old records remain immutable. |
| Installed skill | Valid real CLI examples; self-contained entry/reference links in five layouts; root can select/reuse/confirm/freeze safely from installed docs; unsupported APIs and incomplete native scope described truthfully. |
| Both Pi contracts | Exact upstream SDK shapes and provider/model settings, disabled retries/compaction/cache warming, ordered tools and settlement, fixture release declarations, continuation/session/tool-policy regressions. |

No new unit-test count is invented in advance. Completion requires observable
coverage and a passing full suite, not reaching an arbitrary numerical target.

## Native intent: resources, prerequisites and ceilings

The values below are a planning envelope, not a new execution approval. Confirm
the current Docker allocation and exact source/fixture launch derivation before
freezing. Record actual applied container settings and independently verify them.

| Component | CPU | RAM and equal memory+swap | PIDs | Maximum active |
|---|---:|---:|---:|---:|
| Worker stage, including browser/check/probe | 1 | 1536 MiB | 512 | 2, or 1 in indexed serial lanes |
| Inference broker | 0.25 | 128 MiB | 64 | 1 |
| Disposable authority/controlled routing observer | 0.25 | 128 MiB | 64 | 1 |
| Aggregate Docker ceiling | **2.5** | **3328 MiB** | **1152** | All helper costs included |

- Worker jobs/thread hints remain 1. No memory clamping or Docker allocation
  increase to fit the request. Model-server CPU/GPU/RAM are separate and remain
  operator-declared or explicitly unknown, not inferred from model lists.
- Global inference in-flight 1, pending at most 4. Real-positive queue/upstream
  deadlines 180/180 seconds; derived model-list preflight 360-second request and
  390-second container. Positive stages: 12 turns, 600 seconds, 128,000 reported
  total tokens; reply cap at most 8192 and below selected context. Smaller selected
  supported caps are frozen explicitly, not overwritten to match this envelope.
- Scripted fault stages: 20 turns, 60 seconds, 16,000 reported tokens; scripted
  route queue/request 10/30 seconds and preflight 120/150 seconds. These are separate
  frozen fixtures, not a silent fallback from a real selected service.
- Infrastructure ceiling 20 minutes (at most 16 minutes active admission/probes
  plus 4 minutes cleanup); A collection 3 hours; B collection 4 hours; A/B cleanup
  at most 4 minutes after each. Whole absolute campaign ceiling:
  **7 hours 28 minutes**, including those cleanup allowances. No nested operation
  can exceed its remaining phase/whole deadline. Completion within this envelope
  is unproven; deadline expiry is failure, not permission to increase it.
- Collection A and B have separate counters/manifests within one immutable whole
  intent. A completion permits B only if the approved intent includes both, A's
  cleanup passes and the whole deadline remains. Otherwise obtain the concrete
  B approval before dispatch. Any failure stops further dependent collection.

Use owner-private disposable configuration/catalog/session/store namespaces outside
projects and public evidence. Existing `PI_LAB_CONFIG_DIR`, `PI_LAB_STATE_DIR` and
`PI_LAB_SECRETS_DIR` hooks isolate legacy saved/default and catalog-mutation tests;
the indexed catalog path must have an equivalent reviewed test hook. Import only
approved profile copies and required authority references into these fixtures.
Do not overwrite the operator's saved default/catalog or rotate real credentials.
Rotation/revocation adversaries use synthetic keys and zero-Pi rejection probes.
Verify original user state and stores are unchanged at the end.

Valid existing health receipts may be reused only within exact unchanged scope.
Otherwise enumerate up to **eight approved live non-Pi health HTTP requests**
(model-list and tiny-chat, reply cap 16, serially admitted with a finite per-call
15-second deadline) in infrastructure. Record their endpoints privately, actual
counts and time separately from the at-most-64 scripted probes. They consume the 16-minute
active infrastructure allowance and global request ceiling. No extra Pi smoke,
participant or uncounted API request is permitted before Collection A/B.
Routine per-trial preflight and preserved legacy confirmation/health requests
inside A/B are separately enumerated in those subcollections' HTTP admission
budgets; the eight-request infrastructure allowance does not cover or hide them.
The harness counts these requests as well as model generations and respects each
remaining phase/whole clock.

Require two explicitly selected real profiles **A and B**, each with exact
listed model, route/settings/auth-source confirmation, text/tool capability,
observed/declared context, egress approval and valid health-admission evidence. Prefer
different real base URLs **and** model IDs so the first full matrix exercises both.
Freeze diversity requirements and evidence in the intent. Genuine tool/model
qualification comes from the planned A/B cells, not an uncounted prior smoke.
Do not invent a second model by remapping A's ID or wrap A in a scripted alias
and call it B.

If only one real profile is available, full heterogeneous qualification remains
`not_run_blocked`. A separately approved narrowed campaign can establish narrower
catalog/routing observations, but cannot satisfy this plan's complete acceptance.
Two real profiles on one deployment are valid only when that shared/unknown
capacity is recorded honestly and the global single slot is retained. They do
not establish independent providers or weights identity.

## Native Collection A: indexed selection and legacy compatibility

Use one fixed one-stage read/write/bash challenge and a fresh independent verifier
for the first six rows. The final two rows use the frozen coding/review subject
and independent oracle, with separate fresh stage sessions. Every positive
treatment has three fresh repetitions. Run each row for **each** exact
Pi release, in table order, with a selected matching core image.

| Lane per release | Selection/treatment | Cells | Segment ceiling |
|---|---|---:|---:|
| Indexed single | A and B × 3 | 6 | 6 |
| Indexed serial comparison | Uniform schema-3 A/B variants × 3 | 6 | 6 |
| Legacy saved default | A × 3; catalog/default changes cannot replace it | 3 | 3 |
| Legacy explicit endpoint | B × 3; prior selection semantics retained | 3 | 3 |
| Existing schema-1 serial | Two frozen variants × 3, legacy endpoint route | 6 | 6 |
| Existing homogeneous schema 2 | Two variants × 3 on one identical upstream | 6 | 6 |
| Standalone plan schema 2 | A→B / B→A coding/review pipelines × 3 | 6 | 12 |
| Indexed serial role comparison | Schema-3 explicit A→B / B→A case-stage maps × 3 | 6 | 12 |
| **Per release** | | **42** | **54** |
| **Both releases** | | **84** | **108 real-model segments** |

Root/list/confirmation/mutation/rotation adversaries are deterministic offline or
pre-dispatch native admission fixtures. They do not add undocumented Pi calls.
Qualifying the indexed broker does not erase the legacy direct credential boundary.

## Native Collection B: heterogeneous trials and stage assignments

Run rows in order for 0.87.1 then 1.2.0. Use two isolated parallel trials, one
global request slot and three fresh repetitions for each positive treatment.

| Positive lane per release | Cases and assignments | Cells | Segment ceiling |
|---|---|---:|---:|
| Coding/review | A→B and B→A pipelines × 3 | 6 | 12 |
| Lookup/tool profile | Two frozen subexperiments: builtin A/B × 3 and reviewed fixture A/B × 3 | 12 | 12 |
| Scoped credentials | Two disjoint actor namespaces × A-B-A / B-A-B stage maps × 3; third stage is application-unassigned | 12 | 36 |
| Local browser | A/B × 3 with selected sandbox-enabled browser image | 6 | 6 |
| **Positive per release** | | **36** | **66** |
| **Positive both releases** | | **72** | **132 real-model segments** |

Cross environment A/B with both lookup subjects. Use two separate frozen lookup
subexperiments so each keeps its variant-owned child profile: builtin for both A/B
in one, the exact release-specific fixture profile for both A/B in the other.
Do not add an undeclared case-level profile selector. Assigning A only to builtin
and B only to fixture would confound tool profile and model while leaving two
paths untested. Treat role-swapped pipelines as declared treatments, not an automatic
quality comparison. Application authority effects need independent key-free
readback and distinct namespaces; real application actor acceptance is excluded.

Then run the existing eight scripted Pi fault lanes per release with trusted
profile bindings and strict observed causes. Four planned cells per lane retain
both started and deliberately halted/pending outcomes.

| Fault per release | Required observation | Planned cells | Segment ceiling |
|---|---|---:|---:|
| Abort/cancel | Real overlapping child processes stopped; scoring suppressed; primaries retained | 4 | 4 |
| Timeout | Actual timeout cause/exit and stop-policy sibling accounting, not an unrelated failure | 4 | 4 |
| Exact-session recovery | Two authorized interrupted continuations plus fresh pending trials; binding switch rejected before launch | 4 | 8 |
| Controller crash/resume | Real controller kill, registry-matched cleanup, original lost attempts sealed and pending-only resume | 4 | 4 |
| Discovery | Reviewed tool/profile admission and actual declared fixture behavior | 4 | 4 |
| Protected boundary | Real denied mutations and independently unchanged protected container/control bytes | 4 | 4 |
| Contamination | Actual known-key write/escape, dependent halt and owned snapshot discard | 4 | 4 |
| Fatal provider | Controlled scripted provider error after overlap; correct failure/stop cause | 4 | 4 |
| **Fault per release** | | **32** | **36** |
| **Fault both releases** | | **64** | **72 scripted segment ceiling** |

Expected scripted execution is 26 segments per release (2/2/6/4/4/4/2/2), or 52
total, if the predeclared expected paths complete. This is an expectation, not a
measurement. Rejected tamper/rotation/continuation probes add zero Pi segments;
extra fresh Pi invocations require a new frozen matrix, never hidden expansion.

| Complete campaign accounting | Planned cells | Pi segment ceiling | Expected actual segments |
|---|---:|---:|---:|
| Collection A | 84 | 108 | 108 real |
| Collection B | 136 | 204 | 132 real + 52 scripted = 184 |
| **Total** | **220** | **312** | **240 real + 52 scripted = 292** |

The native campaign is not one experiment exceeding the existing 64-cell limit.
Its bounded lanes/subexperiments obey that limit and share campaign accounting.
Infrastructure's at-most-64 direct HTTP probes are separate from the 220 cell
oracles and consume zero Pi segments. All launched containers still count.

## Oracles, failure retention and completion

For each positive cell, verify exact requested/observed binding, genuine Pi
invocation, ordered paired tools, release-specific clean settlement, successful
process stop, protected inputs and independent task/effect result. Indexed cells
additionally prove original upstream-key exclusion and scoped broker authority.
Legacy direct cells verify their preserved credential/redaction boundary; they
cannot satisfy or claim the stronger indexed exclusion guarantee. Independent controlled routing observations may retain only
opaque route IDs and match booleans; never prompts, headers or key values.

Token/usage categories must support the frozen acceptance claim. Missing or
placeholder usage remains unknown and cannot establish enforcement of a required
token ceiling. Freeze any supported narrower policy before execution, never
replace unknown usage with zero during collection. Actor credentials are disposable;
inference keys and existing model deployments remain unchanged.

For fault cells, require the intended cause, expected statuses, unchanged sealed
originals, remaining blocked/halted denominator, exact session/binding identity,
applied controls and independently stopped writers. Model/provider prose and
generic exception types alone cannot satisfy a negative oracle.

Retain private intent/approval/source/image/model/adapter/profile/authority and
resource receipts, raw redacted streams, ordered events, usage/queue observations,
scorer outputs, diffs/protected hashes, registry/cleanup evidence and original
failure/unrun ledger. Public summaries are separately allowlisted. Do not export
private configuration to demonstrate reproducibility.

On any failed admission/oracle/deadline/cleanup/privacy check: stop dependents,
clean known owned resources under the lease, quarantine uncertainty, retain
original evidence and diagnose offline. Fix/test/review a concrete correction,
freeze a new intent and request explicit authorization for changed or repeated
collection. No automatic retry, relaxed oracle, silent route/model replacement,
budget increase or copying previous success under a new runner identity.
A predeclared negative trial's expected timeout, interruption or failure is not
a qualification failure when its strict fault oracle passes. Campaign/phase
ceiling expiry or an unexpected cause remains a blocker.

Done means all phase gates pass, root can use the self-contained installed skill,
both exact Pi releases satisfy A and B, no cross-binding/workspace/credential
effects occur, every owned resource and private store is reconciled, and review/
publication steps are fulfilled within authorization. A passing catalog test or
the historical 4.4.0 matrix cannot substitute for this native scope.

## Later extension tracks

After this release's acceptance, select an actual additional API use case and
write a separate adapter plan. For each API × exact Pi release, review provider
generation/auth/discovery/request fields/tool-result and stream semantics,
completion/usage/storage/error handling, all-key redaction, cancellation/deadlines,
and immutable continuation. SDK/API names alone do not establish support.

Independent deployment/account group concurrency similarly requires new global
and group resource/connection/rate budgets, atomic multi-constraint admission,
group-wide durable quarantine and separately qualified server capacity. Neither
new catalog entries nor new API keys enable it automatically.

## Related contracts

- [Impact assessment](indexed-inference-environments.md)
- [Fixed parallel-agent plan](parallel-agents.md)
- [Installed skill entry](../../skill/SKILL.md)
- [Current qualification scope](../../skill/QUALIFICATION.md)
- [Pi compatibility](../../skill/references/PI-COMPATIBILITY.md)
- [Application credentials](../../skill/references/APPLICATION-CREDENTIALS.md)
- [Resource and admission rules](../../skill/references/RESOURCES.md)
- [Exact-head promotion procedure](../../skill/references/PULL-REQUESTS.md)
