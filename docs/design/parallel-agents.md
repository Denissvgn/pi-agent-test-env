# Opt-in parallel Pi agents

Status: implementation contract. Experimental schema-2 code must pass the gates
below before promotion; this document alone establishes no qualification. Implement the phases in order; each phase has a verification gate.
The shipped serial path and exact Pi 0.87.1/1.2.0 contracts remain the baseline.

## Objective and first scope

Allow two independent experiment trials to execute concurrently under one owning
parent controller. Each trial retains its own ordered setup, implementer,
read-only reviewer and independent verifier stages. This permits overlap between
trials without granting workers access to another trial's mutable state.

Initial non-goals: arbitrary nested Pi teams, parallel stages sharing a writable
workspace, concurrent in-place execution, automatic patch merging, multi-owner
distributed scheduling, new models, MCP/codemode integrations, emulation or
changes to the selected sandbox. More workers require a separately reviewed and
qualified ceiling. `--jobs` remains a per-container tool-thread hint.

## Frozen execution contract

Use a new experiment-definition version with an explicit concurrency block.
Schema-1 experiments continue to use the serial executor. Do not upgrade or
rewrite existing frozen definitions, snapshots, attempts or reports in place.

Proposed settings (names and schema must be finalized in phase 1):

| Setting | Serial default | Initial opt-in |
|---|---|---|
| Maximum active trials | 1 | 2 |
| Maximum stage containers | 1 | 2, including setup/probes/verifiers |
| Maximum in-flight model requests | 1 | 1 until higher server capacity is qualified |
| Pending queue | Bounded | Bounded, with explicit wait/deadline policy |
| Writable execution | Owned snapshot | Separate owned snapshot per trial |
| Retries | Frozen explicit policy | Same policy; no automatic retries |

Freeze scheduler version, limits, queue/stop policies, resource reservations,
source/oracle inputs, exact image/release/profile, upstream model identity and
inference-admission configuration before execution. Record the selected factors;
do not silently treat serial and parallel timing as comparable measurements.
An execution CLI may select the frozen mode, but cannot raise its ceilings.

## Admission and aggregate resources

The parent retains the existing same-user exclusive admission lease throughout
collection. Older serial clients see a busy lease while that owner is alive. Internal
trial execution needs a narrow parent-issued admission grant; do not expose
`--skip-lock` or achieve concurrency by assigning different lock files.

Represent reservations in integer CPU quota units, MiB and PID counts. Resolve
the host ceiling from Docker's observed allocation and the frozen fractions:

```text
sum(active CPU reservations) <= frozen CPU ceiling
sum(active RAM reservations) <= frozen RAM ceiling
sum(active PID reservations) <= frozen PID ceiling
active trials <= frozen trial ceiling
active stage containers <= frozen stage ceiling
```

Count capability probes, preflight, setup, Pi, browser, scorer, inference gateway,
application fixtures and any builder. Explicitly reserve shared helper costs
once, and per-trial helpers once per instance. Keep CPU/memory/PID limits on every
container, memory+swap equal to memory, and advisory jobs bounded per worker.
Inspect actual applied limits before trusting a reservation's execution.

A request that cannot fit waits within its frozen deadline or returns a safe
admission reason. Never silently reduce worker memory, increase host fractions,
drop limits or modify Docker Desktop allocation to obtain two slots. For example,
an 8-GiB allocation with a 50% budget cannot fit two 2-GiB workers plus a helper.
Reservations cover cooperating runs only; they are not exclusive host capacity
or controls on other users, tools or the remote model server.

For the first implementation, use FIFO among dependency-ready trials in frozen
matrix order. Do not allow younger grants to consume capacity required by a waiting
head request. This intentionally permits head-of-line waiting, with a bounded
deadline, rather than introducing an untested fairness/throughput heuristic.

Initially qualify images/builders before parallel collection and serialize builds.
Any later overlapping build must reserve its complete bounded builder footprint.

## Ownership, grants and recovery

Persist launch intent and resource reservation before every Docker launch. Bind
each grant to controller generation, trial/attempt/stage/segment IDs, native daemon,
immutable image, exact release contract, resource amounts and private workspace.
Only the owning parent issues grants. Host trial controllers may consume a grant
over a private inherited channel; its capability is not mounted into Pi children.
Reject stale, duplicate, enlarged or wrong-owner grants.

Use process-isolated trial controllers. Existing process-global stdout redirection,
mutable argument state and active-container collections make a naive thread pool
unsafe. Give each subprocess its own arguments, streams, run root and cleanup
state; serialize authoritative ledger updates in the owning parent.

Resource states: queued, reserved, launching, running, stopping, released or
quarantined. A deadline or stale heartbeat is not proof that a writer stopped.
Release reservations only after owned-container absence and required sensitive
cleanup are independently confirmed. Unknown cleanup quarantines capacity and
blocks new dispatch. Failed launches retain their intent and actual accounting.

The OS may release the lease when an owner dies while Docker containers survive.
Before a new controller grants capacity, inspect the persisted ownership registry
under the lease and reconcile every prior active launch. Verify exact container
identity/labels; never kill unrelated containers or infer historical ownership
from the current lock PID alone. Reject malformed/aliased/insecure registries and
unverifiable ownership. Old active attempts become controller loss, not successful
completion; they are not silently replayed.

This post-crash guarantee requires a minimum registry-aware host package at every
cooperating serial and parallel admission entry point. Mixed operation with older
installed copies is unsupported for the first parallel release: those binaries can
acquire the released flock without inspecting surviving reservations. Enable the
mode only in a cohort where older clients are quiesced and registry-aware admission
is selected. A self-version check cannot prevent an arbitrary older binary from
running; do not claim it does. Supporting those clients later requires a separate
lease-custodian design and fault qualification. This restriction concerns the host
package, not the supported Pi 0.87.1/1.2.0 binaries.

## Files, credentials and network isolation

Freeze one immutable source/oracle baseline and clone independent writable trial
snapshots. Allocate separate runtime/session/control/outbox/tmp/cache directories,
networks and fixture namespaces. Shared caches are permitted only if reviewed,
read-only and free of secrets. Concurrent in-place execution is rejected.

Keep existing per-stage `application_secrets`: only the assigned agent receives
its `PI_APP_*` values. No ambient/inference/persona fallback. Resolve references
before dispatch; checks, scorers, observers and unassigned stages stay key-free.
Do not share a writable workspace between simultaneously credential-bearing
agents: a post-stop scan cannot prevent another live worker reading a leak.

Retain exact-value/JSON-escape redaction, per-stage sensitive purge and full owned
snapshot inspection. Contamination stops dependent stages of that trial and
applies the frozen experiment stop policy. Preserve other trials' original
observations; discard only the contaminated owned snapshot. No guarantee against
arbitrary transformed secrets is introduced. Use disposable authorities/actors
and independently partitioned effects when qualifying concurrent credentials.

Pi children receive no Docker socket, controller capability or host home mount.
Keep non-root execution, read-only root, dropped capabilities, no-new-privileges,
the selected IPC/network policy and existing sandbox requirements. Native ARM64
must be selected explicitly and observed before each launch on Apple Silicon.

## Independent inference admission

Two Pi containers do not establish that the selected server can serve two model
requests. CPU/GPU/RAM, context slots and concurrency on that server are separate.
Unknown capacity keeps the cooperating request ceiling at one.

Design a bounded parent-owned gateway for cooperating Pi requests: validate exact
model/provider and allowed request fields, forward to the unchanged selected
upstream, and record requested/observed caps. Freeze the routing change explicitly;
it is neither a substitute model nor an application-API replacement. Do not claim
that a gateway or container cap constrains unrelated model-server clients.

The gateway reserves its own container budget. Use per-trial opaque inference
tokens and keep the upstream key outside Pi snapshots, public evidence and build
contexts. Application keys remain separate. Observations exclude headers, keys,
prompts and tool payloads. Qualify forwarding and token isolation before live use.

Bound queue size and wait time within both the Pi request timeout and cumulative
stage/collection deadline. Disconnect/cancel must cancel queued work and stop or
retain accounting for already forwarded work; do not release an in-flight slot
merely because the caller vanished. No hidden retries, compaction, cache warming,
numeric reasoning budget or fallback endpoint is introduced. A request ceiling
above one requires operator-declared capacity and a separately frozen server
qualification, not capacity guessed from the model name.

## Accounting, controls and stop behavior

Replace the single active-attempt field with a versioned map of active attempts
for new controllers; preserve read-only interpretation of older serial records.
Reserve unique attempt identities before launch. Persist completions independently
and export deterministic ledger order by frozen cell/attempt identity, not timing.
Retain planned, dispatched, cancelled, blocked, scored, missing, assisted and
retried dimensions; an attempted trial is never reported as not run.

On `on_failure=stop`, atomically stop new grants, then apply the declared policy
to already active trials. For the first release, request parent cancellation of
active siblings, confirm cleanup and seal their actual partial outcomes; no
scoring after cancellation unless separately permitted. Do not erase a sibling
that completed before cancellation or let a diagnostic retry reopen pending cells.
Continue policy may finish independent siblings only when cleanup remains known.

Controls must name exact run/stage identity when more than one stage is active.
No extension changes a frozen aggregate ceiling. Budget/steering actions stay
parent-authorized and assisted; exact-session recovery remains trial-local.
Patch operations require the target's quiescent state and isolation from every
active writer. Pause/reopen or hot-patching a live shared tree is not added.

## Pi compatibility

| Contract | 0.87.1 | 1.2.0 |
|---|---|---|
| Existing built-in tool policy | Preserve | Preserve |
| MCP discovery suppression | Existing flags | Also `--no-mcp` |
| Session schema | 3 | 3 |
| Clean settlement | Existing fieldless event | Required boolean `aborted: false` |
| Early persistence | Existing behavior | Session may exist before first assistant |
| Fixture profile | Original declaration/assets | Existing separate 1.2.0 declaration |
| Continuation | Same image/release/contract/session | Same image/release/contract/session |

Use the exact registry and current event parser for every worker. Unknown releases,
nested direct-tool traces and cross-release/image/contract continuation stay
unsupported. Preserve original tool/profile violations across authorized recovery.
Parallelism does not grant Pi nested-agent or integration capabilities.

## Fixed implementation order and verification gates

1. **Contracts and frozen schema.** Finalize fields, bounds, defaults, modes,
   admission codes, minimum registry-aware host-client generation, cohort rollout
   constraints and forward/backward reading. Verify serial definitions remain
   valid, unsupported parallel fields reject today, and old results never mutate.
2. **Resource allocator.** Implement weighted reservations and bounded queues.
   Test CPU/RAM/PID/helper accounting, exact-fit and oversubscription, mixed browser/
   core footprints, FIFO starvation policy, duplicate grants and monotonic deadlines.
3. **Ownership registry.** Implement secure atomic intents, generations and
   recovery. Test owner death before/after launch, PID reuse, stale capabilities,
   unknown containers, malformed records and cleanup uncertainty. Verify a new serial
   client reconciles surviving parallel reservations before launch; include an old
   client's post-owner-death acquisition as an unsupported-coexistence negative
   fixture so rollout never claims legacy crash protection. No native dispatch yet.
4. **Isolated subprocess dispatch.** Integrate trial-local controllers and streams
   with trusted grants, preserving the serial API. Test source/session/environment/
   stdout isolation and inability to launch without a valid reservation.
5. **Ledger, dependencies and controls.** Implement active-attempt maps, deterministic
   exports and stop/cancel/resume behavior. Test simultaneous completions, sibling
   failures, pending cells, assisted recovery and exact control targeting.
6. **Credential and fixture boundaries.** Test per-stage delivery, malicious
   contamination, split/escaped capture, independent actor effects, scorer isolation
   and raw-state purge across two overlapping trials. Keep real application keys out.
7. **Inference gateway.** Test bounded stream forwarding, exact model/settings,
   authentication separation, queue cancellation, disconnects, 429/5xx, slot lifetime
   and cumulative deadlines. Scripted inference is not real-model acceptance.
8. **Complete offline/package validation.** Run serial regressions for both Pi
   contracts, parallel state-machine/fault fixtures, extracted manifests, examples
   and standards checks. Use independent forward-testing of actual risky workflows.
9. **Native ARM64 infrastructure qualification.** Freeze images/resources/oracles
   and finite total budgets. Prove actual two-container overlap, limits/reservations,
   namespaces/sandbox, queued third worker, bounded failure/cancel/owner-loss recovery
   and absence of every owned container/network/private store. No emulation/opt-out.
10. **Real Pi and model qualification.** Freeze a finite matrix for both releases,
    at least three fresh repetitions per positive lane and single predeclared fault
    cases. Include overlapping independent coding, builtin/fixture lookup, scoped
    credentials and local browser trials; all eight existing fault categories must
    be adapted to multiple active trials. First use one model-request slot; admit
    more only with separately verified server capacity. Record scripted versus real
    invocations, exact process-segment ceilings and cleanup deadlines before launch.
11. **Review and release.** Document only observed capabilities, audit publication
    files for secrets/internal data, finish actual configured exact-head review and
    all finding dispositions, then use the normal authorized promotion procedure.
    Copilot quota/error notices do not establish completed code review.

Do not invent native/model counts or budgets during collection. Phase 9/10 need a
concrete approved execution intent once resource and server capacity are known.
Qualification failures stop dependent work; retain failed/unrun cells and require
explicit authorization for a changed or repeated collection. Old serial native
receipts cannot establish overlapping-worker behavior.

## Rollout and completion criteria

Ship serial default first, then an explicitly selected experimental two-trial
mode after all gates pass. Avoid enabling it through auto-detected CPU count or
saved configuration migration. Roll back by selecting serial mode in a newly
prepared experiment; do not edit a running/frozen parallel experiment in place.

Complete means two genuine Pi containers overlapped on native ARM64 within the
frozen aggregate budget, both exact Pi releases passed their positive and fault
oracles, no workspace/key/session cross-talk occurred, stop/recovery accounting
remained sealed and owned cleanup was known. Performance improvements, real
application acceptance, other parents/platforms and server-wide enforcement are
separate claims. Report observed queue time versus inference/tool/end-to-end time
and missing usage categories; do not infer throughput from a small happy-path sample.

Primary resource references:
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
- [Docker container run](https://docs.docker.com/reference/cli/docker/container/run/)
