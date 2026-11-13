# Changelog

## Unreleased

Additions for programs that drive the runner unattended. None of them is part
of a qualification campaign yet, and the defaults are unchanged.

- New network mode `--network endpoint-only` for `run`, `smoke` and
  `preflight`. Agent and preflight containers are attached to an internal Docker
  network; a relay container forwards TCP only to the host and port of the
  endpoint's container route, so TLS stays end to end and nothing of the stream
  is logged. Before any key enters a container, a proof must show that a probe
  on that network cannot reach a canary on the default bridge, the bridge
  gateway or a public name, and can reach the relay; any other result blocks
  the run with `egress-not-contained`. The record gains `network` (mode, stage
  networks, allowed host and port, proof, cleanup) and each stage's process
  record gains `network_mode`. `doctor --egress-proof` runs the proof alone.
  An `http` route with an IP literal is rewritten to the relay address and
  recorded; an `https` route with an IP literal is refused with
  `egress-route-unsupported`. The mode is refused with `feature-conflict`
  together with experiment commands, indexed or parallel execution, compiled
  application plans and native tool budgets. Verified on Docker Desktop for
  macOS only; see `references/SECURITY.md`.
- `--network host` and `container:<id>` are now refused with
  `network-mode-refused` unless `--allow-host-network` is given, and a named
  network must exist. Experiment definitions refuse `host`. Upgrade note: a
  caller that passed `--network host` must add the new option.
- `result.json` and `summary.json` gain `verdict`: one object with a closed
  list of outcomes and an attribution of `none`, `model`, `endpoint`,
  `configuration`, `infrastructure` or `operator`, plus the phase, stage,
  reason and exit code. A caller can tell a failed check or an exhausted budget
  from a model-server fault, a host fault or a cancelled run without mapping
  the layered fields by hand. No existing field, status or exit code changes.
  `status` prints the verdict. The lists, the precedence and the reason mapping
  are in `references/EVALUATION-CONTRACT.md`.
- `result.json` gains `usage_summary`, one row per stage with its kind and
  wall time and, for agent stages, turns, tokens and the plan's and effective
  limits; a value the model server did not report is null. `run` accepts
  `--max-turns`, `--max-total-tokens` and `--agent-timeout-seconds`, which
  replace the plan's values for every agent stage within the plan's bounds and
  are recorded as `budget_overrides`.
- When the host lock is busy, the failure names its holder under
  `infrastructure.holder` (pid, command, start time, age, run id when known,
  and whether the process exists), and one text line `Held by pid N (op) for S
  seconds` follows the JSON line on stderr. Upgrade note: a caller that parsed
  the whole of stderr as one JSON document must read its first line. `doctor`
  gains the check `host-lock`. `references/RESOURCES.md` states that the
  default lock is shared by every checkout and worktree of one host user.
- Every container and network the runner creates carries the label
  `org.pi-agent-test-env.run=<run id>`, or `none` outside a run. The new
  command `leftovers [--run RUN]` lists what finished or abandoned runs left in
  Docker, and `cleanup --run RUN [--yes]` removes, under the host lock, exactly
  the resources that carry both the managed label and that run id, lets the
  registry reconcile, and seals a run whose supervisor is gone so that it never
  ends as a pass. Without `--yes` it changes nothing. `status` prints how many
  labelled resources of the run still exist. See
  `references/REGISTRY-RECOVERY.md`.

## 4.10.0

Stable release on Pi 1.5.2. It qualifies the stable scope on upstream Pi 1.5.2
and defers Pi 0.87.1 and 1.2.0 from qualification. It also makes each reviewed
Pi release one registry entry, publishes canonical file modes in release
archives and fixes a Linux crash in the parallel engine.

### Stability

- **Stable:** unchanged from 4.9.1 in scope, now on native ARM64 with Pi 1.5.2:
  serial, parallel and indexed runs, legacy saved and explicit endpoints, frozen
  experiments, the reviewed fixture lookup integration, scoped application
  credentials and sandboxed browser tasks.
- **Deferred:** Pi 0.87.1 and 1.2.0 keep their reviewed contracts unchanged but
  were not qualified for this release. Qualified support covers Pi 1.5.2 only.
- **Experimental:** the features that were experimental in 4.9.1. Endpoint
  `transient_retries` is reviewed for Pi 1.2.0 and 1.5.2; the release campaign
  did not opt into retries.
- The repeated-tool-call guard stopped no stage in the release campaign. Native
  AMD64, including the AMD64 `fd` build, remains unqualified.

### Qualification

- On 11 November 2026 a fresh native ARM64 campaign on the release code
  (`626459c`) passed all 110 planned cell oracles for Pi 1.5.2: 78 real-model
  positive cells and 32 scripted fault oracles, in 146 actual Pi segments. All
  18 coding pipelines were independently inspected, owned cleanup was confirmed
  and evidence scans found no inference keys.
- The campaign selected only Pi 1.5.2 and was the release's only attempt. Its
  images were built with Pi 1.5.2 from the image recipe, unchanged since 4.9.1,
  and all 16 of its offline `find` calls succeeded. See
  [QUALIFICATION.md](QUALIFICATION.md) for budgets and limits.

### Upgrading from 4.9.1

- Build images for Pi 1.5.2 with an explicit `--pi-version 1.5.2`, and select
  `profile.pi-1.5.2.json` for the fixture integration. Images and profiles for
  0.87.1 and 1.2.0 keep working with their reviewed contracts, outside this
  release's qualification. The image recipe is unchanged since 4.9.1, so images
  built from it need no rebuild.
- Experiments prepared with 4.9.1 cannot be run or resumed by this version,
  because the runner content changed. Prepare new experiments; existing results
  still report.
- If you are upgrading from 4.9.0, also follow the
  [4.9.1 upgrade notes](#upgrading-from-490); from 4.5.0, follow the
  [4.9.0 upgrade notes](#upgrading-from-450) as well.

### Changes since 4.9.1

- Pi 1.5.2 has a reviewed contract alongside 0.87.1 and 1.2.0 and is the
  release qualified for 4.10.0. [PI-1.5.2.md](references/PI-1.5.2.md) records
  what changed for this runner, including upstream fixes such as bounded memory
  in `read` and `grep` and the rejection of malformed tool-call arguments. Its
  registry entry keeps the TypeBox 1.3.27 schema builder and pins the pi-schema
  1.5.2 validator in a new `pi_schema` field, which is None for the earlier
  releases; their contract identities are unchanged. Native tool declarations
  are now frozen per release, and 1.5.2 differs from 1.2.0 only in `grep`'s
  `glob` description. With three reviewed releases an indexed campaign must
  select releases with `--release`.
- Each reviewed Pi release is one complete entry in the registry in
  `runtime/release_contracts.py`: upstream commit, settlement shape, extra CLI
  flags, reasoning and sampling support, transient-retry review, early session
  file, fixture profile, TypeBox pin and the pinned upstream sources. The native
  tool, application runtime and endpoint contracts, every release list and the
  fixture profile choice derive from it, and an incomplete or out-of-order entry
  is refused when the module loads. A new release no longer inherits 0.87.1
  behavior by omission. Contract identities for 0.87.1 and 1.2.0 are unchanged.
- Release and export archives record a canonical mode for every packaged file:
  0755 when its owner may execute it, otherwise 0644, the rule git uses. Local
  permission drift, such as a file left at 0600 in one checkout, no longer
  changes the published bytes, and `tools/verify_release.py` expects the same
  modes. The Claude Code command entry keeps its 0600 mode. Earlier source
  archives could carry a checkout's private mode for a file.
- The new maintainer tool `tools/pi_release_intake.py` prepares the review of
  an upstream Pi release. It checks the npm tarball and provenance commit,
  hashes every upstream file that the reviewed contracts pin, checks the
  TypeBox schema-builder and pi-schema validator pins, and writes a review
  packet, a JSON receipt and a draft registry entry, with a check of whether
  that entry loads as written. It is read-only and ships only in the
  source archive; it neither admits nor qualifies a release.
- On Linux, a parallel trial worker that exited before reading the controller's
  last message, such as a cancellation after a sibling trial failed, could stop
  the whole collection with `ConnectionResetError`. Linux reports such a close as
  a connection reset instead of end of file. The private trial channel now treats
  a reset like a clean close: the controller finalizes the worker from its sealed
  result, and a worker whose controller is gone records controller loss.
- A maintainer test of queued admission failed whenever the test run started
  with SIGINT ignored, as a shell background job does. It now installs its own
  SIGINT handler for its duration and interrupts the waiter only once it is
  queued for the lock.
- Documentation corrections: the 4.9.1 campaign made 62 offline `find` calls,
  all successful and all in coding reviewer stages, and the 4.9.0 campaign 41,
  all failed. The figures given earlier, 88 and 56, counted calls reached a
  second time through retained `latest` run links. The `transient_retries`
  reference now names Pi 1.5.2 alongside 1.2.0.

## 4.9.1

Stable patch release on 4.9.0. It fixes an indexed inference gateway race that
its own release campaign found, stops stages that keep repeating one tool call,
adds opt-in transient provider retries for direct endpoints and ships `fd` in the
stock image.

### Stability

- **Stable:** unchanged from 4.9.0, on native ARM64 with Pi 1.2.0: serial,
  parallel and indexed runs, legacy saved and explicit endpoints, frozen
  experiments, the reviewed fixture lookup integration, scoped application
  credentials and sandboxed browser tasks.
- **Experimental:** the features that were experimental in 4.9.0, plus the new
  endpoint field `transient_retries`. The release campaign did not opt into
  retries.
- The repeated-tool-call guard is always on. It stopped no stage in the release
  campaign; its stop path is covered by offline tests.
- Pi 0.87.1 keeps its reviewed contract but was not requalified. Native AMD64,
  including the AMD64 `fd` build, remains unqualified.

### Qualification

- On 9 November 2026 a fresh native ARM64 campaign on the release code
  (`51f1134`) passed all 110 planned cell oracles for Pi 1.2.0: 78 real-model
  positive cells and 32 scripted fault oracles, in 146 actual Pi segments. All
  18 coding pipelines were independently inspected, owned cleanup was confirmed
  and evidence scans found no inference keys.
- The campaign images were built from the 4.9.1 recipe, and all 62 of its
  offline `find` calls succeeded (corrected in 4.10.0 from 88, which counted
  some calls twice).
- Three earlier attempts the same day were blocked and not resumed: by a
  reviewer that looped on one tool call, by a stalled model-server request and by
  the gateway race fixed in this release. See [QUALIFICATION.md](QUALIFICATION.md)
  for budgets, limits and the earlier attempts.

### Upgrading from 4.9.0

- Experiments prepared with 4.9.0 cannot be run or resumed by this version,
  because the runner content changed. Prepare new experiments; existing results
  still report.
- Rebuild images with `ensure-image --policy build` to get `fd`. Reused images
  without it keep working, and `find` then reports `fd` as unavailable offline.
- Result readers should accept the new termination reason `repeated_tool_call`
  and the new evidence fields `tool_repetition` and `provider_retries`.
- If you are upgrading from 4.5.0, also follow the
  [4.9.0 upgrade notes](#upgrading-from-450).

### Changes since 4.9.0

- Fixed spurious `401 unauthorized` replies from the indexed inference gateway
  on Docker Desktop for macOS. When the host atomically replaces the gateway's
  active-token file, the file can briefly look missing inside the container.
  The gateway treated that gap as invalid state and rejected every token until
  its next read, up to 50 ms later, which could fail a running stage. It now
  waits up to about 100 ms to observe the replacement and still never authorizes
  state it has not read. A file that stays missing, or is malformed, is still
  rejected.

- A stage that completes more than five consecutive identical tool calls (same
  tool, arguments, result text and error flag) now stops early with the new
  termination reason `repeated_tool_call`. The worker ends Pi; the parent
  recounts the retained trace before classifying the stop. Stage evidence
  reports the longest run under `tool_repetition`. This ends a looping stage
  sooner and makes the cause explicit; it never turns a failure into a pass.
- Direct endpoints can opt into `transient_retries` (0 to 3, Pi 1.2.0 only).
  Pi's agent-level retry then retries provider errors it classifies as
  transient, such as dropped streams, instead of failing the stage on one bad
  request. Every attempt stays in the trace: stage evidence records the attempts
  and error text under `provider_retries`, retrying beyond the budget or
  exhausting it still fails, and the default remains no retries. Indexed
  bindings reject the field because their gateway still quarantines an
  uncertain upstream request.

- The supplied image recipe installs a pinned upstream `fd` 10.5.0, the static
  musl build for ARM64 or AMD64, after checking its SHA-256. Pi's `find` tool
  uses it, so `find` no longer needs a download in offline runs. Debian
  bookworm's `fd-find` (8.6.0) is not used: `find` passes `--no-require-git`
  outside git repositories, and fd added that flag in 8.7.0. Existing images keep
  working without `fd` until rebuilt with `ensure-image --policy build`. The
  4.9.1 release campaign used it natively on ARM64; the AMD64 build is
  unqualified.
- Two maintainer tests no longer depend on timing. One compared floating-point
  times inexactly, and the other could read a test server's record before the
  server wrote it; both could fail under `tools/docker_ci.py` on Linux.

## 4.9.0

First stable release since 4.5.0. It contains the changes from the 4.6.0, 4.6.1,
4.7.0 and 4.8.0 prereleases (entries below) and the changes listed here.

### Stability

- **Stable:** the capabilities qualified for 4.5.0, on native ARM64 with Pi
  1.2.0: serial, parallel and indexed runs, legacy saved and explicit endpoints,
  frozen experiments, the reviewed fixture lookup integration, scoped
  application credentials and sandboxed browser tasks.
- **Experimental:** the compiled application client and native call budgets
  (4.6.0), `registry-inspect` and `registry-recover` (4.6.1),
  `application-owner-inspect` and `application-owner-recover` (4.7.0), the
  legacy owner proof (4.8.0) and the operation SDK. They are opt-in and outside
  this release's qualification.
- Pi 0.87.1 keeps its reviewed contract but was not requalified for this
  release. Native AMD64 remains unqualified.

### Qualification

- On 8 November 2026 a fresh native ARM64 campaign on the release code
  (`9a80496`) passed all 110 planned cell oracles for Pi 1.2.0: 78 real-model
  positive cells and 32 scripted fault oracles, in 146 actual Pi segments. All
  18 coding pipelines were independently inspected, owned cleanup was confirmed
  and evidence scans found no inference keys. See
  [QUALIFICATION.md](QUALIFICATION.md) for budgets, limits and earlier attempts.
- Known limitation: the supplied image has no `fd`, so Pi's `find` tool reports
  `fd is not available` in offline runs. Agents in the campaign fell back to
  `ls` and `grep`.

### Upgrading from 4.5.0

- Application helpers launched by 4.7.0 or later write schema-3 registry
  records, which 4.5.0 and 4.6.x clients reject before dispatch. Upgrade every
  client that shares a host lease at the same time, and do not roll back after
  running application helpers. Never downgrade or delete records to satisfy an
  older client.
- Experiments prepared with 4.5.0 cannot be run or resumed by this version,
  because the runner content changed. Prepare new experiments; existing results
  still report. Saved environments, plans and historical results stay readable.
- New commands, all experimental: `compile-application-plan` with
  `run --compiled-plan`, `registry-inspect`, `registry-recover`,
  `application-owner-inspect` and `application-owner-recover`.
- An absolute `PI_LAB_LOCK_FILE` selects a dedicated host lease, with its own
  registry, for every command. Clients exclude each other only when they use
  the same lease file; leave it unset to keep the shared per-user lease.
- Maintainers: the regression suite needs Node.js 24 or later on `PATH`, and
  `tools/build_release.py` builds only when this changelog's top entry names the
  package version (`--candidate` makes an unpublishable verification build).

### Changes since 4.8.0

- Add an experimental fixed-operation SDK with independent code/runtime/policy
  approval, fresh workers, private framing, exact-reference reads, bounded
  redaction and create-only registration. Initial execution support is Linux
  ARM64 CPython 3.12.13; native-host and real application integration remain
  separate qualification gates.
- Preserve legacy validation APIs while adding explicit bounded dependency and
  project-metadata readers for the SDK. Validation does not execute a plan or
  freeze scorer assets. Existing releases and historical evidence are unchanged.
- SDK dependency reads clamp fixed provider requests to the approved grant and
  file cap, so legacy plan validation works under caps below 1 MiB. Larger
  files are still refused, never truncated.
- The SDK worker waits for its bootstrap frame with `poll`, accepting inherited
  descriptor numbers above `FD_SETSIZE`. The registration receiver checks the
  stored file's owner, 0600 mode, single link and value size itself.
- The SDK pattern forecast is recalibrated to 259 bytes per protected byte, a
  proven bound for three escape layers; protected references can total about
  32 KB. Registration size remains bounded by the call forecast (about 4 KB).
- Add `resources.existing_admission_lock` and the trusted-library
  `run_suite(existing_lease_identity=...)` binding for native hosts that must
  keep an already selected lease. Ordinary CLI admission is unchanged.
- Add `Reader.read_requirements()` for separately reviewed consumer policies and
  the `artifact_tool_observation` consumer role for the diagnostic adapter.
- Registry and owner-proof reads use bounded descriptor IO without a second
  file wrapper; registry records reject growth beyond 1 MiB after observation.
- `application-owner-inspect` and `application-owner-recover` have distinct
  help text. The `tools/qualification` registration modules are aliases of the
  installed SDK modules.
- Release builds refuse unless this changelog's top entry names the package
  version (`--candidate` builds are marked unpublishable), and archives are
  byte-reproducible. `tools/docker_ci.py` repeats the offline checks in a
  bounded native Linux container; the maintainer suite requires Node.js 24+.
- An absolute `PI_LAB_LOCK_FILE` selects a dedicated host lease (and its own
  registry) as every command's default; unset keeps the shared per-user lease.
  The indexed qualification campaign can freeze a fresh dedicated lease with
  `--lock-file` and exports it to every phase and child command.
- The indexed campaign can qualify a subset of reviewed Pi releases with
  `--release`; its cell, segment, inspection and launch totals are derived from
  the selected matrix (the default for both releases is unchanged), and the
  infrastructure checks use the first selected release's core image.
- Container cleanup after a run has its own 60-second window, and each
  `docker inspect` or `docker rm -f` call may take up to 30 seconds. Previously
  each call had 5 seconds, taken from the remaining process grace (10 seconds
  for an unstaged run such as a preflight), so a loaded Docker daemon could turn
  a completed run into `cleanup_error`. In-run signals keep the 5-second bound,
  and unconfirmed cleanup still fails closed.

## 4.8.0 (experimental candidate)

- Add the versioned `legacy_derived_v1` owner-proof method and
  `application_owner_legacy_1` cohort without rewriting historical records,
  original failure accounting, waits or intent encodings.
- Validate complete original source/instance, launcher, host-root, retained
  namespace and authority closure. Keep standard-workspace and diagnostic
  disposable scopes distinct. The enabled real source family is the reviewed
  artifact diagnostic; standard vectors are synthetic interface conformance.
- Bind fresh writer/daemon/label/holder checks and descriptor-relative removal
  to the original lease, exact roots, protected inputs and namespace identities.
  Preserve strict privacy, byte/reference/entry limits and original removal facts.
- Publish create-only intent, independent anchor, selection, terminal and index
  with explicit durability ordering. Partial or lost selected state blocks;
  failure records never rewrite a terminal or grant adoption/retry authority.
- Add identifier-free inspection summaries, closed cleanup diagnostics and a
  version-1 SDK reader specification with 37 sanitized conformance vectors.
  Unsupported/frozen consumers remain extension-required before provider import.
- Retain Python 3.10 support for queryless browser requests and authenticated
  fixture pagination while preserving strict parsing of nonempty queries.
- Keep real owner cleanup, extended SDK consumption and downstream integration
  qualification pending. Offline/native synthetic checks, source review and
  release metadata do not qualify original evidence gaps or a live campaign.

## 4.7.0

- New ordinary helper records use schema 3 with owner cleanup contract 1.
  Older readers reject these records; use one compatible controller cohort.
  Historical records and outcomes remain unchanged. Native integration and
  extended SDK proof-read qualification remain separate requirements.

- Add read-only application-owner inspection and explicit retained-terminal
  cleanup for already released ordinary helpers. Preserve original failed
  accounting and keep cleanup receipts separate from sealed results.
- Record normal helper custody before dispatch and bootstrap, then publish
  proof after final stage cleanup. Revalidate selected proof, private-path
  absence and retained metadata, including all-released admission.
- Refuse unsupported authority scopes and frozen SDK policies without proof
  read authority. No new model, application or container dispatch is performed
  by owner cleanup.
- Preserve failed credential accounting through dependent generic recovery,
  compare related identities independently of directory order, and enforce
  read limits/privacy across complete proof graphs. Recognize the runner's
  browser stage and avoid allocating receipts before runner identity is available.
- Block file cleanup while another pending registered owner holds an overlapping
  run root or mount, including read-only and aliased paths, without taking over
  unrelated cleanup.

## 4.6.1

- Diagnose blocked host-registry admission with closed phase, condition,
  filesystem operation, OS-error category and possible partial effects in both
  standalone CLI failures and sealed run results.
- Add offline `registry-inspect` and explicit `registry-recover` commands under
  the existing host lease. Recovery records a separate durable intent and
  terminal receipt without dispatching a fresh probe, participant or model call.
- Bind receipt publication to held directory descriptors; reject replaced
  namespaces, linked or tampered receipts and unbounded output. Preserve terminal
  interruption evidence and distinguish lease failures from body/timer failures.
- Keep diagnostic context current when exception objects are reused, while
  preserving the original inner operation through nested error wrappers.
- Freeze the diagnostics dependency in application-helper bundles and preserve
  the exact historical bundle shapes and cleanup evidence. Ownership, writer,
  inference and sensitive-cleanup admission predicates remain enforced.
- Record a bounded, configurable extracted-source release-test budget and retain
  partial stdout/stderr when verification times out.
- Verification covers synthetic Docker/model boundaries, native temporary
  filesystem/lease operations and local service fixtures. Native qualification
  of the changed admission/recovery scope remains deferred; previous measurements
  retain their original source/runtime identities. The experimental application
  and native-budget limits described for 4.6.0 still apply.

## 4.6.0

- Add an opt-in compiled application-client profile with typed API/browser
  operations, helper-owned credential references, automatic evidence receipts
  and bounded explicit pagination. Unsafe requests reject before effects;
  workflows and mutations are never implicitly replayed.
- Independently validate exact participant identity, required artifacts and
  publication receipts after settlement. Diagnose incomplete reports without
  automatically continuing the participant or repairing its output.
- Compile and validate the same final representation used for dispatch,
  including runtime, dependencies, credentials, rendered prompts and contracts.
  Integrate the compiled route with serial, indexed and parallel preparation.
- Centrally account native calls and reserve reporting capacity; close new
  business admission monotonically at the reporting threshold.
- Add an authenticated application example with an independent root oracle and
  correct current harness-version documentation while retaining dated evidence.
- Preserve root-array API result projections, screen known credentials hidden
  by standard JavaScript Unicode code-point escapes, respect declared aggregate
  host budget fractions and report valid compiled stage identifiers up to
  64 characters. Keep historical test fixtures independent of host PID state.
- Native qualification of the new application-client/native-budget scope is
  partial. Authenticated browser acceptance and affected runtime safety/admission
  qualification remain deferred. Offline source/package checks and independent
  code review do not establish live execution, cleanup or model quality. All
  historical measurements retain their original executable and environment
  identities; no new native diagnostics are claimed for this candidate.

## 4.5.0

- Add opt-in indexed inference environments with explicit credential sources,
  exact-authority confirmation, revocation and frozen per-stage assignments.
- Keep upstream credentials outside indexed Pi workers through a bounded broker
  with scoped capabilities, all-selected-key redaction, isolated snapshots and
  networks, one cooperating inference slot and durable uncertainty quarantine.
- Integrate discovery, selection, confirmation, qualification and recovery into
  the installed skill, with single/serial/parallel and role-map examples and
  allowlisted public exports. Preserve legacy schemas and Pi 0.87.1/1.2.0 support.
- Reject ownership intents before registry capacity exhaustion, preserve cleanup
  updates and retained history, and check campaign headroom before dispatch.
- Qualify the recorded executor on native ARM64 across both Pi releases: all
  220 cell oracles passed, with 292 actual Pi segments, 36 inspected coding
  pipelines and confirmed physical/private cleanup. Live profiles used two
  credential references on the same backend/model; broader compatibility and
  downstream application acceptance remain separate claims.

## 4.4.0

- Add explicit schema-2 two-trial scheduling with weighted reservations, private
  host controllers, durable ownership recovery, isolated snapshots/networks and
  a bounded one-slot inference gateway. Schema 1 remains serial.
- Preserve scoped application credentials, cleanup/redaction and exact Pi
  0.87.1/1.2.0 contracts. Keep uncertain cleanup or inference termination blocked.
- Expand developer onboarding with runnable Python/Node examples and endpoint,
  image, qualification and result-inspection guidance.
- Qualify the experimental two-trial contract on native ARM64 for both reviewed
  Pi releases: 124 planned cell oracles and 172 actual Pi segments, with real-model
  and scripted fault evidence separated and owned cleanup confirmed.
- Enforce cumulative inference deadlines through DNS/TLS/headers and response
  metadata; incomplete chunk/trailer framing cannot release an uncertain slot.
- Exact-head configured review must be completed before promotion.

## 4.3.0

- Retain typed, whitelisted host-busy, invalid-policy and insecure/unavailable-lock
  diagnostics with bounded nonsecret guidance, sealed accounting and real lease tests.
- Reject Copilot quota/error/empty submissions as completed review; require the
  recognized completion overview before exact-head review readiness.
- Add exact reviewed Pi 1.2.0 support alongside preserved 0.87.1 behavior and
  fixture declaration/asset identities, with shared host/worker admission.
- Validate release-specific cancellation settlement, reject live legacy fallback,
  and bind continuation to image/release/contract identity.
- Retain profile and tool-policy violations across authorized recovery.
- Freeze release contracts in experiments while preserving historical reading.
- Cover nested client/tool JSON credential escaping without general transformed
  secret guarantees; retain scoped delivery, stopped cleanup and snapshot scanning.
- Add a separately bounded maintainer ARM64 qualification harness with private
  evidence and independent protocol, model, credential, browser and fault oracles.

## 4.2.1

- Require observed sandboxing for browser-check; trusted opt-out runs cannot
  qualify sandbox admission. Reject hidden GPU sandbox-disabling arguments.
- Verify the daemon architecture for native ARM64 browser policy/admission;
  selected or emulated image architecture is insufficient.
- Discard credential snapshots on scan exceptions through the same fail-closed
  inspection path used after stages.
- Add exact-head asynchronous review completion and finding triage before merge,
  with a read-only paginated GitHub readiness gate and regression fixtures.

## 4.2.0

- Add an explicit pinned native ARM64 Chromium user-namespace seccomp policy,
  retaining non-root/no-capability/read-only/resource isolation and no-new-privileges.
- Add credential-free browser-check admission with actual Chromium namespace and
  seccomp observations; default container policy never silently changes.
- Freeze/recheck selected policy bytes and retain identity in run/experiment evidence.
- Reject hidden sandbox opt-outs in browser-options; distinguish environment
  admission from application/model correctness and preserve blocked-run history.

## 4.1.0

- Add per-agent application-secret references resolved from the owner-only host
  store, with isolated `PI_APP_*` delivery and no inference-key/persona fallback.
- Redact exact application values and JSON-escaped forms from capture/diagnostics;
  exclude sensitive emitted files and untrusted live credential-stage heartbeats.
- Remove sensitive stage sessions, resume copies, runtime and outbox on stopped
  success/failure/cancellation; scan shared snapshots before later dispatch and
  fail closed on contamination, unknown coverage or uncertain cleanup.
- Purge registered sensitive material after owned-container crash reconciliation.
- Test two-persona onboarding/authenticated effects with actual local HTTP clients
  and independent service observations. Docker/Pi fixtures do not establish live
  downstream application, container or model qualification.

## 4.0.1

- Scan the complete tree before in-place writable admission, including ignored
  directories; reject symlinks, hardlinks and inspection failures.
- Preserve stop-after-failure across cleanup recovery, controller loss and
  successful diagnostic retries. Keep explicit cancellation behavior separate.
- Use collision-checked UUID paths for frozen case/variant plans while preserving
  unambiguous legacy reporting.
- Reject source-contained exports before manifest, archive or installer mutation,
  including canonical and filesystem aliases.
- Use standard Agent Skills name/description frontmatter.
- Separate maintainer tests and stored validation output from the installable
  skill. Publish clean source and skill archives without internal planning history.

## 4.0.0

- Preserve existing project installations with explicit clean, repeated,
  conflicting and failed outcomes.
- Provide universal, Claude Code, Codex and Antigravity archive layouts with
  complete runtime resources and integrity manifests.
- Document version-scoped parent discovery separately from direct CLI execution.

## 3.0.0

- Add frozen repeated application experiments, independent structured scoring,
  accountable comparison denominators and retained failed attempts.
- Add an opt-in fixture lookup profile with immutable assets and observed tool use.
- Add durable separated outcomes, parent-owned stage controls, bounded budget
  revisions and linked authorized recovery.
- Pin the Pi 0.87.1 CLI/event contract and distinguish source inspection, offline
  fixtures and exact live qualification.

## Earlier versions

Established portable English instructions, project/environment/resource contracts,
Python and Node examples, per-stage working directories, native architecture
checks, bounded image builds and serial host admission. Legacy plan/endpoint
schemas remain readable; current safety and compatibility requirements apply.
