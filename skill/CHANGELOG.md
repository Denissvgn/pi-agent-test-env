# Changelog

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
  WorkChord, container or model qualification.

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
