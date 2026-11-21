kind: changed

Updated the published reference and design pages to describe implemented behavior,
release evidence and public configuration accurately.

- Stable parallel and indexed execution is described as opt-in in
  `skill/references/INFERENCE-ENVIRONMENTS.md`, `skill/references/PARALLEL-AGENTS.md`,
  `CONTRIBUTING.md` and `docs/design/parallel-agents.md`. The parallel and indexed
  design pages identify implementation in 4.5.0 and qualification on Pi 1.5.2
  in 4.10.0, and frame their proposals and rollout language as historical.
- The inference adapter and Pi compatibility references now cover every reviewed
  release. `PI-1.5.2.md` records its 4.10.0 qualification on 11 November 2026;
  `AGENT-PROFILES.md` names its fixture profile. `TEST-CONTRACT.md` and
  `PI-1.2.0.md` state that `--event-contract process-exit` is rejected by every
  reviewed release and cite the 1.2.0 and 1.5.2 event references alongside 0.87.1.
- `SOURCES.md` identifies all inspected releases, removes the obsolete archive
  provenance and accurately records that the pinned Moby seccomp profile is
  redistributed unchanged, as documented by the security asset README.
- `QUALIFICATION.md` clarifies that the 4.6.0 application-client qualification
  was partial on Pi 0.87.1 and 1.2.0 and none is on the current Pi release; adds
  the omitted pull requests 31, 23 and 19 to their historical lists; and keeps
  campaign numbers unchanged. `VALIDATION.md` no longer opens with the unrelated
  4.6.0 paragraph. `OWNER-CLEANUP-COMPATIBILITY.md` describes pre-release gates
  in the past tense. `loop-and-stall-mitigation.md` names both 1.2.0 and 1.5.2.
- `skill/README.md` now documents host-side doctor reachability and its exit
  codes, removes the obsolete migration section, and removes workstation-specific
  image and product connection instructions. `skill.json` lists `ensure-image`.
  `RESOURCES.md` links the Python/Node environment example, filters containers
  by the managed label set by the code, and removes the named local container
  example. `INFERENCE-ENVIRONMENTS.md` links the endpoint and inference-profile
  examples. Owner cleanup commands use `python3` directly.
- The application-contract fixture guide no longer contains an internal key or
  says there are only two reviewed releases. A required passphrase migration
  section was removed because its predecessor was not publicly released.
