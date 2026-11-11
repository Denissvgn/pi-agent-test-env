# Validation

Package checks separate structural integrity, offline behavior and live execution.
Passing one category does not imply the others passed.

For the 4.6.0 application-client/native-budget additions, native qualification
remains partial. Offline tests and reviewed package bytes do not establish
authenticated browser acceptance, affected runtime admission or sensitive
cleanup. Release preparation does not create a native qualification window or
clear historical uncertainty. See the current scope in
[QUALIFICATION.md](QUALIFICATION.md); the dated live evidence below remains
attached to its original executable and environment.

## 4.10.0 release checks

Each pull request merged for 4.10.0 passed a candidate build with
`tools/verify_release.py` on macOS, including the full suite from extracted
source and all five layouts, and `tools/docker_ci.py` on native Linux ARM64 with
Python 3.10 and 3.12. The qualified head `626459c` has the same tree as the last
of them, where the full suite ran 3405 tests: 13 skipped on macOS and 12 in each
Linux image. During the cycle one `tools/docker_ci.py` run failed with
`ConnectionResetError` in the parallel engine, a Linux-only defect that was
fixed before the campaign. One maintainer test of queued admission failed
whenever the suite started with SIGINT ignored, as a shell background job does;
it now installs its own handler. These are offline checks; the dated live
evidence below is separate.

## 4.9.1 release checks

Each pull request merged for 4.9.1 passed the full maintainer suite on macOS. A
candidate build of the qualified head passed `tools/verify_release.py` before
the version bump, including the full suite from extracted source and all five
layouts. On that head, `tools/docker_ci.py` on native Linux ARM64 failed two
tests: one compared floating-point times inexactly, and the other could read a
test server's record before the server wrote it. Both were timing-dependent
defects in tests unchanged since 4.9.0. After they were fixed,
`tools/docker_ci.py` passed with Python 3.10 and 3.12. A Docker reproduction of
the gateway race on macOS went from 5,582 failed activation reads in 25 seconds
to none. These are offline checks; the dated live evidence below is separate.

## 4.9.0 release checks

Each pull request merged for 4.9.0 passed the full maintainer suite on macOS.
`tools/docker_ci.py` also passed on native Linux ARM64 with Python 3.10 and 3.12
for the release candidate and for the later lease and cleanup changes. A
candidate build passed `tools/verify_release.py` before the version bump,
including the full suite from extracted source and all five layouts. These are
offline checks; the dated live evidence below is separate.

## 4.8.0 owner-proof candidate

The owner-proof implementation has synthetic native filesystem/lease, metadata
backend, publication/crash and read-only consumer conformance coverage. Those
checks establish only their recorded candidate and test scope. They do not
supply original historical facts or qualify real owner cleanup, downstream SDK
consumption, application/model behavior or a campaign. The exact final archive/
native/ARM64 Docker release gate and any real eligible owner operation/replay
must be recorded separately before their outcomes are claimed. Native Windows
remains outside the POSIX lease contract.

## Structural and offline checks

Maintainer tests live in the source repository’s `tests/` directory and are omitted
from installable archives. They exercise complete admission scanning, snapshot
isolation, sealed outcomes, stop/retry/cancellation policy, collision-free frozen
plans, scorer contracts, controls, resource limits and preserving installers.
Protocol, Docker and SDK fixtures are synthetic; local subprocess and loopback
HTTP checks remain offline evidence.

Publishing verification extracts each archive independently, rejects unsafe,
duplicate or linked members, compares every resource and manifest entry against
source, and verifies versions and checksums. All five extracted roots are named
`pi-agent-test-env` and are checked by the pinned official Agent Skills validator.
The full maintainer suite runs against the extracted universal package. Complete
before/after inventories detect newly created files and changed bytes or modes.

The host runtime requires Python 3.10+ with no third-party Python dependencies.
Offline standards validation requires Python 3.11+ and uses disposable tooling
with bundled, hash-locked dependencies outside the skill.

## Live evidence

On 11 November 2026, the 4.10.0 release campaign passed 110 frozen cell oracles
on native ARM64 for Pi 1.5.2 at executable head `626459c`: 78 real-model
positives and 32 scripted fault oracles, with 146 actual Pi segments (120
real-model/26 scripted). All 18 coding pipelines were independently inspected,
and owned physical/private cleanup and selected-key scans passed. Pi 0.87.1 and
1.2.0 were deferred and not part of the campaign, which was the release's only
attempt. [QUALIFICATION.md](QUALIFICATION.md) records budgets, review waivers and
limits.

For 4.9.1, on 9 November 2026, the release campaign passed 110 frozen cell
oracles on native ARM64 for Pi 1.2.0 at executable head `51f1134`: 78 real-model
positives and 32 scripted fault oracles, with 146 actual Pi segments (120
real-model/26 scripted). All 18 coding pipelines were independently inspected,
and owned physical/private cleanup and selected-key scans passed. Three earlier
attempts that day were blocked and not resumed, and Pi 0.87.1 was not part of
the campaign. [QUALIFICATION.md](QUALIFICATION.md) records budgets, the earlier
attempts, review waivers and limits.

For 4.9.0, on 8 November 2026, the release campaign passed 110 frozen cell
oracles on native ARM64 for Pi 1.2.0 at executable head `9a80496`: 78 real-model
positives and 32 scripted fault oracles, with 146 actual Pi segments (120
real-model/26 scripted). All 18 coding pipelines were independently inspected,
and owned physical/private cleanup and selected-key scans passed. Pi 0.87.1 was
not part of this campaign. [QUALIFICATION.md](QUALIFICATION.md) records budgets,
earlier attempts, review waivers and limits.

For 4.5.0, on 15 October 2026, the indexed inference campaign passed 220 frozen
cell oracles on native ARM64 for Pi 0.87.1 and 1.2.0: 156 real-model positives
and 64 scripted fault oracles, with 292 actual Pi segments (240 real-model/52
scripted). All 36 coding pipelines were independently inspected and owned
physical/private cleanup and selected-key scans passed. Live profiles used the
same retained backend/model with separate credential references; broader
backend/model/API claims remain unqualified. [QUALIFICATION.md](QUALIFICATION.md)
records budgets, source identity, legacy compatibility, evidence distinctions
and limits.

Native ARM64 core executor, application comparison and fixture integration checks
were observed on 7 October 2026 with Pi 0.87.1 and exact recorded image/model
configurations. Model failures, partial artifacts and explicit recovery remain
failures or separate cohorts; later success never rewrites earlier results.

On 8 October 2026 native ARM64 Docker checker stages exercised host admission,
expected writes/write denials, sealed-failure controller recovery, permanent stop,
selected retry and independently confirmed container absence. Those executor
outcomes are synthetic and are not fresh model acceptance or performance data.

Dated source/configuration identities govern reuse. Repackaging preserves those
limits; it does not claim new live qualification for current runner bytes. A new
image, release, endpoint, profile or executable change needs the affected live
checks before its behavior is claimed as supported.

## Reproduce checks

From a source checkout, run the maintainer suite from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

From an installed skill, validate a selected plan:

```bash
python3 scripts/pi_lab.py validate-plan --plan assets/python-feature.plan.json
```

Before any live invocation, follow [SKILL.md](SKILL.md), confirm the chosen
environment, review the image/endpoint and apply finite budgets. Retain actual
commands, outputs, source/runner/image identities, model configuration, independent
results and cleanup observations. Keep unexecuted checks explicit; never silently
change a model, release or budget to obtain a pass.

See [QUALIFICATION.md](QUALIFICATION.md) for the supported scope. The manifest
establishes file integrity only; it does not attest a model server or signature.
