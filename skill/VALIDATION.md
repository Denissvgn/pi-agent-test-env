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

On 15 October 2026, the indexed inference campaign passed 220 frozen cell oracles
on native ARM64 for Pi 0.87.1 and 1.2.0: 156 real-model positives and 64 scripted
fault oracles, with 292 actual Pi segments (240 real-model/52 scripted). All 36
coding pipelines were independently inspected and owned physical/private cleanup
and selected-key scans passed. Live profiles used the same retained backend/model
with separate credential references; broader backend/model/API claims remain
unqualified. [QUALIFICATION.md](QUALIFICATION.md) records budgets, source identity,
legacy compatibility, evidence distinctions and limits.

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
