# Validation

Package checks separate structural integrity, offline behavior and live execution.
Passing one category does not imply the others passed.

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
