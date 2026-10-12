# pi-agent-test-env

[![Version](https://img.shields.io/badge/version-4.2.1-blue)](skill/CHANGELOG.md)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](skill/README.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-compatible-7B61FF)](skill/SKILL.md)

## About

Evaluate local-model coding agents with frozen application cases, repeated trials
and independent scorers, or delegate bounded coding work to real Pi processes.
Docker limits each child’s CPU, memory, process count and execution time. The model
endpoint and runtime image are selected explicitly by the user.

## Install

Install the complete `skill/` directory as `pi-agent-test-env`, including its
scripts, runtime, assets, examples and references. The required Agent Skills entry
is [SKILL.md](skill/SKILL.md). Copying that file alone does not install the runner.

The preserving installer links the skill into an existing project:

```bash
python3 skill/scripts/export_skill.py --output-dir /tmp/pi-agent-packages \
  --install codex --target-dir /path/to/project
```

Use `claude` or `antigravity` for the corresponding parent. Existing installations
are never replaced automatically. [Installation details](skill/references/HARNESSES.md)
cover archive layouts, checksums, conflicts and discovery compatibility.

## Use

The parent needs Python 3.10+, a local Linux Docker daemon and shell access on
macOS, Linux or WSL. Image builds also need Buildx. The host runner uses only the
Python standard library. On Apple Silicon select native `linux/arm64` images;
cross-architecture emulation requires explicit authorization.

Start with the [skill workflow](skill/SKILL.md), then choose a
[single coding plan](skill/README.md), a
[repeated application experiment](skill/references/EXPERIMENTS.md) or the
[optional fixture lookup profile](skill/references/AGENT-PROFILES.md).
Use [per-stage application credentials](skill/references/APPLICATION-CREDENTIALS.md)
for scoped authenticated client tasks, separately from the inference key.
The environment gate confirms the selected model once per conversation. It never
silently chooses a fallback server or model.

Read the [security contract](skill/references/SECURITY.md) and
[qualification scope](skill/QUALIFICATION.md) before live execution. Offline tests
and structural validation do not establish live model behavior or performance.

## Repository layout

| Path | Purpose |
|---|---|
| `skill/` | Self-contained installable skill and executable resources |
| `tests/` | Maintainer regression suite; excluded from skill archives |
| `tools/` | Publishing checks and pinned offline standards validation |

See
[CONTRIBUTING.md](CONTRIBUTING.md) for tests and the reproducible publishing workflow.

MIT licensed. This is an independent project, not an official Pi or Docker release.
