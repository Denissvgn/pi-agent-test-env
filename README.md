# pi-agent-test-env

[![Version](https://img.shields.io/badge/version-4.4.0-blue)](skill/CHANGELOG.md)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](skill/README.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-compatible-7B61FF)](skill/SKILL.md)

Run real [Pi coding agents](https://github.com/earendil-works/pi) against your chosen
OpenAI-compatible Chat Completions endpoint, give them a bounded Docker workspace,
and evaluate their work with checks you control.

Use it from the terminal or install it as a skill for a parent development agent.
The host runner uses the Python standard library; Pi and the task toolchain run
inside the selected image. You provide the model server separately.

## What can you try?

| Goal | Starting point | What you get |
|---|---|---|
| Implement and review a small Python feature | [Slug helper specification](skill/examples/python-project/SPEC.md) and [Python plan](skill/assets/python-feature.plan.json) | An implementer, a read-only reviewer, and fresh protected acceptance checks; no third-party Python dependencies |
| Try the same workflow with JavaScript | [Node specification](skill/examples/node-project/SPEC.md) and [Node plan](skill/assets/node-cli.plan.json) | A normalization function checked with Node's built-in test runner; no npm install |
| Compare two prompts on fixed tasks | [Application baseline walkthrough](skill/examples/application-baseline/README.md) | Native ARM64 baseline/candidate trials, an independent external oracle, and JSON/Markdown comparisons including failures |
| Measure use of an explicitly supplied tool | [Fixture lookup walkthrough](skill/examples/integration-baseline/README.md) | Native ARM64 built-in retrieval versus the one supported fixture tool, with actual tool-use evidence and independent scoring |
| Add browser acceptance to your own app | [Browser plan template](skill/assets/browser-ui.plan.json) and [browser guide](skill/references/BROWSER.md) | A plan to adapt to your server, locked dependencies and real Chromium assertions |
| Exercise an authenticated API as distinct workers | [Application credential recipe](skill/references/APPLICATION-CREDENTIALS.md) | Per-stage credential delivery, redacted capture and sensitive cleanup; you supply the application, disposable identities and effects oracle |

The Python and Node projects are runnable starter tasks. Browser and authenticated
API recipes require project-specific setup. The fixture integration is optional;
ordinary application experiments use Pi's built-in tools.

## How a run works

1. You review a JSON plan: allowed tools, protected inputs, stages, checks and budgets.
2. The runner copies the subject into an isolated workspace and starts Pi stages
   sequentially against the exact selected model.
3. A separate check container tests the resulting files. Reviewer prose remains
   available for your inspection; it is not parsed into approval.
4. The runner retains traces, check output, the changed workspace and a result
   outside the subject project. You review the diff before applying it back.

CPU, RAM, process and time limits apply to children and image builds. The model
server has its own separate resource budget. Read the
[security contract](skill/references/SECURITY.md) before live execution.

## First run: the Python demo

### 1. Get the code and inspect the plan

```bash
git clone https://github.com/Denissvgn/pi-agent-test-env.git
cd pi-agent-test-env
SKILL_DIR="$(pwd)/skill"
python3 "$SKILL_DIR/scripts/pi_lab.py" --help
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-plan \
  --plan "$SKILL_DIR/assets/python-feature.plan.json"
```

These Python commands work offline with Python 3.10+; they do not start Docker or
contact a model. Read [SPEC.md](skill/examples/python-project/SPEC.md) and the
[plan](skill/assets/python-feature.plan.json). The task is to implement `slugify`
without changing the specification or tests.

For the live steps, you need shell access on macOS, Linux or WSL, a local Docker
daemon running Linux containers, and a reachable model endpoint that supports
the required agent/tool calls. Builds also need Buildx and network access to
package registries. Native Windows Python is unsupported. No host Pi installation
or host Python packages are required.

### 2. Choose and confirm your model endpoint

Keep this shell and session ID for the walkthrough:

```bash
SESSION=$(python3 "$SKILL_DIR/scripts/pi_lab.py" env new-session)
python3 "$SKILL_DIR/scripts/pi_lab.py" env status --session "$SESSION"
```

On a fresh install, `no-environment` with exit 10 is expected. If saved settings
are shown as `needs-confirmation` (11), review them and, if you choose to reuse them,
run the following command and continue to step 3:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" env confirm --session "$SESSION"
```

For new or replacement settings, choose both routes to the same server. This
example uses Docker Desktop with a model server listening on port 8000; adjust
the URLs to your actual deployment:

```bash
HOST_BASE_URL='http://127.0.0.1:8000/v1'
CONTAINER_BASE_URL='http://host.docker.internal:8000/v1'
python3 "$SKILL_DIR/scripts/pi_lab.py" env discover --base-url "$HOST_BASE_URL"
```

`localhost` inside Docker is the child container. The host route is used for
discovery/health checks; the container route is used by Pi. Local Linux Docker
may need `--host-gateway` on the preflight, smoke and run commands below. A sibling
model container needs a shared network and a reachable host route. See
[endpoint routing](skill/references/PROJECTS.md).

If the server requires a key and none is already exported as `PI_API_KEY` or stored,
enter it in your own terminal, then repeat discovery:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set PI_API_KEY
```

Select an exact model ID from discovery. Replace the placeholder and use the
context actually loaded by your server; 32768 and 4096 below are example limits,
not detected capacity. The reply cap must be below the context window.

```bash
PI_MODEL='replace-with-an-exact-model-id-from-discovery'
python3 "$SKILL_DIR/scripts/pi_lab.py" env save --session "$SESSION" \
  --base-url "$CONTAINER_BASE_URL" --host-base-url "$HOST_BASE_URL" \
  --model "$PI_MODEL" --context-window 32768 --max-tokens 4096
```

For a keyless server, add `--no-auth` to `env save`. Saving verifies the model
listing and a small chat request, then confirms the settings for this session.
`ready` (0) means the environment can be reused; `broken` (12) needs repair before
continuing. Keys stay out of plans and chat. See the
[complete environment workflow](skill/SKILL.md#0-environment-gate-before-imagemodel-execution).

### 3. Prepare a native core image

The reviewed Pi releases are **0.87.1 and 1.2.0**. This walkthrough selects
[Pi 0.87.1](skill/references/PI-COMPATIBILITY.md); the
[Pi 1.2.0 guide](skill/references/PI-1.2.0.md) covers its separate image and
fixture-profile contract. Select the exact release explicitly and qualify it
before execution.
The commands below select Apple Silicon's native `linux/arm64`. On an AMD64
host/daemon, replace it with native `linux/amd64` in every command. Live
qualification scope is recorded separately in [QUALIFICATION.md](skill/QUALIFICATION.md).

```bash
IMAGE='pi-agent-tests:core-0.87.1'
python3 "$SKILL_DIR/scripts/pi_lab.py" ensure-image \
  --image "$IMAGE" --profile core --policy auto \
  --pi-version 0.87.1 --platform linux/arm64 \
  --resources "$SKILL_DIR/assets/resources/low-impact.json" \
  --receipt /tmp/pi-core-image.json
```

`auto` probes the selected image for compatibility and builds if needed. Use
`--policy reuse` for an existing trusted image when you want no build. Review its
provenance first: probing executes image programs. `--pi-version` pins a build;
it does not change a reused image. Confirm the receipt reports Pi 0.87.1 before
continuing this walkthrough. Architecture is checked before execution;
cross-architecture emulation requires explicit authorization.

The low-impact policy requests 1 CPU equivalent, 2 GiB RAM, 256 PIDs and one
advisory job, with no extra swap allowance. Requests are capped against Docker's
allocation. It also bounds the separate BuildKit container used for a build.
See [resource policy](skill/references/RESOURCES.md).

### 4. Qualify tool use, then run the task

Run each command individually and continue only after it succeeds. Start with
the prerequisite diagnostic:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" doctor \
  --image "$IMAGE" --platform linux/arm64 --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

Check container-to-model reachability:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" preflight \
  --image "$IMAGE" --platform linux/arm64 --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

Make real model calls and verify paired read/write/bash tool use:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" smoke \
  --image "$IMAGE" --platform linux/arm64 --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

Then run the implementer, read-only reviewer and independent unittest checks:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" run \
  --image "$IMAGE" --platform linux/arm64 --profile core \
  --project "$SKILL_DIR/examples/python-project" \
  --plan "$SKILL_DIR/assets/python-feature.plan.json" --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

The original starter project stays unchanged.
The plan allows up to 20 minutes for implementation, 10 for review and 5 for checks;
actual duration depends on your model and environment.

### 5. Inspect the result

The command prints the run directory, normally under
`~/.local/state/pi-agent-test-env/runs/`. Open `result.json`, the reviewer output,
`check-*/` logs, `changes.json` and the resulting `workspace/` copy. Inspect a
specific run from the terminal with:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" status --run /absolute/path/to/run
```

| Run outcome | Meaning |
|---|---|
| `PASS`, exit 0 | Clean autonomous invocation and mechanical plan acceptance |
| `FAIL`, `ASSISTED` or `RECOVERED`, exit 1 | Failed acceptance or execution with recorded intervention/recovery; inspect the evidence |
| `BLOCKED` or `INTERRUPTED`, exit 2 | An admission/environment failure or interrupted execution |

A passing check does not clear reviewer findings automatically. Fix findings and
review the isolated-copy diff before promoting changes. Offline validation and
maintainer tests do not measure live model quality; recorded qualification applies
only to its exact image, model and configuration.

## Next experiments

The fixed application and fixture walkthroughs target native ARM64 with Pi 0.87.1.
In the fixture walkthrough's `ensure-image` command, substitute your trusted
`"$IMAGE"` for its historical example tag.

- **Node feature:** reuse the qualified core environment and substitute
  `examples/node-project` and `assets/node-cli.plan.json` in the run command.
- **Prompt comparison:** follow the [application baseline](skill/examples/application-baseline/README.md).
  Freeze source, oracle and budgets before collection; its main matrix includes
  eight primary cells and deliberate cutoff failures to show failure accounting.
  Experiment collection exit 0 means terminal collection, including failed trials;
  inspect the report for task success.
- **Two independent trials:** review the explicit [parallel-agent contract](skill/references/PARALLEL-AGENTS.md).
  It keeps workspaces separate and admits one cooperating model request; server
  capacity and native overlap need their own qualification. Serial remains default.
- **Your repository:** start with [project adaptation](skill/references/PROJECTS.md)
  and the [task brief](skill/assets/task-brief.example.md). Replace paths, setup,
  prompts and checks in a copied plan, validate it, then run on a snapshot.
- **Browser acceptance:** qualify a browser image with the
  [browser admission procedure](skill/references/BROWSER.md) before adapting the UI
  plan. Browser sandbox policy is an explicit choice; failed admission stops the run.

For repeated trials, recovery and comparison semantics, use
[EXPERIMENTS.md](skill/references/EXPERIMENTS.md). The
[full runner guide](skill/README.md) covers image recipes, resources and controls.

## Use it through your development agent

Direct CLI use needs no skill installation. To make the workflow discoverable to
a parent agent, install the complete `skill/` directory, including scripts,
runtime, assets, examples and references. Copying `SKILL.md` alone is insufficient.

From this checkout, the preserving installer links it into an existing project:

```bash
python3 skill/scripts/export_skill.py --output-dir /tmp/pi-agent-packages \
  --install codex --target-dir /path/to/project
```

Replace `codex` with `claude` or `antigravity` as appropriate. Existing installations
are preserved; the link follows this checkout, so keep it available. For portable
archives, use the [release downloads](https://github.com/Denissvgn/pi-agent-test-env/releases)
and [installation guide](skill/references/HARNESSES.md) for staging, checksums and
discovery scope.

Example request to your parent agent after selecting the skill:

> Use pi-agent-test-env to try the bundled Python slug task. Confirm my model
> endpoint, qualify a native core image, run the protected plan on a snapshot,
> and show me the reviewer findings, independent checks and resulting diff.

For a project-specific task, describe the observable behavior, protected tests,
endpoint and finite budgets. The parent reviews the plan and evidence; Pi children
execute the declared stages. See [SKILL.md](skill/SKILL.md) for the full workflow.

## Develop this project

| Path | Purpose |
|---|---|
| `skill/` | Self-contained installable skill and executable resources |
| `tests/` | Maintainer regression suite; excluded from skill archives |
| `tools/` | Packaging checks and pinned offline standards validation |

[CONTRIBUTING.md](CONTRIBUTING.md) covers local tests, complete PR review and
reproducible release verification. The maintainer suite uses synthetic protocol
fixtures and local services; it does not require a model server or establish live
Pi performance.

MIT licensed. This is an independent project, not an official Pi or Docker release.
