# Pi Agent Test Environment 4.3.0

**English, project-adaptable, resource-bounded workflows for real local-LLM agents.**

This package replaces the project-specific `pi-local-agent-tests` skill. It includes
an Agent Skills `SKILL.md`, a host-side runner, a Docker build, capability contracts,
sequential agent plans, independent checks, and small starter projects. The parent
can be any development agent or a human with permission to run the host scripts;
children are real Pi Coding Agent processes.

Exact reviewed runtime contracts are Pi 0.87.1 and 1.2.0. The
[1.2.0 reference](references/PI-1.2.0.md) explains cancellation, isolation,
profile selection and compatibility limits. Old 0.87.1 profiles and evidence
remain intact; builds still require an explicit version.

The supplied executor targets Linux ARM64/AMD64 containers and an OpenAI-compatible
Chat Completions endpoint. Other project stacks need their own tested toolchains;
this is not a promise that every language, OS, test runner, or model works unchanged.

Qualification is specific to the recorded image, Pi release, model and resource
configuration. Native host-control checks use synthetic outcomes; repackaging
does not create new model measurements. See [QUALIFICATION.md](QUALIFICATION.md).

## Install the complete skill

Use [HARNESSES.md](references/HARNESSES.md) for preserving project installation,
current discovery paths and emitted archive names. Install the contents of this
repository's `skill/` directory as `pi-agent-test-env`, retaining all resources.
Codex and current Antigravity use `.agents/skills`; Claude Code uses `.claude/skills`.
Documented layout is separate from actual version-scoped discovery qualification.

Set `SKILL_DIR` to the complete installed skill directory before commands below.
No Docker builds or model calls occur during export. Archives must be staged in
an empty directory and verified before any authorized installation/update.

Prerequisites on the parent host: Python 3.10+, local Docker Engine or Docker
Desktop running Linux containers, and Buildx when building. Linux/macOS/WSL are
supported; native PowerShell/Windows Python is not supported by the POSIX lock.
No host Python packages are needed by the runner. Children need a compatible Pi
release; the image probe verifies flags before work starts.

## Evaluation workflow

Choose the subject, cases, independent structured scorer and a declared variant
factor before collecting results. Freeze the complete intended matrix and inputs,
qualify the exact image/model configuration, collect fresh serial trials, score
eligible stopped failures, then compare complete primary denominators and preserve
all evidence. Use [SKILL.md](SKILL.md) as the entry workflow and
[EXPERIMENTS.md](references/EXPERIMENTS.md) for exact preparation/recovery/report rules.
The short single-plan coding path below remains available without an experiment.
Optional fixture integration is separate from application baseline measurement.

Set `IMAGE` to an explicitly trusted/qualified native image before execution.
Examples do not select a Pi release automatically. Existing tags may contain a
different release and must be independently checked. On Apple Silicon use explicit
`--platform linux/arm64` for image selection and verify architecture before launch.

## What is configurable

| Input | Responsibility |
|---|---|
| `--project` and `--plan` | Task, required/protected files, stages, independent tests, working directories |
| `--image`, `--environment`, `--profile` | Trusted runtime/tools, architecture, versions, browser requirements |
| `--session` (saved environment) or `--endpoint` | Exact served model, `/v1` base URL, inference key by name, real context |
| `--resources` | CPU, RAM, process, worker, builder, and host-budget limits |

The runner code has no built-in model or address. The environment gate (below) saves the
user's server once and asks for confirmation in each new session.

Per-stage application credentials use the agent `application_secrets` map and
named owner-only host-store entries. Only explicitly assigned workers receive
`PI_APP_*` variables; inference credentials remain separate and independent checks
stay key-free. See [the application-credential contract](references/APPLICATION-CREDENTIALS.md)
for exact configuration, client use, redaction, sensitive cleanup and qualification
limits. Missing/insecure references or incomplete cleanup fail closed.

For sandboxed browser admission, use the [credential-free browser-check gate](references/BROWSER.md#sandbox-and-webgl)
and explicitly select the reviewed `chromium-userns` policy where required.
Default Docker policy and frozen campaign permissions are never silently changed.

## Resource limits are on by default

| Scope | Requested defaults | Effective behavior |
|---|---|---|
| Each runtime stage | 2 CPU equivalents; 4 GiB; 256 tasks/threads | CPU and RAM capped at half the Docker allocation |
| Swap | Combined memory+swap limit = RAM limit | No additional swap allowance |
| Thread/worker hints | 2 jobs | Lowered to fit the effective CPU allocation |
| Image build | 2 CPUs; 4 GiB; 2 parallel steps; 1,800 seconds | A dedicated verified BuildKit container, then removed |
| Agent concurrency | 1 stage at a time | Same-user host lock also prevents overlapping runner processes |

`--cpus 2` is two CPU-equivalents, **not 2%** and not two dedicated cores. A
container can schedule on several CPUs while its total CPU time is throttled.
No CPU shares alone, unlimited memory, or unrestricted build fallback is used.
See [RESOURCES.md](references/RESOURCES.md) for lower-impact presets, verification,
Docker Desktop settings, and the separate local-model-server budget.

## Reuse first

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" ensure-image \
  --image pi-agent-tests:browser --reuse pi-workspace:chromium \
  --profile browser --policy reuse \
  --environment "$SKILL_DIR/assets/environments/browser.json" \
  --resources "$SKILL_DIR/assets/resources/browser.json" \
  --receipt "$HOME/pi-agent-image.json"
```

A compatible existing image is reused and tagged. `reuse` will not download/build
an alternative. With `auto`, a build is allowed only after reuse fails and an
explicit Pi version was supplied. Choose that version from your approved release
or the compatible installation you already use:

```bash
# Set PI_VERSION to an actual reviewed release before executing this command.
: "${PI_VERSION:?Select a compatible, explicit Pi release first}"
python3 "$SKILL_DIR/scripts/pi_lab.py" ensure-image \
  --image "$IMAGE" --profile core --policy auto \
  --pi-version "$PI_VERSION" --platform linux/arm64 \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

`--policy build` explicitly rebuilds the target; running containers are not updated
in place. Builds use only `docker/`, not your source tree or credentials. An
ephemeral `docker-container` Buildx builder limits the entire build workload, rather
than relying on individual Dockerfile command worker counts. Builder cache is
removed with that dedicated builder; successful images remain in the image store.
For another environment, use `--dockerfile /path/env/Dockerfile` and
`--build-context /path/env` with the same resource policy and explicit Pi version.
Review the custom build context for secrets; do not use the application checkout
as a convenient context. A custom Dockerfile must provide the baseline tools and
honor the requested Pi pin. For reproducible releases pin base and BuildKit image digests as well as Pi and
project dependencies. A tag or pinned Pi alone does not freeze every transitive
package.

## Connect your local model server (environment gate)

The skill assumes no particular server. The first step of every agent session is the
environment gate (full protocol: section 0 of `SKILL.md`):

```bash
SESSION=$(python3 "$SKILL_DIR/scripts/pi_lab.py" env new-session)
python3 "$SKILL_DIR/scripts/pi_lab.py" env status --session "$SESSION"
```

- `ready` (exit 0): a saved environment was confirmed in this session and passed a live check; reuse it.
- `needs-confirmation` (11): a saved environment exists, but this new session has not approved it. The agent
  shows it to you and asks whether to use it or set up a new one.
- `no-environment` (10): the agent asks for the base URL only and uses `PI_API_KEY` from the environment/store for `env discover`. It asks for secure terminal key entry only if authentication requires it, then lets you choose a live-listed model and confirm context/max tokens before `env save`.
- `broken` (12): inspect the concrete failure and repair or replace the saved environment; preserve its chosen model/key variable unless you explicitly change it.

The key never goes through chat. Store it in your own terminal (hidden prompt) or export it:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set PI_API_KEY
```

The saved environment contains only the key variable's *name*. The runner generates its own isolated
`models.json` (provider `local-lab`) for every child and does not read your host Pi configuration. Set
`context_window` to the context the server actually *loaded*, not just the model's maximum. This package does
not install or modify the model server.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" preflight --image "$IMAGE" --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"

python3 "$SKILL_DIR/scripts/pi_lab.py" smoke --image "$IMAGE" --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

A hand-written endpoint file (`assets/endpoint.example.json`, `vllm.example.json`) still works through
`--endpoint FILE` and bypasses the gate.

For a core-only smoke against an image containing Chromium, keep `--profile core`
to test the agent separately from browser availability. Use browser profile when
browser execution is part of the acceptance contract.

On Docker Desktop a host-served endpoint may use `host.docker.internal`. On local
Linux add `--host-gateway`. For a sibling server use a container DNS name and the
same user-defined network with `--network`. Do not assume adding a model to
Studio's Connections automatically republishes it through Studio's plain API.

## Try a real implementation task

The Python and Node starter projects intentionally contain unfinished functions.
Their acceptance tests are included, protected, and need no downloaded dependencies.
The following starts two real agents and a fresh verifier on an isolated copy:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" run \
  --image "$IMAGE" --profile core \
  --project "$SKILL_DIR/examples/python-project" \
  --plan "$SKILL_DIR/assets/python-feature.plan.json" \
  --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

For the Node variant, substitute `examples/node-project` and
`assets/node-cli.plan.json`. These are examples, not automatic adapters for your
repository. Do not claim live-model success based on their existence or unit tests.

## Adapt another repository

Copy a plan outside the project (or leave it in a trusted skill directory). Read
[PROJECTS.md](references/PROJECTS.md) before changing commands. Update all required
paths, protected tests, stage `cwd`, setup commands, and assertions. Then:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-plan --plan /absolute/path/plan.json
python3 "$SKILL_DIR/scripts/pi_lab.py" run \
  --image "$IMAGE" \
  --project /absolute/path/project --plan /absolute/path/plan.json \
  --endpoint /absolute/path/endpoint.json \
  --environment /absolute/path/environment.json \
  --resources "$SKILL_DIR/assets/resources/balanced.json" \
  --cpus 1.5 --memory 3g --jobs 1
```

The extra limits override the policy's runtime requests, but are still capped by
its host-budget fractions. Image-building limits are separate. Use
`--lock-wait-seconds 300` to queue behind another operation, not to create parallel
agents. For image builds, `--build-cpus 1 --build-memory 2g --build-parallelism 1`
provides the equivalent lower-impact build settings.

Useful templates:

| Template | Assumptions to verify |
|---|---|
| `python-feature.plan.json` | Included unittest demo; adapt paths/runner for your app |
| `node-cli.plan.json` | Included Node built-in-test demo; no npm required |
| `browser-ui.plan.json` | Existing npm lockfile, portable test, static HTTP app; adapt real server/build |
| `monorepo.plan.json` | Python API and Node client directories; sequential component stages |
| `environments/go.json`, `rust.json` | Capability contracts only; supply those compilers in a reviewed image |

## Browser tests without host-path mistakes

The browser image installs native Linux Chromium. Tests must honor
`PUPPETEER_EXECUTABLE_PATH`/`CHROME_BIN` or use
`/opt/pi-lab/browser-options.mjs`. Set temporary profiles/cache under $TMPDIR in the isolated runtime.
Never launch `/Applications/...` or run `apt` inside the read-only child.

Browser sandbox disabling and unsafe software WebGL are *separate explicit opt-ins*:
`--allow-browser-no-sandbox` and `--software-webgl`. They are not automatically
turned on after an error. Use only for reviewed local fixtures and read
[BROWSER.md](references/BROWSER.md). Chromium consumes the same finite CPU/RAM
budget as the test; large browser runs may require a reviewed bounded increase.

## Prerequisites Diagnostics & Secret Store

- **Diagnostic Doctor:** Validate host Python, Docker engine & context, container reachability, model endpoint configuration, and secret store in a single diagnostic pass:
  ```bash
  python3 "$SKILL_DIR/scripts/pi_lab.py" doctor --image "$IMAGE" --session "$SESSION"
  ```
  Classifies failure reasons with machine-readable codes and actionable remedies. Exits with code `3` (`EXIT_NEEDS_SECRET`) if the model key is missing.

- **Host-side Secret Store:** Store inference and named application keys securely in `~/.config/pi-agent-test-env/secrets/` (`0600` permissions, directory `0700`):
  ```bash
  # Hidden terminal prompt:
  python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set PI_API_KEY
  # Or pipe from password manager / stdin:
  pass show my-key | python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set PI_API_KEY --stdin
  # Check fingerprint (never reveals key):
  python3 "$SKILL_DIR/scripts/pi_lab.py" secrets status PI_API_KEY
  ```

## Live Orchestrator Control & Dynamic Budgeting

Each stage uses parent-owned controls at /opt/pi-control (read-only), a writable
outbox and separate /pi-state runtime. No writable project alias exposes those
sources. Parent stage UUIDs/revisions route every control; ambiguous legacy
mutations reject. Capability facts describe the effective access/network/mounts
and available commands. PI_OFFLINE disables startup operations, separately from
Docker network mode and actual endpoint reachability.

- `status --stage <STAGE_UUID>` reports parent lifecycle/budgets and untrusted telemetry.
- `extend-budget --turns +10 --timeout +300 --wait-seconds 2` queues bounded increases; only the active supervisor can apply them before the deadline.
- `steer --message "Focus on the implementation"` waits for process completion and enters a new linked exact-session segment. `--interrupt` requests a parent-applied interrupt; neither path promises turn-level delivery.
- `patch-session --run <RUN_DIR> --stage <STAGE_UUID> --file fix.py --target lib/core.py` supports quiescent pending stages only. Active/completed stages, protected inputs and unsafe writers reject.
- Reasoning inputs in env save/endpoint files express requests. Release mapping and server enforcement are not proven by configuration acceptance; the release adapter supplies the reviewed mapping; runtime traces qualify only their exact ingestion path. Server enforcement remains unverified.

Accepted intervention records mark assistance; child acks cannot authorize changes.
The Bash pattern filter is an additional guard, not a general shell parser or a
confinement proof. The OS/mount boundary supplies filesystem isolation, with the
listed runtime/outbox exceptions; VALIDATION.md scopes the dated live observations.

## Read the results

Evidence is under `~/.local/state/pi-agent-test-env/runs/<run-id>/`, outside
the child's mount. The output reports the exact directory. Inspect:

- sealed `result.json`, progress `summary.json`, `plan.json`, and applied resource/image information;
- `agent-*/segments/<SEGMENT_UUID>/stdout.jsonl` and process logs; stage evidence/final text and parent segment/session records;
- `check-*/` outputs and `process.json` including OOM/applied limits when available;
- `changes.json`, protected-file snapshots, and the resulting `workspace/` copy.

An invocation is structurally verified only with matching model/provider,
completed message/agent lifecycles, required successful tool calls, and exit 0.
Both reviewed releases require `agent_settled`; 1.2.0 also requires a valid
non-aborted settlement flag. Historical `process-exit` trace inspection cannot
weaken live execution. Prose cannot replace tool events or authorize another model.

`PASS`/0 is a clean autonomous mechanical plan result. Assisted/recovered success
returns exit 1; blocked/cancelled runs return exit 2. Invocation and independent
artifact scores remain separate, so passing scores do not erase invalid execution.
Mechanical results are not automatic approval of a reviewer's findings
or a security certification. Inspect review output, tests, and diff before applying
anything back to the original. `--in-place` must be consciously opted into; it
mounts original files and is not equivalent to the snapshot's exclusions.

## Migration from the previous package

Use the new directory/name `pi-agent-test-env`. Stage and review the complete
English package separately; do not overwrite an existing installation automatically. Endpoints are now required inputs, and
the model server lives in the saved environment (or an `--endpoint` file), not in the runner. Reuse does not require a build-version argument, but the installed release
still needs its exact interface contract and qualification receipts. A build
requires an explicit reviewed version. Defaults now cap runtime/build resource use, serialize cooperating runs, and
record OOM/applied-limit evidence. Host `.pi-lab` storage and `/opt/pi-lab` helper paths are
retained for test-helper compatibility; plan schema remains version 1.

See [VALIDATION.md](VALIDATION.md) for exactly what was and was not executed during
package preparation. Commands in examples are not claims of successful live runs.

## Repeated application baselines

For fixed baseline/candidate repetitions, use the implemented
[experiment commands and schema](references/EXPERIMENTS.md) and the
[complete Python application example](examples/application-baseline/README.md).
Prepare the entire immutable matrix, collect serial fresh trials, resume only
pending cells or explicit linked retries, then emit complete JSONL/JSON/Markdown
comparisons. Primary attempts, artifact-only correctness, verified invocation,
assistance and retries have separate eligibility and denominators. This built-in
application workflow needs no custom child integration. Offline checks do not
establish model performance; real trials require retained execution and scoring evidence.

## Optional reviewed fixture integration

[Agent profile contracts](references/AGENT-PROFILES.md) and the
[fixed lookup comparison](examples/integration-baseline/README.md) support exactly
one opt-in fixture_lookup extension on reviewed Pi 0.87.1 or 1.2.0 through exact
release-bound declarations. Explicit hashes and
read-only assets preserve isolated defaults; real registration/tool-use evidence
is required separately from independent task scores. Historical observations
remain limited to their exact selected configuration. Broader integrations are unsupported.
