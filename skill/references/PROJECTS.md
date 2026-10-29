# Adapting projects and environments

Application evaluation scope, the optional `fixture_lookup` integration and the
implemented trial/scorer/provenance contracts are defined in
[EVALUATION-CONTRACT.md](EVALUATION-CONTRACT.md). The existing plan examples below
remain schema 1; experiment preparation/execution uses the frozen matrix described
in [EXPERIMENTS.md](EXPERIMENTS.md).

## Discovery contract

Read the repository before writing its plan. Determine runtime and package-manager
versions, lockfiles, generated artifacts, entrypoints, actual test commands,
services, test data, and code-generation steps. Record these in
`assets/task-brief.example.md`. Ask only for genuinely missing acceptance criteria
or permissions; do not infer an absent test as a successful check.

An environment contract is a trusted host-side JSON file:

```json
{
  "schema": 1,
  "required_commands": ["python3", "node"],
  "probes": [
    {
      "name": "python-floor",
      "argv": ["python3", "-c", "import sys; assert sys.version_info >= (3, 10)"],
      "timeout_seconds": 30
    }
  ]
}
```

Probes are offline and key-free. Optional `stdout_regex` enforces a version/output
contract. They run in addition to baseline Pi/Node/Python/Git/Bash/ripgrep checks.
They are executable trusted input, not safe to copy blindly from untrusted tasks.
This contract verifies a supplied image; it does not install missing toolchains.

The stock image provides Node 24 and Debian Python with venv support. A reused
image needs Node >=22.19 for the baseline and the required Pi flags; your project
contract can require Node 24, another application interpreter, or exact versions.
For a project pinned to an older Node incompatible with Pi, put its runtime behind
an explicit alternate executable in a reviewed image while Pi retains a supported
Node. Do not downgrade the agent runtime to satisfy the application accidentally.

Use `--apt-package` for additional Debian packages; the bundled Dockerfile assumes
a Node/Debian-compatible base with `apt-get`, npm, and a `node` user. It is not a
generic recipe for Alpine or arbitrary images. For Go, Rust, Java, dotnet, pnpm,
uv, browser-specific builds, or proprietary dependencies, build a separate reviewed
image from pinned sources and reuse it, or build through the same bounded executor:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" ensure-image \
  --image my-project-agent:dev --policy build --pi-version "$PI_VERSION" \
  --dockerfile /absolute/path/env/Dockerfile \
  --build-context /absolute/path/env \
  --environment /absolute/path/environment.json \
  --resources "$SKILL_DIR/assets/resources/balanced.json"
```

The custom Dockerfile must use the provided `PI_VERSION` build argument (or its
own reviewed equivalent pinned to the same version) and install all baseline
tools. `BASE_IMAGE`, `WITH_BROWSER`, and `EXTRA_APT_PACKAGES` are also passed; a
custom file only uses them if it explicitly declares/handles them. Do not assume
a custom builder inherits the stock Dockerfile's packages or secret exclusions.
Verify the actual required versions.

## Project layouts and test commands

`required_paths` are exact project-relative paths that must exist before execution.
`protected_paths` are files/directories whose initial/final hashes must match.
An agent/check `cwd` is relative to `/workspace`, defaults to `.`, and must already
exist. It is a convenience, not a subdirectory sandbox; a read-write agent still
has access to the whole project mount.

Setup commands run once, then sequential agents, then independent checks. Each
stage starts in a fresh container and shell. An environment activation or `cd`
in one stage does not persist into the next. Files inside the snapshot do persist.
Use explicit paths such as `/workspace/.venv/bin/python` in later commands.

Python with third-party packages: create a Linux venv inside the snapshot and use
a reviewed locked installation command. Do not modify system Python or the LLM
server's environment. Node: use its actual package manager and lockfile; a Node
built-in-test project does not need npm. Rust/Go: provide matching compilers and
respect lockfile/module manifests. Do not copy a macOS venv or native node_modules.

`npm ci --ignore-scripts` is a conservative template, not universally sufficient.
Some reviewed dependencies require lifecycle/build scripts; list those preparation
steps explicitly and run them key-free with parent-approved network access. Never
have the model discover this by turning off container restrictions at runtime.
Use job controls appropriate to each test runner, within `PI_TEST_JOBS` and the
Docker CPU quota. Reject a test command that silently discovers zero tests.

## HTTP/API applications

Test-only services can run in the *same* verifier container on loopback, including
when Docker networking is `none`. The helper starts the service, waits for a 2xx
readiness response, runs the test, and terminates process groups on every exit:

```bash
python3 /opt/pi-lab/with-service.py \
  --start-json '["node", "server.mjs", "--port", "4173"]' \
  --ready-url http://127.0.0.1:4173/health \
  --ready-timeout 45 --test-timeout 300 \
  -- node --test tests/api.test.mjs
```

This is an example; adapt the actual service's start arguments. `TEST_BASE_URL` is
set for the service and tests. Use an in-container fake external service only when
the acceptance contract explicitly permits it. The *agent/model invocation*
required by this skill must remain real, not a mocked provider response.

For a database or dependency in another container, the parent prepares that test
infrastructure outside the child, applies its own resource limits, passes only a
test endpoint, and authorizes check networking. This runner does not provision a
Docker Compose stack or manage its aggregate resource budget automatically. Never
pass the Docker socket to Pi or use production credentials in integration tests.

### Authenticated external applications

External-service reachability does not supply authentication. Declare each
worker's application credential through the schema-1 agent `application_secrets`
map and place values in the owner-only host store outside the project. The runner
supplies only that stage's declared `PI_APP_*` variables, separately from the
inference key. Missing/insecure references and incomplete cleanup block dispatch;
independent checks remain application-key-free. Only isolated snapshots are
supported for credential-bearing plans.

For persona onboarding and authenticated effects, retain the application's actual
handoff payload and an independent service-side identity/effects oracle. A local
fake service tests the client contract but does not qualify real application
semantics. The reviewed fixture profile is unrelated to credential delivery.
See [APPLICATION-CREDENTIALS.md](APPLICATION-CREDENTIALS.md) for exact usage,
redaction, snapshot scanning, retention and crash recovery limits.

## Monorepos and multiple agents

`assets/monorepo.plan.json` illustrates separate API/client starting directories.
Agents are sequential and share the same isolated snapshot. Prompts should identify
allowed components and handoff artifacts. A fresh agent does not inherit another
agent's conversation. Read-only review runs with the project mount read-only and a
writable runtime subdirectory. Test helpers and outer logs stay outside the mutable
checkout. Parent-level final approval must read the reviewer's findings; the
mechanical runner does not classify prose as a merge decision.

For independent alternatives, run distinct plans/snapshots serially. Do not launch
multiple writers on one checkout or bypass the host admission lock. Durable human
handoff should identify the run directory and exact changed files, not merge one
agent's entire workspace automatically.

## Snapshots, Git, and secrets

By default the original project is not mounted. The snapshot skips `.git`, `.pi`,
`.agents`, `.pi-runtime`, `.pi-lab`, dependency caches, venvs, typical key files,
symlinks, and special files. It materializes regular files as new inodes, not hard
links. These are convenience exclusions, not a complete secret scanner. Audit
fixtures and use a disposable source tree for untrusted projects.

No `.git` means Git-history/version-derived builds need preparation. Supply a
version artifact, or use a separate disposable standalone checkout with an
explicitly approved `--in-place` workflow. A linked worktree may reference a host
`.git` outside the container and is not automatically portable. Do not blindly
mount the parent repository, home directory, or hidden credentials to fix it.

`--in-place` exposes the complete selected directory, not the snapshot exclusions;
ignored files can still be read and written by a writable stage. Before the first
writable project stage, admission scans every entry, including excluded and
secret-looking directories, without following links. Symlinks, dangling links,
multiply linked regular files and metadata/enumeration errors block admission.
Normal directory link counts are accepted. `--exclude` affects snapshots only;
it cannot narrow this admission scan. The filtered change inventory retains its
existing exclusions and is not a safety scan. The host lease assumes cooperating
writers; admission cannot prevent arbitrary hostile host mutation afterward.
Prefer the default copy, review `copy.skipped`, and apply only verified changes
after acceptance.

## Separate host discovery and child serving routes

Endpoint `base_url` remains the child serving route. Optional `host_base_url`
defaults to it and is used by saved-environment health and host diagnostics.
For a model on a Docker network with a published host port, discover at
`http://127.0.0.1:18080/v1`, then save with
`--base-url http://model-server:8080/v1 --host-base-url http://127.0.0.1:18080/v1`.
Use the server's existing user-defined network via `--network` for runtime calls.
Setup needs a reachable host route before image qualification; a container-only
route without host discovery is not supported. LAN and legacy single-URL setups
need no extra option. Both routes enter the environment fingerprint and run
record; changing either invalidates session confirmation. Host and child check
the exact selected model independently. Matching IDs do not attest identical
weights. No alternate route or model is chosen after a failure.

## Nested Python unittest checks

Invoke `/opt/pi-lab/verify-unittest.py --start-dir tests` from the selected stage
`cwd`, including `services/api`; the helper puts that working directory on the
import path. No global PYTHONPATH is needed. For a package whose import root is
an ancestor, use `--top-level-dir ..` (relative to cwd) and normal package
`__init__.py` files. Zero discovered tests, failed imports and assertions fail
acceptance. The output retains `INDEPENDENT_TESTS_RUN=N` for legacy consumers;
this legacy verifier does not claim structured scorer metrics.

## Indexed inference opt-in

For different implementation/review inference bindings, select standalone plan schema 2 or schema-3 variant-owned maps explicitly. Each stage starts a fresh Pi session; continuation retains that stage’s exact binding. Setup/scorers receive no inference assignment. See [INFERENCE-ENVIRONMENTS.md](INFERENCE-ENVIRONMENTS.md).
