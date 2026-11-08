# Contributing

Keep the installable skill self-contained under `skill/`. Required runtime files
belong in `scripts/` and `runtime/`; optional procedures belong in `references/`;
copyable plans and profiles belong in `assets/`; runnable examples belong in
`examples/`. Keep maintainer tests, stored test output, publishing tools and
planning history outside the skill.

Runtime changes must retain Python 3.10+ and the standard-library-only host
policy. Standards validation is development tooling and requires Python 3.11+;
its pinned source and wheels are bundled in `tools/validation/` for offline use.
No validation dependency is installed globally or into the skill.

## Checks

Run from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 tools/validation/validate_standard.py --self-test
python3 tools/check_package.py --source skill
```

The tests use synthetic protocol data, mocked Docker boundaries, local
subprocesses and temporary loopback services. They do not invoke a model or
qualify Docker/model execution. Some environments require loopback permission.
Examples retain their own subject tests because those files are acceptance
inputs, separate from the maintainer suite.

The suite also needs `node` (Node.js 24 or later) on `PATH`: several tests run
the bundled JavaScript extensions and fail, rather than skip, without it.

To repeat the checks on native Linux with an exact Python, build the test image
and run the bounded container runner. It stages the published source allowlist,
mounts it read-only, disables the network and records a JSON report:

```bash
docker build -f tools/ci/Dockerfile \
  --build-arg PYTHON_IMAGE=python:3.10-slim-bookworm -t pi-agent-ci:py3.10 tools/ci
python3 tools/docker_ci.py --image pi-agent-ci:py3.10 --report /tmp/pi-ci-py3.10.json
```

Repeat with the newest supported Python as well. The runner does not supply the
synthetic read-only providers that the isolated owner-consumer tests use
(`PI_SYNTHETIC_READER_PROVIDER`) or the operation SDK container fixture
(`tools/qualification/operation_sdk_fixture.py`); those tests skip without them.

## Native qualification campaigns

Offline checks never qualify live execution. A release that claims native
qualification needs a fresh campaign on its exact code: the campaign tools record
a hash of `skill/scripts`, `skill/runtime`, the assets/docker/examples inputs and
`tools/qualification`, so change those first and only documentation afterwards.
A begun or failed campaign is never resumed or repaired; fix the cause, freeze a
new root and run again. Keys stay in disposable owner-only stores outside the
repository and evidence; campaigns need the confirmed environment gate
(`env status --session` ready) and exact native ARM64 images.

| Tool | Gates | Covers |
|---|---|---|
| `tools/qualification/pi_release.py` | `freeze --evidence NEW --session S`, then `images`, `collect`, `status` | Serial Pi 0.87.1/1.2.0 matrix: smoke, coding/review, fixture lookup, scoped credentials, sandboxed browser and fault lanes |
| `tools/qualification/parallel.py` | `freeze --root NEW --images I --endpoint E --session S`, then `infrastructure`, `collect` | Opt-in two-trial parallel execution |
| `tools/qualification/indexed.py` | `freeze --root NEW --profiles P --images I --session S`, `inspect`, `run --approval A`, `finish --inspection J` | Indexed, serial, parallel and legacy-endpoint runs, experiments, fixture lookup, credentials, browser and all fault lanes on both Pi releases |

The images file maps `core-<release>` and `browser-<release>` for each reviewed
Pi release to `{"platform": "linux/arm64", "id": "sha256:..."}` from admitted
`ensure-image` receipts. The indexed profiles file holds two inference
configurations `a` and `b`, a `scope` and `deployment_limits`. Its approval file
must contain the SHA-256 of the frozen `manifest.json` as
`approved_manifest_sha256` and `"older_clients_quiesced": true`. The indexed
`freeze` makes no native call, so it also checks that the campaign still fits
changed code before any collection.
Record the dated outcome, its cell counts and limits in `skill/QUALIFICATION.md`.

## Prepare distributables

Before merging a PR, read all review submissions and inline threads, including
outdated unresolved threads. Wait for this repository's automatic Copilot review
on the exact final head; it can finish after a PR becomes mergeable. Fix and test
valid findings, document any rejected finding's evidence, and resolve only
supported dispositions. A later push requires new exact-head review evidence.

Run the read-only gate immediately before an authorized merge:

```bash
python3 skill/scripts/pr_review_gate.py --repo Denissvgn/pi-agent-test-env \
  --pr PR_NUMBER --head VERIFIED_HEAD_SHA --expect-reviewer Copilot
```

Pending/missing reviews, stale heads, unresolved threads, requests for changes,
incomplete API evidence and failing/in-progress checks block merging. No timeout
or admin bypass turns them into a pass. Use `--match-head-commit` for the merge.
See [the promotion procedure](skill/references/PULL-REQUESTS.md). The
[opt-in parallel-agent design](docs/design/parallel-agents.md) sets the fixed verification order;
serial execution remains the default. Experimental schema-2 selection requires
its documented cohort, resource and qualification contract. Build release
artifacts from the final reviewed tree and preserve published tags/assets when
shipping a corrective patch version.

```bash
python3 tools/build_release.py --output-dir /tmp/pi-agent-release
python3 tools/verify_release.py --archives /tmp/pi-agent-release \
  --report /tmp/pi-agent-release-verification.json
```

The extracted-source maintainer suite has a finite 900-second budget by default.
Use `--test-timeout-seconds` to select 60..1800 seconds for the verification host;
the report records that budget. A timeout remains a failed verification and
retains captured stdout/stderr. It does not skip tests or change runner budgets.

Choose a fresh output directory outside the skill, tests and publishing tools. The build emits five skill
layouts, a clean source archive and `SHA256SUMS`. It retains all runtime assets and
excludes plans, backlogs, development reports, stored test output and earlier
distributions. Source archives include the maintainer tests and publishing tools;
skill archives contain only the installable skill.

A release build refuses unless the first `## ` entry in `skill/CHANGELOG.md`
names the `skill.json` version, so archives can never reuse an already published
version name for different bytes. For candidate verification before the version
bump, pass `--candidate`; its output and the verification report record
`"publishable": false`. Before tagging, confirm the version is new on the remote
with `git ls-remote --tags origin "v<version>"`; local clones can lack newer tags.

Archives are byte-reproducible from the same tree: members carry a fixed time
(`SOURCE_DATE_EPOCH` when set, otherwise 1980-01-01) and explicit Unix modes,
so file timestamps and checkout times do not change `SHA256SUMS`.

Verification safely extracts every layout, checks complete manifests, versions,
permissions and resource hashes, runs the pinned official validator on all five
named skill roots, then runs the maintainer suite against extracted package
bytes. It checks the complete extracted inventory before and after execution.
The report is separate from published files and records actual observed results.

`.gitattributes` also excludes retained internal history from `git archive`,
but export exclusions do not hide files committed to the public repository.
Keep private incident plans, downstream handoffs, raw logs and evidence archives
in the ignored `development/` directory or outside the repository. Public
documentation must be self-contained: do not link to workstation paths, private
projects or internal evidence. Do not add internal task identifiers or stale
implementation status. Explain behavior, configuration, compatibility and
observed limits.
Changes to package or runner bytes require fresh archives and experiments; dated
model evidence cannot be restated under a new runner identity.

Preparing artifacts does not publish, push, tag or change global installations.
