# Contributing

Keep the installable skill self-contained under `skill/`. Required runtime files
belong in `scripts/` and `runtime/`; optional procedures belong in `references/`;
copyable plans and profiles belong in `assets/`; runnable examples belong in
`examples/`. Keep maintainer tests, stored test output, publishing tools and
planning history outside the skill.

Runtime changes must retain Python 3.12+ and the standard-library-only host
policy. Standards validation is development tooling and requires Python 3.11+;
its pinned source and wheels are bundled in `tools/validation/` for offline use.
No validation dependency is installed globally or into the skill.

## Checks

Run from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 tools/validation/validate_standard.py --self-test
python3 tools/check_package.py --source skill --no-manifest
python3 tools/check_examples.py --source skill
```

In a pull request worktree the package check is structural:
`--no-manifest` checks the package layout, metadata and links but not
`skill/MANIFEST.sha256`, which is regenerated only when a release is prepared
(see [Changelog and manifest](#changelog-and-manifest)). **Requires the matching
tooling:** `--no-manifest` is not yet in `tools/check_package.py`; it arrives
with the CI change that adds it. Until then the check accepts only the strict
form. The published and release-preparation integrity checks remain strict:
`python3 tools/check_package.py --source skill` without `--no-manifest`, and the
release build and verifier below, require a complete manifest that matches the
package bytes.

`tools/check_examples.py` is the read-only examples check: it checks the
packaged documentation commands, parser, schemas and JavaScript syntax without
running a model. The release verifier and the container runner below run it too.

The tests use synthetic protocol data, mocked Docker boundaries, local
subprocesses and temporary loopback services. They do not invoke a model or
qualify Docker/model execution. Some environments require loopback permission.
Examples retain their own subject tests because those files are acceptance
inputs, separate from the maintainer suite.

The suite also needs `node` (Node.js 24 or later) on `PATH`: several tests run
the bundled JavaScript extensions and fail, rather than skip, without it.

**Needs Docker.** To repeat the checks on native Linux with an exact Python,
build the test image and run the bounded container runner. It stages the published source allowlist,
mounts it read-only, disables the network and records a JSON report:

```bash
docker build -f tools/ci/Dockerfile \
  --build-arg PYTHON_IMAGE=python:3.12-slim-bookworm -t pi-agent-ci:py3.12 tools/ci
python3 tools/docker_ci.py --image pi-agent-ci:py3.12 --report /tmp/pi-ci-py3.12.json
```

Repeat with the newest supported Python as well. The runner does not supply the
synthetic read-only providers that the isolated owner-consumer tests use
(`PI_SYNTHETIC_READER_PROVIDER`) or the operation SDK container fixture
(`tools/qualification/operation_sdk_fixture.py`); those tests skip without them.

## Adopting a new Pi release

Start with the read-only intake. It fetches the exact upstream tag, the npm
package and its provenance, hashes every upstream file that the reviewed
contracts pin, and compares the result with the newest reviewed release
(`--base` selects another):

```bash
python3 tools/pi_release_intake.py --release 1.6.0 --output-dir /tmp/pi-intake-1.6.0
```

Choose a fresh output directory outside `skill/`, `tests/` and `tools/`. The tool
writes `review-packet.md`, `intake.json` and `draft-contract.json`, using about
60 requests to public GitHub and npm endpoints; `--skip-tarball` leaves the
tarball undownloaded and unchecked. It first reproduces the base release's
recorded commit and pins, checks the downloaded tarball against the registry
integrity metadata and compares the provenance commit with the tag. A mismatch
is a blocking finding and exits with 3. A contract finding marks something the
base contract cannot carry over unchanged, such as a missing required CLI flag
or a new tool-argument validator, as when Pi moved from TypeBox to pi-schema. The
packet lists each changed pinned file with diff links, CLI flag and built-in
tool file changes, dependency drift, keyword-filtered release notes and the
repository files that name the base release.

The packet narrows the review; it does not replace it. Provenance signatures
are not verified, the release-note filter is a heuristic, and unchanged pins do
not prove unchanged behavior. `draft-contract.json` and the packet hold a draft
registry entry: the target's commit, source and package pins and fixture
profile, plus the base entry's behavior fields, marked unreviewed. The packet says whether the entry
loads as written. Read every changed file, decide each carried-over field and
record the result in a `PI-<release>.md` reference. Then:

1. Append the reviewed entry to `_REVIEWED` in `skill/runtime/release_contracts.py`.
   The module refuses an incomplete, malformed or out-of-order entry when it loads.
2. Add the release's tool declarations to `_RELEASE_TOOLS` in
   `skill/runtime/native_tool_contracts.py`, compared with a live `getAllTools()`
   dump of an image built for the release (**needs Docker** to build and run that
   image); the module refuses a reviewed release without them. [PI-1.5.2.md](skill/references/PI-1.5.2.md) records how.
3. Add `skill/assets/profiles/fixture-lookup/profile.pi-<release>.json` and add
   the release to the `pi_release` check in `skill/runtime/tool-budget.mjs`.
4. Append the line that `python3 tests/test_release_registry.py --freeze <release>`
   prints to `REVIEWED_IDENTITIES`. Never edit an earlier line: receipts bind
   those identities.
5. Add the new release identity to `PARALLEL_RELEASE_CONTRACTS` in
   `tools/qualification/application_sdk_admission.py`.
6. Update the documentation and add a changelog fragment. The package manifest
   is regenerated when the release is prepared, not in this pull request.

The maintainer suite fails until steps 1–5 are complete. A stable claim still
needs a native campaign on exact images (**needs Docker** and a person; see
below). With three reviewed releases, select releases for the indexed campaign
with `--release`: qualifying all of them at once exceeds its launch ceiling.

## Native qualification campaigns

Offline checks never qualify live execution. A release that claims native
qualification needs a fresh campaign on its exact code. **Needs Docker:** every
campaign runs on exact native ARM64 images.

The campaign tools record a hash of `skill/scripts`, `skill/runtime`, the
assets, docker and examples inputs and `tools/qualification`, so
`skill/scripts`, `skill/runtime`, `skill/assets`, `skill/docker`,
`skill/examples` and `tools/qualification` are bound into the campaign's source
identity. The code freeze begins when the commit a campaign will run on is
chosen. After the code freeze, until the campaign is finished, only
documentation outside those paths merges; a change inside them waits for the
campaign to finish, and shipping it then needs a new campaign.

A campaign that has begun or failed is never resumed or repaired; fix the cause
on `main`, freeze a new root and run again. Keys stay in disposable owner-only
stores outside the repository and evidence.

**Needs a person:** a person confirms the model environment before a campaign
(the confirmed environment gate, `env status --session` ready) and approves the
frozen campaign manifest (the approval file described below) before `run`.

| Tool | Gates | Covers |
|---|---|---|
| `tools/qualification/pi_release.py` | `freeze --evidence NEW --session S`, then `images`, `collect`, `status` | Serial matrix for each reviewed Pi release: smoke, coding/review, fixture lookup, scoped credentials, sandboxed browser and fault lanes |
| `tools/qualification/parallel.py` | `freeze --root NEW --images I --endpoint E --session S`, then `infrastructure`, `collect` | Opt-in two-trial parallel execution |
| `tools/qualification/indexed.py` | `freeze --root NEW --profiles P --images I --session S [--release R]... [--lock-file L]`, `inspect`, `run --approval A`, `finish --inspection J` | Indexed, serial, parallel and legacy-endpoint runs, experiments, fixture lookup, credentials, browser and all fault lanes on each selected Pi release |

The indexed campaign qualifies every reviewed Pi release unless `--release`
selects a subset. With the three reviewed releases the default selection is 330
cells and exceeds the planning hard launch ceiling (1,600 container launches or
256 networks), so the indexed `freeze` refuses it; select one or two releases.
One release is 110 cells, 724 planned container launches and up to 822 registry
records; two are 220 cells, 1,437 launches and up to 1,633 records. The frozen manifest records the selection, and
its cell, segment and inspection totals are derived from that matrix. A release
left out is not qualified by the campaign. The images file maps
`core-<release>` and `browser-<release>` for each selected release to
`{"platform": "linux/arm64", "id": "sha256:..."}` from admitted
`ensure-image` receipts. The indexed profiles file holds two inference
configurations `a` and `b`, a `scope` and `deployment_limits`. Its approval file
must contain the SHA-256 of the frozen `manifest.json` as
`approved_manifest_sha256` and `"older_clients_quiesced": true`. The indexed
`freeze` makes no native call, so it also checks that the campaign still fits
changed code before any collection.

Campaigns use the shared host lease and registry by default. When that registry
is blocked by retained ownership or lacks headroom (the indexed campaign reserves
up to 822 records of the 8,192 limit for one release and 1,633 for two), pass
`--lock-file` to the indexed `freeze` with a fresh absolute path outside the
qualification root. The frozen
manifest records it, and every later phase and child command uses it through
`PI_LAB_LOCK_FILE`. A dedicated lease leaves the shared registry untouched and
still blocked for ordinary runs; resolve that separately with the owner tools.
Keep dedicated leases out of `~/.local/state/pi-agent-test-env/` (for example in
`~/.local/state/pi-agent-qualification/`): on hosts that still use the legacy
`~/.local/state/pi-agentic-development/` directory, creating the new directory
switches the default lease and session store to new, empty locations.
Record the dated outcome, its cell counts, limits and lease choice in
`skill/QUALIFICATION.md`.

## Review and merge

Several agents change this repository at the same time. Every change takes the
same path: one task, one branch, one pull request, one review of record and one
merge.

### What a pull request may touch

- One task, one branch, one pull request against `main`. A pull request changes
  only what its task names. A defect found outside that scope becomes a task of
  its own, not an addition to the pull request.
- New commands are added as modules, not by editing the parser in
  `skill/scripts/pi_lab.py`.
- A pull request adds one changelog fragment and never edits
  `skill/CHANGELOG.md`; see [Changelog and manifest](#changelog-and-manifest).
- After a code freeze, until its campaign is finished, only documentation
  outside the campaign identity paths merges; see
  [Native qualification campaigns](#native-qualification-campaigns).
- Public text names no workstation, private project, internal identifier or
  personal path. It explains behavior, configuration, compatibility and observed
  limits, and does not record stale implementation status. Keep private plans,
  downstream handoffs, raw logs and evidence archives in the ignored
  `development/` directory or outside the repository. `.gitattributes` excludes
  retained internal history from `git archive`, but export exclusions do not
  hide files committed to the public repository.

### Review of record

An independent reviewer accepts the change against its acceptance criteria;
that acceptance is the review of record. The reviewer is never the author of the
change. The reviewer checks each criterion against its evidence, reads every
review submission and inline thread, including outdated unresolved threads, and
then accepts the change or requests changes. Valid findings are fixed and
tested; a rejected finding is answered with its evidence, and only threads whose
disposition the code and tests support are resolved. A push after acceptance
needs a new acceptance on the new head.

An automatic Copilot review is read when one arrives, and its findings are
handled like any other reviewer's. Its absence, or a quota or error notice in
its place, does not block a merge; neither is a review of record.

### Merge

A pull request merges only when, on its exact head:

- every required check is green. A pull request opened before a required check
  existed is rebased onto `main` first, so that the check runs on its head;
- the review gate passes with `--require-check ci-ok` and the review of record;
- no review is pending, no review requests changes and no thread is unresolved.

Run the read-only review gate immediately before the merge:

```bash
python3 skill/scripts/pr_review_gate.py --repo Denissvgn/pi-agent-test-env \
  --pr PR_NUMBER --head VERIFIED_HEAD_SHA --require-check ci-ok
```

Stale heads, pending reviews, unresolved threads, requests for changes,
incomplete API evidence and failing or in-progress checks block the merge. No
timeout or admin bypass turns them into a pass. Merge with a merge commit pinned
to the verified head, and keep the branch:

```bash
gh pr merge PR_NUMBER --merge --match-head-commit VERIFIED_HEAD_SHA
```

If the head changes, the checks, the review of record and the gate run again on
the new head. [The promotion procedure](skill/references/PULL-REQUESTS.md)
describes the gate's evidence.

**Needs a person:** changing repository settings, such as required checks or
branch protection, is done by a person.

## Changelog and manifest

A pull request adds one fragment under `changes/` that describes its change, and
never edits `skill/CHANGELOG.md`, so concurrent pull requests do not conflict
over the changelog. The package manifest, `skill/MANIFEST.sha256`, is
regenerated only when a release is prepared; that is also when the fragments
become the release's `skill/CHANGELOG.md` entry. A pull request therefore does
not change the manifest, and its package check uses `--no-manifest` (requires
the matching tooling; see [Checks](#checks)); the published and
release-preparation integrity checks remain strict.

## Release

The [opt-in parallel-agent design](docs/design/parallel-agents.md) sets the fixed
verification order; serial execution remains the default. Experimental schema-2
selection requires its documented cohort, resource and qualification contract.

Build release artifacts from the final reviewed tree and preserve published
tags and assets when shipping a corrective patch version. The build regenerates
`skill/MANIFEST.sha256` from the tree it packages:

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
Public release text is self-contained and links to no workstation path, private
project or internal evidence.

Changes to package or runner bytes require fresh archives and experiments; dated
model evidence cannot be restated under a new runner identity.

Preparing artifacts does not publish, push, tag or change global installations.
**Needs a person:** a person publishes the release, including creating its tag
and uploading its assets.
