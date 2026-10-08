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

## Prepare distributables

```bash
python3 tools/build_release.py --output-dir /tmp/pi-agent-release
python3 tools/verify_release.py --archives /tmp/pi-agent-release \
  --report /tmp/pi-agent-release-verification.json
```

Choose a fresh output directory outside the skill, tests and publishing tools. The build emits five skill
layouts, a clean source archive and `SHA256SUMS`. It retains all runtime assets and
excludes plans, backlogs, development reports, stored test output and earlier
distributions. Source archives include the maintainer tests and publishing tools;
skill archives contain only the installable skill.

Verification safely extracts every layout, checks complete manifests, versions,
permissions and resource hashes, runs the pinned official validator on all five
named skill roots, then runs the maintainer suite against extracted package
bytes. It checks the complete extracted inventory before and after execution.
The report is separate from published files and records actual observed results.

`.gitattributes` also excludes retained internal history from `git archive`.
Do not add internal task identifiers or stale implementation status to public
documentation. Explain behavior, configuration, compatibility and observed limits.
Changes to package or runner bytes require fresh archives and experiments; dated
model evidence cannot be restated under a new runner identity.

Preparing artifacts does not publish, push, tag or change global installations.
