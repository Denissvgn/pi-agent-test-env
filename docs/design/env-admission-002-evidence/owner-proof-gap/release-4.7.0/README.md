# 4.7.0 prerelease preparation evidence

The current candidate is `26d3e4aba43a64ef074ac59a83cff2df4c9a94c8`.
Use `candidate-input-r2.json`, `build-r2.json`, `candidate-verification.json`,
`ci-result.json` and `release-verification.json` for its successful verification.
`RELEASE-NOTES.md` and the separate downstream instructions describe its current
availability and remaining integration/promotion gates.

`candidate-input.json`, `candidate-input-attempt-1.json` and `build.json` describe
the earlier candidate. They are historical evidence, not the passing candidate.
`ci-attempt-1/` and `ci-attempt-2/` retain failed execution receipts;
`ci-attempt-3/` retains the final successful execution receipt. The complete raw
bytes for all three attempts and native/image-build logs are preserved in
`ci-raw-evidence.zip`, with SHA-256 and per-member sizes/hashes in
`ci-raw-evidence-inventory.json`. Raw logs are not normalized to satisfy Git
whitespace checks.

`Dockerfile.ci`, `launch_ci.py` and `run_ci.py` record the actual final procedure.
The explicitly named earlier driver/Dockerfile files preserve failed procedure
variants. `ci-image.json` and `ci-container.json` record inspected native ARM64
image identity, bounded isolation and the actual final mounts. No credential,
live registry, downstream workspace or Docker socket was mounted.

The one Linux-inapplicable filesystem test has a passing macOS ARM64 counterpart
in `native-checks.json`, bound to the raw native log by hash. All unexpected skips
fail the CI driver. The standards/toolchain pins and runtime ownership/budget
limits were not relaxed.

Candidate archives stay outside tracked source in
`dist/pi-agent-test-env-4.7.0-candidate-r2/`. This evidence directory and the task
plan are excluded from published source archives by existing export rules.
Subsequent evidence-only commits must verify that all 398 published-source files
remain identical to the Docker-tested candidate before pushing. No merge, tag,
release publication or downstream activation is performed by this preparation.
