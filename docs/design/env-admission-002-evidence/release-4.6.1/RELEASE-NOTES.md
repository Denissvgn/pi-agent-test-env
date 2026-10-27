# pi-agent-test-env 4.6.1 candidate

This patch adds actionable host-registry diagnostics and explicit inspection and
recovery tools while preserving ownership and cleanup admission checks. It also
protects recovery receipts against path replacement and tampering, retains
interruption outcomes, and fixes stale or misclassified diagnostic context.

The application helper freezes the required diagnostics module. Historical
registry bundle shapes, cleanup receipts and prior blocked results retain their
original identities. The release includes all five supported skill archive
layouts, a source archive and SHA256SUMS.

Qualification remains scoped: the package tests use synthetic Docker/model
boundaries, real temporary filesystem/lease operations and local services. Native
admission/recovery qualification and the experimental application/native-budget
limits remain as documented in QUALIFICATION.md and VALIDATION.md. No live
registry or downstream campaign recovery is part of this candidate.

Release state: candidate for a prerelease, following published v4.6.0. Artifacts
are staged locally. Final review/merge, an immutable release tag and publication
remain subsequent steps; this candidate does not restate earlier native evidence
under the changed runner identity.

## Verification

- All five skill archive layouts passed complete manifest, byte, mode and
  official standards checks.
- The extracted source archive passed **2,687 tests**, with zero skips, in
  **598.691 seconds**, under the explicit **900-second** verification budget.
- Example checks and the extracted package checker passed; source and archive
  inputs stayed unchanged and temporary extractions were removed.
- Internal development plans, retained reports and unrelated untracked work
  are excluded from the source and skill archives.

The first candidate exceeded its 600-second test deadline and is retained as a
failed verification attempt. The rebuilt candidate adds bounded test-budget
selection and partial-output retention for timeouts; tests are never skipped to
obtain a pass.

Verified artifacts are in `dist/pi-agent-test-env-4.6.1-candidate-r2/`.
`SHA256SUMS-r2` and `candidate-verification.json` in this evidence directory retain
checksums and provenance. PR: https://github.com/Denissvgn/pi-agent-test-env/pull/9
(draft; CI skipped at the owner's request). Final review, merge and release
publication remain pending; no tag or published release was created.
