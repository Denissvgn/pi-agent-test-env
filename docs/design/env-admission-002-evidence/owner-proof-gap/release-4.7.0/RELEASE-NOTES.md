# 4.7.0 experimental prerelease candidate

This candidate adds separately retained ordinary application-owner cleanup proof,
offline owner inspection and bounded explicit cleanup while preserving original
failed outcomes. It is prepared for review; it has not been merged, tagged or
published.

New helper records use schema 3 with owner cleanup contract 1. Older readers fail
closed. Use one compatible registry-aware cohort; historical schema-1/2 records
remain unchanged. A frozen SDK policy without owner-proof read authority remains
blocked until a new policy scope is reviewed and qualified.

The helper captures actual snapshot, launcher, immutable-container and wait
witnesses. Missing original immutable identity, unknown retained scope, pending
overlapping holders and incomplete proof stay blocked. Selected proof uses bounded
transitive reads, retained privacy, descriptor-bound publication and durable
partial-effect receipts. Generic recovery revalidates accepted owner cleanup
instead of rewriting original failed credential accounting.

Candidate code commit: `26d3e4aba43a64ef074ac59a83cff2df4c9a94c8`.
The complete extracted-source suite ran 2,760 tests in 383.890 seconds on native
Linux ARM64, Python 3.11.2 and Node 24.21.0: 2,759 passed and one filesystem alias
test was inapplicable on Linux. That exact test passed separately on native
macOS ARM64. Package checks, the pinned standards self-test, all five extracted
skill layouts, source/code-origin checks and seven asset checksums passed.
Execution was non-root and offline, limited to two CPUs, 4 GiB and 1,024 processes.
No live registry, Docker socket, downstream workspace or credentials were mounted.

The container run exposed portable-test prerequisites: canonical platform temp
paths, stable serialization of existing AST pins across Python versions and
request-ceiling test isolation from the independent concurrency ceiling. Those
were corrected without changing existing pin values or runtime limits. Earlier
failed attempts remain in the evidence bundle. Native affected tests passed
separately; the earlier 2,757-test native review run remains historical evidence.

Real owner migration, native Docker/browser/inference/application qualification
and extended SDK proof-scope qualification remain unperformed. The old inference
refusal and paused downstream campaign remain separate. This candidate is not
permission to recover live state or resume historical work.

The complete universal/Codex/Claude/Antigravity layouts, clean source archive and
SHA256SUMS are in the candidate directory. The separate downstream handoff is
`../downstream-4.7.0-instructions.md`. Preserve published 4.6.1 assets and tags.

Promotion remains pending: complete review on the final PR head, explicitly
authorize merge/publication, then build and verify final reviewed-tree assets.
The Copilot waiver for 4.6.1 does not apply to this version. Hosted CI is skipped
for this PR at the user's request; no repository workflow was disabled or added.
