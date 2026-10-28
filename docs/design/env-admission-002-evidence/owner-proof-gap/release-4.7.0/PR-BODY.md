Released ordinary application helpers can still block admission after physical
cleanup because their original failed accounting is intentionally retained. This
adds offline owner inspection and explicit, bounded owner cleanup with separate
retained proof, so later recovery can validate supported cleanup without rewriting
the original outcome. Missing original immutable identity, incomplete custody,
unknown scope and pending overlapping holders continue to block.

New helper records use schema 3 / owner contract 1; older readers fail closed and
registry-aware clients need a compatible cohort. The frozen SDK policy still
requires separately reviewed and qualified authority to read owner-proof history.
The branch includes seven local safety-review corrections and their regressions,
plus portable maintainer fixtures and AST serialization preserving existing pins.

**Local verification:** candidate code
`26d3e4aba43a64ef074ac59a83cff2df4c9a94c8`, all 398 published-source files.
Native `linux/arm64` Docker, Python 3.11.2, Node 24.21.0, non-root, offline,
2 CPUs / 4 GiB / 1,024 processes:

- Full extracted-source suite: 2,760 tests ran in 383.890 seconds; 2,759 passed,
  one Linux-inapplicable case-alias test skipped. Its exact counterpart passed on
  native macOS ARM64. Zero unexpected skips.
- Package checks, pinned standards self-test, all five extracted skill layouts,
  clean source archive, code-origin and before/after inventory checks passed.
- Native affected suites: 191 + 313 tests passed, plus four filesystem/serializer
  checks. Earlier failing attempts and corrections remain in the evidence bundle.

Hosted CI is intentionally skipped at the user's request because of Actions
limits. Commit messages and this title contain `[skip ci]`; no workflow or check
policy is disabled. This PR stays draft while final configured review and release
promotion remain pending. The prior 4.6.1 Copilot waiver does not apply here.

The next **4.7.0 experimental prerelease candidate** is prepared and verified
locally with seven assets and separate release notes; it is not tagged or
published. Final publication requires reviewed-tree verification and separate
authorization.

- [Implementation and review plan](docs/design/env-admission-002-fix-plan.md)
- [Exact candidate verification](docs/design/env-admission-002-evidence/owner-proof-gap/release-4.7.0/candidate-verification.json)
- [Release notes](docs/design/env-admission-002-evidence/owner-proof-gap/release-4.7.0/RELEASE-NOTES.md)
- [Separate downstream instructions](docs/design/env-admission-002-evidence/owner-proof-gap/downstream-4.7.0-instructions.md)

The live registry, original six owner histories, downstream installation and
campaign are untouched. Real owner audit/adapters, native browser/inference/
application qualification, the extended SDK read scope and the original API
refusal remain separate integration gates. CI uses synthetic integration
boundaries; it does not qualify or resume the downstream campaign.
