# Reviewed Pi 1.2.0 execution contract

Pi 0.87.1 and 1.2.0 have separate exact contracts in
`runtime/release_contracts.py`. The host chooses from the observed image version,
checks it before dispatch, and binds the selected contract to the worker and
every continuation. Unknown, ambiguous and prerelease versions are unsupported.
Builds still require an explicit Pi pin; no latest release or fallback is selected.

## Inspected upstream identity

| Item | Identity |
|---|---|
| Release | [v1.2.0](https://github.com/earendil-works/pi/releases/tag/v1.2.0) |
| Source commit | `06a466935536f8c9bcacb2d5efc0fc021be1bdff` |
| npm package | `@earendil-works/pi-coding-agent@1.2.0` |
| Tarball SHA-256 | `1dfed308f46a69aec06bf9dc20700ddc6fe2370b1898f01334b7898397541e66` |
| Node engine | `>=22.19.0`; the supplied Docker recipe uses Node 24 |

The downloaded artifact matched registry SHA-1/SHA-512 integrity metadata.
Its registry provenance statement identifies the inspected source commit and
the same artifact subject digest. This is statement consistency, not a claim
that the publisher signature or transparency bundle was cryptographically verified.
Unlike the inspected 0.87.1 artifact, this package has no bundled npm shrinkwrap;
pin base/builder inputs and retain actual installed dependency/image identities.

## Runtime behavior

- Keep `--mode json --print`, explicit provider/model/tools/session identity,
  startup offline mode and all existing discovery suppression flags.
- Keep `--no-extensions`; 1.2.0 also receives explicit `--no-mcp`. Plain
  `--tools` alone does not remove MCP tools. Built-in MCP, codemode, tool search,
  virtual models and arbitrary extensions remain outside this runner's contract.
- Keep session schema 3 and exact-session recovery. Cross-release, image or
  contract continuation is rejected. New session files can exist at the first
  user message; the 0.87.1 persistence behavior remains unchanged.
- Require `agent_settled.aborted` to be a boolean on 1.2.0. True, missing or
  malformed values cannot establish clean completion. The 0.87.1 event remains
  fieldless. A Pi abort cannot authorize parent cancellation or continuation.
- Both releases require settlement, valid ordered tool/message evidence,
  exact model/provider, successful final stop text and process completion.
  JSON exit 0 alone is insufficient; the release's truncation exit-code fix is
  specific to text mode. Historical `process-exit` inspection is separately
  explicit and cannot weaken live admission.
- Nested tool calls carrying `parentToolCallId` remain unsupported by this
  direct-tool profile. Profile receipt or tool-policy violations cannot be
  cleared by a clean successor, even after an authorized interrupt.

## Settings and profiles

The generated provider continues to use OpenAI-compatible Chat Completions.
The bounded reasoning levels and sampling allowlist are the same as for 0.87.1;
retries, compaction and cache warming stay disabled. Numeric reasoning budgets
remain explicitly unsupported, despite the newer upstream schema fields.
Requested/ingested settings remain separate from real-server enforcement.

Select `assets/profiles/fixture-lookup/profile.pi-1.2.0.json` explicitly for the
reviewed fixture integration. The existing `profile.json` still targets 0.87.1
with its original bytes and asset hashes. The generator selects the matching
declaration from the observed native image receipt; no release range or automatic
profile substitution is admitted.

Prepare new experiments after runner/image/contract changes. Frozen experiments
retain the reviewed registry identity and bind the observed release before any
trial reservation. Old sealed results/reports stay readable without mutation
or implicit rescoring; absent new metadata means not recorded.

## Qualification scope

Source review and offline fixtures establish adapter behavior only. Real Pi
scripted protocol tests, real local-model acceptance, application credentials,
browser execution and parent discovery are separate observations. Consult
[QUALIFICATION.md](../QUALIFICATION.md) for actual completed evidence and limits.
The maintainer's bounded native collection tool lives in the repository's
`tools/qualification/`, outside the installable skill. Private endpoint, machine,
credential and raw execution data is not shipped with this package.
