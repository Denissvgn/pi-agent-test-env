# Reviewed Pi 1.5.2 execution contract

Pi 0.87.1, 1.2.0 and 1.5.2 have separate exact contracts in
`runtime/release_contracts.py`. The host chooses from the observed image version,
checks it before dispatch, and binds the selected contract to the worker and
every continuation. Unknown, ambiguous and prerelease versions are unsupported.
Builds still require an explicit Pi pin; no latest release or fallback is selected.
This page records what changed for this runner since the reviewed 1.2.0 contract
([PI-1.2.0.md](PI-1.2.0.md)); everything not listed here carries over unchanged.

## Inspected upstream identity

| Item | Identity |
|---|---|
| Release | [v1.5.2](https://github.com/earendil-works/pi/releases/tag/v1.5.2) |
| Source commit | `b4afdddf44e059c67ccf5097e5317d913521b470` |
| npm package | `@earendil-works/pi-coding-agent@1.5.2` |
| Tarball SHA-256 | `691bde186273b457d9d1c41d0fd47b57853b5e85ded1add1a1f6b78e66c261f4` |
| Tool schema builder | `typebox@1.3.27`, unchanged from 1.2.0 |
| Tool-argument validator | `@earendil-works/pi-schema@1.5.2`, replacing TypeBox validation |
| Node engine | `>=22.19.0`; the supplied Docker recipe uses Node 24 |

The downloaded artifact matched the registry integrity metadata, and its
provenance statement names the inspected commit. This is statement consistency,
not a claim that the publisher signature was cryptographically verified. Like
1.2.0, the package has no bundled npm shrinkwrap; pin base and builder inputs and
retain actual installed dependency and image identities.

The review compared all 22 pinned upstream files between the 1.2.0 and 1.5.2
commits (21 changed) and checked a live 1.5.2 process offline: an image built from
the supplied recipe, the runner's exact command line and settings, and a model
endpoint that refuses connections. The same check against the admitted 1.2.0 image
reproduced the frozen 1.2.0 tool declarations exactly.

## Runtime behavior

- Keep `--mode json --print`, explicit provider, model, tools and session
  identity, startup offline mode, all discovery suppression flags and `--no-mcp`.
  The CLI flag set is unchanged from 1.2.0.
- Keep session schema 3 and exact-session recovery. As with 1.2.0, a new session
  file can exist at the first user message. Cross-release, image or contract
  continuation is rejected.
- Require `agent_settled.aborted` to be a boolean, as on 1.2.0. The JSON event
  types and fields the runner reads are unchanged.
- Tool-argument validation moved from TypeBox to pi-schema. Its coercion never
  inserts defaults or removes fields and leaves an already valid value unchanged,
  so the runner's rule that raw arguments reach a tool unchanged still holds. A
  call that only coercion makes valid still stops its stage, as on 1.2.0. pi-schema
  coerces a few cases that 1.2.0 rejected, such as a single value where an array
  is required; such a call now stops the stage instead of returning a validation
  error to the model.
- A tool call whose arguments are malformed JSON now reaches `message_end` with
  empty arguments and an `argumentsError` field. It fails validation without a
  `tool_call` event and returns an error result, instead of running with the
  fields parsed before the error. The runner's evidence checks do not depend on
  the extra field. Arguments containing a `\u` sequence that is not a valid escape
  no longer lose fields.
- On SIGTERM, Pi now aborts the active run and waits for it before exiting.
  Extensions receive the aborted events and the aborted turn is written to the
  session file; stdout still receives none of it. A tool that ignores its abort
  signal delays exit until a second signal. Native cancellation and continuation
  lanes must confirm that cancelled segments still resume as exact sessions.
- Resuming with a thinking level other than the last recorded one writes a
  `thinking_level_change` session entry. The runner resumes with its frozen
  level, so this does not occur in its runs.
- Validation errors shown to the model use pi-schema's wording, for example
  `- path: missing`. Nothing in the runner parses that text.
- The built-in tool declarations are frozen per release. For 1.5.2 only `grep`'s
  `glob` description changed: globs are relative to `path`, and a pattern without
  `/` matches file names at any depth. Every other name, description and parameter
  schema matches 1.2.0. Only `edit` prepares arguments, with a function
  byte-identical to 1.2.0's; `getAllTools()` does not expose it.
- Tool behavior the model sees changed in places. `read` streams text files and
  keeps only the shown lines in memory. `grep` runs ripgrep with `--no-config`,
  takes context lines from ripgrep and no longer reads matched files itself.
  `edit` keeps each untouched line's own line ending. `find` and `ls` treat a
  limit below 1 as 1, and their limit notices, like `grep`'s, now need a further
  result. A `bash` timeout now also reports the shell's exit when a background
  process kept writing. `edit`'s prompt guidelines and Pi's default system prompt
  are reworded; the runner neither freezes nor overrides that prompt.
- Requests send a detailed `User-Agent` such as `pi/1.5.2 (linux; node/v24.x;
  arm64)`. Attribution headers still go only to OpenRouter, NVIDIA NIM and
  OpenCode hosts. The inference gateway sends its own fixed headers upstream.

## Settings and profiles

The generated provider still uses OpenAI-compatible Chat Completions. Reasoning
levels, the sampling allowlist and the settings file are the same as for 1.2.0:
retries, compaction and cache warming stay disabled unless an endpoint opts into
`transient_retries`. Pi 1.5.1 made idle cache warming the default; the runner's
explicit `cacheWarming: "off"` in the agent directory's global settings keeps it
off. The retry settings Pi reads are unchanged. When an endpoint opts in, Pi now
also retries interrupted streams and "service unavailable" errors, and it never
retries context-overflow errors. Numeric reasoning budgets remain explicitly
unsupported.

Select `assets/profiles/fixture-lookup/profile.pi-1.5.2.json` explicitly for the
reviewed fixture integration. It differs from the 1.2.0 declaration only in its
`pi_release`. The generator selects the matching declaration from the observed
native image receipt; no release range or automatic profile substitution is
admitted.

Prepare new experiments after runner, image or contract changes. Experiments
prepared for 1.2.0 cannot continue on 1.5.2.

## Qualification scope

Source review and the offline process check establish adapter behavior only. A
native campaign on exact 1.5.2 images is required before any qualification
claim. Consult [QUALIFICATION.md](../QUALIFICATION.md) for actual completed
evidence and limits.
