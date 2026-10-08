# Opt-in agent profile schema 1

Profiles configure the child integration under evaluation, separately from the
application case/source/oracle, model endpoint, image/environment and budgets.
Absence of a profile preserves the isolated built-in workflow. The explicit empty
baseline is [builtin.json](../assets/profiles/builtin.json).
`validate-agent-profile --agent-profile FILE` validates offline; optional
`validate-plan --plan FILE --agent-profile FILE` admits only the declared custom
tool. Validation alone does not load a component or establish integration use.

Exact fields: schema 1, document_type `agent_profile`, id, kind, components,
tools, required_tools, assets, service_endpoints. The empty builtin declaration
has id/kind builtin and empty arrays. The only custom kind/id is fixture-lookup,
with one component `{id: fixture-lookup, kind: pi-extension, version: "1",
pi_release: "0.87.1", entrypoint: fixture-lookup.mjs}` and exactly one declared and
required successful tool, fixture_lookup. Service endpoints must be empty: this
profile adds no network service, credentials, setup command or privileges.

Each asset declares relative source, exact target filename and SHA-256. Source
paths stay inside the profile directory; absolute/parent/backslash/NUL paths,
linked/special/multiply-linked files, missing/changed/duplicate assets reject.
The exact four targets are fixture-lookup.mjs, fixtures.json, config.json and
instructions.md. Only the reviewed bundled implementation bytes are supported;
rehashing arbitrary JavaScript does not make it a supported profile.

Config is exactly `{schema: 1, table: "fixtures.json", max_result_bytes: 4096}`.
The fixture table has 1..128 exact slug keys (up to 64 characters), finite JSON
values bounded to 3800 bytes each. Instructions are explicit, nonempty and at most
8 KiB. The tool receives `{key: string}` and returns `{key, found, value}` plus
structured details. It performs no shell, model call, network request or file
write; its fixed table is mounted read-only during loading. Unknown keys return
found=false rather than a fabricated value. Invalid keys/results fail explicitly.

The reviewed Pi [tool example](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/examples/extensions/hello.ts)
uses Type from pi-ai and registerTool with content/details results. Exact release
loading, registration and use require matching runtime evidence. No skills, MCP servers, provider
plugins, arbitrary extensions, nested agents or ambient project/global assets
are supported. Future service declarations would describe permitted use, not
prove Docker egress enforcement. A manifest inventory is not a publisher signature.

## Explicit loading and observed evidence

`run`/`smoke --agent-profile FILE` select the reviewed profile. Default remains
the empty built-in contract. The parent freezes fresh asset copies outside every
writable subject and rechecks them before/after each segment. Custom assets alone
mount read-only at /opt/pi-profile with no writable alias; scorer/setup containers
receive no profile or model key. The mandatory boundary extension and disabled
ambient extensions/skills/context files/templates/themes remain in effect.

The trusted profile monitor reads immutable per-segment context, selects exactly
the declared active tools and emits a pi_lab_profile entry with parent IDs,
profile digest, observed registered/active tools and loaded asset hashes. Custom
fixture code is loaded only by an explicit -e argument on reviewed Pi 0.87.1.
Pi 0.87.1 CLI --tools is a hard allowlist for both built-in and registered custom
tools; it includes the full declared set before the explicit registry selection.
Unknown tool names cannot silently become effective tools.

Parent evidence validates exact receipt identity, active/registered tool set,
asset hashes and successful paired custom-tool declarations/results matching the
frozen table. Loading and use have separate observation states. A receipt alone,
a Bash equivalent or a passing application artifact cannot establish fixture tool
use. Missing/unrelated/duplicate receipts and undeclared tools fail invocation
verification; eligible stopped artifacts may still be scored diagnostically.
These metadata entries never grant control authority or claim network/server
attestation. Node fixtures use an explicitly synthetic SDK; real Pi CLI
registration/use and mount enforcement require runtime observations.

## Experiment variants

Optional variant `agent_profile` selects a profile file explicitly; omission keeps
the empty built-in contract. Preparation freezes each variant's profile assets
with its identity into the immutable inputs/matrix. Profile-defined tools and
required successful tool use are added to agent stage allowlists; case/source/
oracle/budgets are unchanged. Expected plan/configuration hashes include the
profile choice. Explicit-profile comparison eligibility requires matching identity
and observed registration/use; a diagnostic artifact score alone is insufficient.
See [the repeated lookup comparison](../examples/integration-baseline/README.md).

Native observations on 7 October 2026 qualify this exact profile on Pi 0.87.1
with its recorded image/model configuration. They retain actual registered
fixture calls/read-only mounts and original failures; arbitrary configurations
remain unqualified. See VALIDATION.md for evidence scope.
