# Opt-in agent profile schema 1

Profiles configure the child integration under evaluation, separately from the
application case/source/oracle, model endpoint, image/environment and budgets.
Absence of a profile preserves the isolated built-in workflow. The explicit empty
baseline is [builtin.json](../assets/profiles/builtin.json).
`validate-agent-profile --agent-profile FILE` validates offline; optional
`validate-plan --plan FILE --agent-profile FILE` admits the reviewed legacy
fixture tool. Validation alone does not load a component or establish integration
use. The separate compiled application route is described below.

The closed catalog contains the empty built-in profile, `fixture-lookup`, and
`application-client`. The application compiler selects exact release-bound
bundled assets; legacy plans cannot select it through blanket `--agent-profile`
application. There is no ambient profile/plugin discovery.

## Fixture lookup contract

Exact fields: schema 1, document_type `agent_profile`, id, kind, components,
tools, required_tools, assets, service_endpoints. The empty builtin declaration
has id/kind builtin and empty arrays. The fixture kind/id is fixture-lookup,
with one component `{id: fixture-lookup, kind: pi-extension, version: "1",
pi_release: "0.87.1", entrypoint: fixture-lookup.mjs}` (or the separately reviewed
exact `1.2.0` declaration) and exactly one declared and
required successful tool, fixture_lookup. Service endpoints must be empty: this
profile adds no network service, credentials, setup command or privileges.

Legacy application credentials use the runner's separate per-stage
[application_secrets contract](APPLICATION-CREDENTIALS.md), not profile assets or
service declarations. That channel adds no profile, tool or child extension.

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
fixture code is loaded only by an explicit -e argument on reviewed Pi 0.87.1 or 1.2.0.
The direct-tool selection is retained on both reviewed releases. Pi 1.2.0 keeps
MCP tools unless separately excluded, so `--no-extensions` and its `--no-mcp`
flag are mandatory in the newer contract. The CLI selection constrains built-in and registered custom
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

For Pi 1.2.0 select `assets/profiles/fixture-lookup/profile.pi-1.2.0.json` explicitly.
The original `profile.json` remains release-bound to 0.87.1 with unchanged bytes.
See [PI-1.2.0.md](PI-1.2.0.md) for the exact newer contract.

## Compiled application profile

The [application client](APPLICATION-CLIENT.md) uses exactly the bundled
`application-client.mjs` and `instructions.md` bytes, a release-bound component
for Pi 0.87.1 or 1.2.0, and the fixed private helper endpoint
`http://pi-application:8081/tool`. Rehashing arbitrary JavaScript is unsupported.
The source stage explicitly names `profile: "application-client"`; compilation
freezes its identity and selects the stage's exact native tool schemas.

The catalog is `app_api`, optional `app_browser`, `artifact_read`,
`artifact_write`, `report_write`, and `budget_status`. Actual stages expose only
their compiled subset and declared grants. There is no Bash, arbitrary read,
arbitrary URL or nested workflow tool. The stage receives scoped capabilities;
original application credentials, helper control authority and store paths stay
in the owning parent/helper. Service metadata describes a fixed reviewed bridge,
not a general network permission or firewall claim.

Boundary, profile monitor, application adapter and native budget guard load in
the frozen reviewed order. The guard verifies registered names and full schemas
before inference, then reserves native batches before tool effects. No ambient
extensions, skills, MCP, providers or effectful argument preparation are admitted.
Profile loading/tool receipts, independent completion and independent task scoring
remain distinct gates. A normally settled model with a missing report fails
completion without an automatic continuation or repair.

Legacy built-in/fixture stages can opt into native call budgets by declaring the
whole `max_tool_calls`, `reporting_reserve_calls`, `reporting_reserve_seconds`
tuple alongside their existing limits. Omission adds no native defaults. Their
reporting phase allows only `budget_status`; the application profile also allows
its exact declared output/report operations. See the
[budget contract](APPLICATION-CLIENT.md#native-calls-and-reporting-reserves).

Controlled SDK and local-service tests establish bounded source/protocol
behavior. Exact Pi registration, launch mounts, browser capture and real-model
quality require separate runtime evidence; a profile declaration does not upgrade
historical built-in or fixture qualification.
