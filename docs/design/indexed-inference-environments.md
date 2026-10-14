# Indexed inference environments and native skill integration

Status: design proposal for future implementation, not a supported 4.4.0 option.
Assessment date: 14 October 2026. Repository baseline: released 4.4.0,
commit `3664d60370ef48a3b2a696f66c3200618f081487`.

The [fixed implementation and qualification plan](indexed-inference-environments-implementation-plan.md)
now turns this assessment into phase gates and resolves initial-delivery decisions.

## Recommendation

Add a private catalog of **named inference environments**, integrated into the
existing `pi-agent-test-env` skill and `pi_lab.py env` commands. A root agent should
discover, inspect, select, confirm and freeze these environments through the skill.
The child Pi agent must receive only its assigned configuration and credential
authority, never the catalog or a choice of other environments.

Deliver catalog selection and serial comparisons first using the existing
OpenAI-compatible Chat Completions adapter. Heterogeneous parallel trials,
different models for implementer/reviewer stages, additional API protocols and
additional inference slots are separate increases in scope. They require their
own strict contracts, tests and qualification. Removing the current parallel
endpoint-equality check would be incorrect: the runtime still uses the first
trial's endpoint and key for every trial.

Interpret “environment indexing” as stable IDs such as `builder-local` and
`reviewer-service`. Numeric menu indexes can be conveniences, but must resolve
against a captured catalog revision into an ID and configuration fingerprint.
Neither list order nor a mutable default may become an execution identity.

## What the released project actually supports

These findings come from the repository baseline, not live endpoint discovery.
No private endpoint/key files or deployment configuration were inspected for this
assessment, and no model or Docker invocation was performed.

| Area | 4.4.0 behavior | Consequence |
|---|---|---|
| Saved inference environment | `scripts/lab_env.py:66,124` stores one endpoint and metadata pair. `env save --name` names that pair; it does not create independent catalog entries. | Multiple remembered environments need a storage and selection contract. |
| Session admission | `lab_env.py:162,329` confirms one saved configuration fingerprint per session. | A session needs approvals for each exact selected profile, with independent invalidation. |
| Endpoint configuration | `pi_lab.py:546` already supports child/host base URLs, exact model, key-variable reference, context/reply limits, input, compatibility flags, reasoning, sampling and declared server provenance. | Most useful settings already exist; avoid inventing a second incompatible endpoint vocabulary. |
| Serial comparisons | `experiments.py:125-135` accepts and freezes a different endpoint file per variant. | Different compatible services/models can already be compared sequentially. Indexing primarily improves selection and reuse here. |
| Parallel comparisons | `experiments.py:142-143` requires identical normalized endpoints; `tests/test_parallel_contract.py:94` protects this restriction. | This is an intentional qualification boundary. |
| Parallel gateway | `parallel_execution.py:61-63,181-182` resolves one endpoint/key from `work[0]`; `runtime/inference_gateway.py` validates one selected model. | Multiple parallel environments need trusted route bindings and all-key admission. |
| Stage selection | `pi_lab.py:699-701` accepts no inference selector on an agent stage; `_execute_suite` loads one endpoint for the run. | A different implementer/reviewer environment requires a versioned plan change. |
| Wire API | `runtime/pi_contract.py:55` generates `local-lab` with `api: openai-completions`; endpoint admission requires a `/v1` route. | Another API protocol is not enabled by supplying another base URL. |
| Continuation | `scripts/segments.py:59-62` rejects provider/model switches in a continued session. | Environment identity must remain fixed for every segment of a stage. |
| Evidence/reporting | `provenance.py` and `comparisons.py` bind configuration, plan, runner, oracle and resource identities. | A role-to-environment map must enter identity and reporting, not merely CLI arguments. |

Paths in this table are relative to `skill/`, except the maintainer test path.

Do not conflate these existing concepts:

- **Inference environment:** API contract, endpoint, exact model, settings and
  inference credential reference.
- **`execution.environment` / `--environment FILE`:** offline container command
  and capability probes, not model selection (`pi_lab.py:604-642`).
- **Agent profile:** the declared child tools/integration, not a provider catalog.
- **`application_secrets`:** stage-specific application/persona credentials,
  separate from model authentication.
- **Capacity group:** the shared inference deployment, separate from environment
  identity and Docker worker limits.
- **Account/rate-limit groups:** optional overlapping quota constraints. These
  memberships are separate from deployment capacity and can span several servers.

## Useful cases and scope

1. Reuse several approved compatible services without overwriting the current
   saved default each time. Each can have its own routes, model and key reference.
2. Compare model/service A with B over identical application cases and scorers.
   Serial variants already provide the execution basis for this first milestone.
3. Run two independent trials with different models through one globally bounded
   gateway. Container overlap does not require simultaneous model requests.
4. Assign an implementation stage and a read-only review stage different models.
   Their source-sharing and outbound-data permissions must be deliberate; fresh
   stage sessions remain distinct from exact-session continuation.
5. Later add one reviewed alternative wire API at a time. Choosing a provider
   brand, API key or familiar model name does not establish protocol support.

Changing to a remote service also changes where prompts, source and tool results
are sent. Root must make that destination choice concrete when obtaining the
selection authorization. Application credentials retain their existing scoped
delivery, scanning and contamination-stop rules.

## Catalog and immutable binding proposal

Use an owner-only catalog outside projects and build contexts. Reuse the endpoint
normalizer for the first adapter. Catalog entries contain references to credentials,
not values, commands, OAuth files or arbitrary provider configuration.

Illustrative future shape; this is not accepted by the current CLI:

```json
{
  "schema": 1,
  "catalog_revision": 7,
  "default_id": "builder-local",
  "entries": [
    {
      "id": "builder-local",
      "revision": 2,
      "api": "openai-completions",
      "adapter_contract": "chat-completions-v1",
      "endpoint": {
        "base_url": "http://inference-a.invalid/v1",
        "host_base_url": "http://inference-a.invalid/v1",
        "model": "fixture-coder",
        "api_key_env": "PI_MODEL_BUILDER_KEY",
        "context_window": 32768,
        "max_tokens": 4096,
        "input": ["text"]
      },
      "capacity_group": "shared-inference"
    },
    {
      "id": "reviewer-service",
      "revision": 1,
      "api": "openai-completions",
      "adapter_contract": "chat-completions-v1",
      "endpoint": {
        "base_url": "https://inference-b.invalid/v1",
        "host_base_url": "https://inference-b.invalid/v1",
        "model": "fixture-reviewer",
        "api_key_env": "PI_MODEL_REVIEWER_KEY",
        "context_window": 32768,
        "max_tokens": 4096,
        "input": ["text"]
      },
      "capacity_group": "shared-inference"
    }
  ]
}
```

The addresses, models and key-reference names above are synthetic. Sharing the
group illustrates conservative admission, not an assertion about a deployment.
Finalize field names and schemas before implementation.

Recommended rules:

- Stable, bounded IDs are authoritative. Reject duplicates, unknown fields,
  escaping paths, unsupported adapters and conflicting selectors. Put finite
  limits on catalog size and profiles used in one collection; do not load an
  unbounded catalog into workers or a gateway.
- A semantic fingerprint includes normalized routes/model/settings, adapter
  contract, capability declarations, credential **reference** and relevant
  capacity policy. Secret values never enter frozen JSON or public identities.
- Distinguish configuration revision, authorization, health and qualification.
  A listed model or passing health request does not qualify tool use or capacity.
- Resolve numeric selections against the exact displayed revision. Stale indexes
  fail with a safe reason rather than selecting a different entry.
- Freeze the complete resolved configuration and assignment map before dispatch.
  Do not reread a mutable default/catalog to choose a model during execution.
- Editing an unrelated entry does not revoke an unchanged selected profile's
  confirmation. Editing selected content requires confirmation of the new identity
  and a fresh experiment. Renaming a label cannot silently rebind an ID.
- Deletion/revocation must have explicit semantics: block future dispatch for a
  revoked binding, retain sealed history, and use existing cancel/cleanup controls
  for active work. Never replace a removed profile with the default.
- Credential rotation is separate from nonsecret execution identity. Define a
  private binding/authorization receipt for the selected credential source; do
  not silently change authority during a started stage. Rotation/resume behavior
  needs a deliberate contract and tests, not key bytes in experiment files.

## Native integration into the existing skill

This is a required implementation deliverable, not an optional separate skill,
root prompt hack or standalone launcher. Repository design documentation alone
does not reach an installed root agent.

Ship the user-facing contract through:

| Installed component | Required change |
|---|---|
| `SKILL.md` environment gate | Teach root to discover IDs, inspect private details when needed, select exact bindings, reuse unchanged approvals, qualify and freeze before dispatch. Explain legacy and multi-environment paths. |
| `scripts/pi_lab.py` and `scripts/lab_env.py` | Add catalog operations and one common selection resolver used by run, smoke, preflight, doctor and experiment commands. Preserve command-specific execution/admission boundaries. |
| `references/INFERENCE-ENVIRONMENTS.md` | Define selectors, capability states, confirmation, credential precedence, frozen bindings, egress, recovery, error remedies and examples; link it from the entry. |
| `references/EXPERIMENTS.md`, `PARALLEL-AGENTS.md`, `PI-COMPATIBILITY.md`, `PROJECTS.md`, `RESOURCES.md` | Document each supported stage of rollout and its evidence limits. |
| `assets/` and `examples/` | Provide synthetic catalog/assignment examples; expose heterogeneous parallel and per-stage examples only when implemented and qualified. |
| Manifest/export/verification | Include new installed files in all five layouts, test root entry-to-reference links, and verify source archive inclusion deliberately. |

Root's workflow must be explicit and machine-readable:

1. Reuse this conversation's session. List catalog entries **offline**, without
   credential resolution, network discovery, login or model calls.
2. Inspect intended entries. Default output gives bounded IDs, adapter status,
   declared/observed/unknown capabilities, credential-availability state and
   known/unknown capacity. Detailed routes/model identifiers are private data;
   an explicit local detailed view can show them when needed for the decision.
3. Resolve the user's selection to exact trial/role bindings. If several entries
   are plausible and no explicit default is selected, ask which to use.
4. Obtain authorization for newly selected exact fingerprints, destinations and
   budgets. Reuse unchanged confirmed profiles without asking repeatedly. A
   conversation approved for A is not automatically approved for B.
5. Perform adapter-specific health and the existing image/model/tool/browser
   gates for every selected scope. Admission may reject settings; it must not
   invent replacement models, reasoning modes, context or larger budgets.
6. Validate offline and freeze endpoint snapshots, binding maps, resource groups,
   helper reservations, deadlines and provenance. Inspect the concrete admission
   intent before any newly required bounded native qualification.
7. Dispatch using frozen bindings. Child agents neither enumerate nor modify
   the catalog and cannot choose a different route from their request payload.
8. On failure, inspect safe reason codes and retain sealed results. Resume uses
   frozen identities and reconciled ownership; fallback, automatic retry or model
   switching is not implied by having several entries available.

Proposed CLI sketch, **not current commands**:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" env list --json
python3 "$SKILL_DIR/scripts/pi_lab.py" env inspect --id builder-local --json
python3 "$SKILL_DIR/scripts/pi_lab.py" env confirm --id builder-local --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" env check --id builder-local --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" run --inference-env builder-local ...
```

Keep `--inference-env` distinct from existing `--environment FILE`. Registration,
inspection and confirmation should be separate operations. Existing
`--endpoint FILE` callers retain their explicit selection semantics; catalog
selection must not accidentally inherit an approval bypass by being translated
into an endpoint-file argument. Reject multiple selection sources rather than
inventing a precedence that hides a mistaken override.

New strict schemas are needed for catalog references in experiments and per-stage
selection in plans. Proposed direction: preserve plan schema 1 and experiment
schemas 1/2; introduce a new plan version for role bindings and a new experiment
version for resolved multi-environment metadata. Keep `parallel-trials-v1` intact;
heterogeneous execution gets an explicit reviewed successor. Never rewrite old
frozen matrices, identities, receipts or defaults during catalog migration.

## Gateway, capacity and isolation impact

For the initial heterogeneous mode, prefer one bounded routing gateway with
exactly two existing worker slots and **one global inference slot**. This avoids
automatically increasing helper containers or asserting independent server
capacity. It increases the gateway's credential and routing responsibility and
therefore needs independent forward tests before native execution.

Root must issue an opaque capability bound to the frozen environment, trial,
attempt and, when stage selection is added, stage/segment. The gateway obtains
the upstream route, exact model, settings and key from that trusted binding. No
body field, header, URL parameter or model alias may choose another environment.
`/models` must expose only the model allowed for that capability. Keep original
inference keys outside Pi; do not forward a complete catalog to its home/state.

Capacity is not equivalent to URL, model, API key or environment ID. Two aliases,
reverse proxies or model IDs can share one GPU deployment; different keys may
share account quotas. Unknown grouping stays behind the global single slot.
Later independently qualified capacity groups may each have gates, subject to a
separate global request/thread/connection ceiling. Account rate limits, token
limits and optional cost policy are additional constraints, not CPU/GPU evidence.
Represent them as separate, potentially overlapping memberships: an environment
can share a GPU with one peer and an account quota with a different peer. Future
admission must satisfy its deployment gate, every applicable account constraint
and the global ceiling without partial reservations or inconsistent lock ordering.
Do not infer independent accounts from different key references.

Every helper counts in aggregate Docker CPU/RAM/PID reservations. For example,
the 4.4.0 qualification footprint with two workers, one gateway and one disposable
authority was 2.5 CPUs/3328 MiB/1152 PIDs. Adding a second helper at the same
0.25 CPU/128 MiB/64 PID budget would require 2.75 CPUs/3456 MiB/1216 PIDs.
These are arithmetic examples, not authorization to raise a frozen limit or
reduce worker memory. Separate gateways give stronger key compartmentalization
but still need shared admission for aliases using the same capacity group.

Freeze queue/upstream deadlines per environment/group and make their sum fit
every assigned stage. Preserve cumulative DNS, address, TLS, header, body and
stream-metadata deadlines. Model-list preflight must cover its applicable queue
plus request budget, with finite container headroom and collection accounting.
Do not silently copy inappropriate defaults between fast and slow services.

Start with global fail-closed quarantine: unknown upstream completion blocks
further inference admission even if its container is removed. Later group-scoped
quarantine must cover all aliases in that group, survive owner loss in the secure
registry and respect the frozen stop policy. Local EOF/cancellation or a cleanup
deadline is not evidence that a remote model stopped.

## Credential and privacy changes that cannot be skipped

- Resolve all **selected** inference references in the trusted parent before
  probes/setup/dispatch. Current `app_admission` checks against only one key;
  compare every application reference/value against the entire selected inference
  set. Keep alias/key equivalence checks and shared-actor serialization.
- Explicitly strip every selected key-variable name from host trial controllers,
  including names that do not match heuristic secret suffixes. Deliver only the
  assigned opaque inference authority; checks/scorers stay key-free.
- Decide credential source semantics explicitly. Legacy resolution prefers
  exported variables over the secure store. New profiles must declare the binding
  source or deliberately retain and expose that precedence; no ambient provider
  credential lookup or credential-command execution is introduced.
- Apply all-held-key and surrogate-token redaction to shared gateway captures,
  denial paths and escaped/split response streams. Preserve stage purge, full
  snapshot contamination scans, writer-absence checks and private-store cleanup.
  The existing guarantee remains exact-value/JSON-escape redaction, not arbitrary
  transformed-secret detection.
- Catalog CRUD must use owner checks, secure directories, no-follow/hardlink
  rejection and bounded atomic replacement. Do not simply multiply the current
  saved-environment writer into a new sensitive shared registry.
- A credential-free catalog is still private: routes, model IDs, key-reference
  names, account metadata and configuration fingerprints can reveal deployments.
  Freeze only selected entries; exports must not enumerate the entire catalog.
  Public outputs need explicit allowlists and safe labels/opaque identities, not
  raw private fields or key-derived hashes, lengths or suffixes.

Per-stage model selection also changes which service sees the shared trial source
and preceding artifacts. Admit every stage's destination up front; retain a fresh
session per stage and prevent a continued session from changing environment,
protocol, release/image or authority. Independent scorers remain unchanged and
reviewer-model prose is still not mechanical approval.

## Additional APIs are separate adapters

Pinned upstream Pi documentation permits custom providers and several API
implementations; that is broader than this package's reviewed wrapper. The
1.2.0 API types include `openai-responses` and `anthropic-messages`, among others.
The 0.87.1 and 1.2.0 model-configuration documents are separate sources, so a
shared field name is not evidence of equivalent behavior. See the pinned sources
below. No additional protocol is qualified by this proposal.

Each new adapter needs reviewed, release-specific provider generation, permitted
routes and authentication, discovery/preflight semantics, request allowlists,
tool-result encoding, streaming/completion proof, usage/error parsing, storage
policy, redaction and cancellation/deadline behavior. Do not assume `/models`,
`/v1`, Bearer authentication, token-field names or streaming events are universal.
Do not silently translate a protocol to Chat Completions or delegate unrestricted
`models.json`, headers, extensions, credential commands or OAuth/ambient cloud
chains into a worker. Keep retries, compaction and cache warming explicitly off.

Support must be stated per **adapter contract × exact Pi release × tested scope**.
Unsupported combinations fail admission. Do not upgrade Pi, change images,
enable new integrations or relax the browser sandbox as part of indexing.

## System impact and implementation order

| Work package | Relative impact | Main affected code |
|---|---|---|
| Catalog, resolver and per-profile approvals | Moderate; mostly parent state/UX, but sensitive identity/storage rules | `lab_env.py`, `pi_lab.py`, `secret_store.py`, new catalog module, installed skill guidance |
| Catalog-selected single runs/serial variants | Moderate; reuse existing transport and frozen endpoints | `experiments.py`, provenance, controls, examples and comparison identities |
| Multi-route one-slot gateway | High; authority routing, all-key handling and failure boundary | `parallel_execution.py`, `parallel_dispatch.py`, `inference_gateway.py`, `application_credentials.py`, registry |
| Heterogeneous parallel contract | High; schema, reservations, group accounting and recovery | `parallel_contract.py`, `parallel_engine.py`, allocator, ledger/comparisons |
| Per-stage environments | High; run lifecycle, source egress, sessions and budget/provenance maps | plan validation, `_execute_suite`, `segments.py`, worker model generation, evidence/reports |
| Another wire API or more inference slots | Very high; a separate protocol/capacity qualification | adapter registry, SDK mapping, preflight, gateway/parser, qualification harness |

Recommended fixed order for subsequent implementation planning:

1. Finalize strict catalog/selection/approval/binding schemas and native skill
   workflow. Define bounded sizes, private/public views and deletion/rotation rules.
2. Implement secure catalog plus one common resolver; preserve legacy saved
   environment, explicit endpoint files and all old frozen-result reading.
3. Add catalog-selected single runs and serial variants. Ship truthful root
   instructions and installable examples with these supported commands.
4. Implement offline token-bound multi-route Chat Completions gateway and all-key
   credential/privacy admission, initially retaining global one-slot quarantine.
5. Introduce the opt-in heterogeneous parallel scheduler/experiment contract,
   keeping worker/aggregate limits fixed and existing schema 2 behavior intact.
6. Add versioned per-stage assignments and immutable continued-session identity.
7. Complete offline/package/independent forward tests; freeze and approve bounded
   native ARM64 qualification for both exact Pi releases before promotion.
8. Extend installed guidance/examples to the newly qualified scope, complete
   publication privacy and actual exact-head review, then release normally.

Additional API adapters, independent capacity-group concurrency, mixed Pi
images/releases and automatic selection/fallback are later projects, each with
a new explicit plan. No estimate of model speed, cost, deployment capacity or
engineering duration is inferred from this source inspection.

## Required verification

| Layer | Observable acceptance |
|---|---|
| Catalog/selection | Reorder/delete/stale numeric index, duplicates, corrupt/insecure/symlink/hardlink entries, ambiguous selectors and bounded sizes reject safely; unrelated edits preserve selected approvals. |
| Legacy compatibility | Current single saved environment, `--endpoint`, schema-1 serial and homogeneous schema-2 definitions/results retain their meanings; unknown new fields cannot silently opt in. |
| Frozen bindings | Catalog mutation cannot reroute prepared work; tampered bindings/groups/settings reject; revoked authorization and key rotation follow declared rules; sealed originals stay unchanged. |
| Gateway authority | Two synthetic upstreams with distinct keys and also identical model names; wrong token/model/API/route/body/header cannot cross bindings; `/models` remains token-scoped. |
| Credentials/privacy | All inference keys excluded from application refs/values; arbitrary selected variable names stripped; every held key and token redacted over byte splits/JSON escapes; observers/scorers have no key; no catalog/private data in public exports. |
| Resource/failure behavior | Shared aliases serialize, pending fairness/deadlines remain bounded, helpers fit CPU/RAM/PIDs, queued cancellation/forwarded disconnect/slow DNS-TLS-chunked replies/401-429/owner loss preserve quarantine, cleanup and accounting; no automatic retry/fallback. |
| Stage/session/evidence | Fresh role-specific sessions use their binding; continuation switches reject; per-stage identity/usage/budgets are recorded; reviewer prose remains advisory. |
| Installed root workflow | All five layouts contain the entry/reference/assets; a fresh root can follow catalog inspection → selection → confirmation → qualification → frozen execution and safe failure handling without hidden external instructions. |
| Native ARM64 | Genuine overlapping workers against two explicitly selected environments on both Pi releases; independent actor effects, sandboxed local browser paths and adapted fault/cleanup oracles; declared totals/ceilings and no emulation. |

Use at least three fresh repetitions per positive lane and predeclared fault
oracles in a finite approved native matrix. Resolve capacity/groups, image/model
selection, egress, helper budgets, Pi segment and cleanup ceilings before launch.
Stop on qualification failure, retain failed/unrun observations and require the
existing explicit decision before any changed/repeated collection.

Keep artifact correctness comparisons on shared cases, protected source, scorers,
tools and declared budgets. Model/protocol/settings differences are treatment
factors. Per-role pipelines are different treatments from one-model trials.
Tokenizers, cache accounting, API usage categories and queue contention differ:
missing usage stays unknown; agent end-to-end time is not inference time; no
throughput, cost or improvement claim follows automatically from mixed profiles.
Update `comparisons.py` to verify a stage-binding map and capacity contract, while
preserving old reports without retroactive reclassification.

The 4.4.0 homogeneous single-upstream qualification cannot be relabelled as
multi-environment, alternative-API or higher-capacity evidence. This note changes
no supported capability or released qualification claim.

## Open decisions before coding

- Exact catalog bounds, schema/CLI names and whether explicit credential-source
  binding is required for all new entries or retained as a reviewed legacy mode.
- Whether catalog deletion implies revocation for already prepared pending work,
  and the explicit key-rotation authorization/recovery procedure.
- One routing helper versus separate key compartments, with corresponding helper
  reservations and durable group quarantine.
- The first additional protocol, if any, selected by an actual use case rather
  than enabling the full upstream provider catalog.
- Which root-facing details are private-only and which identities can be safely
  exported for reproducibility without revealing deployment inventory.

## Sources

- Repository modules and regression anchors in the current-behavior table;
  [parallel design](parallel-agents.md),
  [installed parallel contract](../../skill/references/PARALLEL-AGENTS.md),
  [Pi compatibility](../../skill/references/PI-COMPATIBILITY.md),
  [qualification scope](../../skill/QUALIFICATION.md) and
  [native skill entry](../../skill/SKILL.md).
- [Pi 0.87.1 model configuration](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/docs/models.md).
- [Pi 1.2.0 model configuration](https://github.com/earendil-works/pi/blob/06a466935536f8c9bcacb2d5efc0fc021be1bdff/packages/coding-agent/docs/models.md)
  and [API type registry](https://github.com/earendil-works/pi/blob/06a466935536f8c9bcacb2d5efc0fc021be1bdff/packages/ai/src/types.ts).

Pinned upstream sources establish available upstream interfaces, not this
package's admission, isolation or live qualification for those interfaces.
