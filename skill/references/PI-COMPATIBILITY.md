# Pi 0.87.1 release contract

This preserved contract is supported alongside the separately reviewed
[Pi 1.2.0 contract](PI-1.2.0.md). Historical observations retain their original
identities; the newer adapter does not requalify older receipts.

Source inspected on 7 October 2026. Native ARM64 executor observations used
Pi 0.87.1 with an exact recorded model/image configuration. Low/off reasoning and
sampling request ingestion were observed; server enforcement remains unverified.
See [VALIDATION.md](../VALIDATION.md) for scope. This reference alone does not
qualify another image/server, install Pi, change a selected release/model or enable
an integration. Different releases need their own inspection and live traces.

## Release identity

| Item | Inspected identity |
|---|---|
| Package | `@earendil-works/pi-coding-agent@0.87.1` |
| Release | [v0.87.1](https://github.com/earendil-works/pi/releases/tag/v0.87.1), published 22 September 2026 at 19:43:43 UTC |
| Tag commit / npm `gitHead` | `f07218c4d4bbc12bef056a7058c3dd49dfe41abe` (both matched) |
| Node engine | `>=22.19.0`; stock recipe uses Node 24, still requiring an installed-version probe |
| npm artifact | [pi-coding-agent-0.87.1.tgz](https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-0.87.1.tgz) |
| SHA-512 SRI | `sha512-m8ArJUtVcQMSe1lLE/Ei7vX/JV7O39sWmWBsXV2NOU70F0qCp8GubA24pT3LnwTmM6LL2xV80/h6sQg85n69ew==` |
| SHA-256 | `1423ee3c61e7c96464e1cbf3c8dc24d3056cb3410995c3671a98c3ecc527540f` |

The npm artifact was downloaded and its SHA-512/SHA-1 checked against registry
metadata; package metadata/JSON docs matched immutable source. The inspection
retains immutable source blob identities and reproduction information.
These hashes do not verify a publisher signature. The tarball contains
`npm-shrinkwrap.json`; qualification must still record installed dependencies,
Node and immutable image ID.

## Mandatory isolated CLI profile

The pinned [argument parser](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/src/cli/args.ts)
and [CLI reference](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/docs/cli.md)
declare these interfaces. The runner must verify all of them, not just version:

| Capability | Required route |
|---|---|
| One-shot JSON | `--mode json --print`; stdin supplies the initial prompt and is closed; stdout continuously drained as LF JSONL, diagnostics on stderr |
| Exact provider/model | `--provider local-lab --model <exact-id>`; generated provider contains only the selected local model, with `api: openai-completions` |
| Explicit tools | `--tools read,bash,edit,write` or the reviewed subset, required successful pairs declared by the task |
| Isolated configuration | `PI_CODING_AGENT_DIR` points to a fresh stage-owned directory; host home/settings/auth are never mounted |
| Disable discovery | `--no-extensions --no-skills --no-prompt-templates --no-context-files --no-themes --no-approve` |
| Boundary extension | `-e /opt/pi-lab/workspace-boundary.mjs` explicitly loads the reviewed asset even with extension discovery disabled; OS mounts/isolation are separate gates |
| Startup offline mode | `--offline` / `PI_OFFLINE=1` disables startup network work; it does not prevent model requests or replace Docker network controls |
| Thinking/persistence | `--thinking off` (or the selected supported level), `--session-dir <stage-dir>`; retain actual header/session file identity |
| Targeted recovery | `--session <exact-session-file>` under parent-controlled metadata; do not guess the most recent session |

Pi can fuzzy-match model names, parse provider/thinking suffixes and restore a
session with fallback in its model resolver (immutable source URL in the receipt).
Prevent/identify substitution: exact generated ID, explicit provider on every
segment, session metadata validation and assistant identity checking. Slash/colon
or unusual IDs need matching live traces. Retain full model IDs unchanged. Never shorten or alias them.

[pi-0.87.1.examples.json](pi-0.87.1.examples.json) contains synthetic configuration
and events. Its baseline settings disable agent/provider retries, automatic
compaction and cache warming. This is the runner’s evaluation policy, not Pi's
default: Pi enables agent retry and compaction by default. Record
effective settings and fail unexpected retry/recovery policy rather than calling
it autonomous success.

## Optional reasoning and sampling

| Request | Release interface and admission rule |
|---|---|
| Thinking off/on/level | Model `reasoning` is boolean capability, separate from execution level. `--thinking` and `settings.defaultThinkingLevel` accept off/minimal/low/medium/high/xhigh/max; this runner currently exposes only off through high. Validate selected model support and observable effective level; never silently clamp a request |
| Reasoning budget | `settings.thinkingBudgets` maps minimal/low/medium/high to tokens; SDK assembly forwards it to the agent. No built-in `--thinking-budget` or singular `settings.thinkingBudget` |
| Budget delivery for Chat Completions | AI adapter uses explicit `compat.thinkingTokenBudgetField` or alias `supportsThinkingTokenBudget` to emit the server field. Its shared ceiling reserves 1024 answer tokens and may lower the budget. These compat fields are **not declared** in this release's coding-agent `models.json` schema; source AI support does not prove CLI ingestion. Treat numeric budgets as unsupported for this profile until a reviewed route passes ingestion and request observation; a settings map alone is insufficient |
| Sampling/seed | `models.json` model `samplingParams` is a source-supported Chat Completions route, e.g. `temperature`, `top_p`, `top_k`, `seed`. No corresponding built-in CLI sampling flags. The runner validates a finite bounded allowlist and retains requested/effective/unverified values; server enforcement is separate |
| Reply cap | Model `maxTokens`, adapter `compat.maxTokensField` (`max_tokens` or `max_completion_tokens`); the effective cap may be lowered to estimated available context. Separate from total-run token limits |

These distinctions come from pinned
[settings](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/src/core/settings-manager.ts),
[SDK assembly](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/src/core/sdk.ts),
[model schema](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/src/core/model-config.ts),
[base options](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/ai/src/api/simple-options.ts)
and [Chat Completions adapter](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/ai/src/api/openai-completions.ts).
`samplingParams` merges last and can override request fields: the runner rejects
keys that change model/messages/tools/auth/stream or evade token budgets. A seed
records a request, not deterministic replay. Missing/all-zero usage is unknown;
do not double-count reasoning already included in output. Configured zero model
costs are not observed billing. Effective caps/settings need evidence.

Setting `thinkingBudgets.medium = 2048` plus `--thinking medium` requests that
level's budget inside Pi; it does not prove an arbitrary server receives/enforces
2048. Unknown long flags are collected as potential extension flags by the parser;
absence of a CLI error is not evidence an option was honored.

## JSON lifecycle

The pinned [JSON specification](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/docs/json.md),
[message types](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/ai/src/types.ts),
[low-level loop](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/agent/src/agent-loop.ts)
and [session layer](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/src/core/agent-session.ts)
establish this input contract. Ordered analysis and matching runtime traces
provide separate implementation and execution evidence:

1. One-shot JSON starts with one `session` header (version 3, ID, timestamp, cwd).
   RPC omits it. Split only LF, with optional preceding CR; JSON strings can
   contain Unicode separators. Malformed records fail.
2. `agent_start` opens a low-level run, `turn_start` a turn. Message starts/ends
   pair inside the run, including user/system/tool-result messages. Updates
   belong to an active assistant. Reject unmatched/overlapping/out-of-order
   transitions. A streaming `pending` start is normal, not completed success.
3. Assistant `message_end.message` is authoritative: role/api/provider/model,
   content/usage/stopReason/timestamp, optional response/provider metadata.
   Require local-lab and the exact selected ID on every completed assistant.
   `message_update` has cumulative usage plus delta-only `assistantMessageEvent`,
   without full `message`/`partial` snapshots (see pinned `modes/json-event.ts`).
4. Assistant `toolUse` declares `toolCall` IDs/names/arguments. Pair executions
   start/update/end with the declaration; required successful tools need
   `isError: false`. Tool results are paired messages after execution. `turn_end`
   closes assistant and results. Sequential or overlapping tool pairs inside a
   turn are allowed; unfinished/duplicate/forged pairs fail.
5. `agent_end` closes a low-level run with messages and boolean willRetry. It
   does not establish completion. Require final `agent_settled` after all open
   message/turn/tool/retry/compaction work closes. Later work needs a new properly
   ended/settled run; an earlier settlement cannot settle it. Require final
   nonempty assistant stop text and process exit 0.

With retries/compaction disabled, any such event is a policy discrepancy, even
if eventually settled. In an explicitly authorized diagnostic profile track
`auto_retry_start` (attempt/maxAttempts/delayMs/errorMessage) and `auto_retry_end`
(success/attempt/finalError). A successful retry closes at its successful assistant
message end, potentially before the next agent end. Repeated starts can represent
successive failed attempts in one pending retry episode, not overlapping
independent retries. Pending/exhausted retries fail. Retain failed/aborted/length
responses after later success; later success cannot rewrite them as a clean invocation.

Compaction has start/end with reason manual/threshold/overflow; end carries
aborted/willRetry and optional result/error. Overflow can retry even with ordinary
agent retry disabled, so disable compaction too by default. Track summarization
retry scheduled/attempt-start/finished when enabled, queue_update state and
unexpected custom events for diagnosis. Unknown execution-affecting lifecycle
events fail compatibility; metadata cannot grant completion. Settlement alone
is not success: print-mode source can return 0 for JSON with error/abort messages.

## Continuation and interruption

`--continue` selects the latest project session. This adapter instead selects
the exact parent-frozen file, verifies header/cwd/model and preserves separate
process segments. Sessions restore model/thinking
settings: CLI selection and evidence still enforce the exact model. Missing or
ambiguous sessions fail recovery. Child-written session context does not prove
parent authority or unchanged history.

One-shot JSON consumes an initial prompt, not live JSONL commands. The worker's
control polling/process restart is not in-process delivery. Optional RPC has
`steer`, `clear_queue` and `abort`:
[RPC commands](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/docs/rpc-commands.md).
Steer delivers after current turn/tools; a success response means accepted, not
applied. Abort alone may leave queued work eligible to continue: clear queues
before cancellation and use bounded host termination/cleanup. RPC is not enabled
by this adapter.

The pinned [print implementation](https://github.com/earendil-works/pi/blob/f07218c4d4bbc12bef056a7058c3dd49dfe41abe/packages/coding-agent/src/modes/print-mode.ts)
registers SIGTERM/SIGHUP cleanup handlers with exits 143/129. It does not establish
a graceful SIGINT session-abort guarantee. Check the actual signal path,
session durability, process-group/container cleanup and bounded escalation.
Truncated/killed segments remain invalid even with passing artifacts. Explicit
user cancellation starts no new work by default.

## Legacy adapter and unsupported settings

0.87.1 requires `agent_settled`; process-exit is not a workaround for missing
settlement at this pin. Preserve the explicit legacy option for inspection and
backward compatibility, but no earlier release is qualified here. An older
release needs exact identity, source-confirmed absence of settlement, complete
ordering/tool/identity/final-stop traces and live evidence before enabling a
named legacy adapter. Never auto-downgrade from missing events or help strings.

The adapter preserves ordered evidence, linked segments/outcomes and failure
scoring. It maps bool/level through the
reviewed release's model.reasoning/defaultThinkingLevel/--thinking interfaces.
Numeric budget requests fail explicitly for this CLI profile; its undeclared
compat route is not promoted to support by guessing. No singular setting/flag is
emitted. Requested/configured/ingestion-unverified/server-unverified provenance
remains separate. Sampling and usage measurements retain unknown values; live
support depends on the exact observed runtime configuration.

## Live verification requirements

Use the skill's confirmed environment, exact user
model and finite budgets. Select `linux/arm64` explicitly for every pull/build/run,
verify architecture before launch. Record image ID, Node, Pi artifact/version/
dependencies, effective argv/settings, source hashes, endpoint/model identity,
process exits and independent results.

Capture real clean tool-use/settlement, error/timeout/recovery/cancellation traces,
absence of unexpected retries/compaction, exact session targeting, observed
thinking/sampling request values and any verifiable server enforcement, reply/
context caps, actual mount/control/resource/cleanup effects. Use bounded controlled
stimuli; mark unobservable enforcement unknown and unsupported features explicitly
without changing model/release/budgets. Boundary-extension loading/use is mandatory;
optional fixture_lookup use needs its own matching registration/use evidence.
Source/synthetic examples here
satisfy none of these live gates.

### Reported context capacity

Host discovery, saved-environment health and container preflight use the packaged
`context_contract.py` interpreter. Positive integers in `max_model_len`,
`context_length`, `context_window`, `max_context_length`, and
`loaded_context_length` (including model `meta`) are current limits. Training
maxima (`n_ctx_train`, `training_context_length`) are separate information and do
not verify serving capacity. Conflicting effective limits use the minimum and
retain every source. `/props` limits, including `default_generation_settings.n_ctx`,
apply only to an exact declared model identity or an explicitly labeled inference
from a single listed model. Unidentified multi-model or unrelated properties are
ignored. Missing or malformed values leave capacity unknown; a configured value
is a user declaration, not a verified loaded context.

### Sampling and execution provenance

Reviewed Pi 0.87.1 reads `model.samplingParams`; its OpenAI completions adapter
merges those keys last into the request. This runner permits only `temperature`
(0..2), `top_p`/`min_p` (0..1), integer `top_k` (0..10000),
`repetition_penalty` (0.1..2), and integer `seed` (0..4294967295). Other request
fields and unqualified releases reject explicitly. Configure endpoint `sampling`
or `env save --sampling '{"temperature":0.5,"seed":123}'`.

Requested and emitted values are recorded separately from unverified ingestion
and server enforcement. Saving a seed does not guarantee deterministic replay.
Run provenance includes image/platform/Pi identity, runner file content digests
(without requiring Git), included source and snapshot trees, normalized plan,
frozen scorers and configuration digests. Credential names/values are excluded
from configuration identity. Per-segment task hashes and bounded no-follow copies
of emitted configuration/prompt artifacts are recorded after confirmed cleanup;
these copies are labeled worker-reported and do not authorize recovery or prove
server ingestion. Missing/unsafe artifacts stay unavailable.

Optional endpoint `server_provenance` accepts bounded user-declared `engine`,
`version`, `weights`, `quantization`, and `configuration_digest`. Its origin stays
user-declared, and absent fields remain null. No matching model ID attests weights.

### Usage and timing migration

New heartbeat `usage` and process/result usage receipts contain independent
`input`, `output`, `cache_read`, `cache_write`, and `total` categories. Each has
`reported` (null when incomplete), `known_sum`, and `missing_messages`. Completed
assistant `message_end` events contribute once; cumulative streaming updates and
turn/agent summary copies do not contribute. Repeated prompt context and failed
attempts remain real reported costs; segment aggregation adds disjoint invocations.
All-zero provider placeholders remain unknown. Legacy
`provider_reported_total_tokens` now returns null for an incomplete total, with
known subtotal available in `usage.categories.total.known_sum`.

Heartbeat `speed_tok_sec` is removed. Consumers should migrate to category counts
and `timing.segment_end_to_end_seconds`; no replacement generation-rate field is
provided. Stage end-to-end time includes orchestration, tool work and cleanup.
`observed_tool_event_interval_seconds` measures worker event-arrival intervals and
is labeled accordingly; overlapping tools can overlap these intervals. Inference
seconds remain null because the provider does not expose reliable inference
timing. Budget counts carry known reported usage across segments; missing usage
is explicit and is not a verified token ceiling.

## Indexed inference opt-in

Indexed environments support only the reviewed Chat Completions adapter on both exact releases. Each fresh stage admits its own frozen settings and retains environment/authority identity during continuation. Other API protocols need separate qualification; see [INFERENCE-ENVIRONMENTS.md](INFERENCE-ENVIRONMENTS.md).
