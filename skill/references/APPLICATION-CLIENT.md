# Reviewed application client

The `application-client` profile runs explicitly declared API and browser actions
with application credentials held in a parent-owned helper. The participant
receives scoped capabilities and bounded results. It has no Bash, arbitrary file
read, arbitrary URL, JavaScript evaluation, nested agent or model tool. Legacy
`application_secrets` environment delivery remains a separate contract described
in [APPLICATION-CREDENTIALS.md](APPLICATION-CREDENTIALS.md).

The [authenticated participant example](../examples/authenticated-application/README.md)
includes API/browser configuration, two disposable personas, explicit pagination
and publication, and a separate key-free oracle over stopped fixture journals.

The implemented contract supports exact Pi releases 0.87.1 and 1.2.0 on native
`linux/arm64`. Interface support and offline checks do not qualify a particular
image, model, application or overlapping execution. Use the dated observations
in [QUALIFICATION.md](../QUALIFICATION.md) and qualify the actual selected scope.

## Compile the representation that will execute

Author a JSON document with `schema: 1` and
`document_type: "application_plan_source"`. Its exact top-level fields are
`schema`, `document_type`, `name`, `runtime`, `application`, `stages`, and `checks`.
Unknown fields reject. Review these decisions before compiling:

| Declaration | Required decision |
|---|---|
| Runtime | Exact Pi release, immutable `sha256:` image ID, `linux/arm64`, `core` or `browser` container profile, resource policy, inference owner |
| Browser policy | `null` for core; `chromium-userns` for browser, with a matching successful browser admission receipt |
| Application | Named origins, credential aliases pointing to host-store references, typed operations, optional reviewed browser targets, finite evidence/receipt limits |
| Stage | Unique ID, dependencies, exact participant, granted aliases/operations/targets, `profile: "application-client"`, task prompt, input artifact grants, six budget fields, completion contract |
| Checks | Independent protected commands and, for experiments, the declared structured scorer and frozen assets |

Standalone sources use `runtime.inference_owner: "compiler_input"`. Every
credential alias needs an explicit identity operation returning exactly
`application_id`, `tenant_id`, `actor_id`, and `role`. The helper verifies that
tuple against the stage before admitting dependent operations. Input artifacts
must name a declared artifact from an ancestor stage; a dependency alone grants
no arbitrary workspace access.

Use an already obtained image observation or browser admission receipt. The
compiler reads this supplied observation; it does not probe Docker, contact an
application/model, resolve credential values or refresh qualification:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" compile-application-plan \
  --spec /path/to/application-source.json \
  --runtime-receipt /path/to/reviewed-runtime-receipt.json \
  --endpoint /path/to/endpoint.json \
  --output-dir /path/to/new-compiled-application
```

Alternatively replace `--endpoint` with `--inference-env EXACT_ID` and
`--catalog-dir /path/to/private-catalog`. Compilation binds the selected full
configuration and catalog incarnation; live use still requires current session
authorization. Endpoints contain credential references, never literal keys.

The new output directory contains `plan.json` with
`document_type: "application_execution_plan"`, source/inference/runtime and prompt
policy documents, exact profile/scorer assets, diagnostics and an input manifest.
Publication is atomic and an existing output is not overwritten. The final plan
freezes dependency order, effective prompt, actual tool schemas, operation grants,
completion contracts, endpoint context/reply limits, resources and content hashes.
Initial prompt admission counts system/profile/task/variant text, schemas,
operation/report overhead and conservative framing/history reserves. It is a
conservative initial bound, not a promise about later context growth.

After the normal image/model environment gates, run that exact representation:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" run \
  --compiled-plan /path/to/new-compiled-application/plan.json \
  --project /path/to/application-fixtures --session "$SESSION" \
  --results-dir /path/to/private-results
```

The project is copied. Runtime, profile, resource and inference selections come
from the compiled inputs; competing `--plan`, `--endpoint`, `--inference-env`,
`--agent-profile`, runtime override and `--in-place` selections reject. The legacy
endpoint route requires a confirmed saved environment matching the frozen
endpoint. Indexed bindings require their exact current catalog authorization.
Changed runner bytes, changed prepared inputs, missing credentials or mismatched
runtime admission block execution. Prepare a fresh artifact for intentional
changes. A manifest proves byte consistency, not publisher trust or permission.

## Explicit tools and effects

The compiler selects each stage's closed subset from this catalog:

| Tool | Behavior |
|---|---|
| `app_api` | One granted operation ID with typed path parameters, query, body and optional pagination cursor |
| `app_browser` | One granted target and explicit `navigate`, `snapshot`, `screenshot`, `click`, `fill` or `select` action |
| `artifact_read` | Read an explicitly granted input or declared output artifact by ID |
| `artifact_write` | Write bounded UTF-8 text/Markdown/JSON to a declared output artifact ID |
| `report_write` | Store the participant-supplied completion manifest after structural validation |
| `budget_status` | Return the trusted budget snapshot after charging this call |

API grants fix transport, effect class, origin, method, route, credential alias,
request/wire/response schemas, deadlines and bounded result projections. Identity
and read operations use GET; mutations/publications use explicit write methods.
Pagination advances only through explicit participant calls. Its chain binds a
snapshot and cursor sequence, with finite pages/items/bytes/time; exhaustion is
checked independently when required. There is no automatic page crawl, workflow,
write retry or publication retry. An uncertain transmitted write closes business
admission and retains `outcome_unknown` evidence.

Browser targets freeze selectors, typed inputs, operation bindings and permitted
static resources. Each action has bounded subrequests and permits at most one
write request. Hidden page requests do not create extra authority. Unsupported
opaque content, including content that cannot be safely inspected before screen
capture, fails closed; a missing screenshot is not replaced with synthetic pixels.
Browser admission requires the selected sandbox policy and exact image. There
is no automatic sandbox or software-rendering fallback.

The helper validates scope and raw typed arguments before application effects.
Every admitted operation retains a parent-bound receipt and sealed raw evidence
after declared credential redaction. Receipts bind native call, operation/action,
participant, run/attempt/stage/segment, release/profile/plan/report identities,
outcome, evidence bytes/digests and pagination/publication metadata. Bounded model
results are projections; they do not replace those retained receipts. Application
content is untrusted data and cannot authorize another tool, endpoint or actor.

## Completion is an independent gate

Every stage declares an exact participant and a completion contract with `id`,
`report_path`, required `artifacts`, `pagination`, and `publications`. Artifacts
declare ID, contained path, media type and maximum bytes. Publications bind an
artifact, operation and target with required state `published`. Publication is
a business action and must finish before reporting-only mode.

The participant must call `report_write` with an
`application_completion_report` containing `schema`, `document_type`,
`contract_id`, `participant`, `artifacts`, `pagination`, `publications`, and
`unresolved`. Artifact entries name exact ID/path/SHA-256/byte count. Pagination
maps operation IDs to ordered receipt IDs. Publication entries bind declared
publication IDs to receipt IDs. The writer validates shape and stores the supplied
manifest; it does not fill missing fields, invent receipts or rewrite the report.

After writers stop and helper/credential cleanup is confirmed, an independent
evaluator reads actual report/artifact/evidence bytes and the parent's receipt
index. It checks exact identities, declared paths/media/limits, digests, complete
pagination chains and matching published artifact receipts. Clean model
settlement alone cannot satisfy completion. Missing or contradictory requirements
produce bounded diagnostics and `incomplete` or `invalid`; unsafe cleanup or
cancellation produces `not_evaluated` without reading outputs. No automatic
continuation, report repair or extra model request follows a failed report.

`result.json` keeps invocation validity, task score and `application_completion`
separate. A passing independent task score can coexist with a failed report and
a failing run. Failure prevents later application stages; dependent stages are
`dependency_blocked`, and other later stages are `prior_failure`. Independent
scoring may still inspect eligible stopped clean artifacts under its own policy.
Public summaries retain stage ordinals/status/diagnostic counts, with no private
receipt pointers, participant identity or payload. Never turn unavailable
accounting or unevaluated completion into zero or success.

## Native calls and reporting reserves

Application stage `limits` requires all six fields:

```json
{
  "timeout_seconds": 300,
  "max_turns": 20,
  "max_total_tokens": 20000,
  "max_tool_calls": 40,
  "reporting_reserve_calls": 5,
  "reporting_reserve_seconds": 20
}
```

The call ceiling is 2..500; the call reserve is 1..20 and below that ceiling.
The time reserve is 1..120 seconds and below the stage timeout. Legacy stages
can opt in with the entire native three-field tuple; absence preserves their
existing budgets. The central parent ledger counts native built-in/custom calls,
including calls declared together and schema-invalid attempts, before effects.
Subprocess operations are not individual native calls. Missing/corrupt accounting,
unmatched grants or unreconciled calls closes admission.

Phases advance monotonically from `business` to `reporting` to `exhausted`.
Reaching the call or time reserve prevents new application/business actions.
Reporting admits only bounded declared output artifact operations, the matching
report contract and `budget_status`; legacy profiles admit only `budget_status`.
Denied business calls cannot drain the reporting reserve. Status itself costs a
call and reports the remaining count after that charge. The time threshold is a
best-effort helper threshold; the parent hard deadline remains independent.

Status distinguishes attempted, charged, blocked and known/unknown execution.
Exact charged call accounting does not imply every built-in execution entry was
observed: `executed: null` represents unknown execution, never an invented zero.
Trusted helper effects and worker-observed built-in entry counts remain distinct.
Safe budget projections expose no raw arguments or credential capabilities.

Explicit assistance can increase an existing ceiling:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" extend-budget \
  --run /path/to/run --stage STAGE_UUID --tool-calls +10 \
  --revision 1 --budget-revision 1
```

Replace both example revision values with the current values from status. Requests are audited and separately
applied by the parent; acceptance marks assistance. An increase preserves consumed
counts, reserves and phase, and cannot reopen business mode. A max-call-only
increase preserves the helper deadline. Explicit `--timeout` assistance is a
separate time increase. Authorized exact-session continuation carries the same
ledger; it never resets allowances or authorizes report repair.

Failed parent settlement may retain `application_settlement_failure` in process
metadata as `{"schema":1,"code":"FINISH_RPC_FAILED"}`. The code identifies the
first failed finish, receipt, helper-cleanup or private-context check. The closed
catalog is `application_execution.SETTLEMENT_CODES`; unclassified failures use
`UNKNOWN`. Downstream credential cleanup preserves this metadata. It contains no
exception text, values, identifiers or private paths, and supplies no cleanup
clearance or retry authority. Successful settlement omits the field. Historical
records without the field remain unchanged.

## Prepared application experiments

Use `document_type: "application_experiment_source"` to distinguish compiled
participant experiments from legacy coding experiments. Cases name `project`,
application source `plan`, and `runtime_receipt`; source inference owner must be
`experiment_variant`. Each case has one independent structured root scorer.
Variants select explicit endpoints or catalog bindings and optional
`prompt_suffix`. Global/case budgets contain all six fields; execution declares
immutable image, ARM64 platform and a resource file. Policies retain first-primary,
assistance exclusion, finite attempts and explicit continue/stop-on-failure.

| Schema | Inference and collection |
|---|---|
| 1 | Serial; each variant requires an explicit endpoint file |
| 2 | Explicit bounded two-trial parallel contract; all variants use one identical upstream; frozen concurrency includes helper resources |
| 3 | Explicit `serial` or `parallel` mode and indexed execution contract; each variant selects `inference_env` or exhaustive per-case/per-stage `inference_bindings` |

Parallel helpers use a frozen class: API helper 1 CPU/512 MiB/128 PIDs or browser
helper 2 CPUs/2048 MiB/512 PIDs. Worker, helper and gateway capacity must fit the
explicit aggregate; no hidden helper or automatic resizing is allowed. Shared
application actor/credential authorities serialize even when two trial slots are
available. Parent-owned helpers stay with their trial through stage transitions.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-experiment \
  --definition /path/to/application-experiment.json
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-prepare \
  --definition /path/to/application-experiment.json \
  --experiment-dir /path/to/new-application-experiment --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-run \
  --experiment /path/to/new-application-experiment --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-report \
  --experiment /path/to/new-application-experiment
```

Preparation compiles every transformed case/variant through the same compiler,
then freezes final plans, source/scorer/profile bytes and full inference identity.
Indexed preparation additionally confirms the current catalog authorization and
scans known original credentials before copying. It performs no Docker/model or
application operation. Collection resolves all selected authorities before probes
and rechecks current catalog authorization before activation. Parallel workers
receive delegate tokens and scoped helper capabilities; original application,
upstream inference and helper control credentials remain parent-owned.

Only explicit `experiment-resume`/`--retry-trial` requests can advance interrupted
or retryable collections; sealed primary attempts remain unchanged. Unknown
application helper/context/credential cleanup blocks generic recovery, preserves
dependent networks/private state and requires independent owned cleanup proof.
Collection exit 0 means collection reached a terminal state, including failed
reports/trials. Inspect comparison denominators, every completion gate and actual
independent scorer result before making a success claim.
