# Named inference environments

Indexed inference is an explicit experimental path. The root owns selection,
confirmation and frozen assignment; Pi cannot enumerate or choose another profile.
The reviewed adapter is OpenAI-compatible Chat Completions for exact Pi 0.87.1 and
1.2.0. Other API protocols, OAuth/ambient cloud chains and fallback are unsupported.
Qualification is separate from configuration; inspect QUALIFICATION.md before use.

An inference environment is distinct from `--environment FILE` (image capability
probes), the child agent profile (tools/integration) and `application_secrets`.
Existing saved-environment and explicit `--endpoint` commands retain their legacy
behavior. Indexed commands use `--inference-env ID` and a bounded broker; upstream
keys stay outside Pi. Do not claim that stronger boundary for legacy direct runs.

## Root discovery and selection

Reuse this conversation's session ID. Start offline:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" env list --json
python3 "$SKILL_DIR/scripts/pi_lab.py" env inspect --id builder-local
```

Listing does not resolve key values, discover models, contact a service or log in.
Credential availability is metadata, not proof of authentication. A private local
view with `env inspect --id builder-local --private` shows exact routes, model,
settings and references; those details must not enter public reports or source.
Numeric choices require the displayed revision through `--index N
--catalog-revision REV`; execution always uses the resolved named ID.

Choose the user's exact intended destination/model/settings and credential source.
When several profiles are plausible, ask which one. Confirm newly chosen profiles
once per unchanged configuration and authority in this session; reuse those
approvals rather than repeatedly asking. Do not infer approval of B from approval
of A. Selecting a remote profile also selects where source/tool results are sent.

## Register and confirm

Copy `assets/inference-profile.example.json`, replace its synthetic values and
register explicitly. Do not copy real configuration into the project/build context.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" env register --id builder-local --config /private/profile.json
python3 "$SKILL_DIR/scripts/pi_lab.py" env confirm --id builder-local --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" env status --id builder-local --session "$SESSION"
```

Credentials specify `store`, `env` or `none`. Indexed selection never falls back
between sources. Use the existing hidden `secrets set NAME` prompt for store keys;
never enter values in chat, prompts, plans, CLI arguments or images. `none` sends no
upstream Authorization header. Confirmation is offline; `ready` means the binding
is authorized and consistent, not that model/tool/browser use was qualified.

`env update --id ID --config FILE --expected-revision REV` protects against stale
updates. `env revoke`/`env delete --id ID --expected-revision REV` prevents future
admissions for that incarnation. Recreating its name cannot inherit approval.
Unrelated profile edits preserve unchanged approvals. Credential rotation, store-location changes or
selected configuration changes require fresh authorization and prepared inputs;
they never replace a begun stage's authority.

## Execute only after admission and qualification

Use a trusted native image and an explicit worker resource file that leaves room
for the broker. It reserves 0.25 CPU, 128 MiB and 64 PIDs. Worker memory is not
silently reduced to fit it. On Apple Silicon select and verify `linux/arm64`.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" preflight --image "$IMAGE" --platform linux/arm64 \
  --resources "$RESOURCES" --inference-env builder-local --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" smoke --image "$IMAGE" --platform linux/arm64 \
  --resources "$RESOURCES" --inference-env builder-local --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" run --image "$IMAGE" --platform linux/arm64 \
  --resources "$RESOURCES" --inference-env builder-local --session "$SESSION" \
  --project /path/to/project --plan /path/to/plan.json
```

Do not combine `--endpoint` with indexed selection or use indexed in-place runs.
Scoped stage tokens, private snapshots/networks, raw-state purge and contamination
stops are mandatory. Model-list preflight has finite queue/request/container
budgets. Missing credentials, unsafe state or unknown upstream termination stops
dependent work; another available profile is not permission for fallback.

Schema-3 serial variants select `inference_env`; preparation needs `--session` and
freezes an exhaustive stage map and private authority reference. Run/resume uses
the frozen map; catalog defaults never reroute it. Legacy experiment schemas 1/2
keep their original meanings and are not upgraded in place.

Selected profiles and frozen inputs contain private deployment inventory even
without literal keys. Public summaries must use reviewed allowlists. Preserve
unknown deployment capacity and usage; one cooperating inference slot does not
constrain unrelated clients or establish throughput, cost or model-review quality.

## Assignment owners and frozen schemas

Standalone plan schema 2 supplies `inference_bindings`, an exact object from every
agent stage name to an explicit profile ID. Do not pass `--inference-env` as an
override. Setup/check stages have no binding. An experiment-owned plan uses
`"inference_bindings": "external"`; it is valid only with a frozen schema-3 map.
Use `validate-plan --external-inference-bindings` for that offline validation.
A schema-1 plan can use one explicit CLI profile for all agents.

Schema 3 requires `mode` (`serial` or `parallel`) and `indexed_execution` with
`contract: indexed-inference-v1`, `host_generation: 2`, `max_workers: 1` or `2`,
aggregate CPU/memory/PID ceilings and the one-slot gateway contract. Each variant
owns either `inference_env: ID` (uniform) or `inference_bindings`, an exhaustive
case → stage → ID map. These selectors are mutually exclusive; inline plan maps
cannot compete with variant maps. Parallel mode additionally requires matching
`parallel-trials-v2` concurrency, host generation 2 and a registry-aware cohort.
Keep older host clients quiesced even after controller death.

Every selected source/value is admitted before image probes or setup. Preparation
also rejects credential-bearing configuration, plans or uninspectable source trees
before freezing/copying inputs. Different
application reference names cannot share an authority, and application values
cannot equal any selected inference key. Resource admission includes the helper;
no worker cap is reduced to fit it. Capacity/account group labels are observations:
all routes share one cooperating inference slot and one uncertainty quarantine.
They do not authorize independent-server concurrency.

Each stage has a fresh Pi session and a scoped token. Authorized continuation
checks the frozen incarnation, configuration, authority, adapter, image and exact
release again, then rotates the capability. Revoked or rotated sources block
future segments. Patching/steering cannot change the assigned environment. Old
results remain immutable; create fresh prepared inputs for changed selections.

## Examples, execution and public evidence

The self-contained examples in `examples/indexed-inference` include a single
indexed run, serial comparison, parallel profiles and role-swapped pipelines:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-plan --plan "$SKILL_DIR/examples/indexed-inference/roles.plan.json"
python3 "$SKILL_DIR/examples/indexed-inference/configure.py" --image-receipt "$IMAGE_RECEIPT" --output-dir /path/to/new-definitions --a builder-local --b reviewer-local
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-prepare --definition /path/to/new-definitions/serial.json --experiment-dir /path/to/new-experiment --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-run --experiment /path/to/new-experiment --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-report --experiment /path/to/new-experiment
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-export --experiment /path/to/new-experiment --public
```

Preparation is offline but resolves sources to freeze private authorization
references. Catalog/store paths must be outside every original project and all
snapshot/evidence roots. Native execution requires prior approval of selected
egress, images, sandbox, worker/helper/collection limits and qualified scope.

Private ledgers retain exact stage identities and failed/missing/retry/assisted
accounting. Comparisons reject mismatched binding, oracle, snapshot or runner;
role swaps are declared treatments. `--public` writes `public-trials.jsonl` with
collection-local labels, finite scores and reported usage/missingness. It omits
URLs, model/profile/stage names, key references, fingerprints, raw errors, traces
and file paths. Private ledgers and comparison reports remain private.

The indexed executor is pending native qualification on both reviewed releases.
Offline routing fixtures or historical homogeneous results do not qualify it.
A same-backend two-credential campaign does not establish distinct URL/model/API
or independent provider/weights acceptance. Unsupported API adapters fail before
execution; no automatic authentication, profile fallback or API conversion exists.
