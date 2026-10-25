# Authenticated application participant

This synthetic application has two disposable personas, three fixed records on
two pages, and a single publication target. The participant explicitly verifies
Alice's identity, reads both pages, writes a canonical Markdown summary, publishes
it once and writes a completion report. The API and browser plans use the same
identity, content and report contracts.

The normal content scorer checks only stopped summary bytes. The parent
completion evaluator checks the declared identity, raw receipts, pagination,
publication binding and report. A separate key-free root oracle checks the
stopped fixture journal and its trusted terminal receipt. Neither participant
PASS prose nor a passing content score establishes complete success.

Configuration and unit tests do not qualify Docker, Chromium, a model, an
endpoint or a live application. Qualification and credential-safe cleanup remain
required before any run.

## Configure an explicit plan

Set `SKILL_DIR` to the installed skill directory. Supply an already reviewed
immutable native `linux/arm64` image/runtime receipt identifying exact Pi 0.87.1
or 1.2.0. Browser configuration additionally requires a matching successful
`chromium-userns` browser admission receipt with confirmed cleanup. The API
variant uses a core receipt; it rejects a browser-only admission receipt.

Choose the fixture's exact reachable origin and pinned IP address yourself. On
Docker Desktop, the fixture must bind a reviewed host interface reachable by the
helper; the origin hostname and allowed address must describe that route. A
loopback address inside a container refers to that container. No DNS lookup,
image probe, credential read or model request occurs during configuration.

```bash
python3 "$SKILL_DIR/examples/authenticated-application/configure.py" \
  --variant api \
  --runtime-receipt /absolute/path/core-runtime.json \
  --origin http://YOUR_REVIEWED_FIXTURE_HOST:YOUR_PORT \
  --allowed-address YOUR_REVIEWED_FIXTURE_IP \
  --credential-reference DIAGNOSTIC_ALICE \
  --endpoint /absolute/path/explicit-endpoint.json \
  --output-dir /absolute/path/new-api-example
```

Repeat `--allowed-address` for each explicitly admitted address. Use a fresh output
directory. For the browser variant, select `--variant browser` and the matching
browser admission receipt. For explicit indexed inference, replace `--endpoint`
with `--inference-env EXACT_ID --catalog-dir /absolute/path/private-catalog`.
There is no saved-environment or catalog-default selection. Indexed confirmation
and live inference admission happen separately when running.

The output contains a reusable `source.json`, compiled immutable `compiled/`
artifact, a participant `project/TASK.md`, content-only scorer inputs outside the
project and a nonsecret configuration record. The bundled `source.template.json`
contains unfilled runtime/origin/reference fields and is not executable until
configured. Existing output survives rejected configuration; failed compilation
publishes no partial bundle.

The participant budget is one CPU, 1 GiB, 256 PIDs and one job; the native budget
is 32 calls with a six-call/30-second reporting reserve, 300 seconds, 16 turns and
64,000 reported tokens. The separate owning helper also consumes its finite API
or browser resource class. Host admission may reject insufficient aggregate
capacity; this example does not expand the frozen policy.

## Disposable fixture lifetime

Create distinct disposable application keys through the existing private store,
using hidden terminal entry. Keep the store, fixture journal and run results
outside the participant project. Never put values in this README, shell command
arguments, plan, endpoint, prompt, browser page or output artifact.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set DIAGNOSTIC_ALICE \
  --secrets-dir /absolute/path/private-store
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set DIAGNOSTIC_BOB \
  --secrets-dir /absolute/path/private-store
python3 "$SKILL_DIR/examples/authenticated-application/fixture.py" \
  --secrets-dir /absolute/path/private-store \
  --alice-reference DIAGNOSTIC_ALICE --bob-reference DIAGNOSTIC_BOB \
  --journal-dir /absolute/path/new-private-fixture-journal \
  --host 0.0.0.0 --port YOUR_EXPLICIT_PORT --timeout-seconds 300
```

Binding `0.0.0.0` makes the fixture reachable on host interfaces; select that only
for the reviewed local test route and lifetime. It is a disposable diagnostic
service, not a production server. Keep it running only for the bounded trial,
then interrupt it and wait for the parent-owned terminal receipt before evaluating
the journal. The service also stops at its explicit lifetime cap (1–1,800 seconds).
Use a new fixture journal and new run snapshot for every trial.
`--mode timeout-after-commit` is an explicit failure fixture: it commits one
publication and disconnects. The participant must retain an unknown outcome and
must never retry that publication.

## Run and inspect

After the exact image/model/profile scope is qualified and the selected session
is authorized, run the configured immutable plan:

For this standalone legacy `--endpoint` route, the confirmed saved environment
must exactly match the frozen explicit endpoint when dispatch begins. Offline
configuration selects no saved default; this separate run gate checks current
session authorization. Indexed plans require current authorization for the exact
selected catalog entry instead. See the [application-client contract](../../references/APPLICATION-CLIENT.md)
for the full admission policy.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" run \
  --compiled-plan /absolute/path/new-api-example/compiled/plan.json \
  --project /absolute/path/new-api-example/project \
  --secrets-dir /absolute/path/private-store \
  --session "$SESSION"
```

Inspect the sealed result's invocation, task score, application completion and
cleanup dimensions separately. A missing report, wrong persona, missing page,
stale hash or ambiguous publication fails the relevant independent gate even
when the model settles normally. There is no automatic continuation, report
repair, mutation retry, inference fallback or budget growth.

Browser pages contain only reviewed text/controls. Each `records-button` click
admits one records request; each page is read through a separate snapshot. The
participant explicitly fills `summary-editor` and `summary-hash` from its actual
artifact result, then clicks `publish-button` once. The helper supplies the
artifact bytes and enforces its hash/target binding. Arbitrary JavaScript, raw
URLs and fallback selectors are unavailable.

Use the independent root oracle only after fixture writers and the run's
participant/helper writers have stopped and sensitive cleanup is confirmed. Keep
its journal and terminal receipt outside the participant workspace. Root loads
no participant or inference key, performs no model or application request and
checks the stopped bytes and authoritative effects. The frozen `expected.json`
is shared with the content scorer; it is never copied into the participant
project or accepted from participant output.

After independently verifying physical writer absence, use the terminal receipt
hash printed when the fixture stopped. The parent sealer checks the sealed run
cleanup and binds its result hash to that stopped fixture. It reads no credentials
and does not inspect Docker; its receipt cannot replace the parent's physical
absence check. Save the printed parent receipt hash for the read-only oracle:

```bash
python3 "$SKILL_DIR/examples/authenticated-application/fixture.py" \
  --journal-dir /absolute/path/new-private-fixture-journal \
  --seal-run-root /absolute/path/results/RUN_UUID \
  --terminal-sha256 "$FIXTURE_TERMINAL_SHA256"
python3 "$SKILL_DIR/examples/authenticated-application/oracle.py" \
  --run-root /absolute/path/results/RUN_UUID \
  --journal-dir /absolute/path/new-private-fixture-journal \
  --parent-receipt /absolute/path/new-private-fixture-journal/parent-receipt.json \
  --parent-sha256 "$PARENT_RECEIPT_SHA256"
```

The oracle exits zero only for complete content, Alice identity, both pages,
exactly one correctly bound publication and validated reporting. It never repairs
the report, invokes the model or reads the private key store. A passing result
describes this bounded synthetic fixture and does not qualify a third-party
application or an untested runtime mode.
