# Experimental two-trial execution

Select this mode only for two independent experiment trials. Each trial keeps
setup, Pi stages and independent checks sequential, with its own snapshot,
sessions, controls, temporary files, caches and Docker bridge. The parent retains
the same-user host lease for the entire collection. Schema 1 and the ordinary
`run` command remain serial; `--jobs` is a tool-thread hint.

Exact Pi 0.87.1 and 1.2.0 contracts, including their separate fixture profiles,
remain unchanged. Use only native images and the selected browser sandbox. No
in-place execution, nested Pi teams, shared writable tree, automatic patch merge,
new integration or model/server fallback is introduced.

## Freeze a new definition

Copy a reviewed definition into a new input file. Select `schema: 2` and add this
explicit `concurrency` block; these numbers are requests, not detected capacity:

```json
{
  "scheduler": "parallel-trials-v1",
  "host_generation": 1,
  "registry_aware_cohort": true,
  "max_trials": 2,
  "max_stages": 2,
  "max_pending": 16,
  "queue_wait_seconds": 300,
  "collection_timeout_seconds": 14400,
  "aggregate": {"cpu_millis": 2500, "memory_mib": 3328, "pids_limit": 1152},
  "gateway": {
    "resources": {"cpu_millis": 250, "memory_mib": 128, "pids_limit": 64},
    "max_inflight": 1,
    "max_pending": 4,
    "queue_wait_seconds": 180,
    "request_timeout_seconds": 180
  }
}
```

Use an explicit worker resource file. For example, each worker may request
`{"schema":1,"runtime":{"cpus":1,"memory":"1536m","pids_limit":512,"jobs":1}}`.
Two such workers plus the gateway require 2250 milli-CPUs, 3200 MiB and 1088
PIDs. The aggregate must cover every active helper and both unchanged workers,
and fit the policy's observed daemon CPU/RAM fractions. Model/application server
budgets are separate facts. Capacity shortage rejects; parallel workers are never
silently clamped. Admission counts reservations conservatively for an entire trial,
including gaps between its sequential containers.

All variants must select one identical upstream endpoint/model/settings. Explicit
parallel selection also freezes the gateway routing factor. `execution.network`
must be `bridge`; the parent allocates a new bridge per trial, with a gateway DNS
alias. Setup, browser admission and scorers retain their network-none policies.
The selected image must be immutable and already trusted; experiments do not build.
The gateway uses that image's Python toolchain with the frozen runtime helper.

The pending limit must cover the planned matrix (at most 64 cells). Stage budgets
must exceed inference queue wait plus upstream request deadline. Queue limits are
1..3600 seconds for trials and 1..600 for inference; inference wait must remain
at or below the selected upstream request deadline. Collection is 60..14400 seconds,
with exactly two trial/stage slots and one cooperating inference slot. No execution
CLI option raises frozen ceilings. Keep the queue deadline long enough for the
planned preceding trials; expiration blocks collection and retains pending cells.
An inference queue wait of 30 seconds can expire while another trial's valid
generation is running. Select the finite wait explicitly for the endpoint's
observed request duration; the queue may cover the full upstream request budget.
A shorter wait can expire while the other request remains within its deadline.
A longer wait never adds another inference slot.
Parallel model-list preflight uses the greater of 120 seconds or the selected
queue plus upstream deadlines, with 30 seconds of container startup/exit headroom.
These derived ceilings are recorded in each outcome and consume the frozen
collection budget. Serial preflight retains its 120/150-second request/container
ceilings. The example therefore requires Pi stage budgets greater than 360 seconds
and records a 360-second preflight request/390-second container ceiling.

Preparation freezes the complete contract and source/oracle/profile inputs.
Schema-2 matrix order is repetition, declared variant, then declared case; reports
retain this frozen order regardless of completion order. Prepare a new experiment
when source, runner, settings or concurrency changes; never upgrade old evidence.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-experiment --definition /path/to/new-definition.json
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-prepare \
  --definition /path/to/new-definition.json --experiment-dir /path/to/new-experiment
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-run \
  --experiment /path/to/new-experiment --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-report --experiment /path/to/new-experiment
```

Validation/preparation are offline. Passing them does not establish Docker,
browser, model, credentials or parallel qualification. Follow the environment
and qualification gates in SKILL.md and consult QUALIFICATION.md for observed scope.

## Cohort admission and recovery

Host generation 1 means every cooperating host entry point must inspect the secure
launch registry under the host lease. It does not change the supported Pi binary
versions. Quiesce older installed host clients before enabling this mode. Their
flock-only behavior cannot reconcile surviving containers after an owner crash;
a version field cannot constrain arbitrary old binaries or another host user.

Private inherited channels issue trial-bound grants. Host controllers inherit
lease custody so a new owner cannot race an approved launch after parent death.
Pi containers receive neither channel nor lease descriptor. There is no public
skip-lock option. Before every launch the parent persists the exact ownership
intent; wrong image, quota, network, mount, trial or duplicate active launch rejects.

The owner-only `operation.lock.registry` directory beside the selected admission
lock retains container/network generations and independently matched cleanup.
PID reuse or a deadline never proves a writer stopped. New serial and parallel
clients reconcile prior ownership before dispatch. Malformed/insecure records,
daemon changes, unmatched containers, uncertain absence or incomplete sensitive
purge block admission. Unknown ownership never authorizes killing unrelated work.
BuildKit intents also persist before bootstrap; an unobserved live builder cannot
be removed through inferred ownership alone.

Resume uses `experiment-resume` and explicit `--retry-trial TRIAL_UUID` only within
the frozen attempt cap. Old primary outcomes remain sealed. A new controller
reconciles lost attempts rather than silently replaying them. Stop-policy failures
halt pending cells and cancel live siblings; a sibling that already completed
retains its outcome. Continue policy still stops when cleanup is uncertain.

Use exact `--run` and stage identity for controls. Assistance remains recorded;
aggregate CPU/RAM/PID ceilings and the collection deadline remain frozen.
`patch-session` still requires its ordinary quiescent-state admission; an active
parallel collection holds the host lease and blocks patching. Live hot-patching
and pause/reopen are not added.

## Credentials and inference

Keep application references in each stage's existing `application_secrets` map.
Admission resolves every reference before dispatch against the original inference
credential, then delivers only that trial's assigned values over its private host
channel. Scorers, observers and unassigned stages stay key-free. Actor references
that share a key reject; reuse of the same actor reference serializes those trials
in FIFO order. Choose separately partitioned disposable actors to qualify actual
credential overlap. Stage redaction, raw-session purge and contaminated-snapshot
discard remain mandatory. Arbitrarily transformed secret strings are not covered
by the existing exact-value/JSON-escape redaction guarantee.

The gateway keeps the upstream key in a separate owner-only control store, mounted
only into its bounded helper container. Workers receive opaque per-trial inference
tokens. The gateway validates the exact model, supported settings and reply cap,
forwards streams without retry/fallback, bounds queued callers, and captures no
prompts, headers, keys or tool bodies. Two containers do not prove two server slots:
the cooperating inference ceiling stays one while server capacity is unknown.

A queued disconnect removes the caller. A forwarded disconnect retains its slot
until the upstream response terminates. A forwarding timeout with unknown upstream
termination quarantines inference and stops new admission. Cleanup preserves that
uncertainty rather than treating a removed container as proof the server stopped.
The absolute upstream deadline covers resolution, address attempts, TLS setup,
response headers, model-list bodies and stream chunk metadata/trailers. Late
resolver results cannot launch an upstream request. Partial declared lengths or incomplete chunk
termination cannot release the slot as known completion.
This gateway does not constrain unrelated model-server clients or establish model
throughput. Request bodies are bounded to 2 MiB, responses to 64 MiB, and helper
threads are bounded by the inference queue limit.
