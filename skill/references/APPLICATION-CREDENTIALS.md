# Scoped application credentials

Version 4.1.0 supports separate application credentials on explicitly assigned
agent stages. The runner delivers each stage's named host-store values as
`PI_APP_*` environment variables. Built-in Bash clients can use them for HTTP
authentication; no child extension, proxy, arbitrary environment flag or extra
mount is required. The inference key remains `PI_LAB_API_KEY`. Images declaring the reserved
`PI_APP_*` namespace are rejected, including empty baked variables.

## Plan and admission

Schema-1 agent stages may declare `application_secrets`, mapping 1..8 variables
to host-store entry names. Variable names must match
`PI_APP_[A-Z][A-Z0-9_]{0,56}`; references must match `[A-Z_][A-Z0-9_]{0,63}`.
Literal values, paths, general environment declarations and setup/check/scorer
secret assignments are unsupported. Omit the field on unassigned agents.

```json
{
  "schema": 1,
  "name": "authenticated-personas",
  "agents": [
    {
      "name": "persona-a",
      "application_secrets": {"PI_APP_WORKCHORD_API_KEY": "WORKCHORD_A"},
      "tools": ["read", "bash"],
      "require_tools": ["bash"],
      "prompt": "Read the application task. Use PI_APP_WORKCHORD_API_KEY in the HTTP client for your assigned persona. Acknowledge the exact current onboarding handoff, then perform the assigned authorized operation. Print only sanitized identities and effects; never print credentials."
    },
    {
      "name": "persona-b",
      "application_secrets": {"PI_APP_WORKCHORD_API_KEY": "WORKCHORD_B"},
      "tools": ["read", "bash"],
      "require_tools": ["bash"],
      "prompt": "Read the application task. Use PI_APP_WORKCHORD_API_KEY for your assigned persona's onboarding and authorized operation. Never print credentials."
    }
  ],
  "checks": [{"name": "effects", "argv": ["python3", "tests/verify_effects.py"]}]
}
```

Use the real application's handoff/API payloads and independent oracle in the
task and project. The JSON above illustrates ownership; it does not provide the
project, service, handoff or verifier. Plans retain existing finite time/turn/token
defaults or may declare smaller budgets.

The operator obtains disposable application keys through the application's
authorized credential sink and stores them outside the project, installed package and experiment/run evidence:

```bash
# Hidden terminal input; do not put a value in an argument or chat.
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set WORKCHORD_A
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set WORKCHORD_B
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-plan --plan /path/to/plan.json
python3 "$SKILL_DIR/scripts/pi_lab.py" run \
  --project /path/to/project --plan /path/to/plan.json \
  --image "$IMAGE" --platform linux/arm64 --session "$SESSION" \
  --resources "$SKILL_DIR/assets/resources/low-impact.json"
```

Qualify the image/model environment using SKILL.md first. Architecture selection,
read-only root/helpers/controls, CPU/memory/PID/time limits and network policy
remain in force. `--secrets-dir` may select another owner-only host store for a
single run. Experiments use the default store (or host `PI_LAB_SECRETS_DIR`);
preparation freezes references only, without resolving credential values. Prepare
a fresh experiment after runner changes. Reference reuse does not establish
identical credential/server state across repetitions; use service-side identity
and effect receipts to verify the intended persona.

Application values are read from the store only, without an exported-variable
fallback. The directory must be owned by the operator and owner-only (0700).
Files must be owned, owner-only (0600), regular, singly linked and readable without
following a symlink. Keys must contain 16..4096 characters without whitespace or
control characters. Missing/unreadable/insecure entries, inference-key references
or values, and duplicate values under distinct reference names block before any
Docker probe or worker dispatch. The same reference may be explicitly assigned
to more than one stage when sharing is intended. `--in-place` is unsupported for
credential-bearing plans; isolated snapshots are required.

Admission also rejects a literal resolved credential in the normalized plan or
snapshot before worker dispatch. This detects the selected exact values, not
every possible secret or encoded form. Keep all project, image, prompt and frozen
inputs free of credentials regardless of this check.

## Client use and stage ownership

A built-in Bash tool can run a Python client that reads its authorized key
internally and keeps it out of shell/command arguments:

```python
import json
import os
import urllib.request

# These nonsecret values come from the reviewed task/project configuration.
base_url = application_base_url
acknowledgement = exact_current_handoff_payload
request = urllib.request.Request(
    base_url + "/api/agent/team-setup/onboarding/acknowledge",
    data=json.dumps(acknowledgement).encode(),
    headers={"X-Agent-API-Key": os.environ["PI_APP_WORKCHORD_API_KEY"],
             "Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=10) as response:
    acknowledgement_result = json.load(response)
# Perform the task's subsequent authorized operation with the same header.
# Print only explicitly selected nonsecret fields from application responses.
```

Only that agent and its authorized continuation segments receive the declared
application variables. Docker arguments and command receipts contain variable
names only. Ambient `PI_APP_*` variables are removed from subprocess environments
before adding the assigned set. Unassigned agents, image probes, preflight,
setup and independent checks receive no application variables. Credentials never
fall back to another persona or the inference key. Stages still share application
artifacts and run sequentially; `cwd` is not an access boundary.

## Redaction, retention and cleanup

Captured stdout/stderr (including tool events and transport errors), process
diagnostics and emitted-configuration admission use exact-value redaction for
the inference key and all application keys admitted for the plan. Redaction-only
values stay in parent memory; they are not forwarded to unassigned workers.
Up to three JSON-string escape layers are covered, including client JSON inside
tool JSON, UTF-8/Unicode escaping and values spanning pipe reads. Other transformed
or encoded secrets remain outside exact-value redaction guarantees.
Credential-bearing emitted prompt/configuration files are not copied into
evidence. Status omits untrusted raw child heartbeat fields for credential stages.
Plans, task configuration, ownership receipts and frozen metadata retain names
and references only; application ownership receipts publish no value fingerprint.

Raw Pi sessions, temporary files, models/settings and outbox material are private
runtime data. They remain available within the assigned stage for exact-session
continuation, then are removed after independently confirmed container cleanup,
including failure, timeout and cancellation paths. Resume-session control copies
are removed too. A stage receipt records `status: removed` and workspace coverage.

Before another agent or scorer can run, the complete shared snapshot is checked
for literal/JSON-escaped credentials admitted for the plan, including ignored
files and entry names.
The scan rejects links, special files, unreadable entries and coverage above
10,000 entries or 256 MiB. Contaminated/uninspectable snapshots are discarded and
the run fails closed; no later worker or scorer is dispatched from that snapshot.
This deliberately sacrifices suspect artifacts rather than forwarding a token.

Uncertain container cleanup or filesystem removal quarantines the private run,
records `cleanup_unconfirmed`, and blocks later dispatch/scoring. After controller
loss, experiment-resume verifies owned containers are absent/removed before
purging registered sensitive runtimes and discarding the abandoned snapshot.
A hard host/process crash cannot guarantee immediate removal. For a standalone
crashed run, stop the owned container, revoke the application keys, and remove its
private run directory after confirming no writers; do not use its artifacts for
checks. Operator-owned store entries are retained until explicitly cleared:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets clear WORKCHORD_A
python3 "$SKILL_DIR/scripts/pi_lab.py" secrets clear WORKCHORD_B
```

Clearing the store does not revoke a key at the application. Revoke disposable
keys there after the campaign. Filesystem removal is not forensic secure erasure;
backups, Docker daemon memory and host process memory are outside this guarantee.

A worker with Bash can read its own environment and intentionally disclose or
encode it, send it over the network, or include it in tool output sent to the
model. Exact capture redaction is not a credential-withholding boundary or a
network firewall. Encoded/transformed values and unrelated secrets are not
comprehensively scrubbed. Use disposable scoped identities and review evidence
before publishing.

## Evidence scope

Offline regressions exercise actual local HTTP onboarding and authenticated
operations for two synthetic personas, service-recorded effects, key-free stages,
redaction and cleanup with real subprocesses. Docker/Pi boundaries in those tests
are synthetic. This does not qualify live WorkChord authorization, a real Pi
invocation, Docker isolation or the intended campaign. Record separate native
ARM64 image/model qualification and live application identity/effect receipts
before claiming those outcomes.

## Indexed inference opt-in

Indexed admission rejects application references or values matching any selected inference authority. Store/env/none sources are explicit; ambient overrides do not replace store bindings. All selected inference references are stripped from host workers, and Pi receives only its scoped broker token. Legacy direct credential semantics remain available; see [INFERENCE-ENVIRONMENTS.md](INFERENCE-ENVIRONMENTS.md).
