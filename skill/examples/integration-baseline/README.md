# Built-in baseline versus fixture lookup integration

This optional example retrieves alpha/beta/gamma records into answer.json.
Source, requested keys, fixture values, independent oracle, exact model/image and
finite budgets are fixed. Baseline explicitly selects the empty built-in profile
and uses read; candidate explicitly loads the reviewed fixture_lookup extension
and must actually call it. Two fresh repetitions produce four intended cells.
No candidate improvement is assumed. Application baselines remain usable without
this integration example or profile.

The independent read-only oracle compares all three complete records and exact
output shape (four equal assertion groups; score 1 required). It reads data only,
never executes application/extension code, and receives no model credential.
Requested profile alone is insufficient: exact registered/active tools, asset
hashes, successful paired custom arguments/results and independent score must all
be visible. Bash equivalents, text claims and a load receipt without tool use fail
integration eligibility. Different data/entrypoint/configuration changes produce
new profile/configuration hashes; assets never load through ambient discovery.

## Run the fixed comparison

First apply the current-session environment gate and qualify a trusted native ARM64
Pi 0.87.1 or 1.2.0 image as in SKILL.md. Reuse an already confirmed environment within the
conversation; do not ask for the key again. Use explicit image identity from a
reviewed capability receipt and new output paths, outside the subject project. Set IMAGE to that trusted image; the generator selects its exact matching release profile:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" ensure-image \
  --image "$IMAGE" --policy reuse --platform linux/arm64 \
  --resources "$SKILL_DIR/assets/resources/low-impact.json" --receipt /tmp/lookup-image.json
python3 "$SKILL_DIR/examples/integration-baseline/configure.py" \
  --image-receipt /tmp/lookup-image.json --output /tmp/lookup-definition.json
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-experiment --definition /tmp/lookup-definition.json
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-prepare \
  --definition /tmp/lookup-definition.json --experiment-dir /tmp/lookup-experiment
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-run \
  --experiment /tmp/lookup-experiment --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-report --experiment /tmp/lookup-experiment
```

Each agent has a 90-second/12-turn/60000-reported-token limit with serial stages,
1 CPU/2 GiB/256 PIDs/1 job resource policy. The extension only reads fixed declared
data; no new endpoint, host home, socket, package discovery or privilege is added.
The mandatory boundary extension remains active. Built-in runs never mount or
register the fixture component. Requested versus observed load/use stays separate
in result/segment evidence; receipts never authorize runtime controls.

Inspect matrix.json, all four trials.jsonl rows/attempts, comparison.md/JSON,
agent_profile observations, real tool_execution pairs, asset/image/Pi/runner/scorer
hashes and independent scorer output. Protected fixture/request input changes
exclude clean attribution. Assisted/retry/missing results retain separate counts
and denominators. Unknown server weights/enforcement/inference timing stay unknown;
two repetitions do not establish significance or deterministic replay.

The fixture tests validate profile/case/scorer relationships and real local oracle
behavior; synthetic SDK/protocol tests do not prove Pi loading. Real registration,
paired use, mount enforcement and scoring require matching runtime traces. Arbitrary extensions,
skills, MCP, providers, nested agents and broader integrations remain unsupported.
