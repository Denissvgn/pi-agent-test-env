# Fixed Python application baseline

The subject implements the ASCII slug specification in `project/services/api`.
Every trial begins from the same unimplemented source. Baseline uses the unchanged
application plan prompt; candidate adds a declared instruction to reason through
type/Unicode/separator/empty/idempotence cases before editing. Image, model endpoint,
tools, source, oracle and budgets remain the same. This measures a prompt change
in the built-in agent workflow, not a custom child integration or served weights.
No candidate improvement is assumed.

The external `oracle.py` and `cases.json` are frozen outside the writable project
and mounted read-only only in key-free scorer containers. Application calls run
in short child interpreters; the parent oracle never imports application code or
accepts a child-reported grade. Eight equally weighted
assertion groups cover the specification, including Unicode lowercase versus
casefold. Score = passing groups / eight, with 1 required to pass. The supplied
seven visible unittest methods help implementation but do not replace this oracle.
Assertions cover a fixed case set, not all possible inputs or vulnerabilities.

The main matrix contains two cases × two variants × two fresh repetitions = eight
primary cells. `slug` has 120 seconds, 12 turns and 60000 reported tokens per agent;
`cutoff` first requests a 20-second sleep under a declared five-second stage limit.
It intentionally demonstrates bounded failure scoring. Scorer timeouts are also
capped to the case budget. Every case shares the same independent oracle.
Raw artifact scores after invalid/timeout invocation remain diagnostic; clean
model success and primary eligibility have separate denominators. The resume
matrix has one normal case × two variants × one repetition for a bounded control
demonstration; retries are allowed only explicitly, at most two attempts per cell.

## From a clean checkout

Prerequisites: Python 3.10+, local Docker on native ARM64, trusted Pi 0.87.1 or 1.2.0 core
image, and a confirmed reachable OpenAI-compatible model with the stored key.
Use the skill's environment gate once per conversation; keep `SESSION` and do not
put keys in chat, definitions or commands. Set `SKILL_DIR` to the absolute `skill/`
(or installed skill) directory. Qualify image/tool smoke as in SKILL.md first.
Set `IMAGE` to your explicitly trusted native image before running these commands.
Never silently replace a release.

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" ensure-image \
  --image "$IMAGE" --policy reuse --platform linux/arm64 \
  --resources "$SKILL_DIR/assets/resources/low-impact.json" --receipt /tmp/slug-image.json
python3 "$SKILL_DIR/examples/application-baseline/configure.py" \
  --image-receipt /tmp/slug-image.json --output-dir /tmp/slug-definitions
python3 "$SKILL_DIR/scripts/pi_lab.py" validate-experiment \
  --definition /tmp/slug-definitions/baseline.experiment.json
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-prepare \
  --definition /tmp/slug-definitions/baseline.experiment.json --experiment-dir /tmp/slug-baseline
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-run \
  --experiment /tmp/slug-baseline --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-report --experiment /tmp/slug-baseline
```

Choose new output paths if these already exist; no existing definitions/results are
overwritten. Configuration renders paths from the installed example location and
uses the exact image ID in the reviewed receipt; that receipt is not a signature.
Validation/preparation are offline and do not prove endpoint health or performance.
`experiment-run` collection exit 0 means all cells reached terminal records, even
when deliberate cutoff trials fail. Read `comparison.md`, `comparison.json`,
`trials.jsonl`, each immutable run result, real Pi trace and scorer result.

## Bounded interrupted/resumed example

Prepare `/tmp/slug-resume` using `resume.experiment.json` and run it with the same
session. From another terminal, send SIGTERM to that **experiment controller**
once its first agent is running (identify the exact owned PID, never broad pkill).
Wait for bounded cleanup and its INTERRUPTED record. Then:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-resume \
  --experiment /tmp/slug-resume --session "$SESSION"
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-export --experiment /tmp/slug-resume
# Read the interrupted cell's trial_id from trials.jsonl, then explicitly authorize:
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-resume \
  --experiment /tmp/slug-resume --session "$SESSION" --retry-trial TRIAL_UUID
python3 "$SKILL_DIR/scripts/pi_lab.py" experiment-report --experiment /tmp/slug-resume
```

Pending cells run once; the interrupted primary stays visible, score unknown when
scoring was skipped. Retry has index 2/new run and attempt IDs and links to index 1.
Its score cannot replace the primary or improve the primary success denominator.
A hard controller crash is separately recorded as controller_lost after independently
matched owned cleanup. Changed frozen inputs/runner or uncertain writers reject.

## Records and evidence levels

`matrix.json` has eight fixed trial UUIDs and initially planned cells. `trials.jsonl`
has one schema-1 `trial_record` per cell with primary ID, configuration digest and
all linked schema-2 `run_result` attempts. `comparison.json` separates planned,
started, terminal, scored, eligible, autonomous success, blocked/cancelled,
unscorable and retry counts; fractions retain their denominators. Case-specific
pairs/spread and measured usage/timing retain missingness. Inference timing is
unknown. Tiny samples do not establish significance or deterministic replay.

`tests/test_application_example.py` runs the real oracle locally against
known correct, unimplemented and casefold-bug implementations and freezes a
synthetic endpoint/image matrix. Those checks establish reset/schema/oracle
behavior, **not model performance**. Real Docker/Pi observations from 7 October
2026 remain limited to their exact recorded configuration. Normal baseline/candidate both passed two repetitions; the
four declared cutoff cases were scored failures. That finite observation does not
establish improvement or qualify a different image/server/configuration.
