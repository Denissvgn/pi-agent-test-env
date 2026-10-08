# Parent-approved task brief

Project root: <absolute host path>
Objective: <observable behavior to add, fix, or validate>
In scope: <components and files>
Out of scope: <changes the child must not make>

## Environment
Runtime versions: <read manifests/lockfiles; do not guess>
Image candidate: <trusted tag or digest, or build required>
Profile: <core or browser>
Project-specific probes: <environment JSON file>
Dependency setup: <exact locked commands and network consent>
Service requirements: <test-only service + readiness + cleanup, or none>

## Model
Endpoint config: <reviewed file; no literal key>
Exact model ID and context: <verify server identity and capacity>
Required capabilities: <structured tool calls, image input only when needed>

## Acceptance
- <test/assertion that distinguishes the requested change from the old behavior>
- <negative case or regression assertion>
- <what counts as zero tests / skipped tests / blocked dependencies>

Protected paths: <spec, test oracles, fixtures, manifests as appropriate>
New tests permitted: <where, without replacing the independent oracle>
Agents: <bounded implementer / reviewer / explorer stages>
Limits: <wall time, turns, reported tokens, memory, output volume>
Evidence: <commands, logs, artifacts, model identity, files changed>
Promotion: <review changes; never automatically overwrite original project>

## Resource policy
Runtime CPU-equivalents / RAM / tasks / jobs: <finite budgets>
Build CPU-equivalents / RAM / parallel steps / timeout: <separate finite budgets>
Docker allocation and headroom: <do not consume the whole VM/host>
Concurrency: one stage; use the common host admission lock
Model-server budget: <managed independently from the Pi client>
Disk-growth risk: <quota or disposable storage if required>

## Fixed evaluation (when measuring variants)
Subject contract/cases: <fixed observable cases; no post-result edits>
Independent scorer: <immutable assets/hash, structured score/domain, assertions>
Zero/all-skipped policy: <declared fail behavior>
Baseline and candidate factor: <prompt/endpoint/reviewed profile only>
Repetitions/intended matrix: <fresh trial count and bounded cell count>
Primary/retry policy: first; explicit linked retries only, capped; never best-score selection
Assistance policy: exclude from primary eligible comparison; preserve diagnostic scores
Freeze destination: <new directory outside all subjects; immutable input inventory>
Qualification: <exact image/Pi/model/configuration receipts; unsupported capabilities>
Failure handling: <continue/stop; retain failed/unscorable/missing planned cells>
Reporting: <JSONL/comparison/evidence links; all-planned primary denominators>
Limitations: <finite case coverage, visible tests, tiny sample, unknown server enforcement/timing>
