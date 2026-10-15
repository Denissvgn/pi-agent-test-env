# CPU, memory, builder, and concurrency budgets

## What is enforced

Every child launched by `pi_lab.py` has a finite Docker CPU quota, memory limit,
combined memory-plus-swap limit equal to memory (no additional swap), and a PID
limit. This includes capability probes, preflight, setup, Pi, Chromium, and tests.
The entire process tree shares its container quota; launching extra subprocesses
does not multiply its CPU or memory allowance. Linux counts threads as tasks for
PID limits, so a browser can hit the PID limit even with few visible processes.

The built-in defaults request:

```json
{
  "schema": 1,
  "runtime": {"cpus": 2, "memory": "4g", "pids_limit": 256, "jobs": 2},
  "build": {"cpus": 2, "memory": "4g", "max_parallelism": 2, "timeout_seconds": 1800},
  "host_budget": {"cpu_fraction": 0.5, "memory_fraction": 0.5}
}
```

Use `--resources path/to/policy.json`. Unknown fields, zero/unlimited CPU,
negative/unlimited RAM, nonfinite numbers, and out-of-range process/time settings
are rejected. CLI runtime overrides are `--cpus`, `--memory`, `--pids-limit`, and
`--jobs`. Image-build overrides are `--build-cpus`, `--build-memory`,
`--build-parallelism`, and `--build-timeout`.

Requested CPU and memory for runtime and build are independently capped against
Docker's **total allocated** `NCPU` and `MemTotal`, not the Mac's physical CPU count
or a promise of currently unused capacity. Both default fractions are 0.5. A
policy can explicitly change them up to 0.9; never increase them just to hide a
failure. Small allocations may produce too little RAM for Chromium or compilation;
report the shortfall and request a bounded adjustment.

Examples (assuming at least 8 GiB allocated to Docker):

| Docker allocation | Runtime request | Effective CPU cap |
|---|---|---|
| 8 logical CPUs | 2 | 2 CPU-equivalents |
| 2 logical CPUs | 2 | 1 CPU-equivalent |
| 1 logical CPU | 2 | 0.5 CPU-equivalent |

`--cpus 2` means the time budget of two logical CPUs, not 2% of the computer,
exclusive physical cores, CPU affinity, or a reservation. Docker may schedule
threads across multiple cores and throttle their aggregate CPU time. `--cpu-shares`
alone is a relative weight, not a hard cap; this runner does not rely on it.
`--cpuset-cpus` is intentionally not guessed from macOS core IDs.

## Workload parallelism

Each trial executes one stage at a time. An implementation agent, reviewer, and
independent verifier within that trial do not run concurrently. Schema-2 mode
permits overlap between two independent owned trial snapshots. All subcommands that touch Docker
also take the same-user host lock:

```text
~/.local/state/pi-agent-test-env/operation.lock
```

A second cooperating invocation exits busy by default, or waits with
`--lock-wait-seconds 300`. The lease stays held by cooperating host controllers until they exit;
the file remains to avoid unlink races. Registry-aware clients reconcile surviving
ownership after lease release instead of assuming all containers stopped. Do not select different lock files merely
to bypass the budget. This is not a scheduler for other users, other tools, or the
whole Docker daemon. If you introduce separate parallel jobs, the aggregate
ceiling is approximately `parallel jobs * per-job CPU/RAM limit`; use a real parent
scheduler or cgroup budget before doing that. Explicit schema-2 collections use a weighted parent scheduler for two independent
trials; see [PARALLEL-AGENTS.md](PARALLEL-AGENTS.md). Serial remains default.

Known admission failures use a closed nonsecret diagnostic catalog:
`host-admission-busy`, `resource-policy-invalid`, `admission-lock-insecure` and
`admission-lock-unavailable`. Run/smoke retain sealed BLOCKED/2 outcomes with zero
dispatch when rejected before execution. Other admission CLI failures emit a
structured `admission_failure` on stderr with exit 2. Guidance is static and
bounded; raw exception details remain represented only by their SHA-256 digest.
Unknown errors are not classified by matching messages or digest values.

The following worker hints are set from the effective job count:
`PI_TEST_JOBS`, `OMP_NUM_THREADS`, `OPENBLAS_NUM_THREADS`, `MKL_NUM_THREADS`,
`NUMEXPR_NUM_THREADS`, `VECLIB_MAXIMUM_THREADS`, `UV_THREADPOOL_SIZE`,
`CMAKE_BUILD_PARALLEL_LEVEL`, `MAKEFLAGS`, `CARGO_BUILD_JOBS`, `RAYON_NUM_THREADS`,
`GOMAXPROCS`, and `npm_config_jobs`. These are **advisory**, not a second security
boundary. A tool can ignore them. The Docker quota still applies. Some test
runners need an explicit project-specific worker flag; inspect their installed
help rather than assume a universal `--workers` syntax. Do not use `make -j$(nproc)`
or unconstrained worker auto-detection in plans on shared machines.

## Image-build limits are separate

`docker run --cpus` does not constrain a later `docker build`. The runner therefore
creates an ephemeral Buildx builder with the `docker-container` driver and:

```text
cpu-period=100000
cpu-quota=<effective_build_cpus * 100000>
memory=<effective_build_memory>
memory-swap=<effective_build_memory>
restart-policy=no
```

Its BuildKit configuration sets `[worker.oci] max-parallelism`. The parent boots
this builder, inspects the underlying Docker container to verify quota and memory
settings, invokes `buildx build --builder NAME --load`, and removes the builder in
`finally`. The user's selected builder is not changed (`--use` is never used).
If Buildx is missing, limits do not appear in inspection, or the build times out,
there is no unrestricted fallback. The browser/extra-package build runs as trusted
parent infrastructure, not an untrusted Pi child.

Buildx's container driver convention `buildx_buildkit_<builder-name>0` is used for
limit verification. If a future driver changes that convention, this runner stops
instead of claiming a verified cap. The builder has a cold cache each time;
prefer reusing a suitable already-built image. Pin `--buildkit-image` by digest for
reproducible infrastructure. Default tags can change upstream.

The wall-time limit covers the build invocation; builder bootstrap has its own
300-second bound. Docker daemon/buildx-client overhead and image transfer are not
fully contained in the build container quota. Ctrl+C triggers cleanup; after a
hard kill of the parent, inspect leftover named builders manually:

```bash
docker buildx ls
docker ps -a --filter name=buildx_buildkit_pi-agentic-build-
# Remove ONLY the specific confirmed abandoned builder, not all builders:
docker buildx rm --force EXACT_ABANDONED_BUILDER_NAME
```

## Runtime observation

Before final cleanup, `process.json` records a subset of container state and
HostConfig (`NanoCpus`, `CpuPeriod`, `CpuQuota`, `Memory`, `MemorySwap`, `PidsLimit`),
when inspection is available. OOM status is retained and cannot become exit 0.
A killed/timed-out container may have been removed before observation; the missing
observation is recorded rather than invented.

While a stage runs, use these on the parent host:

```bash
docker ps --filter label=org.pi-agentic-development.managed=1
docker stats --no-stream
docker inspect CONTAINER_ID --format \
  'CPU={{.HostConfig.NanoCpus}} memory={{.HostConfig.Memory}} swap={{.HostConfig.MemorySwap}} pids={{.HostConfig.PidsLimit}}'
```

For your *already running* interactive Pi container, a separate manual change is:

```bash
docker update --cpus 1.5 pi-workspace
```

This changes only that container's CPU quota. It is not persistent policy for
future `docker run` commands. Do not lower a running process's memory limit below
its usage; recreate it with a reviewed memory setting instead. The packaged runner
sets limits on every new container and never edits unrelated running containers.

## Limits of these limits

The local LLM server is separate. A request can consume CPU, RAM, GPU memory, and
GPU compute there regardless of the Pi client's quota. Configure server-side
request concurrency, context limits, and CPU/GPU budgets independently. Default
sequential agents reduce overlapping requests but are not a server-wide limit.
For a local model server (for example Unsloth), keep the default one-stage-at-a-time
execution and do not add parallel agents until its parallel-request and loaded-context
settings have been checked in Unsloth; a 262144-token context multiplies memory use
per concurrent request.

Docker Desktop's Settings > Resources controls the whole VM's CPU/RAM allocation.
Leave capacity for the desktop and model server. Per-container headroom does not
guarantee responsiveness when other applications are already consuming it.
CPU throttling may cause legitimate tests to need longer wall-time budgets.

This package does not enforce disk quotas or network egress bandwidth. Snapshot
input size and captured logs are bounded, but generated workspace files and
package caches can grow. Use a quota-backed working volume/VM where disk exhaustion
is a concern. Do not describe these controls as limiting *all* host resources.

Primary references:
- https://docs.docker.com/engine/containers/resource_constraints/
- https://docs.docker.com/build/builders/drivers/docker-container/
- https://docs.docker.com/build/buildkit/configure/
- https://docs.docker.com/reference/cli/docker/container/update/
- https://docs.docker.com/desktop/settings-and-maintenance/settings/

Registry-aware admission also reports `host-registry-unsafe` with bounded guidance
when ownership, daemon identity, writer absence or sensitive/inference cleanup
cannot be reconciled. Do not delete the registry or bypass its host lease.

`host-registry-capacity` means the finite ownership inventory cannot admit another
intent or the planned collection's headroom. The registry retains at most 8192
committed records; observation separately bounds 32 secure atomic temporary files.
New container, network and builder intents reject before creation at capacity;
existing-record cleanup updates remain possible. Records are not automatically
deleted or archived, since abandoned-attempt reconciliation can require released
ownership history. Request reviewed maintenance or a separately reviewed bounded
capacity change; never delete records or select another lock to continue. This
host metadata bound does not increase Docker worker or inference concurrency.

## Indexed inference opt-in

Indexed execution reserves the inference helper even for a single worker. `assets/resources/indexed-workers.json` selects 1 CPU, 1536 MiB and 512 PIDs per worker; the helper requires another 0.25 CPU, 128 MiB and 64 PIDs. Selected route queue plus upstream deadlines must fit every effective Pi-stage budget; see [INFERENCE-ENVIRONMENTS.md](INFERENCE-ENVIRONMENTS.md).
