# Indexed inference examples

Read [the indexed environment workflow](../../references/INFERENCE-ENVIRONMENTS.md)
first. Profile IDs here are synthetic placeholders for explicit, separately
confirmed selections; no real URL, model or key belongs in these files.

Use `roles.plan.json` with the packaged `application-baseline/project` for a
standalone implementation/review pipeline. Its map owns both assignments, so omit
`--inference-env`. For a uniform single run, use `application.plan.json` from the
application-baseline folder with `--inference-env builder-local`.

`configure.py` renders serial, parallel and role-map schema-3 definitions from an
exact reviewed ARM64 image receipt. It performs no Docker/model calls or secret
reads. The role example uses `external.plan.json`, whose bindings belong solely to
the variants. Every source/score and stage budget is frozen before dispatch.

The included worker policy selects 1 CPU, 1536 MiB, 512 PIDs and one thread hint;
the broker adds 0.25 CPU, 128 MiB and 64 PIDs. Parallel definitions explicitly
permit two workers and one inference request. Deployment capacity remains unknown
unless separately declared. Native qualification is still required.

The recorded native ARM64 campaign passed on Pi 0.87.1 and 1.2.0 using two
credential references against the same retained backend/model; see
[QUALIFICATION.md](../../QUALIFICATION.md). Qualify your own selected scope before
execution. This evidence does not establish distinct-backend/model/API support.
