# Primary sources and verification notes

Original general-source list reviewed on 2026-10-05; release-specific Pi inspection
added on 2026-10-07. Mutable references below are background reading, not pins.
[PI-COMPATIBILITY.md](PI-COMPATIBILITY.md) defines the exact 0.87.1 source-inspected
candidate at `f07218c4d4bbc12bef056a7058c3dd49dfe41abe`, artifact integrity,
mandatory/optional interfaces and scoped native runtime evidence. It does
not automatically select that version or qualify a different user configuration.

## Skill format and Pi

- Agent Skills format: https://agentskills.io/specification
- Pi skills: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/skills.md
- Pi model configuration: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/models.md
- Pi CLI: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/cli.md
- Pi JSON lifecycle: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/json.md
- Message types: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/message-types.md
- Pi isolation: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/containerization.md
- Pi security boundaries: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/security.md

Use the immutable source links in PI-COMPATIBILITY.md for lifecycle, continuation, reasoning and sampling.
General links above describe concepts and can change. Different versions expose
different events/settings; help-string probes and explicit legacy mode alone do
not qualify a release or establish application correctness. A different requested
release needs its own contract/evidence or an unsupported result, with no
automatic substitution.

## Docker resource and filesystem controls

- CPU/RAM/swap: https://docs.docker.com/engine/containers/resource_constraints/
- Docker-container Buildx driver limits: https://docs.docker.com/build/builders/drivers/docker-container/
- BuildKit parallelism: https://docs.docker.com/build/buildkit/configure/
- Buildx build/load: https://docs.docker.com/reference/cli/docker/buildx/build/
- Updating existing runtime limits: https://docs.docker.com/reference/cli/docker/container/update/
- Docker Desktop allocation: https://docs.docker.com/desktop/settings-and-maintenance/settings/
- Container options: https://docs.docker.com/engine/containers/run/
- Bind mounts and daemon-side paths: https://docs.docker.com/engine/storage/bind-mounts/
- Build contexts: https://docs.docker.com/build/building/context/
- Multi-platform images: https://docs.docker.com/build/building/multi-platform/

The package's particular defaults (2 CPUs/4 GiB/half of the daemon allocation),
policy presets, host lock, stage orchestration, environment contracts, and evidence
gates are design choices in this package, not universal Docker/Pi recommendations.
Per-container limits do not cap unrelated processes or the model server.

## Browser testing

- Puppeteer troubleshooting: https://pptr.dev/troubleshooting
- Puppeteer configuration: https://pptr.dev/guides/configuration
- Browser launch options: https://pptr.dev/api/puppeteer.launchoptions
- Native Debian Chromium: https://packages.debian.org/bookworm/chromium
- Chromium SwiftShader: https://chromium.googlesource.com/chromium/src/+/main/docs/gpu/swiftshader.md

These support using the correct Linux executable/architecture, explicit browser
paths, and treating disabled browser sandbox/unsafe software rendering as optional
weakened modes rather than automatic fixes. Browser launch does not prove a UI test.

## Source and test provenance

This is a revised workflow package built from the user-provided
`pi-local-agent-tests.zip`. It is not an official Pi/Docker/Unsloth release. The
English documentation, generic templates, resource policy/builder code, and new
tests are part of this revision. No upstream source files or font assets are
redistributed. Test fixtures simulate protocol data only for unit testing.
