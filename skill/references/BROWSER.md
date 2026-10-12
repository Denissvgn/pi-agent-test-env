# Real browser and UI tests

## Native Linux browser, not a host application

Use `--profile browser`. The bundled Dockerfile installs Debian Chromium and fonts
at build time for the selected Linux architecture. A Linux ARM64 container cannot
run macOS Chrome from `/Applications/...`; an x86-64 Chrome-for-Testing download is
not a native ARM64 Linux binary. Prefer native packages or a reviewed compatible
browser image. Do not mask an architecture mismatch with an invented loader path
or an automatic `--platform linux/amd64` fallback.

Reused image checks locate a runnable `chromium`/`chromium-browser` and record its
version. The workflow then runs a real headless DOM/JavaScript smoke before agents.
This proves browser execution, not application correctness or GPU performance.

## Launch configuration

Tests must honor the explicit Linux executable, even when using `puppeteer-core`:

```javascript
import puppeteer from 'puppeteer-core';
import { browserOptions } from '/opt/pi-lab/browser-options.mjs';

const browser = await puppeteer.launch(browserOptions());
try {
  const page = await browser.newPage();
  await page.goto(process.env.TEST_BASE_URL, { waitUntil: 'networkidle0' });
  // Assert observable behavior, input handling, errors, and persistence.
} finally {
  await browser.close();
}
```

Confirm the helper's actual export before copying this pattern. Install the
project's tested Puppeteer version through its lockfile. The skill does not choose
or claim compatibility for an arbitrary Puppeteer/Chromium combination.

The helper sets a temporary user profile below `TMPDIR`, uses
`--disable-dev-shm-usage` for `--ipc=none`, and honors the explicit sandbox/WebGL
permissions. Profile/cache/temp directories remain under the isolated `/pi-state` runtime. Do not
add a writable `/tmp`, host IPC, or a writable root to fix a hardcoded path; patch
the test to use its assigned temporary directory.

Playwright usually expects its matching browser build. Use an audited image with
the matching Playwright/browser versions or a explicitly verified `executablePath`
configuration. Do not assume a system Chromium that works with Puppeteer also
passes every Playwright test. Environment probes can verify required commands;
project checks must verify actual browser behavior.

## Static and application servers

For a static application:

```bash
python3 /opt/pi-lab/with-http-server.py --port 4173 -- node tests/ui.acceptance.mjs
```

For an actual application server:

```bash
python3 /opt/pi-lab/with-service.py \
  --start-json '["npm", "run", "start:test"]' \
  --ready-url http://127.0.0.1:4173/health \
  --ready-timeout 60 --test-timeout 300 \
  -- node tests/ui.acceptance.mjs
```

Both are examples; inspect the real app command/port and include necessary build
steps. Readiness and tests execute in the same container, so they can use loopback
without external network. CDN scripts, remote assets, and external APIs still need
explicit network approval or a reviewed local test fixture. A `file://` URL is not
a universal replacement for an HTTP application.

## Sandbox and WebGL

Keep the browser sandbox enabled. With `cap-drop=ALL` and
`no-new-privileges=true`, Chromium cannot use its setuid helper; its unprivileged
USER/PID/NET namespace path needs a compatible seccomp/kernel policy. Docker's
default profile may deny those operations. This is an environment-admission
failure, not evidence that the application or Pi is defective. Missing executable,
namespace denial, missing chroot permission, OOM and absent sandbox observations
must remain separate failures.

The default `--browser-sandbox-policy docker-default` remains unchanged and never
falls back. An explicit `--browser-sandbox-policy chromium-userns` selects the
[pinned policy](../assets/security/README.md) on native Linux ARM64, while retaining
non-root execution, zero outer capabilities, no-new-privileges, read-only root,
configured network/IPC isolation and finite resource limits. Its exact namespace
and chroot syscall permissions change the container policy for every process in
that browser-profile container, including Bash; review this scope before selection.
No arbitrary seccomp file, SYS_ADMIN, privileged container or unconfined policy
is admitted. `chromium-userns` rejects `--allow-browser-no-sandbox`, the core profile and
daemons whose observed native architecture is not ARM64. Selected ARM64 images
under emulation cannot qualify native admission. Kernels/LSM policies can still prohibit user namespaces; no global host
sysctl or AppArmor setting is changed automatically.

Use the independent credential-free gate before application deployment/dispatch:

```bash
python3 "$SKILL_DIR/scripts/pi_lab.py" browser-check \
  --image "$IMAGE" --platform linux/arm64 \
  --browser-sandbox-policy chromium-userns \
  --resources "$SKILL_DIR/assets/resources/browser.json" \
  --cpus 2 --memory 2g --pids-limit 512 --results-dir /path/to/evidence
```

This gate always requires sandboxing and rejects `--allow-browser-no-sandbox`
before Docker admission. It also requires a known matching native daemon platform.
The separate trusted opt-out route remains available for ordinary browser runs.

This command needs no model session or application key and invokes no Pi
participant/model. It inspects the selected image, tests DOM/JavaScript and
requires Chromium's `chrome://sandbox` report to show Namespace, PID/network
namespaces and seccomp-BPF active. Missing/changed diagnostic labels fail closed;
a successful launch or a no-sandbox flag being absent is insufficient. Receipts
retain selected policy bytes/hash, exact command, image/host, actual observations,
applied limits and container cleanup. Exit 0 qualifies only this narrow browser
scope; exit 2 blocks admission. Browser/application clients still need separate
navigation, cookies, login/OIDC, API/WebGL and mutation/readback tests.

Use the same explicit policy with `ensure-image`, `doctor`, `preflight`, `smoke`
and `run --profile browser`. Experiment execution may declare `profile: "browser"`
and `browser_sandbox_policy: "chromium-userns"`; these choices and the policy
identity enter the frozen configuration. A source/runner/policy change requires
fresh experiments and qualification. Do not silently modify a frozen campaign or
relabel its blocked episodes. Its operator must admit the new policy and install
this package before preparing a new run. Existing core/endpoint receipts retain
their original scoped identities.

For explicitly trusted local content only, the parent may separately select
`--allow-browser-no-sandbox` under the default container policy. That opt-out
cannot satisfy a contract requiring sandboxing. The browser-options helper rejects
sandbox-disable arguments, including GPU sandbox opt-outs and their `=...` forms,
supplied through `extra.args` without the explicit opt-out.

WebGL tests in Docker Desktop may have no hardware GPU. Explicit `--software-webgl`
adds SwiftShader flags and makes the browser smoke require a WebGL context. This
uses CPU and is not a GPU benchmark. The unsafe SwiftShader permission and browser
sandbox opt-out are independent. Neither is enabled automatically.

The browser and its subprocesses share the runtime CPU/RAM/PID budget. The
`assets/resources/browser.json` preset increases the task count to 512, not CPU
or RAM. Do not respond to resource pressure with unrestricted workers. Review
bounded memory/time adjustments and meaningful per-project test concurrency.

## Required evidence

Capture asserted UI outcomes, browser console/runtime errors, test counts, relevant
screenshots, and the command's exit status. Store generated UI artifacts under the
stage runtime directory or an approved output path, and identify them in the final
report. A successful DOM smoke, screenshot alone, or agent saying "looks correct"
is not acceptance. Independent tests run after agent work in a fresh container.

Sources:
- https://pptr.dev/troubleshooting
- https://pptr.dev/guides/configuration
- https://pptr.dev/api/puppeteer.launchoptions
- https://packages.debian.org/bookworm/chromium
- https://chromium.googlesource.com/chromium/src/+/main/docs/gpu/swiftshader.md
