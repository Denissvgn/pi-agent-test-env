# Chromium user-namespace seccomp policy

`moby-default.json` is copied unchanged from
[moby/profiles at 4b8214fc4971e06172938a1f1554ccff6647ee80](https://github.com/moby/profiles/blob/4b8214fc4971e06172938a1f1554ccff6647ee80/seccomp/default.json).
Its SHA-256 is `514c38e72edc5363e87287ea87212211172c6c3251a974ca21ebfd05a56c7f5d`.
The upstream profile is Apache-2.0 licensed; [LICENSE.moby](LICENSE.moby) is retained.
It is a pinned upstream policy, not an assertion that it equals every installed
Docker daemon's built-in default. Review updates independently of Docker upgrades.

`chromium-userns.json` preserves that complete base and adds exactly ten rules:

- Seven `clone` allow rules on argument 0, masking `0x7e020000`; only nonempty
  combinations of USER (`0x10000000`), PID (`0x20000000`) and NET (`0x40000000`)
  namespace bits match. Mount/UTS/IPC namespace flags remain denied.
- Two exact `unshare` argument values: USER and PID|NET (`0x60000000`).
- `chroot`, used by Chromium to discard filesystem access inside its own user
  namespace. Kernel capability checks still reject chroot in the outer process,
  whose effective capabilities are zero. Seccomp cannot filter pathname strings.

No unrestricted clone/unshare/setns permission, clone3 permission, capability,
mount or seccomp opt-out is added. The base's existing argument filters and
capability conditions remain intact. Chromium creates capabilities inside its
new user namespace; those do not grant capabilities in the outer container/host
namespace. Allowing user namespaces exposes additional kernel code and therefore
requires an explicit container-policy selection, even with Chromium sandboxing on.

The reviewed delta follows Chromium's
[namespace sandbox](https://github.com/chromium/chromium/blob/main/sandbox/linux/services/namespace_sandbox.cc)
and [filesystem isolation](https://github.com/chromium/chromium/blob/main/sandbox/linux/services/credentials.cc).
Playwright documents a [broader namespace seccomp recipe](https://playwright.dev/docs/docker);
this package uses its narrower fixed delta, retains zero outer capabilities and
does not adopt host IPC or SYS_ADMIN recommendations.

`browser_security.py` admits only the exact SHA-256
`a424392ea9e982712eda600d3502269d59c18b8d13287c1022097b55daef7621`, with no caller-provided
policy path. Runs freeze an owner-only parent copy and recheck it before every
container launch. The initial qualified platform is native Linux ARM64.
