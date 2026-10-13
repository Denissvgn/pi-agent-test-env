"""Classify host prerequisite failures into a stable reason code plus a concrete remedy.

A parent agent must not end a session with "could not start". Every blocker
returned here names what failed and the next action the user or agent can take.
"""
from __future__ import annotations

SANDBOX_HINT = ('If this command runs inside an AI agent\'s command sandbox, the sandbox (not Docker) may be '
                'denying access: re-run the SAME command with elevated/unsandboxed execution after the user '
                'approves it. Never mount the Docker socket into a Pi child to work around this.')

REMEDIES = {
    'unsupported-pi-release': 'Select an explicitly reviewed Pi 0.87.1 or 1.2.0 native image. Verify the observed version and contract; do not bypass admission or fall back to another release.',
    'browser-sandbox-blocked': 'Review BROWSER.md and the explicit chromium-userns policy. Qualify it with browser-check on the selected native image, then freeze a new admitted run. Do not disable Chromium sandboxing, add capabilities or silently change a frozen campaign.',
    'docker-cli-missing': 'Install Docker Desktop (macOS/Windows) or Docker Engine (Linux) on the host, then re-run `doctor`.',
    'docker-permission-denied': SANDBOX_HINT + ' Outside a sandbox: make sure Docker Desktop is running as this user; '
                                'on Linux add the user to the `docker` group and log in again, or use rootless Docker with DOCKER_HOST set.',
    'docker-daemon-unavailable': 'Start Docker Desktop (macOS: `open -a Docker`) or the engine (Linux: `sudo systemctl start docker`), '
                                 'wait until `docker info` succeeds, then re-run. Check `docker context ls` points to the local engine. ' + SANDBOX_HINT,
    'docker-context-invalid': 'Select a valid local context: `docker context ls`, then `docker context use desktop-linux` (Docker Desktop) or `default`.',
    'docker-remote': 'This runner needs a local daemon because bind sources must exist on the daemon host. Run the orchestrator on that host.',
    'docker-error': 'Run `docker info` in a terminal to see the full error. ' + SANDBOX_HINT,
    'missing-secret': 'Store the key once with hidden terminal input: `python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set {name}` '
                      '(the user types it; it is never shown or written to the project). Or export {name} in the parent shell, '
                      'or pipe it: `<password-manager command> | python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set {name} --stdin`. '
                      'Never ask the user to paste a key into chat.',
    'secret-store-insecure': 'Fix the secret file permissions (`chmod 600 <file>`, owned by you, not a symlink) or re-run `secrets set`.',
    'endpoint-unreachable': 'Check the model server is running and listens on the LAN interface, the firewall allows the port, '
                            'and the base_url host/port are right. ' + SANDBOX_HINT.replace('Docker', 'the network'),
    'endpoint-auth-failed': 'The server rejected the key. Store the correct one: `python3 "$SKILL_DIR/scripts/pi_lab.py" secrets set {name}`.',
    'model-not-found': 'The exact model ID is not in /v1/models. Load it on the server, or correct `model` in the endpoint file. No fallback model is allowed.',
    'environment-missing': 'No saved model environment. Ask the user for the server base URL, run `env discover`, let the user choose a model, and `env save`.',
    'environment-no-environment': 'No saved model environment. Ask the user for the server base URL, run `env discover`, let the user choose a model, and `env save`.',
    'environment-needs-confirmation': 'Show the saved environment to the user; on approval run `env confirm --session ID`, otherwise run discover/save for a new one.',
    'environment-broken': 'The saved environment fails its live check. Tell the user the reason and ask whether to fix the variable or set up a new environment.',
    'image-missing': 'Reuse or build the image: `python3 "$SKILL_DIR/scripts/pi_lab.py" ensure-image --image {image} --policy auto ...` (see SKILL.md section 3).',
}


def remedy(reason: str, **fields) -> str:
    text = REMEDIES.get(reason, REMEDIES['docker-error'])
    try:
        return text.format(**fields)
    except (KeyError, IndexError):
        return text


def classify_docker_error(text: str) -> str:
    low = (text or '').lower()
    if 'permission denied' in low or 'operation not permitted' in low or 'access is denied' in low:
        return 'docker-permission-denied'
    if 'context' in low and ('not found' in low or 'does not exist' in low):
        return 'docker-context-invalid'
    if any(s in low for s in ('cannot connect to the docker daemon', 'is the docker daemon running',
                              'connection refused', 'no such file or directory', 'error during connect',
                              'docker desktop is not running', 'failed to connect')):
        return 'docker-daemon-unavailable'
    return 'docker-error'


def first_line(text: str, limit: int = 300) -> str:
    for line in (text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''
