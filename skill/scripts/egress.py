"""Network modes of stage containers, and the endpoint-only mode (host side).

`--network endpoint-only` gives agent and preflight containers one owned Docker
network created with --internal. The only other member is a relay container that
is also attached to the default bridge and forwards TCP to the host and port of
the endpoint's container route (runtime/egress_relay.py). Before a key enters any
container a proof runs: a canary listens on the default bridge, a control probe
on the bridge must reach it, and an inside probe on the internal network must
fail to reach the canary, the bridge gateway, the internal network's own gateway
and a public name, and must reach the relay. Any other result blocks the run.

The mode restricts where a container can connect. It does not inspect what is
sent to the endpoint. Every resource is labelled, registered in the ownership
registry when one is active, and removed with absence confirmed on every exit.
"""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

import ownership_registry
import stage_control as controls

MODE = 'endpoint-only'
HELPER = '/opt/pi-lab/egress_relay.py'
SESSION_LABEL = 'org.pi-agent-test-env.egress'
ROLE_LABEL = 'org.pi-agent-test-env.egress-role'
MANAGED_LABELS = ('--label=org.pi-agent-test-env.managed=1', '--label=org.pi-agentic-development.managed=1')
# Small fixed footprint of the relay, the canary and the probes. The relay keeps
# at most 32 connections with two threads each.
HELPER_MEMORY = '64m'
HELPER_CPUS = '0.5'
HELPER_PIDS = '128'
CANARY_PORT = 18080
# Reserved for documentation and publicly resolvable; only its resolution is tried.
PUBLIC_NAME = 'example.com'
NATIVE_BUDGET_FIELDS = {'max_tool_calls', 'reporting_reserve_calls', 'reporting_reserve_seconds'}
# Outcomes that count as blocked. `refused` never does: a reset means that a host
# on that address replied. The canary is known to listen, so silence is enough
# for it. For an address of the engine host only the kernel's own "no route" or
# "no such neighbour" counts: a host that silently drops one port may answer on
# another.
CANARY_BLOCKED = ('unreachable', 'timeout')
HOST_BLOCKED = ('unreachable',)
NAME_BLOCKED = ('unresolved', 'timeout')

REMEDIES = {
    'network-mode-refused': 'Use --network none, bridge, endpoint-only or the name of an existing user-defined '
                            'Docker network. host and container:<id> remove the network boundary of the child; '
                            'they are accepted only with --allow-host-network after reading SECURITY.md.',
    'feature-conflict': 'Use --network endpoint-only only with a plain run, smoke or preflight and an explicit or '
                        'saved endpoint. Experiment commands, --inference-env and indexed or parallel execution, '
                        'compiled application plans and native tool budgets manage their own networks: keep '
                        '--network bridge for them.',
    'egress-route-unsupported': 'Give the endpoint a host name in base_url (for a server on this host: '
                                'host.docker.internal, with --host-gateway on Linux). An https URL with an IP '
                                'literal cannot be relayed without failing the certificate check, and a loopback '
                                'address means the container itself.',
    'egress-not-contained': 'No key entered a container. Read network.proof in the run record, or run '
                            '`doctor --egress-proof`, to see which probe reached what. Do not use endpoint-only '
                            'on this Docker engine until the proof passes; update Docker, or choose another '
                            'network mode knowing that it does not restrict destinations.',
    'egress-relay-exited': 'The relay between the stage containers and the model endpoint is not running. Read '
                           'egress/relay.log in the run directory and start a new run; no stage is started '
                           'without the relay.',
    'egress-proof-unavailable': 'Run `doctor` without --egress-proof to check Docker and the image, then repeat '
                                'the proof with an admitted local image.',
    'egress-cleanup-unconfirmed': 'Run `docker ps -a` and `docker network ls` with the filter '
                                  f'label={SESSION_LABEL} and remove what is listed, or start any run under the '
                                  'same host lock: the ownership registry reconciles its own leftovers.',
}


def _blocker(lab, message, reason):
    return lab.LabError(message, reason, REMEDIES[reason])


def _host_mode(value):
    return value == 'host' or (isinstance(value, str) and value.startswith('container:'))


def _self_managed(args):
    """Execution kinds that create and own their networks."""
    return bool(getattr(args, 'inference_env', None) or getattr(args, '_indexed_plan_selection', False)
                or getattr(args, '_indexed_session', None) or getattr(args, '_parallel_session', None)
                or getattr(args, 'compiled_plan', None) or getattr(args, '_experiment_root', None))


def _indexed_plan(args):
    """A schema 2 plan selects indexed execution by itself; its own errors are reported later."""
    if not getattr(args, 'plan', None):
        return False
    try:
        value = json.loads(Path(args.plan).expanduser().read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 2


def validate_request(lab, args):
    """Refuse an unsafe or conflicting --network before any Docker action."""
    mode = getattr(args, 'network', 'bridge')
    if _host_mode(mode):
        if not getattr(args, 'allow_host_network', False):
            raise _blocker(lab, f'--network {mode} shares a host or container network namespace with the child '
                                'and is refused by default', 'network-mode-refused')
        return
    if not isinstance(mode, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', mode) is None:
        raise _blocker(lab, '--network must be none, bridge, endpoint-only or a Docker network name',
                       'network-mode-refused')
    if mode == MODE and (_self_managed(args) or _indexed_plan(args)):
        raise _blocker(lab, '--network endpoint-only cannot be combined with experiment commands, --inference-env, '
                            'indexed or parallel execution or a compiled application plan', 'feature-conflict')


def experiment_network(lab, value):
    """Experiment definitions freeze a network name; they cannot select these modes."""
    if value == MODE:
        raise _blocker(lab, 'Experiment commands cannot use the endpoint-only network mode', 'feature-conflict')
    if _host_mode(value):
        raise _blocker(lab, 'Experiment commands cannot use the host network', 'network-mode-refused')


def route(lab, endpoint):
    """Classify the container route with the ipaddress module; refuse what cannot be relayed."""
    url = urlsplit(endpoint['base_url'])
    host = url.hostname or ''
    port = url.port or (443 if url.scheme == 'https' else 80)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is None:
        if host == 'localhost' or host.endswith('.localhost'):
            raise _blocker(lab, 'The endpoint route names the loopback host; a relay cannot reach it',
                           'egress-route-unsupported')
        return {'kind': 'name', 'scheme': url.scheme, 'host': host, 'port': port}
    if literal.is_loopback or literal.is_unspecified:
        raise _blocker(lab, 'The endpoint route is a loopback or unspecified address; a relay cannot reach it',
                       'egress-route-unsupported')
    if url.scheme == 'https':
        raise _blocker(lab, 'The endpoint route is https with an IP literal; endpoint-only needs a host name',
                       'egress-route-unsupported')
    return {'kind': 'ip-literal', 'scheme': url.scheme, 'host': host, 'port': port}


def _stage_policy(args):
    mode = getattr(args, 'network', 'bridge')
    inherited = 'bridge' if mode == MODE else mode
    policy = {'image_probe': 'none', 'preflight': mode}
    if hasattr(args, 'allow_setup_network'):
        policy.update(boundary='none', browser='none', agent=mode, setup='none', check='none',
                      setup_inherit=inherited if args.allow_setup_network else 'refused',
                      check_inherit=inherited if getattr(args, 'allow_check_network', False) else 'refused')
    return policy


def admit(lab, args, endpoint=None, plan=None):
    """Validate the selected mode after the host check and return the record block.

    Nothing is created here. A named network must already exist; its existence
    is checked only for a plain run, because other owners create theirs later.
    """
    mode = getattr(args, 'network', 'bridge')
    validate_request(lab, args)
    record = {'mode': mode, 'stages': _stage_policy(args)}
    if _host_mode(mode):
        record['host_network_allowed'] = True
    elif mode == MODE:
        if plan is not None and any(NATIVE_BUDGET_FIELDS & set(task) for task in plan.get('agents', [])):
            raise _blocker(lab, '--network endpoint-only cannot be combined with native tool budgets; their '
                                'helper owns the stage network', 'feature-conflict')
        selected = route(lab, endpoint)
        record.update(allowed={'host': selected['host'], 'port': selected['port']},
                      route={'kind': selected['kind'], 'scheme': selected['scheme']},
                      url_rewritten=False, proof=None)
    elif mode not in ('none', 'bridge') and not _self_managed(args):
        reply = _docker(lab, ['docker', 'network', 'inspect', '--format', '{{.Name}}', mode], 15)
        if reply.returncode:
            raise _blocker(lab, f'--network {mode}: no such Docker network on this host', 'network-mode-refused')
    return record


def _docker(lab, argv, timeout=30):
    """A bounded Docker call that reports failure instead of raising."""
    try:
        return lab.command(argv, timeout=timeout, required=False)
    except lab.LabError as exc:
        return argparse.Namespace(returncode=1, stdout='', stderr=str(exc))


def _last_json(text, key):
    for line in reversed((text or '').splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and key in value:
            return value
    return None


def evaluate(control, inside, nonce, internal_gateway, relay_banner):
    """Decide the proof from the two probe reports. Missing data fails closed."""
    def outcome(report, name):
        entry = (report or {}).get('tcp', {}).get(name)
        return entry.get('outcome') if isinstance(entry, dict) else None

    def name_outcome(report):
        entry = (report or {}).get('resolve', {}).get('public_name')
        return entry.get('outcome') if isinstance(entry, dict) else None

    reported = isinstance(inside, dict) and inside.get('egress_probe') == 1
    canary = ((control or {}).get('tcp', {}).get('canary') or {})
    relay = ((inside or {}).get('tcp', {}).get('relay') or {})
    checks = {
        'control_reaches_canary': canary.get('outcome') == 'connected' and canary.get('banner') == nonce,
        'inside_blocked_canary': outcome(inside, 'canary') in CANARY_BLOCKED,
        'inside_blocked_bridge_gateway': outcome(inside, 'bridge_gateway') in HOST_BLOCKED,
        'inside_blocked_internal_gateway': (not internal_gateway and reported
                                            or outcome(inside, 'internal_gateway') in HOST_BLOCKED),
        'inside_public_name_unresolved': name_outcome(inside) in NAME_BLOCKED,
        'inside_no_ipv6_interface': reported and inside.get('ipv6_interfaces') == [],
        'inside_reaches_relay': relay.get('outcome') == 'connected' and (not relay_banner or relay.get('banner') == nonce),
    }
    return checks


class Incomplete(Exception):
    """A proof step that could not be carried out; the mode stays blocked."""
    def __init__(self, step, detail=''):
        super().__init__(step)
        self.step = step
        self.detail = detail


class Session:
    """One owned internal network with its relay, and the containment proof."""

    def __init__(self, lab, args, image, helpers, upstream=None, mapped_host=None, evidence=None):
        if re.fullmatch(r'sha256:[a-f0-9]{64}', image or '') is None:
            raise lab.LabError('The endpoint-only mode needs an immutable image identifier')
        self.lab = lab
        self.args = args
        self.image = image
        self.helpers = Path(helpers).resolve()
        self.upstream = upstream
        self.mapped_host = mapped_host
        self.evidence = Path(evidence) if evidence is not None else None
        self.registry = ownership_registry.CURRENT.get()
        self.id = uuid.uuid4().hex[:12]
        self.network = 'pi-lab-egress-' + self.id
        self.network_record = None
        self.network_attempted = False
        self.containers = {}
        self.relay = None
        self.relay_address = None
        self.relay_port = None
        self.relay_exit = None
        self.dns_override = False
        self.ready = False
        self.proof = None
        self.closed = None

    def _run_label(self):
        """The run these resources belong to, so that a per-run cleanup finds them."""
        return ownership_registry.run_label((getattr(self.args, '_attempt_identity', None) or {}).get('run_id'))

    # Construction of Docker arguments. No key and no inherited variable is passed.
    def _labels(self, role, record):
        labels = ['--label', SESSION_LABEL + '=' + self.id, '--label', ROLE_LABEL + '=' + role, *MANAGED_LABELS,
                  '--label', self._run_label()]
        if record is not None:
            labels += ['--label', ownership_registry.LABEL + '=' + record['launch_id'],
                       '--label', ownership_registry.REGISTRY_LABEL + '=' + self.registry.registry_id]
        return labels

    def _container(self, verb, name, role, network, operation, options=()):
        record = self._intent(name, role)
        args = self.args
        argv = ['docker', *verb, '--name', name, '--init', '--platform', args.platform, *self._labels(role, record),
                '--read-only', '--user', f'{args.uid}:{args.gid}', '--cap-drop=ALL',
                '--security-opt=no-new-privileges=true', '--ipc=none', '--pids-limit', HELPER_PIDS,
                '--memory', HELPER_MEMORY, '--memory-swap', HELPER_MEMORY, '--cpus', HELPER_CPUS,
                '--network', network, '--workdir=/', '--entrypoint=python3',
                '--mount', f'type=bind,src={self.helpers},dst=/opt/pi-lab,readonly,bind-recursive=disabled',
                '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTHONUNBUFFERED=1', '--env', 'PI_LAB_API_KEY=',
                *options, self.image, HELPER, *operation]
        return argv

    def _intent(self, name, role):
        """Persist ownership before the Docker call, in the shape of a stage launch."""
        self.containers[name] = None
        if self.registry is None:
            return None
        record = {'schema': ownership_registry.SCHEMA, 'launch_id': str(uuid.uuid4()),
                  'generation': self.registry.generation, 'registry': self.registry.registry_id,
                  'status': 'intent', 'container': name, 'image': self.image,
                  'mounts': [{'source': str(self.helpers), 'target': '/opt/pi-lab', 'rw': False}],
                  'binding': {**self.registry.binding, 'egress_role': role}, 'runroot': None,
                  'created_at': controls.now(), 'owner_pid': os.getpid(), 'daemon': self.registry.daemon}
        self.registry.write(record)
        self.containers[name] = record
        return record

    def stage_options(self):
        """Network options shared by stage containers and the inside probe."""
        options = []
        if self.mapped_host:
            options += ['--add-host', f'{self.mapped_host}:{self.relay_address}']
        if self.dns_override:
            options += ['--dns', self.relay_address]
        return options

    def stage_arguments(self, argv):
        """Rewrite stage arguments built for the internal network.

        The host mapping of --host-gateway belongs to the relay, and the child
        sees the mode name instead of the generated network name.
        """
        result = []
        index = 0
        while index < len(argv):
            pair = argv[index:index + 2]
            if len(pair) == 2 and pair[0] == '--add-host' and pair[1].endswith(':host-gateway'):
                index += 2
            elif pair == ['--env', 'PI_LAB_NETWORK_MODE=' + self.network]:
                result += ['--env', 'PI_LAB_NETWORK_MODE=' + MODE]
                index += 2
            else:
                result.append(argv[index])
                index += 1
        result[-2:-2] = self.stage_options()
        return result

    # Resource creation.
    def _run(self, argv, timeout=30):
        return _docker(self.lab, argv, timeout)

    def _create_network(self):
        self.network_attempted = True
        if self.registry is not None:
            self.network_record = self.registry.network_intent(self.network)
        labels = ['--label', SESSION_LABEL + '=' + self.id, '--label', ROLE_LABEL + '=network',
                  '--label', 'org.pi-agent-test-env.managed=1', '--label', self._run_label()]
        if self.network_record is not None:
            labels += ['--label', ownership_registry.LABEL + '=' + self.network_record['launch_id'],
                       '--label', ownership_registry.REGISTRY_LABEL + '=' + self.registry.registry_id]
        # inhibit_ipv4 keeps the engine host without an address on this bridge;
        # whether that holds on the running engine is decided by the proof.
        reply = self._run(['docker', 'network', 'create', '--driver', 'bridge', '--internal', '--ipv6=false',
                           '--opt', 'com.docker.network.bridge.inhibit_ipv4=true', *labels, self.network])
        if reply.returncode:
            raise Incomplete('network_create', reply.stderr.strip()[:300])
        try:
            data = json.loads(self._run(['docker', 'network', 'inspect', self.network]).stdout)[0]
            pools = [item for item in data['IPAM']['Config']
                     if ipaddress.ip_network(item['Subnet']).version == 4]
            subnet = pools[0]['Subnet']
            gateway = pools[0].get('Gateway') or None
        except (ValueError, KeyError, IndexError, TypeError):
            raise Incomplete('network_inspect') from None
        if data.get('Internal') is not True:
            raise Incomplete('network_not_internal')
        return subnet, gateway

    def _bridge_gateway(self):
        try:
            data = json.loads(self._run(['docker', 'network', 'inspect', 'bridge']).stdout)[0]
            for item in data['IPAM']['Config']:
                gateway = item.get('Gateway')
                if gateway and ipaddress.ip_address(gateway).version == 4:
                    return gateway
        except (ValueError, KeyError, IndexError, TypeError):
            pass
        raise Incomplete('bridge_gateway_unknown')

    def _address(self, name, network):
        try:
            data = json.loads(self._run(['docker', 'container', 'inspect', name]).stdout)[0]
            address = data['NetworkSettings']['Networks'][network]['IPAddress']
            ipaddress.ip_address(address)
            return address
        except (ValueError, KeyError, IndexError, TypeError):
            raise Incomplete(name.rsplit('-', 1)[-1] + '_address') from None

    def _ready(self, name, key, seconds=20):
        deadline = time.monotonic() + seconds
        while True:
            line = _last_json(self._run(['docker', 'logs', name]).stdout, key)
            if line is not None and line[key] == 'ready':
                return line
            if time.monotonic() >= deadline:
                raise Incomplete(name.rsplit('-', 1)[-1] + '_not_ready')
            time.sleep(0.2)

    def _mark_running(self, name):
        record = self.containers.get(name)
        if record is not None:
            record['status'] = 'running'
            self.registry.write(record)

    def _start_canary(self, nonce):
        name = self.network + '-canary'
        argv = self._container(['run', '--detach'], name, 'canary', 'bridge',
                               ['canary', '--port', str(CANARY_PORT), '--token', nonce])
        if self._run(argv).returncode:
            raise Incomplete('canary_start')
        self._mark_running(name)
        address = self._address(name, 'bridge')
        self._ready(name, 'egress_canary')
        return address

    def _start_relay(self, subnet, upstream):
        name = self.network + '-relay'
        options = ['--sysctl', 'net.ipv4.ip_forward=0']
        if getattr(self.args, 'host_gateway', False):
            options += ['--add-host', 'host.docker.internal:host-gateway']
        argv = self._container(['create'], name, 'relay', self.network,
                               ['relay', '--listen-port', str(upstream[1]), '--upstream-host', upstream[0],
                                '--upstream-port', str(upstream[1]), '--allow', subnet], options)
        self.relay = name
        for step, command in (('relay_create', argv), ('relay_connect', ['docker', 'network', 'connect', 'bridge', name]),
                              ('relay_start', ['docker', 'start', name])):
            if self._run(command).returncode:
                raise Incomplete(step)
        self._mark_running(name)
        self.relay_address = self._address(name, self.network)
        self.relay_port = upstream[1]
        line = self._ready(name, 'egress_relay')
        if line.get('listen') != f'{self.relay_address}:{self.relay_port}':
            raise Incomplete('relay_listen_mismatch')

    def _probe(self, role, network, tcp=(), banner=(), options=()):
        name = self.network + '-' + role
        operation = ['probe']
        for flag, targets in (('--tcp', tcp), ('--banner', banner)):
            for label, host, port in targets:
                operation += [flag, f'{label}={host}:{port}']
        operation += ['--resolve', PUBLIC_NAME]
        reply = self._run(self._container(['run'], name, role, network, operation, options), 90)
        self._remove(name)
        report = _last_json(reply.stdout, 'egress_probe')
        if report is None:
            raise Incomplete(role + '_probe_failed', (reply.stderr or '').strip()[:300])
        # The public name is reported under a fixed key, not under its own name.
        report['resolve'] = {'public_name': report.get('resolve', {}).get(PUBLIC_NAME)}
        return report

    def open(self):
        """Create the resources and run the proof. No key is involved. Returns the proof."""
        proof = {'schema': 1, 'passed': False, 'incomplete': None, 'failed': [], 'checks': {},
                 'public_name': {'name': PUBLIC_NAME}, 'resolver': {'override': False}}
        self.proof = proof
        try:
            version = self._run(['docker', 'version', '--format', '{{.Server.Version}}'])
            proof['engine'] = {'server_version': version.stdout.strip() if not version.returncode else None}
            subnet, internal_gateway = self._create_network()
            bridge_gateway = self._bridge_gateway()
            proof['network'] = {'name': self.network, 'internal': True, 'subnet': subnet,
                                'gateway': internal_gateway, 'bridge_gateway': bridge_gateway}
            nonce = secrets.token_hex(16)
            canary_address = self._start_canary(nonce)
            proof['canary'] = {'address': canary_address, 'port': CANARY_PORT}
            # Without an endpoint the relay forwards to the canary, so the inside
            # probe also shows that bytes pass through it to its one destination.
            forwards_to_canary = self.upstream is None
            self._start_relay(subnet, self.upstream or (canary_address, CANARY_PORT))
            proof['relay'] = {'address': self.relay_address, 'port': self.relay_port,
                              'upstream': 'canary' if forwards_to_canary else 'endpoint'}
            control = self._probe('control', 'bridge', tcp=[('bridge_gateway', bridge_gateway, CANARY_PORT)],
                                  banner=[('canary', canary_address, CANARY_PORT)])
            proof['control'] = control
            blocked = [('canary', canary_address, CANARY_PORT), ('bridge_gateway', bridge_gateway, CANARY_PORT)]
            if internal_gateway:
                blocked.append(('internal_gateway', internal_gateway, CANARY_PORT))
            relay = [('relay', self.mapped_host or self.relay_address, self.relay_port)]
            targets = {'tcp': blocked + ([] if forwards_to_canary else relay),
                       'banner': relay if forwards_to_canary else []}
            control_name = (control['resolve']['public_name'] or {}).get('outcome')
            # Without a control that resolves the name, an unresolved name inside
            # proves nothing: the resolver setting is then applied as a precaution.
            self.dns_override = control_name != 'resolved'
            inside = self._probe('inside', self.network, options=self.stage_options(), **targets)
            checks = evaluate(control, inside, nonce, internal_gateway, forwards_to_canary)
            failing = [name for name, passed in checks.items() if not passed]
            if failing == ['inside_public_name_unresolved'] and not self.dns_override:
                # Only the engine's resolver answered for an outside name: retry with
                # the resolver setting that stage containers would then get.
                proof['inside_without_resolver_setting'] = inside
                self.dns_override = True
                inside = self._probe('inside-2', self.network, options=self.stage_options(), **targets)
                checks = evaluate(control, inside, nonce, internal_gateway, forwards_to_canary)
            proof['inside'] = inside
            proof['checks'] = checks
            proof['failed'] = sorted(name for name, passed in checks.items() if not passed)
            proof['public_name'].update(control=control_name,
                                        inside=(inside['resolve']['public_name'] or {}).get('outcome'),
                                        conclusive=control_name == 'resolved')
            proof['resolver'] = {'override': self.dns_override,
                                 'server': self.relay_address if self.dns_override else None}
            proof['passed'] = not proof['failed']
        except Incomplete as exc:
            proof.update(passed=False, incomplete=exc.step)
            if exc.detail:
                proof['detail'] = exc.detail
        finally:
            # The canary and the probes end with the proof; the relay stays for the stages.
            for name in [name for name in self.containers if name != self.relay]:
                self._remove(name)
            self._save('proof.json', proof)
        self.ready = proof['passed']
        return proof

    # Observation and removal.
    def relay_state(self):
        reply = self._run(['docker', 'container', 'inspect', '--format',
                           '{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}', self.relay], 15)
        parts = reply.stdout.split()
        if reply.returncode or len(parts) != 3:
            return {'status': 'unknown'}
        state = {'status': parts[0]}
        if parts[0] != 'running':
            state.update(exit_code=int(parts[1]) if parts[1].lstrip('-').isdigit() else None,
                         oom_killed=parts[2] == 'true')
        return state

    def _save(self, name, value):
        if self.evidence is None:
            return
        try:
            self.evidence.mkdir(parents=True, exist_ok=True)
            if isinstance(value, str):
                (self.evidence / name).write_text(value, encoding='utf-8')
            else:
                controls.atomic(self.evidence / name, value)
        except (OSError, ValueError, controls.ControlError):
            pass

    def _remove(self, name):
        """Remove one owned container and confirm that it is gone."""
        record = self.containers.get(name)
        self._run(['docker', 'rm', '--force', name])
        try:
            if record is not None:
                confirmed = self.registry.confirm_absent(record)
                if confirmed:
                    self.registry.release(record, True)
            else:
                confirmed = ownership_registry.absent(self._run(['docker', 'container', 'inspect', name], 15))
        except (OSError, ValueError, RuntimeError):
            # Registry and Docker failures alike leave the record pending for reconciliation.
            confirmed = False
        if confirmed:
            self.containers.pop(name, None)
        return confirmed

    def _remove_network(self):
        if not self.network_attempted:
            return True
        try:
            if self.network_record is not None:
                self.registry.remove_network(self.network_record)
                self.registry.release(self.network_record, True)
                return True
            self._run(['docker', 'network', 'rm', self.network])
            return ownership_registry.network_absent(self._run(['docker', 'network', 'inspect', self.network], 15),
                                                     self.network)
        except (OSError, ValueError, RuntimeError, LookupError):
            return False

    def _labelled(self, argv):
        reply = self._run([*argv, '--filter', f'label={SESSION_LABEL}={self.id}'], 15)
        return None if reply.returncode else [line for line in reply.stdout.splitlines() if line.strip()]

    def close(self):
        """Remove the relay, any remaining probe or canary and the network. Idempotent."""
        if self.closed is not None:
            return copy.deepcopy(self.closed)
        self.ready = False
        relay = None
        if self.relay is not None and self.relay in self.containers:
            state = self.relay_exit or self.relay_state()
            # A stopped relay prints its connection counts; no stream content exists in its output.
            self._run(['docker', 'stop', '--time', '2', self.relay], 20)
            logs = self._run(['docker', 'logs', '--tail', '50', self.relay], 15)
            counts = _last_json(logs.stdout, 'accepted') or {}
            relay = {'state_before_removal': state,
                     'connections': {key: counts[key] for key in ('accepted', 'rejected_peers', 'over_capacity',
                                                                  'upstream_failures') if key in counts} or None}
            self._save('relay.log', ((logs.stdout or '') + (logs.stderr or ''))[-65536:])
        removed = [self._remove(name) for name in list(self.containers)]
        network = self._remove_network()
        containers = self._labelled(['docker', 'ps', '--all', '--format', '{{.Names}}'])
        networks = self._labelled(['docker', 'network', 'ls', '--format', '{{.Name}}'])
        self.closed = {'confirmed': all(removed) and network and containers == [] and networks == [],
                       'remaining_containers': containers, 'remaining_networks': networks, 'relay': relay}
        return copy.deepcopy(self.closed)


def _failure(lab, proof):
    if proof.get('incomplete'):
        text = 'The egress containment proof could not be completed (' + proof['incomplete'] + ')'
    else:
        text = 'The egress containment proof failed: ' + ', '.join(proof.get('failed') or ['no result'])
    return _blocker(lab, text + '; no key was passed to a container', 'egress-not-contained')


def begin(lab, args, image, runroot, endpoint, record=None):
    """Start the mode for a run: resources, proof, then the endpoint the containers get.

    Returns the endpoint unchanged for other modes and for a named route. With an
    http IP literal the returned copy has the relay's address as host.
    """
    if getattr(args, 'network', 'bridge') != MODE:
        return endpoint
    validate_request(lab, args)
    selected = route(lab, endpoint)
    session = Session(lab, args, image['id'], lab.trusted_runtime(Path(runroot)),
                      upstream=(selected['host'], selected['port']),
                      mapped_host=selected['host'] if selected['kind'] == 'name' else None,
                      evidence=Path(runroot) / 'egress')
    args._egress = session
    try:
        proof = session.open()
        if not proof['passed']:
            raise _failure(lab, proof)
    except BaseException:
        cleanup = session.close()
        args._egress = None
        if record is not None:
            record.update(proof=session.proof, cleanup=cleanup)
        raise
    result = endpoint
    block = {'proof': proof, 'resolver': proof['resolver'],
             'relay': {'address': session.relay_address, 'port': session.relay_port, 'memory': HELPER_MEMORY}}
    if selected['kind'] == 'ip-literal':
        url = urlsplit(endpoint['base_url'])
        result = copy.deepcopy(endpoint)
        result['base_url'] = urlunsplit((url.scheme, f'{session.relay_address}:{session.relay_port}', url.path, '', ''))
        block.update(url_rewritten=True, container_base_url=result['base_url'])
    if record is not None:
        record.update(block)
    return result


def stage_network(lab, args, operation, network=None):
    """The Docker network of one stage. Setup and checks never join the internal network."""
    selected = network or args.network
    if selected != MODE:
        return selected
    if operation not in ('agent', 'preflight'):
        return 'bridge'
    session = getattr(args, '_egress', None)
    if session is None or not session.ready:
        raise _blocker(lab, 'No proven endpoint-only network is active for this stage', 'egress-not-contained')
    state = session.relay_state()
    if state['status'] != 'running':
        session.relay_exit = state
        raise _blocker(lab, 'The egress relay is not running; the stage was not started', 'egress-relay-exited')
    return session.network


def contained_arguments(args, network, argv):
    session = getattr(args, '_egress', None)
    if session is None or network != session.network:
        return argv
    return session.stage_arguments(argv)


def stamp(lab, args, folder, result, network):
    """Name the stage's network mode in its process record; record a relay that exited."""
    session = getattr(args, '_egress', None)
    contained = session is not None and network == session.network
    result['network_mode'] = MODE if contained else network
    try:
        if contained:
            state = session.relay_state()
            if state['status'] != 'running':
                session.relay_exit = state
                result['egress_relay'] = state
        path = Path(folder) / 'process.json'
        if path.exists():
            lab.save(path, result)
    except (OSError, ValueError, lab.LabError):
        pass


def finish(lab, args, record=None):
    """Remove the mode's resources on every exit path of a run."""
    session = getattr(args, '_egress', None)
    if session is None:
        return
    cleanup = session.close()
    args._egress = None
    if record is not None:
        record['cleanup'] = cleanup
    if not cleanup['confirmed'] and sys.exc_info()[0] is None:
        raise _blocker(lab, 'Removal of the endpoint-only relay or network is unconfirmed', 'egress-cleanup-unconfirmed')


def doctor(lab, args):
    """The proof alone, with no endpoint and no key: the doctor check egress-containment."""
    from resources import admission_lock, requested_policy
    item = {'check': 'egress-containment', 'status': 'fail', 'detail': ''}
    try:
        requested_policy(args)
        with admission_lock(args.lock_file, args.lock_wait_seconds) as registry:
            if registry is not None:
                registry.command = lambda argv: lab.command(argv, timeout=15, required=False)
            lab.require_host(args)
            image = lab.image_info(args.image, args.platform)
            session = Session(lab, args, image['id'], lab.RUNTIME)
            try:
                proof = session.open()
            finally:
                cleanup = session.close()
        item.update(proof=proof, cleanup=cleanup)
        if not proof['passed']:
            reason = 'egress-not-contained'
            item['detail'] = str(_failure(lab, proof))
        elif not cleanup['confirmed']:
            reason = 'egress-cleanup-unconfirmed'
            item['detail'] = 'The proof passed, but removal of its containers or network is unconfirmed'
        else:
            item.update(status='ok', detail='Inside probe: canary, bridge gateway and public name blocked; relay '
                                            'reached and forwarding to its one destination. Proof resources removed.')
            return item
    except lab.LabError as exc:
        reason = exc.reason or 'egress-proof-unavailable'
        item['detail'] = str(exc)[:1000]
    item.update(reason=reason, remedy=REMEDIES.get(reason, REMEDIES['egress-not-contained']))
    return item
