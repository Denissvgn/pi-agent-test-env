"""Endpoint-only network mode. Synthetic Docker only: real containment is shown by `doctor --egress-proof`."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))
import pi_lab as lab
import egress
import ownership_registry
sys.path.insert(0, str(ROOT / 'runtime'))
import egress_relay
from test_results import fixture, mocked_suite

IMAGE = 'sha256:' + 'a' * 64
RELAY = '172.30.0.2'
CANARY = '172.17.0.3'
SECRET = 'synthetic-key'


def reply(code=0, stdout='', stderr=''):
    return argparse.Namespace(returncode=code, stdout=stdout, stderr=stderr)


class FakeDocker:
    """The Docker CLI calls made by the egress module and the registry, over an in-memory engine."""

    def __init__(self, inside=None, control=None, internal_gateway=None, resolver='blocked', events=None):
        self.networks = {'bridge': {'labels': {}, 'internal': False, 'subnet': '172.17.0.0/16',
                                    'gateway': '172.17.0.1', 'members': set()}}
        self.containers = {}
        self.calls = []
        self.inside = inside or {}
        self.control = control or {}
        self.internal_gateway = internal_gateway
        # blocked: never answers outside names; engine: answers unless --dns is set; always: answers.
        self.resolver = resolver
        self.relay_state = 'running 0 false'
        self.events = events if events is not None else []
        self.token = None
        self.silent = set()
        self.fail = set()

    def __call__(self, argv, timeout=30, required=True):
        self.calls.append(list(argv))
        self.events.append(('docker', list(argv)))
        if tuple(argv[1:3]) in self.fail or argv[1] in self.fail:
            return reply(1, stderr='synthetic Docker failure')
        if argv[1] == 'version':
            return reply(stdout='29.0.0\n')
        if argv[1] == 'info':
            return reply(stdout='daemon-fixture\n')
        if argv[1] == 'network':
            return self.network(argv[2], argv[3:])
        if argv[1] in ('run', 'create'):
            return self.launch(argv)
        if argv[1] == 'container' and argv[2] == 'inspect':
            return self.inspect(argv[3:])
        if argv[1] == 'ps':
            return self.labelled(self.containers, argv)
        name = argv[-1]
        if argv[1] == 'logs':
            return reply(stdout=self.logs(name))
        if name not in self.containers:
            return reply(1, stderr='Error response from daemon: No such container: ' + name)
        if argv[1] == 'start':
            self.containers[name]['started'] = True
        elif argv[1] == 'stop':
            self.containers[name]['stopped'] = True
        elif argv[1] == 'rm':
            for network in self.networks.values():
                network['members'].discard(name)
            del self.containers[name]
        else:
            raise AssertionError('Unexpected Docker call: ' + ' '.join(argv))
        return reply()

    def labelled(self, items, argv):
        key, unused, value = argv[argv.index('--filter') + 1][len('label='):].partition('=')
        return reply(stdout=''.join(name + '\n' for name, item in items.items() if item['labels'].get(key) == value))

    def network(self, verb, rest):
        name = rest[-1]
        if verb == 'ls':
            return self.labelled(self.networks, rest)
        if verb == 'create':
            labels = dict(rest[i + 1].split('=', 1) for i, value in enumerate(rest) if value == '--label')
            self.networks[name] = {'labels': labels, 'internal': '--internal' in rest, 'subnet': '172.30.0.0/16',
                                   'gateway': self.internal_gateway, 'members': set(), 'options': list(rest[:-1])}
            return reply(stdout=name + '\n')
        if verb == 'connect':
            self.networks[rest[0]]['members'].add(name)
            return reply()
        if name not in self.networks:
            return reply(1, stderr=f'Error response from daemon: network {name} not found')
        item = self.networks[name]
        if verb == 'rm':
            if item['members']:
                return reply(1, stderr='network has active endpoints')
            del self.networks[name]
            return reply()
        if '--format' in rest:
            return reply(stdout=name + '\n')
        pool = {'Subnet': item['subnet']}
        if item['gateway']:
            pool['Gateway'] = item['gateway']
        return reply(stdout=json.dumps([{'Name': name, 'Driver': 'bridge', 'Internal': item['internal'],
                                         'Labels': item['labels'], 'IPAM': {'Config': [pool]},
                                         'Containers': {member: {} for member in item['members']}}]))

    def launch(self, argv):
        image = argv.index(IMAGE)
        options, operation = argv[2:image], argv[image + 2:]
        def values(flag):
            return [options[i + 1] for i, value in enumerate(options) if value == flag]
        name = values('--name')[0]
        labels = dict(value.split('=', 1) for value in values('--label'))
        network = values('--network')[0]
        self.containers[name] = {'labels': labels, 'argv': list(argv), 'network': network, 'operation': operation,
                                 'dns': values('--dns'), 'started': argv[1] == 'run', 'stopped': False}
        self.networks[network]['members'].add(name)
        if operation[0] == 'canary':
            self.token = operation[operation.index('--token') + 1]
        if operation[0] != 'probe':
            return reply(stdout=name + '\n')
        role = labels[egress.ROLE_LABEL]
        if role in self.silent:
            return reply(1, stderr='synthetic probe failure')
        return reply(stdout=json.dumps(self.report(role, network, operation, values('--dns'))) + '\n')

    def report(self, role, network, operation, dns):
        inside = role.startswith('inside')
        tcp = {}
        for index, value in enumerate(operation):
            if value not in ('--tcp', '--banner'):
                continue
            target = operation[index + 1].split('=', 1)[0]
            if inside and target != 'relay':
                tcp[target] = {'outcome': 'unreachable', 'errno': 'ENETUNREACH'}
            elif target == 'bridge_gateway':
                tcp[target] = {'outcome': 'refused'}
            else:
                tcp[target] = {'outcome': 'connected'}
                if value == '--banner':
                    tcp[target]['banner'] = self.token
        answers = not inside or self.resolver == 'always' or (self.resolver == 'engine' and not dns)
        report = {'egress_probe': 1, 'tcp': tcp, 'resolve': {egress.PUBLIC_NAME: {'outcome': 'resolved' if answers else 'unresolved'}},
                  'ipv6_interfaces': [], 'default_route': not inside}
        for name, value in (self.inside if inside else self.control).items():
            if name == 'public_name':
                report['resolve'][egress.PUBLIC_NAME] = value
            elif name in ('ipv6_interfaces',):
                report[name] = value
            else:
                report['tcp'][name] = value
        return report

    def address(self, name, network):
        return CANARY if network == 'bridge' and name.endswith('-canary') else RELAY if network != 'bridge' else '172.17.0.9'

    def inspect(self, rest):
        name = rest[-1]
        if name not in self.containers:
            return reply(1, stderr='Error response from daemon: No such container: ' + name)
        item = self.containers[name]
        if '--format' in rest:
            return reply(stdout=self.relay_state + '\n')
        mounts = []
        for index, value in enumerate(item['argv']):
            if value == '--mount':
                fields = dict(part.split('=', 1) for part in item['argv'][index + 1].split(',') if '=' in part)
                mounts.append({'Source': fields['src'], 'Destination': fields['dst'], 'RW': 'readonly' not in item['argv'][index + 1]})
        networks = {network: {'IPAddress': self.address(name, network)}
                    for network, value in self.networks.items() if name in value['members']}
        return reply(stdout=json.dumps([{'Id': 'c' * 64, 'Image': IMAGE, 'Config': {'Labels': item['labels']},
                                         'Mounts': mounts, 'NetworkSettings': {'Networks': networks}}]))

    def logs(self, name):
        item = self.containers.get(name)
        if item is None:
            return ''
        operation = item['operation']
        if operation[0] == 'canary':
            return json.dumps({'egress_canary': 'ready', 'port': egress.CANARY_PORT}) + '\n'
        port = operation[operation.index('--listen-port') + 1]
        text = json.dumps({'egress_relay': 'ready', 'listen': f'{RELAY}:{port}'}) + '\n'
        if item['stopped']:
            text += json.dumps({'egress_relay': 'stopped', 'accepted': 3, 'rejected_peers': 0, 'over_capacity': 0,
                                'upstream_failures': 0}) + '\n'
        return text

    def launched(self, role):
        return [call for call in self.calls if call[1] in ('run', 'create') and egress.ROLE_LABEL + '=' + role in call]

    def empty(self):
        return not self.containers and set(self.networks) == {'bridge'}


def option(argv, flag):
    return [argv[i + 1] for i, value in enumerate(argv) if value == flag]


def session_args(**fields):
    value = dict(platform='linux/arm64', uid=os.getuid(), gid=os.getgid(), memory='1g', cpus=1, network=egress.MODE,
                 allow_browser_no_sandbox=False, software_webgl=False, host_gateway=False)
    value.update(fields)
    return argparse.Namespace(**value)


@contextlib.contextmanager
def owned(top, docker):
    """An active ownership registry whose Docker calls go to the fake engine."""
    registry = ownership_registry.Registry(Path(top) / 'registry', command=lambda argv: docker(argv))
    registry.bind_daemon('daemon-fixture')
    token = ownership_registry.CURRENT.set(registry)
    try:
        with mock.patch.object(lab, 'command', side_effect=docker), mock.patch.object(egress.time, 'sleep'):
            yield registry
    finally:
        ownership_registry.CURRENT.reset(token)


def statuses(registry):
    return {(record.get('kind', 'container'), record['container'].rsplit('-', 1)[-1]): record['status']
            for record in registry.load()}


def endpoint(base_url='http://model.example.test:8000/v1'):
    return {'base_url': base_url, 'model': 'fixture-model', 'api_key_env': 'PI_API_KEY',
            'context_window': 8192, 'max_tokens': 1024}


class RouteTests(unittest.TestCase):
    def refused(self, base_url):
        with self.assertRaises(lab.LabError) as caught:
            egress.route(lab, endpoint(base_url))
        self.assertEqual(caught.exception.reason, 'egress-route-unsupported')
        self.assertIn('host name', caught.exception.remedy)

    def test_https_ip_literal_and_loopback_routes_are_refused(self):
        for base_url in ('https://192.0.2.10:8443/v1', 'https://[2001:db8::10]/v1', 'http://127.0.0.1:8000/v1',
                         'http://[::1]:8000/v1', 'http://localhost:8000/v1', 'http://0.0.0.0:8000/v1'):
            with self.subTest(base_url=base_url):
                self.refused(base_url)

    def test_refusal_happens_at_admission_before_any_docker_call(self):
        docker = FakeDocker()
        with mock.patch.object(lab, 'command', side_effect=docker), self.assertRaises(lab.LabError) as caught:
            egress.admit(lab, session_args(), endpoint('https://192.0.2.10/v1'))
        self.assertEqual(caught.exception.reason, 'egress-route-unsupported')
        self.assertEqual(docker.calls, [])

    def test_route_kinds_use_default_ports(self):
        self.assertEqual(egress.route(lab, endpoint('https://model.example.test/v1')),
                         {'kind': 'name', 'scheme': 'https', 'host': 'model.example.test', 'port': 443})
        self.assertEqual(egress.route(lab, endpoint('http://192.0.2.10/v1')),
                         {'kind': 'ip-literal', 'scheme': 'http', 'host': '192.0.2.10', 'port': 80})

    def started(self, top, docker, base_url, **fields):
        args = session_args(**fields)
        runroot = Path(top) / 'run'
        runroot.mkdir()
        record = egress.admit(lab, args, endpoint(base_url))
        result = egress.begin(lab, args, {'id': IMAGE}, runroot, endpoint(base_url), record)
        return args, record, result

    def stage(self, args, top):
        top = Path(top)
        return lab.docker_args(args, IMAGE, top / 'workspace', top / 'control', top / 'state', 'pi-lab-stage',
                               egress.stage_network(lab, args, 'agent'), key=True, helpers=top / 'helpers')

    def test_named_route_is_unchanged_and_gets_the_host_mapping(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top, owned(top, docker):
            args, record, result = self.started(top, docker, 'https://model.example.test:8443/v1')
            self.assertEqual(result, endpoint('https://model.example.test:8443/v1'))
            self.assertEqual(record['allowed'], {'host': 'model.example.test', 'port': 8443})
            self.assertFalse(record['url_rewritten'])
            self.assertNotIn('container_base_url', record)
            argv = self.stage(args, top)
            self.assertEqual(option(argv, '--network'), [args._egress.network])
            self.assertEqual(option(argv, '--add-host'), ['model.example.test:' + RELAY])
            self.assertEqual(option(argv, '--dns'), [])
            self.assertIn('PI_LAB_NETWORK_MODE=endpoint-only', argv)
            self.assertEqual(argv[-2:], [IMAGE, '/opt/pi-lab/worker.py'])
            relay = docker.launched('relay')[0]
            self.assertEqual(relay[relay.index(egress.HELPER) + 1:],
                             ['relay', '--listen-port', '8443', '--upstream-host', 'model.example.test',
                              '--upstream-port', '8443', '--allow', '172.30.0.0/16'])
            egress.finish(lab, args, record)
            self.assertTrue(docker.empty())

    def test_http_ip_literal_route_is_rewritten_and_recorded(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top, owned(top, docker):
            args, record, result = self.started(top, docker, 'http://192.0.2.10:8000/v1')
            self.assertEqual(result['base_url'], f'http://{RELAY}:8000/v1')
            self.assertEqual({k: v for k, v in result.items() if k != 'base_url'},
                             {k: v for k, v in endpoint().items() if k != 'base_url'})
            self.assertTrue(record['url_rewritten'])
            self.assertEqual(record['container_base_url'], f'http://{RELAY}:8000/v1')
            self.assertEqual(record['allowed'], {'host': '192.0.2.10', 'port': 8000})
            self.assertEqual(record['route'], {'kind': 'ip-literal', 'scheme': 'http'})
            argv = self.stage(args, top)
            self.assertEqual(option(argv, '--add-host'), [])
            relay = docker.launched('relay')[0]
            self.assertEqual(option(relay, '--upstream-host'), ['192.0.2.10'])
            egress.finish(lab, args, record)

    def test_host_gateway_mapping_goes_to_the_relay_not_to_the_stage(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top, owned(top, docker):
            args, record, unused = self.started(top, docker, 'http://host.docker.internal:8000/v1', host_gateway=True)
            argv = self.stage(args, top)
            self.assertEqual(option(argv, '--add-host'), ['host.docker.internal:' + RELAY])
            self.assertEqual(option(docker.launched('relay')[0], '--add-host'), ['host.docker.internal:host-gateway'])
            self.assertEqual(option(docker.launched('inside')[0], '--add-host'), ['host.docker.internal:' + RELAY])
            egress.finish(lab, args, record)

    def test_other_networks_keep_their_arguments(self):
        args = session_args(network='bridge', host_gateway=True)
        argv = lab.docker_args(args, IMAGE, Path('/x/w'), Path('/x/c'), Path('/x/s'), 'n', 'bridge', helpers=Path('/x/h'))
        self.assertEqual(option(argv, '--add-host'), ['host.docker.internal:host-gateway'])
        self.assertIn('PI_LAB_NETWORK_MODE=bridge', argv)


class ProofTests(unittest.TestCase):
    def proof(self, docker, **fields):
        with tempfile.TemporaryDirectory() as top, owned(top, docker) as registry:
            session = egress.Session(lab, session_args(**fields), IMAGE, Path(top))
            try:
                return session.open(), session
            finally:
                self.cleanup = session.close()
                self.records = statuses(registry)

    def test_passing_proof_and_the_arguments_of_its_containers(self):
        docker = FakeDocker()
        proof, session = self.proof(docker)
        self.assertTrue(proof['passed'])
        self.assertEqual(proof['failed'], [])
        self.assertEqual(set(proof['checks'].values()), {True})
        self.assertEqual(proof['inside']['tcp']['canary']['outcome'], 'unreachable')
        self.assertEqual(proof['control']['tcp']['canary']['outcome'], 'connected')
        self.assertEqual(proof['relay'], {'address': RELAY, 'port': egress.CANARY_PORT, 'upstream': 'canary'})
        self.assertEqual(proof['resolver'], {'override': False, 'server': None})
        network = next(call for call in docker.calls if call[1:3] == ['network', 'create'])
        self.assertIn('--internal', network)
        self.assertIn(egress.SESSION_LABEL + '=' + session.id, network)
        self.assertEqual(option(docker.launched('canary')[0], '--network'), ['bridge'])
        self.assertEqual(option(docker.launched('control')[0], '--network'), ['bridge'])
        self.assertEqual(option(docker.launched('inside')[0], '--network'), [session.network])
        relay = docker.launched('relay')[0]
        self.assertEqual(relay[:2], ['docker', 'create'])
        self.assertEqual(option(relay, '--network'), [session.network])
        self.assertIn(['docker', 'network', 'connect', 'bridge', session.relay], docker.calls)
        for flag in ('--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--ipc=none', '--init'):
            self.assertIn(flag, relay)
        self.assertEqual(option(relay, '--memory'), ['64m'])
        self.assertEqual(option(relay, '--memory-swap'), ['64m'])
        self.assertEqual(option(relay, '--user'), [f'{os.getuid()}:{os.getgid()}'])
        self.assertEqual(option(relay, '--sysctl'), ['net.ipv4.ip_forward=0'])
        # No variable is inherited from the host, and the key variable is empty.
        self.assertEqual(option(relay, '--env'), ['PYTHONDONTWRITEBYTECODE=1', 'PYTHONUNBUFFERED=1', 'PI_LAB_API_KEY='])
        self.assertEqual([m for m in option(relay, '--mount') if 'readonly' not in m], [])
        for bad in ('--privileged', '--publish', '-p', '--cap-add', '/var/run/docker.sock'):
            self.assertNotIn(bad, relay)

    def test_every_other_result_blocks(self):
        gateway = '172.30.0.1'
        cases = {
            'inside_blocked_canary': dict(inside={'canary': {'outcome': 'connected'}}),
            'inside_blocked_bridge_gateway': dict(inside={'bridge_gateway': {'outcome': 'refused'}}),
            'inside_blocked_internal_gateway': dict(internal_gateway=gateway, inside={'internal_gateway': {'outcome': 'refused'}}),
            # A host that drops the probed port may answer on another: silence is not enough for a host address.
            'inside_blocked_bridge_gateway ': dict(inside={'bridge_gateway': {'outcome': 'timeout'}}),
            'inside_blocked_internal_gateway ': dict(internal_gateway=gateway, inside={'internal_gateway': {'outcome': 'timeout'}}),
            'inside_blocked_canary ': dict(inside={'canary': {'outcome': 'error', 'errno': 'EPERM'}}),
            'inside_blocked_canary  ': dict(inside={'canary': {'outcome': 'refused'}}),
            'inside_public_name_unresolved': dict(resolver='always'),
            'inside_no_ipv6_interface': dict(inside={'ipv6_interfaces': ['eth0']}),
            'inside_reaches_relay': dict(inside={'relay': {'outcome': 'refused'}}),
            'control_reaches_canary': dict(control={'canary': {'outcome': 'timeout'}}),
        }
        for check, scenario in cases.items():
            with self.subTest(check=check):
                docker = FakeDocker(**scenario)
                proof, session = self.proof(docker)
                self.assertFalse(proof['passed'])
                self.assertEqual(proof['failed'], [check.strip()])
                self.assertFalse(session.ready)
                self.assertTrue(self.cleanup['confirmed'])
                self.assertTrue(docker.empty())
                self.assertEqual(set(self.records.values()), {'released'})

    def test_a_wrong_canary_token_or_a_missing_report_fails_closed(self):
        docker = FakeDocker(control={'canary': {'outcome': 'connected', 'banner': 'other'}})
        self.assertEqual(self.proof(docker)[0]['failed'], ['control_reaches_canary'])
        for role in ('control', 'inside'):
            docker = FakeDocker()
            docker.silent.add(role)
            proof = self.proof(docker)[0]
            self.assertFalse(proof['passed'])
            self.assertEqual(proof['incomplete'], role + '_probe_failed')
            self.assertTrue(docker.empty())
        checks = egress.evaluate({}, {}, 'token', None, False)
        self.assertEqual({name for name, passed in checks.items() if passed}, set())
        self.assertFalse(any(egress.evaluate(None, None, 'token', '172.30.0.1', True).values()))

    def test_setup_failures_leave_the_mode_blocked_and_nothing_behind(self):
        for step, fail in (('network_create', ('network', 'create')), ('canary_start', 'run'),
                           ('relay_connect', ('network', 'connect')), ('relay_start', 'start')):
            with self.subTest(step=step):
                docker = FakeDocker()
                docker.fail.add(fail)
                proof = self.proof(docker)[0]
                self.assertEqual((proof['passed'], proof['incomplete']), (False, step))
                docker.fail.clear()

    def test_a_silent_canary_is_blocked_but_recorded(self):
        docker = FakeDocker(inside={'canary': {'outcome': 'timeout'}})
        proof = self.proof(docker)[0]
        self.assertTrue(proof['passed'])
        self.assertEqual(proof['inside']['tcp']['canary']['outcome'], 'timeout')

    def test_internal_gateway_is_probed_when_the_engine_assigns_one(self):
        docker = FakeDocker(internal_gateway='172.30.0.1')
        proof = self.proof(docker)[0]
        self.assertTrue(proof['passed'])
        self.assertEqual(proof['inside']['tcp']['internal_gateway']['outcome'], 'unreachable')
        self.assertIn(f'internal_gateway=172.30.0.1:{egress.CANARY_PORT}', docker.launched('inside')[0])

    def test_resolver_setting_is_applied_when_the_engine_answers_for_outside_names(self):
        docker = FakeDocker(resolver='engine')
        proof, session = self.proof(docker)
        self.assertTrue(proof['passed'])
        self.assertEqual(proof['resolver'], {'override': True, 'server': RELAY})
        self.assertEqual(proof['inside_without_resolver_setting']['resolve']['public_name']['outcome'], 'resolved')
        self.assertEqual(option(docker.launched('inside')[0], '--dns'), [])
        self.assertEqual(option(docker.launched('inside-2')[0], '--dns'), [RELAY])
        self.assertEqual(session.stage_options(), ['--dns', RELAY])

    def test_resolver_setting_does_not_rescue_another_failed_check(self):
        docker = FakeDocker(resolver='engine', inside={'canary': {'outcome': 'connected'}})
        proof = self.proof(docker)[0]
        self.assertEqual(proof['failed'], ['inside_blocked_canary', 'inside_public_name_unresolved'])
        self.assertEqual(docker.launched('inside-2'), [])
        docker = FakeDocker(resolver='always')
        proof = self.proof(docker)[0]
        self.assertEqual(proof['failed'], ['inside_public_name_unresolved'])
        self.assertEqual(option(docker.launched('inside-2')[0], '--dns'), [RELAY])

    def test_resolver_setting_is_a_precaution_when_the_control_cannot_resolve(self):
        docker = FakeDocker(control={'public_name': {'outcome': 'unresolved'}})
        proof = self.proof(docker)[0]
        self.assertTrue(proof['passed'])
        self.assertEqual(proof['public_name'], {'name': egress.PUBLIC_NAME, 'control': 'unresolved',
                                                'inside': 'unresolved', 'conclusive': False})
        self.assertTrue(proof['resolver']['override'])
        self.assertEqual(option(docker.launched('inside')[0], '--dns'), [RELAY])

    def test_no_stage_network_without_a_passed_proof_or_a_running_relay(self):
        args = session_args()
        with self.assertRaises(lab.LabError) as caught:
            egress.stage_network(lab, args, 'agent')
        self.assertEqual(caught.exception.reason, 'egress-not-contained')
        self.assertEqual(egress.stage_network(lab, args, 'check', egress.MODE), 'bridge')
        self.assertEqual(egress.stage_network(lab, args, 'check', 'none'), 'none')
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top, owned(top, docker):
            session = egress.Session(lab, args, IMAGE, Path(top))
            args._egress = session
            self.assertTrue(session.open()['passed'])
            self.assertEqual(egress.stage_network(lab, args, 'preflight'), session.network)
            docker.relay_state = 'exited 137 true'
            with self.assertRaises(lab.LabError) as caught:
                egress.stage_network(lab, args, 'agent')
            self.assertEqual(caught.exception.reason, 'egress-relay-exited')
            self.assertEqual(session.close()['relay']['state_before_removal'],
                             {'status': 'exited', 'exit_code': 137, 'oom_killed': True})


class OwnershipTests(unittest.TestCase):
    def test_resources_are_registered_labelled_and_released(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top, owned(top, docker) as registry:
            session = egress.Session(lab, session_args(), IMAGE, Path(top))
            self.assertTrue(session.open()['passed'])
            self.assertEqual(statuses(registry), {('network', session.id): 'intent', ('container', 'relay'): 'running',
                                                  ('container', 'canary'): 'released', ('container', 'control'): 'released',
                                                  ('container', 'inside'): 'released'})
            records = {record['container']: record for record in registry.load()}
            for name, item in list(docker.containers.items()) + [(session.network, docker.networks[session.network])]:
                self.assertEqual(item['labels'][ownership_registry.LABEL], records[name]['launch_id'])
                self.assertEqual(item['labels'][ownership_registry.REGISTRY_LABEL], registry.registry_id)
                self.assertEqual(item['labels'][egress.SESSION_LABEL], session.id)
            cleanup = session.close()
            self.assertEqual(cleanup['confirmed'], True)
            self.assertEqual((cleanup['remaining_containers'], cleanup['remaining_networks']), ([], []))
            self.assertEqual(cleanup['relay']['connections']['accepted'], 3)
            self.assertTrue(docker.empty())
            self.assertEqual(set(statuses(registry).values()), {'released'})
            self.assertEqual(session.close(), cleanup)
            registry.close()

    def test_leftovers_of_a_dead_supervisor_are_reconciled_by_the_registry(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top:
            with owned(top, docker):
                session = egress.Session(lab, session_args(), IMAGE, Path(top))
                session.open()
            self.assertEqual(set(docker.containers), {session.relay})
            self.assertIn(session.network, docker.networks)
            successor = ownership_registry.Registry(Path(top) / 'registry', command=lambda argv: docker(argv))
            self.assertEqual({record['container'] for record in successor.reconcile()}, {session.relay, session.network})
            self.assertTrue(docker.empty())
            self.assertEqual({record['status'] for record in successor.load()}, {'released'})

    def test_unconfirmed_removal_is_reported_and_not_released(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top, owned(top, docker) as registry:
            args = session_args()
            session = egress.Session(lab, args, IMAGE, Path(top))
            args._egress = session
            session.open()
            docker.fail.add('rm')
            record = {}
            with self.assertRaises(lab.LabError) as caught:
                egress.finish(lab, args, record)
            self.assertEqual(caught.exception.reason, 'egress-cleanup-unconfirmed')
            self.assertFalse(record['cleanup']['confirmed'])
            self.assertEqual(record['cleanup']['remaining_containers'], [session.relay])
            self.assertEqual(record['cleanup']['remaining_networks'], [session.network])
            self.assertEqual(statuses(registry)[('container', 'relay')], 'quarantined')

    def test_resources_are_labelled_and_removed_without_a_registry(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as top, mock.patch.object(lab, 'command', side_effect=docker), \
                mock.patch.object(egress.time, 'sleep'):
            session = egress.Session(lab, session_args(), IMAGE, Path(top))
            self.assertIsNone(session.registry)
            self.assertTrue(session.open()['passed'])
            self.assertTrue(session.close()['confirmed'])
            self.assertTrue(docker.empty())


def suite(stack, top, docker, events, network=egress.MODE, extra=()):
    """A run with a synthetic engine; stages are recorded instead of started."""
    a = fixture(top)
    a.network = network
    for name in extra:
        setattr(a, name, True)
    mocked_suite(stack)
    stack.enter_context(mock.patch.object(lab, 'probe_image', return_value={'id': IMAGE, 'reference': 'fixture',
                                                                            'capabilities': {'pi': '0.87.1'}}))
    stack.enter_context(mock.patch.object(lab, 'command', side_effect=docker))
    stack.enter_context(mock.patch.object(egress.time, 'sleep'))
    def stage(argv, logdir, timeout, name, secret='', stage=None, **kw):
        events.append(('stage', list(argv), secret))
        logdir.mkdir(parents=True, exist_ok=True)
        (logdir / 'stdout.jsonl').write_text('')
        (logdir / 'stderr.log').write_text('')
        result = {'exit_code': 0, 'cleanup_confirmed': True}
        lab.save(logdir / 'process.json', result)
        return result
    stack.enter_context(mock.patch.object(lab, 'stream_run', side_effect=stage))
    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    return a


def result_of(top):
    return lab.controls.read((Path(top) / 'results/latest').resolve() / 'result.json')


class RunTests(unittest.TestCase):
    def test_run_record_names_the_mode_the_route_the_proof_and_every_stage_network(self):
        events = []
        docker = FakeDocker(events=events)
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td)
            a = suite(stack, top, docker, events, extra=('allow_setup_network',))
            plan = json.loads(Path(a.plan).read_text())
            plan['setup'] = [{'name': 'fetch', 'argv': ['true'], 'network': 'inherit'}, {'name': 'build', 'argv': ['true']}]
            lab.save(Path(a.plan), plan)
            self.assertEqual(lab.run_suite(a), 0)
            result = result_of(top)
            network = result['network']
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(network['mode'], egress.MODE)
            self.assertEqual(network['allowed'], {'host': 'example.invalid', 'port': 80})
            self.assertFalse(network['url_rewritten'])
            self.assertTrue(network['proof']['passed'])
            self.assertTrue(network['cleanup']['confirmed'])
            self.assertEqual(network['stages']['setup_inherit'], 'bridge')
            self.assertEqual(network['stages']['check_inherit'], 'refused')
            self.assertEqual(lab.controls.read((top / 'results/latest').resolve() / 'summary.json')['network'], network)
            run = Path(result['run_dir'])
            modes = {path.parent.name: lab.controls.read(path)['network_mode'] for path in run.glob('*/process.json')}
            self.assertEqual(modes, {'boundary': 'none', 'preflight': egress.MODE, 'setup-1-fetch': 'bridge',
                                     'setup-2-build': 'none', 'agent-1-dev': egress.MODE, 'check-1-oracle': 'none'})
            self.assertEqual(result['agents'][0]['process']['network_mode'], egress.MODE)
            stages = [event for event in events if event[0] == 'stage']
            internal = network['proof']['network']['name']
            attached = {event[1][-1] if event[1][-1] in ('boundary', 'check') else event[1][event[1].index('/opt/pi-lab/worker.py') + 1]:
                        option(event[1], '--network') for event in stages}
            self.assertEqual(attached['preflight'], [internal])
            self.assertEqual(attached['agent'], [internal])
            self.assertEqual(attached['boundary'], ['none'])
            for event in stages:
                if option(event[1], '--network') == [internal]:
                    self.assertEqual(option(event[1], '--add-host'), ['example.invalid:' + RELAY])
                    self.assertIn('PI_LAB_NETWORK_MODE=endpoint-only', event[1])
            # The proof is complete before the first stage, and the key is in no proof argument.
            first_stage = events.index(stages[0])
            proof_calls = [event[1] for event in events[:first_stage] if event[0] == 'docker']
            self.assertTrue(any(egress.ROLE_LABEL + '=inside' in call for call in proof_calls))
            self.assertFalse(any(SECRET in ' '.join(event[1]) for event in events))
            self.assertFalse(any('PI_LAB_API_KEY' in option(call, '--env') for call in docker.calls if call[1] in ('run', 'create')))
            self.assertTrue(docker.empty())

    def test_inside_probe_reaching_the_canary_blocks_before_any_stage_or_key(self):
        events = []
        docker = FakeDocker(inside={'canary': {'outcome': 'connected', 'banner': 'x'}}, events=events)
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td)
            a = suite(stack, top, docker, events)
            self.assertEqual(lab.run_suite(a), 2)
            result = result_of(top)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertEqual(result['infrastructure']['reason'], 'egress-not-contained')
            self.assertIn('No key entered a container', result['infrastructure']['remedy'])
            self.assertEqual(result['network']['proof']['failed'], ['inside_blocked_canary'])
            self.assertFalse(result['network']['proof']['passed'])
            self.assertTrue(result['network']['cleanup']['confirmed'])
            self.assertEqual([event for event in events if event[0] == 'stage'], [])
            self.assertEqual(result['invocation']['attempted_stages'], 0)
            self.assertNotIn(SECRET, json.dumps(events))
            self.assertTrue(docker.empty())

    def test_interrupted_run_removes_relay_and_network(self):
        events = []
        docker = FakeDocker(events=events)
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td)
            a = suite(stack, top, docker, events)
            def interrupted(argv, logdir, timeout, name, secret='', stage=None, **kw):
                if 'preflight' in argv:
                    self.assertEqual(len(docker.containers), 1)
                    raise KeyboardInterrupt
                return {'exit_code': 0, 'cleanup_confirmed': True}
            stack.enter_context(mock.patch.object(lab, 'stream_run', side_effect=interrupted))
            self.assertEqual(lab.run_suite(a), 2)
            result = result_of(top)
            self.assertEqual(result['status'], 'INTERRUPTED')
            self.assertTrue(result['network']['cleanup']['confirmed'])
            self.assertTrue(docker.empty())
            registry = ownership_registry.Registry(Path(str(a.lock_file) + '.registry'), command=lambda argv: docker(argv))
            self.assertEqual({record['status'] for record in registry.load()}, {'released'})

    def test_relay_exit_during_a_stage_is_recorded_and_stops_the_next_stage(self):
        events = []
        docker = FakeDocker(events=events)
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td)
            a = suite(stack, top, docker, events)
            def stage(argv, logdir, timeout, name, secret='', stage=None, **kw):
                if 'preflight' in argv:
                    docker.relay_state = 'exited 137 true'
                events.append(('stage', list(argv), secret))
                result = {'exit_code': 0, 'cleanup_confirmed': True}
                lab.save(logdir / 'process.json', result)
                return result
            stack.enter_context(mock.patch.object(lab, 'stream_run', side_effect=stage))
            self.assertEqual(lab.run_suite(a), 1)
            result = result_of(top)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['infrastructure']['reason'], 'egress-relay-exited')
            self.assertEqual(result['network']['cleanup']['relay']['state_before_removal'],
                             {'status': 'exited', 'exit_code': 137, 'oom_killed': True})
            run = Path(result['run_dir'])
            # The stage during which the relay exited records the exit; no agent container starts after it.
            self.assertEqual(lab.controls.read(run / 'preflight/process.json')['egress_relay'],
                             {'status': 'exited', 'exit_code': 137, 'oom_killed': True})
            self.assertNotIn('egress_relay', lab.controls.read(run / 'boundary/process.json'))
            started = [event[1][event[1].index('/opt/pi-lab/worker.py') + 1] for event in events if event[0] == 'stage']
            self.assertEqual(started, ['boundary', 'preflight'])
            self.assertEqual(result['agents'], [])
            self.assertTrue(docker.empty())

    def test_default_network_stays_bridge_and_makes_no_docker_call(self):
        events = []
        docker = FakeDocker(events=events)
        self.assertEqual(lab.parser().parse_args(['run']).network, 'bridge')
        self.assertFalse(lab.parser().parse_args(['preflight']).allow_host_network)
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td)
            a = suite(stack, top, docker, events, network='bridge')
            self.assertEqual(lab.run_suite(a), 0)
            result = result_of(top)
            self.assertEqual(result['network']['mode'], 'bridge')
            self.assertNotIn('proof', result['network'])
            self.assertEqual(docker.calls, [])
            self.assertEqual(result['agents'][0]['process']['network_mode'], 'bridge')

    def test_preflight_report_has_the_network_block(self):
        docker = FakeDocker()
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td)
            suite(stack, top, docker, [])
            a = lab.parser().parse_args(['preflight', '--endpoint', str(top / 'endpoint.json'), '--results-dir', str(top / 'results'),
                                         '--platform', 'linux/arm64', '--network', egress.MODE])
            stack.enter_context(mock.patch.object(lab, 'admit_image', return_value={'release': '0.87.1'}))
            stack.enter_context(mock.patch.object(lab.pi_contract, 'model_configuration'))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(lab.preflight_only(a), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report['network']['mode'], egress.MODE)
            self.assertEqual(report['network']['allowed'], {'host': 'example.invalid', 'port': 80})
            self.assertTrue(report['network']['proof']['passed'])
            self.assertTrue(report['network']['cleanup']['confirmed'])
            self.assertEqual(report['process']['network_mode'], egress.MODE)
            self.assertEqual(lab.controls.read(Path(report['run_dir']) / 'egress/proof.json'), report['network']['proof'])
            self.assertTrue(docker.empty())


class RefusalTests(unittest.TestCase):
    def blocked(self, argv, reason):
        with mock.patch.object(lab, 'command', side_effect=AssertionError('no Docker call expected')), \
                mock.patch.object(lab, 'run_suite', side_effect=AssertionError('not dispatched')), \
                mock.patch.object(lab, 'admission_lock', side_effect=AssertionError('no admission expected')), \
                self.assertRaises(lab.LabError) as caught:
            lab.main(argv)
        self.assertEqual(caught.exception.reason, reason)
        self.assertTrue(caught.exception.remedy)
        return caught.exception

    def test_mode_conflicts_are_refused_before_any_container(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            indexed = top / 'plan.json'
            lab.save(indexed, {'schema': 2, 'agents': [], 'checks': [], 'inference_bindings': {}})
            base = ['--network', egress.MODE]
            for argv in (['run', '--inference-env', 'local', *base], ['smoke', '--inference-env', 'local', *base],
                         ['preflight', '--inference-env', 'local', *base],
                         ['run', '--project', str(top), '--compiled-plan', str(top / 'compiled/plan.json'), *base],
                         ['run', '--project', str(top), '--plan', str(indexed), *base]):
                with self.subTest(argv=argv[:3]):
                    self.blocked(argv, 'feature-conflict')

    def test_private_execution_kinds_and_native_budgets_conflict(self):
        for name in ('_indexed_session', '_parallel_session', '_experiment_root', '_indexed_plan_selection'):
            with self.subTest(owner=name), self.assertRaises(lab.LabError) as caught:
                egress.admit(lab, session_args(**{name: object()}), endpoint())
            self.assertEqual(caught.exception.reason, 'feature-conflict')
        plan = {'agents': [{'name': 'dev', 'max_tool_calls': 5}]}
        with self.assertRaises(lab.LabError) as caught:
            egress.admit(lab, session_args(), endpoint(), plan)
        self.assertEqual(caught.exception.reason, 'feature-conflict')
        self.assertEqual(egress.admit(lab, session_args(), endpoint(), {'agents': [{'name': 'dev'}]})['mode'], egress.MODE)

    def test_experiment_definitions_cannot_select_the_mode_or_the_host_network(self):
        with self.assertRaises(lab.LabError) as caught:
            egress.experiment_network(lab, egress.MODE)
        self.assertEqual(caught.exception.reason, 'feature-conflict')
        with self.assertRaises(lab.LabError) as caught:
            egress.experiment_network(lab, 'host')
        self.assertEqual(caught.exception.reason, 'network-mode-refused')
        self.assertIsNone(egress.experiment_network(lab, 'bridge'))
        import experiments
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            lab.save(top / 'resources.json', {})
            definition = {'schema': 1, 'name': 'e', 'baseline': 'a', 'repetitions': 1, 'cases': [], 'variants': [],
                          'budgets': {}, 'policies': {},
                          'execution': {'image': IMAGE, 'platform': 'linux/arm64', 'resources': 'resources.json',
                                        'network': egress.MODE}}
            lab.save(top / 'experiment.json', definition)
            with mock.patch.object(experiments, 'budget', return_value={}), self.assertRaises(lab.LabError) as caught:
                experiments.validate(top / 'experiment.json', lab)
            self.assertEqual(caught.exception.reason, 'feature-conflict')

    def test_host_network_is_refused_with_a_remedy_and_accepted_with_the_explicit_option(self):
        for value in ('host', 'container:abc123'):
            for op in ('run', 'smoke', 'preflight'):
                with self.subTest(op=op, value=value):
                    error = self.blocked([op, '--network', value], 'network-mode-refused')
                    self.assertIn('--allow-host-network', error.remedy)
            a = lab.parser().parse_args(['run', '--network', value, '--allow-host-network'])
            egress.validate_request(lab, a)
            with mock.patch.object(lab, 'command', side_effect=AssertionError('no Docker call expected')):
                record = egress.admit(lab, a)
            self.assertEqual((record['mode'], record['host_network_allowed']), (value, True))
        for value in ('', 'two words', '-flag', 'a/b'):
            with self.subTest(value=value), self.assertRaises(lab.LabError) as caught:
                egress.validate_request(lab, session_args(network=value))
            self.assertEqual(caught.exception.reason, 'network-mode-refused')

    def test_run_record_states_the_host_network_choice(self):
        events = []
        docker = FakeDocker(events=events)
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td)
            a = suite(stack, top, docker, events, network='host', extra=('allow_host_network',))
            self.assertEqual(lab.run_suite(a), 0)
            result = result_of(top)
            self.assertEqual((result['network']['mode'], result['network']['host_network_allowed']), ('host', True))
            self.assertEqual(result['agents'][0]['process']['network_mode'], 'host')
            second = top / 'second'
            second.mkdir()
            a = suite(stack, second, docker, events, network='host')
            self.assertEqual(lab.run_suite(a), 2)
            refused = result_of(second)
            self.assertEqual(refused['infrastructure']['reason'], 'network-mode-refused')
            self.assertNotIn('network', refused)
            self.assertEqual([event for event in events if event[0] == 'stage' and 'second' in ' '.join(event[1])], [])

    def test_named_network_must_exist(self):
        docker = FakeDocker()
        docker.networks['lab-net'] = {'labels': {}, 'internal': False, 'subnet': '172.31.0.0/16', 'gateway': None, 'members': set()}
        with mock.patch.object(lab, 'command', side_effect=docker):
            self.assertEqual(egress.admit(lab, session_args(network='lab-net'))['mode'], 'lab-net')
            with self.assertRaises(lab.LabError) as caught:
                egress.admit(lab, session_args(network='missing-net'))
            self.assertEqual(caught.exception.reason, 'network-mode-refused')
            # Other owners create their network after admission; it is not looked up here.
            calls = len(docker.calls)
            egress.admit(lab, session_args(network='pi-trial-1', _indexed_session=object()))
            self.assertEqual(len(docker.calls), calls)


class DoctorTests(unittest.TestCase):
    def run_doctor(self, docker):
        with tempfile.TemporaryDirectory() as td:
            a = lab.parser().parse_args(['doctor', '--image', 'fixture:core', '--egress-proof', '--skip-network',
                                         '--endpoint', str(Path(td) / 'missing.json'), '--lock-file', str(Path(td) / 'lease'),
                                         '--platform', 'linux/arm64'])
            output = io.StringIO()
            info = {'ServerVersion': '29.0.0', 'OSType': 'linux', 'Architecture': 'aarch64'}
            def command(argv, timeout=30, required=True):
                if argv[:3] == ['docker', 'context', 'show']:
                    return reply(stdout='default\n')
                if argv[:3] == ['docker', 'context', 'inspect']:
                    return reply(stdout=json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]))
                if argv[:3] == ['docker', 'image', 'inspect']:
                    return reply(stdout='arm64\n')
                return docker(argv, timeout, required)
            with mock.patch.object(lab, 'docker_info', return_value=info), mock.patch.object(lab, 'command', side_effect=command), \
                    mock.patch.object(lab, 'require_host', return_value={}), mock.patch.object(egress.time, 'sleep'), \
                    mock.patch.object(lab, 'image_info', return_value={'id': IMAGE}), contextlib.redirect_stdout(output):
                code = lab.cmd_doctor(a)
            report = json.loads(output.getvalue())
            return code, next(item for item in report['checks'] if item['check'] == 'egress-containment'), report

    def test_doctor_reports_the_proof_as_a_check(self):
        docker = FakeDocker()
        code, check, report = self.run_doctor(docker)
        self.assertEqual(check['status'], 'ok')
        self.assertTrue(check['proof']['passed'])
        self.assertEqual(check['proof']['relay']['upstream'], 'canary')
        self.assertEqual(check['proof']['inside']['tcp']['relay']['banner'], docker.token)
        self.assertTrue(check['cleanup']['confirmed'])
        self.assertNotIn('reason', check)
        self.assertTrue(docker.empty())
        self.assertEqual(option(docker.launched('relay')[0], '--mount'),
                         [f'type=bind,src={lab.RUNTIME.resolve()},dst=/opt/pi-lab,readonly,bind-recursive=disabled'])

    def test_doctor_blocks_when_the_inside_probe_reaches_the_canary(self):
        docker = FakeDocker(inside={'canary': {'outcome': 'connected'}})
        code, check, report = self.run_doctor(docker)
        self.assertEqual(code, 2)
        self.assertEqual((check['status'], check['reason']), ('fail', 'egress-not-contained'))
        self.assertEqual(check['proof']['failed'], ['inside_blocked_canary'])
        self.assertIn('[egress-containment] ' + egress.REMEDIES['egress-not-contained'], report['next_steps'])
        self.assertTrue(docker.empty())

    def test_doctor_without_the_option_runs_no_proof(self):
        a = lab.parser().parse_args(['doctor'])
        self.assertFalse(a.egress_proof)


class RelayTests(unittest.TestCase):
    """The in-container helper as a real process on loopback sockets; no Docker."""

    def free_port(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    def upstream(self):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(4)
        def serve():
            while True:
                try:
                    client, unused = server.accept()
                except OSError:
                    return
                with client:
                    data = client.recv(65536)
                    client.sendall(b'reply:' + data)
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(server.close)
        return server.getsockname()[1]

    def start(self, *arguments):
        process = subprocess.Popen([sys.executable, str(ROOT / 'runtime/egress_relay.py'), *arguments],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env={'PATH': os.environ.get('PATH', ''), 'PYTHONDONTWRITEBYTECODE': '1'})
        self.addCleanup(lambda: (process.kill(), process.wait(), process.stdout.close(), process.stderr.close()))
        return process

    def test_relay_forwards_to_its_one_destination_and_prints_no_stream_content(self):
        upstream, port = self.upstream(), self.free_port()
        process = self.start('relay', '--listen-port', str(port), '--upstream-host', '127.0.0.1',
                             '--upstream-port', str(upstream), '--allow', '127.0.0.0/8')
        ready = json.loads(process.stdout.readline())
        self.assertEqual(ready, {'egress_relay': 'ready', 'listen': f'127.0.0.1:{port}', 'allow': '127.0.0.0/8',
                                 'upstream_host': '127.0.0.1', 'upstream_port': upstream})
        marker = b'PRIVATE-PROMPT-AND-KEY-MARKER'
        for unused in range(2):
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.sendall(marker)
                client.shutdown(socket.SHUT_WR)
                received = b''
                while True:
                    data = client.recv(65536)
                    if not data:
                        break
                    received += data
            self.assertEqual(received, b'reply:' + marker)
        process.send_signal(signal.SIGTERM)
        output, errors = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(json.loads(output), {'egress_relay': 'stopped', 'accepted': 2, 'rejected_peers': 0,
                                              'over_capacity': 0, 'upstream_failures': 0})
        self.assertNotIn(marker.decode(), output + errors)

    def test_relay_rejects_peers_outside_the_allowed_network(self):
        allowed = egress_relay.ipaddress.ip_network('172.30.0.0/16')
        self.assertTrue(egress_relay.inside('172.30.0.7', allowed))
        for peer in ('172.17.0.3', '127.0.0.1', '192.0.2.1', '::1', 'not-an-address'):
            self.assertFalse(egress_relay.inside(peer, allowed))
        # The relay refuses to start when it has no address inside the allowed network.
        process = self.start('relay', '--listen-port', str(self.free_port()), '--upstream-host', '127.0.0.1',
                             '--upstream-port', '9', '--allow', '192.0.2.0/24')
        output, errors = process.communicate(timeout=10)
        self.assertEqual((process.returncode, output), (2, ''))
        self.assertIn('PI_LAB_ERROR', errors)

    def test_relay_has_no_destination_option_a_client_could_use(self):
        upstream, port, other = self.upstream(), self.free_port(), self.upstream()
        process = self.start('relay', '--listen-port', str(port), '--upstream-host', '127.0.0.1',
                             '--upstream-port', str(upstream), '--allow', '127.0.0.0/8')
        process.stdout.readline()
        # A proxy request for another destination is plain bytes for the one upstream.
        request = f'CONNECT 127.0.0.1:{other} HTTP/1.1\r\n\r\n'.encode()
        with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(65536), b'reply:' + request)

    def test_probe_and_canary_report_outcomes_without_content(self):
        port = self.free_port()
        canary = self.start('canary', '--port', str(port), '--token', 'token-1')
        self.assertEqual(json.loads(canary.stdout.readline()), {'egress_canary': 'ready', 'port': port})
        closed = self.free_port()
        probe = self.start('probe', '--banner', f'canary=127.0.0.1:{port}', '--tcp', f'open=127.0.0.1:{port}',
                           '--tcp', f'closed=127.0.0.1:{closed}', '--resolve', 'name.invalid')
        output, unused = probe.communicate(timeout=30)
        report = json.loads(output)
        self.assertEqual(report['tcp'], {'canary': {'outcome': 'connected', 'banner': 'token-1'},
                                         'open': {'outcome': 'connected'}, 'closed': {'outcome': 'refused'}})
        self.assertIn(report['resolve']['name.invalid']['outcome'], ('unresolved', 'timeout'))
        self.assertEqual(report['egress_probe'], 1)

    def test_worker_manifest_names_the_allowlist_only_in_this_mode(self):
        import worker
        for mode, routing, allowlist in ((egress.MODE, 'endpoint_only', True), ('bridge', 'unverified', False),
                                         ('none', 'disabled', False)):
            with mock.patch.dict(os.environ, {'PI_LAB_NETWORK_MODE': mode}):
                facts = worker.capability_facts({'tools': []}, '/workspace')['network']
            self.assertEqual(facts, {'mode': mode, 'external_routing': routing, 'destination_allowlist': allowlist})


if __name__ == '__main__':
    unittest.main()
