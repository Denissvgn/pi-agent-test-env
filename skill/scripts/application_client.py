"""Parent-owned scoped authority and finite application-helper lifecycle.

Admission is mandatory before any probe/setup. Values are private process memory
and one bounded stdin bootstrap only. Local IPC tests do not qualify Docker/Pi.
Callers hold the existing host ownership lease for every lifecycle operation.
"""
from dataclasses import dataclass, field
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import secret_store
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid

import application_contracts as c
import application_credentials as credentials
import agent_profiles
import ownership_registry as ownership
import stage_control as controls
import resources

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import application_client_service as service

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
# No project path, inferred extension, or user-supplied bundle entry is accepted.
TRUSTED_CODE = service.TRUSTED_CODE
API_RESOURCES = {'cpu_millis': 1000, 'memory_mib': 512, 'pids_limit': 128}
BROWSER_RESOURCES = {'cpu_millis': 2000, 'memory_mib': 2048, 'pids_limit': 512}
DOCKER_ENVIRONMENT = ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
                      'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION')
STARTUP_REASONS = frozenset(('accounting_unavailable','authority_changed','cleanup_unconfirmed',
    'credential_scope_invalid','evidence_unavailable','operation_not_granted','request_invalid',
    'resource-policy-invalid','runtime_mismatch','startup_failed'))
STARTUP_PHASES = frozenset(('reserve_topology','daemon_admission','image_admission','private_roots',
    'code_freeze','network_admission','launch_intent','bootstrap_prepare','process_launch',
    'container_identity','bootstrap_send','service_readiness','container_observation','host_route_observation',
    'authority_status','allocation_running'))
READINESS_CONDITIONS = frozenset(('timeout', 'eof', 'oversize', 'invalid_json',
    'unexpected_ready', 'transport_unavailable', 'interrupted'))


def _docker_environment():
    return {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(Path.home()),
            **{key: os.environ[key] for key in DOCKER_ENVIRONMENT if key in os.environ}}


class ClientError(ValueError):
    def __init__(self, reason, message='Application client admission or cleanup failed'):
        self.reason = reason
        super().__init__(message)


def validate_startup_failure(value, *, runroot):
    """Closed parent projection only; raw helper pipes remain private evidence."""
    c.exact(value,{'schema','phase','reason','diagnostic'},'/application_helper_startup')
    if type(value['schema']) is not int or value['schema']!=1:raise ClientError('request_invalid')
    c.choice(value['phase'],tuple(STARTUP_PHASES),'/phase');c.choice(value['reason'],tuple(STARTUP_REASONS),'/reason')
    reference=value['diagnostic']
    if reference is not None:
        c.exact(reference,{'path','sha256'},'/diagnostic');c.sha256(reference['sha256'],'/diagnostic/sha256')
        if type(reference['path']) is not str:raise ClientError('request_invalid')
        path=Path(reference['path']);expected=Path(runroot).absolute()/'application-startup'
        if (not path.is_absolute() or path.parent!=expected or str(path)!=reference['path']
                or re.fullmatch(r'pi-application-[a-f0-9]{16}\.json',path.name) is None):raise ClientError('request_invalid')
    return copy.deepcopy(value)


def _binding(value, plan_sha256):
    c.exact(value, service.BINDING_FIELDS, '/binding')
    for name in service.BINDING_FIELDS - {'plan_sha256'}:
        if name == 'trial_id' and value[name] is None:
            continue
        try:
            if str(uuid.UUID(value[name])) != value[name]:
                raise ValueError()
        except (ValueError, AttributeError, TypeError):
            raise ClientError('credential_scope_invalid') from None
    if value['plan_sha256'] != plan_sha256:
        raise ClientError('authority_changed')
    return copy.deepcopy(value)


@dataclass(frozen=True)
class Grant:
    scope: dict
    capability: str = field(repr=False)
    def context(self):
        return {'schema': 1, 'scope': copy.deepcopy(self.scope), 'capability': self.capability}


class Authority:
    def __init__(self, plan, endpoint, inference_key, store, project, runroot,
                 in_place=False, forbidden_roots=(), inference_authorities=None):
        self._plan = c.validate_ir(plan)
        self.project, self.runroot = Path(project).resolve(), Path(runroot).resolve()
        if (self.runroot == self.project or self.project in self.runroot.parents
                or self.runroot in self.project.parents):
            raise ClientError('credential_scope_invalid')
        self._store, self._endpoint, self._inference_key = store, copy.deepcopy(endpoint), inference_key
        selected = {stage['inference_binding']['configuration_sha256'] for stage in self.plan['stages']}
        if inference_authorities is None:
            if len(selected) != 1 or any(stage['inference_binding']['kind'] != 'legacy' for stage in self.plan['stages']):
                raise ClientError('credential_scope_invalid')
            inference_authorities = {next(iter(selected)): {'reference': endpoint['api_key_env'], 'value': inference_key}}
        if type(inference_authorities) is not dict or set(inference_authorities) != selected:
            raise ClientError('credential_scope_invalid')
        self._inference_authorities = copy.deepcopy(inference_authorities)
        for config, entry in self._inference_authorities.items():
            if type(entry) is not dict or set(entry) != {'reference', 'value'}:
                raise ClientError('credential_scope_invalid')
            if entry['reference'] is None:
                if entry['value'] != '':
                    raise ClientError('credential_scope_invalid')
            else:
                secret_store.check_name(entry['reference'])
                if type(entry['value']) is not str or len(entry['value'].encode()) > 16384:
                    raise ClientError('credential_scope_invalid')
                if entry['value'] and secret_store.clean_value(entry['value']) != entry['value']:
                    raise ClientError('credential_scope_invalid')
        self._inference_values = [inference_key, *(entry['value'] for entry in self._inference_authorities.values())]
        synthetic = {'agents': [], 'application_plan': self.plan}
        self._names = {}
        for stage in self.plan['stages']:
            aliases = {alias: 'PI_APP_ALIAS_' + str(i) for i, alias in enumerate(stage['credential_aliases'])}
            self._names[stage['id']] = aliases
            synthetic['agents'].append({'name': stage['id'], 'application_secrets': {
                aliases[alias]: self.plan['application']['credentials'][alias] for alias in aliases}})
        values = credentials.resolve(synthetic, endpoint, inference_key, store, self.project,
                                     self.runroot, in_place, (PACKAGE_ROOT, *forbidden_roots))
        self._values = {name: {alias: values[name][variable] for alias, variable in aliases.items()}
                        for name, aliases in self._names.items()}
        all_app_values = [value for aliases in self._values.values() for value in aliases.values()]
        app_references = {self.plan['application']['credentials'][alias]
                          for stage in self.plan['stages'] for alias in stage['credential_aliases']}
        if any(entry['reference'] in app_references for entry in self._inference_authorities.values() if entry['reference'] is not None):
            raise ClientError('credential_scope_invalid')
        if any(value and secrets.compare_digest(value.encode(), app.encode())
               for value in self._inference_values for app in all_app_values):
            raise ClientError('credential_scope_invalid')
        if credentials.Redactor([*self._inference_values, *all_app_values]).contains(c.canonical(self.plan)):
            raise ClientError('credential_scope_invalid')
        if any(not value.isascii() or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)
               for aliases in self._values.values() for value in aliases.values()):
            raise ClientError('credential_scope_invalid')
        self._generation = str(uuid.uuid4())
        self._control_token = secrets.token_hex(32)
        self._grants = []
        self._revoked = set()
        self._launched = False

    @property
    def plan(self):
        return copy.deepcopy(self._plan)

    def __repr__(self):
        return '<ApplicationAuthority private values withheld>'

    def launch_spec(self):
        return {'runtime': copy.deepcopy(self._plan['runtime']),
                'plan_sha256': self._plan['plan_sha256'], 'mode': 'authority-only',
                'browser': bool(self._plan['application']['browser_targets']),
                'actors': sorted({'application-actor:' + c.digest(stage['participant'])
                                  for stage in self._plan['stages']})}

    def revalidate(self):
        for stage in self.plan['stages']:
            for alias in stage['credential_aliases']:
                reference = self.plan['application']['credentials'][alias]
                value = credentials.read(reference, self._store)
                if not secrets.compare_digest(value.encode(), self._values[stage['id']][alias].encode()):
                    raise ClientError('authority_changed')
        return True

    def ensure_snapshot_clean(self):
        workspace = self.runroot / 'workspace'
        if (workspace.is_symlink() or not workspace.is_dir()
                or not credentials.workspace_inspected_clean(workspace, self.redactor())):
            raise ClientError('credential_scope_invalid')
        return True

    def grant(self, stage_name, binding):
        if self._launched:
            raise ClientError('authority_changed')
        stage = next((s for s in self.plan['stages'] if s['id'] == stage_name), None)
        if stage is None or len(self._grants) >= 64:
            raise ClientError('credential_scope_invalid')
        scope = {**_binding(binding, self.plan['plan_sha256']), 'stage_name': stage_name,
                 'participant': copy.deepcopy(stage['participant']),
                 'operation_ids': list(stage['operations']),
                 'credential_aliases': list(stage['credential_aliases']),
                 'authority_generation': self._generation}
        if self._grants and any(scope[key] != self._grants[0].scope[key]
                                for key in ('run_id', 'trial_id', 'attempt_id')):
            raise ClientError('authority_changed')
        if any(g.scope['segment_id'] == scope['segment_id']
               or g.scope['stage_name'] == stage_name and any(g.scope[key] != scope[key] for key in ('stage_id', 'session_id'))
               for g in self._grants):
            raise ClientError('authority_changed')
        if any(g.scope == scope for g in self._grants):
            raise ClientError('authority_changed')
        grant = Grant(scope, secrets.token_hex(32)); self._grants.append(grant)
        return grant

    def _bootstrap(self, evidence_root, code_identity, mode='authority-only', state_root=None):
        c.choice(mode, ('authority-only',), '/mode')
        if not self._grants:
            raise ClientError('credential_scope_invalid')
        self.revalidate()
        result = {'schema': 1, 'document_type': 'application_client_private_bootstrap',
                  'plan': copy.deepcopy(self.plan), 'authorities': copy.deepcopy(self._values),
                  'capabilities': [{'token': g.capability, 'scope': copy.deepcopy(g.scope)} for g in self._grants],
                  'control_token': self._control_token, 'evidence_root': str(evidence_root),
                  'code_identity': copy.deepcopy(code_identity), 'mode': mode}
        body = c.canonical(result)
        if len(body) > service.MAX_CONFIG_BYTES:
            raise ClientError('credential_scope_invalid')
        return body

    def independent_context(self):
        """Scorers/reviewers never receive application or inference capabilities."""
        return {'schema': 1, 'application_access': False}

    def redactor(self):
        return credentials.Redactor([*self._inference_values,
                                     *(value for aliases in self._values.values() for value in aliases.values())])

    def finish_stage(self, descriptor, result):
        stage = next((g for g in self._grants if g.scope['stage_id'] == descriptor['stage_id']), None)
        if stage is None or stage.capability not in self._revoked:
            raise ClientError('cleanup_unconfirmed')
        return credentials.finish(self.runroot, descriptor, self._values[stage.scope['stage_name']],
                                  self._inference_key, result,
                                  [*self._inference_values, *(v for values in self._values.values() for v in values.values())])


def admit(plan, *, endpoint, inference_key, store, project, runroot, in_place=False, forbidden_roots=(), inference_authorities=None):
    return Authority(plan, endpoint, inference_key, store, project, runroot, in_place, forbidden_roots, inference_authorities)


def _private_root(path):
    path = Path(path).absolute()
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ClientError('evidence_unavailable')
    finally:
        os.close(descriptor)
    return path


def freeze_code(root):
    root = _private_root(root)
    identity = {}
    for target in TRUSTED_CODE:
        body = agent_profiles.read_asset(PACKAGE_ROOT / target)
        path = root / target; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as output:
            output.write(body)
        path.chmod(0o400)
        identity[target] = hashlib.sha256(body).hexdigest()
    return identity


def _request(host, port, path, bearer, body):
    wire = c.canonical(body)
    if len(wire) > service.MAX_REQUEST_BYTES:
        raise ClientError('request_invalid')
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.request('POST', path, wire, {'Authorization': 'Bearer ' + bearer,
                                              'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(service.MAX_RESULT_BYTES + 1)
        if len(raw) > service.MAX_RESULT_BYTES:
            raise ClientError('evidence_unavailable')
        value = c.loads(raw, max_bytes=service.MAX_RESULT_BYTES)
        if response.status != 200 or value.get('ok') is not True:
            raise ClientError('operation_not_granted')
        return value
    except (OSError, http.client.HTTPException, c.ContractError):
        raise ClientError('evidence_unavailable') from None
    finally:
        connection.close()


def _send_bootstrap(process, body, timeout=10):
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        pending = memoryview(body)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ClientError('evidence_unavailable')
            try:
                count = os.write(process.stdin.fileno(), pending[:65536])
                pending = pending[count:]
            except BlockingIOError:
                continue
    finally:
        selector.close()
        process.stdin.close()


def _ready(process, deadline=10):
    selector = selectors.DefaultSelector()
    expires = time.monotonic() + deadline
    buffered = b''
    process._application_readiness_condition = None
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while b'\n' not in buffered:
            remaining = expires - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                process._application_readiness_condition = 'timeout'
                raise ClientError('evidence_unavailable')
            chunk = os.read(process.stdout.fileno(), min(8193 - len(buffered), 4096))
            if len(buffered) + len(chunk) > 8192:
                process._application_startup_output_unsafe = True
                process._application_readiness_condition = 'oversize'
                raise ClientError('evidence_unavailable')
            if not chunk:
                process._application_readiness_condition = 'eof'
                raise ClientError('evidence_unavailable')
            buffered += chunk
            # Keep consumed readiness bytes only on the owned private process
            # object; a later failure screens them before any persistence.
            process._application_startup_stdout = buffered
        try:
            value = c.loads(buffered.split(b'\n', 1)[0], max_bytes=8192)
        except c.ContractError:
            process._application_readiness_condition = 'invalid_json'
            raise
        if type(value) is not dict or value.get('status') != 'ready' or value.get('business_effects_enabled') is not False:
            process._application_readiness_condition = 'unexpected_ready'
            raise ClientError('evidence_unavailable')
        return value
    except OSError:
        process._application_readiness_condition = 'transport_unavailable'
        raise
    except KeyboardInterrupt:
        process._application_readiness_condition = 'interrupted'
        raise
    finally:
        selector.close()


def _startup_output(process, *, maximum=32768, seconds=3):
    """Drain only the already-owned Popen pipes, never a container selected by name."""
    if process is None:return {'status':'unavailable','stdout':b'','stderr':b''}
    if getattr(process,'_application_startup_output_unsafe',False) is True:return {'status':'withheld','stdout':b'','stderr':b''}
    prefix=getattr(process,'_application_startup_stdout',b'')
    if type(prefix) is not bytes or len(prefix)>maximum:return {'status':'withheld','stdout':b'','stderr':b''}
    streams={'stdout':bytearray(prefix),'stderr':bytearray()};deadline=time.monotonic()+seconds
    try:
        with selectors.DefaultSelector() as selector:
            for name in streams:
                stream=getattr(process,name)
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:return {'status':'withheld','stdout':b'','stderr':b''}
                for key,_ in selector.select(remaining):
                    body=os.read(key.fileobj.fileno(),min(4096,maximum-sum(map(len,streams.values()))+1))
                    if not body:selector.unregister(key.fileobj);continue
                    streams[key.data].extend(body)
                    if sum(map(len,streams.values()))>maximum:return {'status':'withheld','stdout':b'','stderr':b''}
        return {'status':'complete',**{name:bytes(value) for name,value in streams.items()}}
    except (OSError,ValueError,AttributeError):return {'status':'unavailable','stdout':b'','stderr':b''}


def _startup_diagnostic(helper, phase, error):
    """Safe private evidence before cleanup; credentials never enter exception text."""
    reason=getattr(error,'reason',None)
    if type(reason) is not str or reason not in STARTUP_REASONS:reason='startup_failed'
    if phase not in STARTUP_PHASES:phase='process_launch'
    projection={'schema':1,'phase':phase,'reason':reason,'diagnostic':None}
    captured=_startup_output(helper.process)
    extra=[getattr(helper.authority,'_control_token',''),
        *(grant.capability for grant in helper.authority._grants),
        *getattr(helper.authority,'_budget_tokens',{}).values(),
        *(item.capability for item in helper.reservations if item.capability)]
    participant=getattr(helper,'_participant_reservation',None)
    if participant is not None and participant.capability:extra.append(participant.capability)
    redactors=(helper.authority.redactor(),credentials.Redactor([value for value in extra if value]))
    if captured['status']=='complete' and any(redactor.contains(captured['stdout']+captured['stderr']) for redactor in redactors):
        captured={'status':'withheld','stdout':b'','stderr':b''}
    try:
        decoded={name:captured[name].decode('utf-8') for name in ('stdout','stderr')}
        if any((ord(character)<32 and character not in '\t\n\r') or 127<=ord(character)<=159
               for text in decoded.values() for character in text):raise ValueError()
    except (UnicodeError,ValueError):
        captured={'status':'withheld','stdout':b'','stderr':b''};decoded={'stdout':'','stderr':''}
    payload={'schema':1,'phase':phase,'reason':reason,'output_status':captured['status'],
        **decoded}
    # Closed parent observations survive withheld pipes without revealing their
    # contents or changing the original failure, deadline, reads or cleanup.
    condition=getattr(helper.process,'_application_readiness_condition',None)
    if phase=='service_readiness' and type(condition) is str and condition in READINESS_CONDITIONS:
        payload['readiness_condition']=condition
    wire=c.canonical(payload)
    if any(redactor.contains(wire) for redactor in redactors):return projection
    directory=_private_root(helper.authority.runroot/'application-startup')
    parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    path=directory/(helper.name+'.json')
    try:
        identity=os.fstat(parent);fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as stream:stream.write(wire);stream.flush();os.fsync(stream.fileno())
        os.fsync(parent);named=directory.lstat()
        if (identity.st_dev,identity.st_ino)!=(named.st_dev,named.st_ino):return projection
        projection['diagnostic']={'path':str(path),'sha256':hashlib.sha256(wire).hexdigest()}
    finally:os.close(parent)
    return projection


def _intent(registry, argv, name, image, private_root, binding, code_identity, mode='authority-only'):
    """Service-specific equivalent of Registry.intent; persist before Popen."""
    record = {'schema': 1, 'launch_id': str(uuid.uuid4()), 'generation': registry.generation,
              'registry': registry.registry_id, 'status': 'intent', 'container': name,
              'image': image, 'mounts': [], 'binding': {**copy.deepcopy(registry.binding), **copy.deepcopy(binding)},
              'runroot': str(private_root.parent.parent), 'created_at': controls.now(),
              'owner_pid': os.getpid(), 'daemon': registry.daemon,
              'application_helper': True, 'client_mode': mode, 'code_identity': copy.deepcopy(code_identity),
              # Generic gateway recovery refuses this prefix. Application recovery
              # must prove cleanup; it cannot silently purge/release this helper.
              'private_store': str(private_root)}
    for index, option in enumerate(argv):
        if option == '--mount':
            parts = argv[index + 1].split(','); fields = dict(p.split('=', 1) for p in parts if '=' in p)
            record['mounts'].append({'source': fields['src'], 'target': fields['dst'], 'rw': 'readonly' not in parts})
    registry.write(record)
    labels = ['--label', ownership.LABEL + '=' + record['launch_id'],
              '--label', ownership.REGISTRY_LABEL + '=' + registry.registry_id]
    return record, argv[:2] + labels + argv[2:]


class OwnedHelper:
    def __repr__(self):
        return '<OwnedApplicationHelper private authority withheld>'

    @classmethod
    def start(cls, authority, *, lab, args, registry, allocator, participant_resources,
              popen=subprocess.Popen, participant_reservation=None, borrowed_network=None):
        from native_budget_client import NativeBudgetAuthority
        from application_execution_authority import ReviewedAuthority
        if type(authority) not in (Authority, NativeBudgetAuthority, ReviewedAuthority) or authority._launched or not authority._grants:
            raise ClientError('authority_changed')
        authority.revalidate()  # precedes even Docker image inspection and setup
        if type(authority) is ReviewedAuthority:authority.preflight_bootstrap()
        authority.ensure_snapshot_clean()
        if args.platform != 'linux/arm64' or getattr(args, 'native_platform', None) != 'linux/arm64':
            raise ClientError('runtime_mismatch')
        if type(registry.daemon) is not str or not registry.daemon:
            raise ClientError('runtime_mismatch')
        if args.uid == 0 or args.uid != os.getuid():
            raise ClientError('runtime_mismatch')
        spec = authority.launch_spec()
        runtime = spec['runtime']['resources']['runtime']
        expected_participant = {'cpu_millis': round(runtime['cpus'] * 1000),
                                'memory_mib': resources.memory_bytes(runtime['memory']) // (1024 ** 2),
                                'pids_limit': runtime['pids_limit']}
        if participant_resources != expected_participant:
            raise ClientError('resource-policy-invalid')
        registry.require_capacity((1 if borrowed_network else 2) + len(authority._grants))
        if participant_reservation is not None and (
                allocator.records.get(participant_reservation.identity) is not participant_reservation
                or participant_reservation.kind != 'stage'
                or participant_reservation.state not in ('reserved', 'launching', 'running')
                or participant_reservation.resources != participant_resources
                or participant_reservation.binding.get('generation') != registry.generation):
            raise ClientError('resource-policy-invalid')
        if participant_reservation is not None:
            scope = authority._grants[0].scope
            binding = participant_reservation.binding
            if (any(key not in binding or binding[key] != scope[key] for key in ('run_id', 'attempt_id', 'trial_id'))
                    or binding.get('workspace') != str(authority.runroot / 'workspace')
                    or (scope['trial_id'] is None or 'stage_id' in binding) and binding.get('stage_id') != scope['stage_id']):
                raise ClientError('resource-policy-invalid')
        helper = cls(); helper.authority = authority; helper.lab = lab; helper.registry = registry
        helper.allocator = allocator; helper.process = None; helper.record = None
        helper.network_record = None; helper.private_root = None; helper.host_port = None
        helper.cleanup_receipt = None; helper.reservations = []; helper.container_id = None
        helper._participant_reservation = participant_reservation
        helper.borrowed_network = borrowed_network is not None
        helper.borrowed_network_id = None
        helper.docker_environment = _docker_environment()
        if authority.redactor().contains(c.canonical(helper.docker_environment)):
            raise ClientError('credential_scope_invalid')
        helper.name = 'pi-application-' + uuid.uuid4().hex[:16]
        footprint = BROWSER_RESOURCES if spec['browser'] else API_RESOURCES
        binding = {'generation': registry.generation, 'credential_authorities': spec['actors'],
                   'plan_sha256': spec['plan_sha256']}
        if spec['mode']=='budget-only':
            binding.update({key:authority._grants[0].scope[key] for key in
                            ('run_id','trial_id','attempt_id','stage_id','session_id')})
        phase='reserve_topology';launch_attempted=False
        try:
            requests = [('helper', footprint, 'helper', binding)]
            if participant_reservation is None:
                requests.append(('participant', participant_resources, 'stage', {'generation': registry.generation}))
            for suffix, weight, kind, scope in requests:
                item = allocator.request(helper.name + '-' + suffix, scope, weight, 30, kind)
                helper.reservations.append(item)
            allocator.dispatch()
            if any(item.state != 'reserved' for item in helper.reservations):
                raise ClientError('resource-policy-invalid')
            # Full topology is reserved before the first Docker probe.
            phase='daemon_admission';helper._check_daemon()
            phase='image_admission'
            image = lab.image_info(spec['runtime']['image_id'], 'linux/arm64')
            if image['id'] != spec['runtime']['image_id'] or image['platform'] != 'linux/arm64':
                raise ClientError('runtime_mismatch')
            phase='private_roots'
            helper.private_root = _private_root(authority.runroot / 'application-helpers' / uuid.uuid4().hex)
            root = helper.private_root
            helper.evidence_root = _private_root(authority.runroot / 'application-evidence' / helper.name)
            helper.state_root = _private_root(root / 'state')
            helper.evidence_data_root = helper.evidence_root
            helper.state_data_root = helper.state_root
            if spec['mode'] == 'application-execution':
                # A bind mount's synthetic root ownership may differ from its
                # owned children. Keep strict service checks on fixed children;
                # cleanup and privacy inspection still cover both whole mounts.
                helper.evidence_data_root = _private_root(helper.evidence_root / 'private')
                helper.state_data_root = _private_root(helper.state_root / 'private')
            code_root = _private_root(root / 'code')
            phase='code_freeze';code_identity = freeze_code(code_root)
            if type(authority) is ReviewedAuthority:authority.verify_code_identity(code_identity)
            phase='network_admission'
            if borrowed_network is None:
                helper.network_record = registry.network_intent(helper.name + '-network')
                network = helper.network_record['container']
                helper._command(['docker', 'network', 'create', '--driver', 'bridge',
                             '--label', ownership.LABEL + '=' + helper.network_record['launch_id'],
                             '--label', ownership.REGISTRY_LABEL + '=' + registry.registry_id, network], timeout=15)
            else:
                record = copy.deepcopy(borrowed_network)
                if (record.get('kind') != 'network' or record.get('registry') != registry.registry_id
                        or record.get('generation') != registry.generation or record.get('daemon') != registry.daemon
                        or record.get('status') not in ('intent', 'running')
                        or not any(item == record for item in registry.load())):
                    raise ClientError('runtime_mismatch')
                observed_network = json.loads(helper._command(['docker', 'network', 'inspect', record['container']], timeout=15).stdout)
                if len(observed_network) != 1:
                    raise ClientError('runtime_mismatch')
                observed_network = observed_network[0]; labels = observed_network.get('Labels') or {}
                if (observed_network.get('Driver') != 'bridge' or labels.get(ownership.LABEL) != record['launch_id']
                        or labels.get(ownership.REGISTRY_LABEL) != registry.registry_id
                        or type(observed_network.get('Id')) is not str or len(observed_network['Id']) != 64
                        or any(ch not in '0123456789abcdef' for ch in observed_network['Id'])):
                    raise ClientError('runtime_mismatch')
                helper.network_record, network = record, record['container']
                helper.borrowed_network_id = observed_network['Id']
            argv = ['docker', 'run', '--pull=never', '--interactive', '--name', helper.name, '--init', '--platform', 'linux/arm64',
                    '--read-only', '--user', str(args.uid) + ':' + str(args.gid), '--cap-drop=ALL',
                    '--security-opt=no-new-privileges=true', '--ipc=none', '--pids-limit', str(footprint['pids_limit']),
                    '--memory', str(footprint['memory_mib']) + 'm', '--memory-swap', str(footprint['memory_mib']) + 'm',
                    '--cpus', str(footprint['cpu_millis'] / 1000), '--network', network,
                    '--network-alias', 'pi-application', '--publish', '127.0.0.1::8081',
                    '--entrypoint=python3', '--workdir=/pi-client/state',
                    '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTHONUNBUFFERED=1',
                    '--mount', 'type=bind,src=' + str(code_root) + ',dst=/opt/pi-application,readonly,bind-recursive=disabled',
                    '--mount', 'type=bind,src=' + str(helper.evidence_root) + ',dst=/pi-client/evidence,bind-recursive=disabled',
                    '--mount', 'type=bind,src=' + str(helper.state_root) + ',dst=/pi-client/state,bind-recursive=disabled']
            if spec['browser'] and spec['runtime']['container_profile'] == 'browser':
                import browser_security
                policy = browser_security.verify(PACKAGE_ROOT / 'assets/security/chromium-userns.json')
                argv += ['--security-opt', 'seccomp=' + str(policy)]
            if spec['mode'] == 'application-execution':
                argv += ['--env', 'HOME=/pi-client/state/private/home', '--env', 'TMPDIR=/pi-client/state/private/tmp']
            argv += [image['id'], '/opt/pi-application/runtime/application_client_service.py', '--port', '8081']
            phase='launch_intent'
            helper.record, argv = _intent(registry, argv, helper.name, image['id'], root, binding, code_identity, spec['mode'])
            item = helper.reservations[0]
            allocator.consume(item.identity, item.capability, item.binding, item.resources)
            authority.revalidate()
            phase='bootstrap_prepare'
            bootstrap = authority._bootstrap('/pi-client/evidence/private' if spec['mode'] == 'application-execution' else '/pi-client/evidence',
                                             code_identity, mode=spec['mode'],
                                             state_root='/pi-client/state/private' if spec['mode'] == 'application-execution' else '/pi-client/state')
            helper._check_daemon()
            phase='process_launch';launch_attempted=True;identity_deadline=time.monotonic()+5
            helper.process = popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=helper.docker_environment,
                                   start_new_session=True)
            phase='container_identity';helper._bind_container_identity(identity_deadline)
            phase='bootstrap_send';_send_bootstrap(helper.process, bootstrap)
            authority._launched = True
            phase='service_readiness';_ready(helper.process)
            phase='container_observation'
            observed = json.loads(helper._command(['docker', 'container', 'inspect', helper.container_id], timeout=15).stdout)[0]
            helper._verify_observation(observed)
            phase='host_route_observation'
            host = observed['HostConfig']; ports = observed['NetworkSettings']['Ports']['8081/tcp']
            if (host.get('NanoCpus') != footprint['cpu_millis'] * 1000000
                    or host.get('Memory') != footprint['memory_mib'] * 1024 ** 2
                    or host.get('MemorySwap') != host.get('Memory') or host.get('PidsLimit') != footprint['pids_limit']
                    or len(ports) != 1 or ports[0].get('HostIp') != '127.0.0.1'
                    or not str(ports[0].get('HostPort', '')).isdigit()):
                raise ClientError('runtime_mismatch')
            helper.container_id = observed['Id']
            helper.record['container_id'] = helper.container_id
            helper.host_port = int(ports[0]['HostPort'])
            first = authority._grants[0]
            phase='authority_status'
            status = _request('127.0.0.1', helper.host_port, '/ipc', first.capability,
                              {'schema': 1, 'action': 'status', 'scope': first.scope, 'operation_id': None})
            if status.get('business_effects_enabled') is not False:
                raise ClientError('runtime_mismatch')
            if spec['mode'] == 'budget-only' and status.get('native_budget_enabled') is not True:
                raise ClientError('runtime_mismatch')
            phase='allocation_running';allocator.running(helper.reservations[0].identity)
            helper.record['status'] = 'running'; registry.write(helper.record)
            return helper
        except BaseException as error:
            try:startup=_startup_diagnostic(helper,phase,error)
            except Exception:
                reason=getattr(error,'reason',None)
                startup={'schema':1,'phase':phase,'reason':reason if type(reason) is str and reason in STARTUP_REASONS else 'startup_failed','diagnostic':None}
            try:error.application_helper_startup=startup;error.application_helper_launch_attempted=launch_attempted
            except Exception:pass
            try:
                receipt=helper.cleanup(writers_absent=True)
                error.application_helper_cleanup=copy.deepcopy(receipt)
            except BaseException:pass
            raise

    @property
    def participant_reservation(self):
        return self._participant_reservation if self._participant_reservation is not None else self.reservations[1]

    def context(self, grant):
        if grant not in self.authority._grants or grant.capability in self.authority._revoked or self.cleanup_receipt is not None:
            raise ClientError('operation_not_granted')
        return {**grant.context(), 'base_url': 'http://pi-application:8081/ipc',
                'network': self.network_record['container']}

    def revoke(self, grant):
        if grant not in self.authority._grants:
            raise ClientError('operation_not_granted')
        if grant.capability in self.authority._revoked:
            return {'schema': 1, 'ok': True, 'revoked': True}
        result = _request('127.0.0.1', self.host_port, '/control', self.authority._control_token,
                          {'schema': 1, 'action': 'revoke', 'capability': grant.capability})
        self.authority._revoked.add(grant.capability)
        return result

    def native_budget_status(self):
        from native_budget_client import NativeBudgetAuthority
        import native_budget_controls
        if type(self.authority) is not NativeBudgetAuthority or self.cleanup_receipt is not None:
            raise ClientError('operation_not_granted')
        result = _request('127.0.0.1', self.host_port, '/control', self.authority._control_token,
                          {'schema': 1, 'action': 'status'})
        return native_budget_controls.public_snapshot(result['budget'],
            allowed_tools=[tool['name'] for tool in self.authority.tools])

    def extend_native_budget(self, *, max_tool_calls, remaining_seconds):
        import native_budget_controls
        self.native_budget_status()  # proves the live helper mode and private context
        result = _request('127.0.0.1', self.host_port, '/control', self.authority._control_token,
            {'schema': 1, 'action': 'extend', 'max_tool_calls': max_tool_calls,
             'remaining_seconds': remaining_seconds})
        return native_budget_controls.public_snapshot(result['budget'],
            allowed_tools=[tool['name'] for tool in self.authority.tools])

    def checkpoint_native_budget(self):
        import native_budget_controls
        self.native_budget_status()
        result = _request('127.0.0.1', self.host_port, '/control', self.authority._control_token,
                          {'schema': 1, 'action': 'checkpoint'})
        return native_budget_controls.public_snapshot(result['budget'],
            allowed_tools=[tool['name'] for tool in self.authority.tools])

    def continue_native_budget(self, segment_id, extension_order_sha256):
        from native_budget_client import NativeBudgetAuthority
        import native_budget_controls
        c.sha256(extension_order_sha256, '/extension_order_sha256')
        if (type(self.authority) is not NativeBudgetAuthority or self.cleanup_receipt is not None
                or not self.authority._grants or len(self.authority._grants) >= 64):
            raise ClientError('operation_not_granted')
        previous = self.authority._grants[-1]
        if previous.capability in self.authority._revoked:
            raise ClientError('operation_not_granted')
        binding = {key: previous.scope[key] for key in service.BINDING_FIELDS}
        binding['segment_id'] = segment_id; _binding(binding, self.authority.plan_sha256)
        if any(grant.scope['segment_id'] == segment_id for grant in self.authority._grants):
            raise ClientError('operation_not_granted')
        authority_token, budget_token = secrets.token_hex(32), secrets.token_hex(32)
        old_tokens = {self.authority._control_token, *self.authority._budget_tokens.values(),
                      *(grant.capability for grant in self.authority._grants)}
        if authority_token == budget_token or authority_token in old_tokens or budget_token in old_tokens:
            raise ClientError('authority_changed')
        result = _request('127.0.0.1', self.host_port, '/control', self.authority._control_token,
            {'schema': 1, 'action': 'continue', 'segment_id': segment_id,
             'authority_token': authority_token, 'budget_token': budget_token})
        if result.get('ok') is not True:
            raise ClientError('accounting_unavailable')
        native_budget_controls.public_snapshot(result['budget'],
            allowed_tools=[tool['name'] for tool in self.authority.tools])
        self.authority._revoked.add(previous.capability)
        grant = Grant({**previous.scope, 'segment_id': segment_id}, authority_token)
        self.authority._grants.append(grant); self.authority._budget_tokens[segment_id] = budget_token
        self.authority._grant_digests[grant.capability] = c.digest(grant.scope)
        return self.authority.budget_context(grant, extension_order_sha256)

    def _command(self, argv, **kwargs):
        if _docker_environment() != self.docker_environment:
            raise ClientError('runtime_mismatch')
        return self.lab.command(argv, **kwargs)

    def _check_daemon(self,timeout=15):
        observed = self._command(['docker', 'info', '--format', '{{.ID}}'], timeout=timeout, required=False)
        if observed.returncode or observed.stdout.strip() != self.registry.daemon:
            raise ClientError('runtime_mismatch')

    def _bind_container_identity(self,deadline):
        """Bind custody before sending any private bootstrap bytes, without a launch retry."""
        while time.monotonic()<deadline:
            self._check_daemon(timeout=max(.01,min(1,deadline-time.monotonic())))
            if time.monotonic()>=deadline:break
            reply=self._command(['docker','container','inspect',self.name],timeout=max(.01,min(1,deadline-time.monotonic())),required=False)
            if time.monotonic()>=deadline:break
            if ownership.absent(reply):
                if self.process.poll() is not None:break
                time.sleep(min(.05,max(0,deadline-time.monotonic())));continue
            if reply.returncode or len(reply.stdout.encode())>1048576:raise ClientError('cleanup_unconfirmed')
            observed=json.loads(reply.stdout)
            if type(observed) is not list or len(observed)!=1:raise ClientError('cleanup_unconfirmed')
            identifier=self._verify_observation(observed[0])
            if time.monotonic()>=deadline:break
            self.container_id=identifier
            self.record['container_id']=self.container_id;self.registry.write(self.record)
            return
        raise ClientError('cleanup_unconfirmed')

    def _reap_owned_process(self):
        if self.process is None:return
        if getattr(self.process,'stdin',None) is not None and not self.process.stdin.closed:self.process.stdin.close()
        try:self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        for stream in (self.process.stdout,self.process.stderr):stream.close()

    def _verify_observation(self, observed):
        identifier = observed.get('Id')
        if (type(identifier) is not str or len(identifier) != 64
                or any(ch not in '0123456789abcdef' for ch in identifier)):
            raise ClientError('cleanup_unconfirmed')
        labels = observed.get('Config', {}).get('Labels') or {}
        if (observed.get('Image') != self.record['image']
                or labels.get(ownership.LABEL) != self.record['launch_id']
                or labels.get(ownership.REGISTRY_LABEL) != self.registry.registry_id
                or self.container_id is not None and identifier != self.container_id):
            raise ClientError('cleanup_unconfirmed')
        actual = observed.get('Mounts', [])
        if len(actual) != len(self.record['mounts']) or any(not any(
                mount.get('Source') == expected['source']
                and mount.get('Destination') == expected['target']
                and mount.get('RW') == expected['rw'] for mount in actual)
                for expected in self.record['mounts']):
            raise ClientError('cleanup_unconfirmed')
        if getattr(self, 'borrowed_network_id', None) is not None:
            network = observed.get('NetworkSettings', {}).get('Networks', {}).get(self.network_record['container'], {})
            if network.get('NetworkID') != self.borrowed_network_id:
                raise ClientError('cleanup_unconfirmed')
        return identifier

    def cleanup(self, *, writers_absent):
        if self.cleanup_receipt is not None:
            return copy.deepcopy(self.cleanup_receipt)
        physical = self.record is None
        clean = writers_absent is True
        workspace_status, evidence_status = 'clean', 'quarantined'
        try:
            if self.record is not None:
                self._check_daemon()
                if (type(self.container_id) is not str or re.fullmatch(r'[a-f0-9]{64}',self.container_id) is None
                        or self.record.get('container_id')!=self.container_id):raise ClientError('cleanup_unconfirmed')
                inspected = self._command(['docker', 'container', 'inspect', self.container_id], timeout=15, required=False)
                if ownership.absent(inspected):
                    # A process that exits before readiness still needs the
                    # real registry's positive absence transition before release.
                    physical = self.registry.confirm_absent(self.record)
                else:
                    if inspected.returncode or len(inspected.stdout.encode()) > 1048576:
                        raise ClientError('cleanup_unconfirmed')
                    identifier = self._verify_observation(json.loads(inspected.stdout)[0])
                    for grant in self.authority._grants:
                        try:
                            if self.host_port is not None:
                                self.revoke(grant)
                        except (ClientError, OSError):
                            pass
                    # The verified immutable ID prevents a same-name replacement
                    # between inspection and removal from becoming a deletion target.
                    self._command(['docker', 'rm', '--force', identifier], timeout=15, required=False)
                    physical = self.registry.confirm_absent(self.record)
            self._reap_owned_process()
            if not physical or not clean:
                raise ClientError('cleanup_unconfirmed')
            self.authority._revoked.update(g.capability for g in self.authority._grants)
            workspace = self.authority.runroot / 'workspace'
            if workspace.exists() or workspace.is_symlink():
                if workspace.is_symlink():
                    raise ClientError('cleanup_unconfirmed')
                if not credentials.workspace_inspected_clean(workspace, self.authority.redactor()):
                    shutil.rmtree(workspace)
                    workspace_status = 'discarded'
            if getattr(self, 'evidence_root', None) is not None:
                if self.evidence_root.is_symlink() or not credentials.workspace_inspected_clean(self.evidence_root, self.authority.redactor()):
                    raise ClientError('cleanup_unconfirmed')
                evidence_status = 'retained'
            if self.private_root is not None:
                if self.private_root.is_symlink():
                    raise ClientError('cleanup_unconfirmed')
                shutil.rmtree(self.private_root)
            if self.network_record is not None and not getattr(self, 'borrowed_network', False):
                self.registry.remove_network(self.network_record)
                self.registry.release(self.network_record, True)
            if self.record is not None:
                self.registry.release(self.record, True)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            clean = False
            if self.record is not None:
                self.record['status'] = 'quarantined'; self.registry.write(self.record)
            try:self._reap_owned_process()
            except (OSError,ValueError,subprocess.TimeoutExpired):pass
        for item in self.reservations:
            if item.state == 'queued':
                self.allocator.cancel_queued(item.identity)
            elif item.state in ('reserved', 'launching', 'running', 'stopping', 'quarantined'):
                self.allocator.release(item.identity, physical, clean)
        self.cleanup_receipt = {'schema': 1, 'status': 'removed' if physical and clean else 'cleanup_unconfirmed',
                                'workspace': workspace_status if physical and clean else 'quarantined',
                                'evidence': evidence_status,
                                'evidence_root': str(self.evidence_root) if getattr(self, 'evidence_root', None) is not None else None,
                                'safe_to_continue': physical and clean and workspace_status == 'clean'}
        return copy.deepcopy(self.cleanup_receipt)

    def require_clean(self):
        if self.cleanup_receipt is None or self.cleanup_receipt['safe_to_continue'] is not True:
            raise ClientError('cleanup_unconfirmed')
        return True
