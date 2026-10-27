"""Report-only restrictive original-SDK admission preflight. Not live authority.

AdmissionGate(policy) is pure at construction. resources.admission_lock calls it
after the ORIGINAL flock and before its header/Registry constructor. The original
Registry/reconcile/CURRENT/capacity path must still run. No cached SDK evidence is
returned. Only the explicit accepted all-released branch is eligible.
"""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time


class AdmissionDenied(ValueError):
    pass


def require(value, code):
    if not value:
        raise AdmissionDenied(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def identifier(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9-]{36}', value) is not None


def canonical_uuid(value):
    return type(value) is str and re.fullmatch(
        r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', value) is not None


def sha(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def absolute(value):
    require(type(value) is str and value.startswith('/') and not value.startswith('//')
            and '..' not in Path(value).parts and str(Path(value)) == value
            and value != '/', 'path_not_exact')
    return Path(value)


def decode(body):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_metadata_field')
            value[key] = item
        return value
    return json.loads(body, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          AdmissionDenied('nonfinite_metadata')))


def signature(info):
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size',
        'st_mtime_ns', 'st_ctime_ns'))


RECORD_REQUIRED = frozenset(('schema','launch_id','generation','registry','status',
                            'container','image','mounts','daemon','runroot'))
RECORD_ALLOWED = RECORD_REQUIRED | frozenset(('binding','created_at','owner_pid',
    'kind','application_helper','client_mode','code_identity','private_store',
    'container_id','qualification_cell','qualification_role',
    'qualification_service_cleanup','qualification_preworker_cleanup','diagnostic_entrypoint',
    'gateway_state','gateway_ready','inference_uncertain'))
BINDING_ALLOWED = frozenset(('run_id','attempt_id','trial_id','stage_id','segment_id',
    'generation','credential_authorities','plan_sha256','startup_diagnostic',
    'qualification_id','artifact_diagnostic','indexed_host_generation','session_id'))
PARALLEL_BINDING_REQUIRED = frozenset(('generation','trial_id','image','release_contracts',
    'daemon','credential_authorities','run_id','attempt_id','workspace'))
PARALLEL_BINDING_OPTIONAL = frozenset(('stage_id','segment_id','indexed_host_generation'))
PARALLEL_BINDING_MARKERS = frozenset(('image','release_contracts','daemon','workspace'))
# Literal identities from runtime/release_contracts.py. A regression compares
# these to its snapshot; admission never imports a new product module.
PARALLEL_RELEASE_CONTRACTS = {
    '0.87.1': {'release':'0.87.1','id':'pi-json-direct-0.87.1','revision':1,
        'sha256':'4f15d43728d06659bd5156458c895aea8babfcbfebcfc0d4ba9819ef98df3acb'},
    '1.2.0': {'release':'1.2.0','id':'pi-json-direct-1.2.0','revision':1,
        'sha256':'65a4620bd2d51eec37524bfe0c5cb3e6c648b4460dee2612637129f25eec36bc'},
}
AUXILIARY_BINDING_KEYS = frozenset(('authorization_id','case_id','auxiliary_binding_sha256'))
AUXILIARY_RECORD_REQUIRED = RECORD_REQUIRED | frozenset(('binding','created_at','owner_pid','diagnostic'))
AUXILIARY_AUTHORIZATION_ID = 'ae0a11fc-e188-46a4-b6e7-a50b7918f734'
AUXILIARY_BINDING_SHA256 = '710f5674ab772db745e1a0dfa8f17d82fe4d734ac494db421a4afd070c360665'
AUXILIARY_IMAGE = 'sha256:47856fc949cc114980b4befa37bf6ae17711e84b56be2fb5370fe66e1d216102'
CODE_KEYS = frozenset(('runtime/application-browser-cdp.mjs','runtime/application_api.py',
    'runtime/application_browser.py','runtime/application_budget.py',
    'runtime/application_client_service.py','runtime/application_execution_service.py',
    'runtime/application_files.py','runtime/application_runtime_contracts.py',
    'runtime/native_budget_service.py','runtime/native_tool_contracts.py',
    'runtime/prompt_contract.py','runtime/release_contracts.py','scripts/application_contracts.py',
    'scripts/application_credentials.py','scripts/application_documents.py',
    'scripts/application_evidence.py','scripts/resources.py','scripts/secret_store.py',
    'scripts/stage_control.py','scripts/tool_budgets.py'))
# Historical records retain their exact bundles. Current helpers additionally
# freeze the diagnostics dependency imported by their existing host utilities.
BROWSER_CODE_KEYS = CODE_KEYS | frozenset(('runtime/browser-options.mjs',))
CURRENT_CODE_KEYS = BROWSER_CODE_KEYS | frozenset(('scripts/registry_diagnostics.py',))
KNOWN_OWNERS_DIGEST = '86448b597f9d069231eb173ec9978fa726f232a8f3e310f0a8aeb276f9b9919e'
KNOWN_PREWORKER_DIGEST = '2f8f1416af87de688ab90b07601489f1434c83620d2867275d0b348b37153f9c'
PREWORKER_ID = '0234d21b-a2fd-40cb-bd28-0467e5ae4484'
PROOF_AGGREGATE_BYTES = 67108864
_TICKET = object()


class _CurrentPolicy(dict):
    """Only the source-owned under-flock extender creates an activation ticket."""
    pass


def reference(value):
    require(type(value) is dict and set(value) == {'path','sha256'} and sha(value['sha256']),
            'reference_schema')
    absolute(value['path']); return value


def derive_read_closure(owners, projection):
    """Pure source-defined role graph; classification cannot be caller-expanded."""
    require(digest(projection) == KNOWN_PREWORKER_DIGEST, 'preworker_projection_changed')
    files = {}; absent = set()
    def add(ref, role, maximum, multiplicity=1):
        reference(ref); require(ref['path'] not in files, 'duplicate_proof_role')
        files[ref['path']] = {**ref,'role':role,'maximum_bytes':maximum,
                              'read_multiplicity':multiplicity}
    for key, owner in sorted(owners.items()):
        require(identifier(key) and type(owner) is dict, 'owner_schema')
        if owner.get('subtype') == 'service':
            require(set(owner) == {'subtype','reference','private_mount_source'}, 'service_owner_schema')
            absent.add(str(absolute(owner['private_mount_source'])))
            add(owner['reference'],'typed_service_owner_metadata',65536,
                2 if owner['reference'] in projection['service_receipts'] else 1)
        else:
            require(key == PREWORKER_ID and set(owner) == {'subtype','reference'}
                    and owner['subtype'] == 'preworker'
                    and owner['reference'] == projection['source_reference'], 'preworker_subject')
            add(owner['reference'],'typed_preworker_owner_metadata',262144)
    require(len(projection['qualification']['lineage']) == 2, 'lineage_count')
    for item in projection['qualification']['lineage']:
        for field in ('manifest','state','ledger'):
            add(item[field],'fixed_qualification_'+field,4194304)
    for field in ('descriptor','state','process','result'):
        add(projection['stage'][field],'exact_historical_SDK_'+field,4194304)
    for field in ('parent_terminal','original_invocation'):
        add(projection['controller'][field],'closed_controller_'+field,4194304)
    private = projection['private_cleanup']
    for field,pathkey in (('helper','source'),('parent_bootstrap','path'),('workspace','path')):
        absent.add(str(absolute(private[field][pathkey])))
    control = private['control']; require(len(control['retained_files']) == 3, 'control_count')
    for row in control['retained_files']:
        require(set(row) == {'path','sha256','bytes'} and type(row['bytes']) is int
                and row['bytes'] >= 0 and row['path'] in ('endpoint.json','stage.json','task.json'), 'control_schema')
        add({'path':str(absolute(control['path'])/row['path']),'sha256':row['sha256']},'classified_control_metadata',row['bytes'])
    require(sum(r['bytes'] for r in control['retained_files']) == 17487, 'control_bytes')
    require(len(projection['launches']) == 19 and len({r['launch_id'] for r in projection['launches']}) == 19,
            'current_reference_count')
    return {'files':files,'absent_paths':sorted(absent),
        'control_tree':{k:copy.deepcopy(control[k]) for k in ('path','device','inode','directories')},
        'current_registry_ids':sorted(r['launch_id'] for r in projection['launches']),
        'numeric_PID_calls':0,'original_semantic_validators_mandatory':True}


class AdmissionGate:
    """A source-owned restrictive callback, never an alternative SDK admission."""
    def __init__(self, policy):
        require(type(policy) in (dict,_CurrentPolicy), 'policy_type')
        require(policy.get('schema') == 1 and policy.get('document_type') ==
                'qualification_sdk_admission_policy', 'policy_schema')
        ticket = getattr(policy,'_ticket',None)
        self._initial_bytes = getattr(policy,'_bytes',0)
        # Pure validation. No path is opened/resolved/statted by the constructor.
        self.policy = decode(canonical(policy))
        self.lock_path = absolute(policy['lock_path'])
        self.registry_root = absolute(policy['registry_root'])
        require(str(self.registry_root) == str(self.lock_path) + '.registry',
                'registry_not_original_lock')
        self.expected = dict(policy['expected_canonical_records'])
        require(0 < len(self.expected) <= 8192 and all(
            identifier(k) and sha(v) for k, v in self.expected.items()),
            'record_selector_schema')
        require(len(set(policy['selected_task_records'])) == 281 and
                set(policy['selected_task_records']) <= set(self.expected),
                'selected_task_scope')
        limits = policy['limits']
        require(limits == {'seconds': 120, 'per_record_bytes': 1048576,
                           'aggregate_record_bytes': 33554432,
                           'maximum_committed_records': 8192,
                           'minimum_headroom': 210}, 'policy_limits')
        base = policy['base_qualification_owners']
        require(digest(base) == KNOWN_OWNERS_DIGEST and len(base) == 56, 'known_owner_set_changed')
        self.profiles = dict(policy['qualification_owners'])
        require(all(self.profiles.get(k) == v for k,v in base.items()), 'baseline_owner_changed')
        if self.profiles != base or policy.get('extension') is not None:
            require(ticket is _TICKET, 'extension_not_source_derived')
        require(all(identifier(k) and v.get('subtype') in ('service', 'preworker')
                    for k, v in self.profiles.items()), 'qualification_owner_schema')
        self.closure = derive_read_closure(self.profiles,policy['preworker_projection'])
        self.reads = self.closure['files']
        require(set(self.closure['current_registry_ids']) <= set(self.expected), 'current_refs_outside_snapshot')
        require(len(self.profiles) <= 56+56 and len(self.reads) <= 127, 'proof_role_limit')
        require(policy['proof_limits'] == {'base_unique_files':71,'maximum_unique_files':127,
            'aggregate_maximum_bytes':PROOF_AGGREGATE_BYTES}, 'proof_limits')
        activation = policy['activation']; budget = policy['admission_budget']
        require(type(activation) is dict and set(activation) == {'lease_device','lease_inode',
            'registry_device','registry_inode','global_deadline_monotonic','global_deadline_wall',
            'proof_read_authority'}, 'activation_unbound')
        for key in ('lease_device','lease_inode','registry_device','registry_inode'):
            require(type(activation[key]) is int and activation[key] >= (1 if key.endswith('inode') else 0), 'activation_identity')
        require(type(budget) is dict and set(budget) == {'started_monotonic','started_wall',
            'deadline_monotonic','deadline_wall'}, 'budget_unbound')
        for value in list(budget.values())+[activation['global_deadline_monotonic'],activation['global_deadline_wall']]:
            require(type(value) in (int,float) and math.isfinite(value), 'clock_unbound')
        for suffix in ('monotonic','wall'):
            require(budget['started_'+suffix] < budget['deadline_'+suffix] <= min(
                budget['started_'+suffix]+120,activation['global_deadline_'+suffix]-30), 'clock_or_reserve')
        require(activation['proof_read_authority'] == digest(self.closure), 'exact_proof_authority_unbound')
        self.witness = None
        self._snapshots = None
        self._called = False

    def _begin(self):
        b=self.policy['admission_budget'];self._end=b['deadline_monotonic'];self._wall_end=b['deadline_wall']
        self._last_mono=b['started_monotonic'];self._last_wall=b['started_wall']
        self._fence()
        require(time.monotonic() >= b['started_monotonic'] and time.time() >= b['started_wall'], 'clock_before_entry')

    def _fence(self):
        mono=time.monotonic();wall=time.time()
        require(self._last_mono<=mono<self._end and self._last_wall<=wall<self._wall_end, 'preflight_deadline_or_clock_regression')
        self._last_mono=mono;self._last_wall=wall

    def _directory(self, path):
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:]:
                self._fence()
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _lease(self, fd):
        self._fence()
        held = os.fstat(fd)
        parent = self._directory(self.lock_path.parent)
        try:
            named = os.stat(self.lock_path.name, dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)
        require(signature(held) == signature(named) and stat.S_ISREG(held.st_mode)
                and held.st_uid == os.getuid() and stat.S_IMODE(held.st_mode) == 0o600
                and held.st_nlink == 1, 'original_lease_identity')
        a=self.policy['activation']
        require((held.st_dev,held.st_ino)==(a['lease_device'],a['lease_inode']), 'lease_snapshot_changed')
        return held.st_dev, held.st_ino

    def _registry(self,fd):
        self._fence();held=os.fstat(fd);parent=self._directory(self.registry_root.parent)
        try:named=os.stat(self.registry_root.name,dir_fd=parent,follow_symlinks=False)
        finally:os.close(parent)
        a=self.policy['activation']
        require(signature(held)==signature(named) and stat.S_ISDIR(held.st_mode)
            and held.st_uid==os.getuid() and stat.S_IMODE(held.st_mode)==0o700
            and (held.st_dev,held.st_ino)==(a['registry_device'],a['registry_inode']), 'original_registry_identity')
        return held

    def _names(self, fd, wanted=None):
        seen = set()
        wanted = {key + '.json' for key in self.expected} if wanted is None else wanted
        with os.scandir(fd) as entries:
            for entry in entries:
                self._fence()
                require(len(seen) < len(wanted), 'namespace_overflow')
                name = entry.name
                require(name in wanted and name not in seen, 'unknown_registry_name')
                seen.add(name)
        require(seen == wanted, 'missing_registry_name')
        return sorted(seen)

    def _auxiliary_shape(self, value, binding):
        # Only this fixed source-produced C02 incident has diagnostic/numeric
        # timestamp metadata. It is not a generic top-level allowance.
        require(AUXILIARY_RECORD_REQUIRED <= set(value) <=
                AUXILIARY_RECORD_REQUIRED | {'container_id'}, 'auxiliary_record_fields_not_classified')
        require(type(binding) is dict and set(binding) == AUXILIARY_BINDING_KEYS,
                'auxiliary_binding_fields_not_classified')
        require(binding['authorization_id'] == AUXILIARY_AUTHORIZATION_ID
                and type(binding['case_id']) is int and 1 <= binding['case_id'] <= 3
                and binding['auxiliary_binding_sha256'] == AUXILIARY_BINDING_SHA256,
                'auxiliary_binding_identity')
        current = self.policy.get('current_scope')
        require(type(current) is dict and 'repository_root' in current, 'auxiliary_repository_unbound')
        expected = absolute(current['repository_root']) / 'reports/application-agent-enhancements/A15/campaign-002/auxiliary/cases' / str(binding['case_id'])
        require(type(value['schema']) is int and value['schema'] == 1
                and value['diagnostic'] is True and value['image'] == AUXILIARY_IMAGE
                and value['runroot'] == str(expected), 'auxiliary_record_identity')
        created = value['created_at']
        require(type(created) is int or type(created) is float and math.isfinite(created),
                'auxiliary_created_at_shape')

    def _binding_shape(self, value, binding, auxiliary):
        if auxiliary:
            return
        require(type(binding) is dict, 'binding_fields_not_classified')
        parallel = bool(set(binding) & PARALLEL_BINDING_MARKERS)
        if parallel:
            require(PARALLEL_BINDING_REQUIRED <= set(binding) <=
                    PARALLEL_BINDING_REQUIRED | PARALLEL_BINDING_OPTIONAL,
                    'parallel_binding_fields_not_classified')
            require(binding['generation'] == value['generation']
                    and binding['image'] == value['image'] and binding['daemon'] == value['daemon'],
                    'parallel_binding_record_identity')
            require(all(canonical_uuid(binding[field]) for field in ('run_id','attempt_id','trial_id'))
                    and all(canonical_uuid(binding[field]) for field in ('stage_id','segment_id') if field in binding),
                    'parallel_binding_uuid')
            runroot = absolute(value['runroot'])
            require(runroot.name == binding['run_id'] and runroot.parent.name == 'runs'
                    and binding['workspace'] == str(runroot / 'workspace'), 'parallel_workspace_identity')
            contracts = binding['release_contracts']
            require(type(contracts) is dict and set(contracts) == set(PARALLEL_RELEASE_CONTRACTS),
                    'parallel_release_contracts')
            for release, expected in PARALLEL_RELEASE_CONTRACTS.items():
                item = contracts[release]
                require(type(item) is dict and set(item) == {'release','id','revision','sha256'}
                        and type(item['revision']) is int
                        and all(type(item[field]) is str for field in ('release','id','sha256'))
                        and item == expected, 'parallel_release_contract_identity')
        else:
            require(set(binding) <= BINDING_ALLOWED, 'binding_fields_not_classified')
        # Only the complete parallel worker binding carries named store refs.
        # Application/native helper bindings continue to carry actor hashes only.
        named_authorities = (parallel and value.get('kind', 'container') == 'container'
                             and value.get('application_helper', False) is False)
        for field, item in binding.items():
            if field == 'release_contracts':
                continue
            if field == 'credential_authorities':
                require(type(item) is list and len(item) <= 128 and all(type(v) is str and
                    (re.fullmatch(r'application-actor:[a-f0-9]{64}',v) or named_authorities and
                     re.fullmatch(r'[A-Z_][A-Z0-9_]{0,63}',v)) for v in item), 'authority_reference_shape')
            elif field == 'indexed_host_generation':
                require(type(item) is int and item == 2, 'indexed_generation')
            elif field == 'session_id':
                require(canonical_uuid(item), 'session_id_shape')
            elif field == 'workspace':
                absolute(item)
                require(len(item) <= 4096, 'parallel_workspace_length')
            elif field == 'trial_id' and item is None:
                pass
            else:
                require(type(item) is str and 0 < len(item) <= 256 and not any(ord(c)<32 for c in item),
                        'binding_value_shape')

    def _shape(self, value, key):
        require(type(value) is dict, 'record_not_object')
        # Crucial: refuse unknown keys BEFORE any canonical hash/export.
        binding = value.get('binding', {})
        auxiliary = 'diagnostic' in value or type(binding) is dict and bool(set(binding) & AUXILIARY_BINDING_KEYS)
        if auxiliary:
            self._auxiliary_shape(value, binding)
        else:
            require(RECORD_REQUIRED <= set(value) <= RECORD_ALLOWED, 'record_fields_not_classified')
        require(type(value.get('schema')) is int and value['schema'] in (1, 2)
                and value.get('launch_id') == key and identifier(value.get('generation'))
                and value.get('registry') == hashlib.sha256(
                    str(self.registry_root).encode()).hexdigest()
                and value.get('status') == 'released', 'record_identity_or_not_terminal')
        require(value.get('kind', 'container') in ('container', 'network', 'builder'),
                'record_kind')
        require(type(value.get('container')) is str and re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', value['container']), 'container_name')
        require(value.get('kind') == 'network' and value['image'] is None or type(value.get('image')) is str
                and re.fullmatch(r'sha256:[a-f0-9]{64}', value['image']), 'image_identity')
        mounts = value.get('mounts')
        require(type(mounts) is list and len(mounts) <= 32, 'mounts_shape')
        for mount in mounts:
            require(type(mount) is dict and set(mount) == {'source', 'target', 'rw'}
                    and type(mount['rw']) is bool, 'mount_schema')
            absolute(mount['source']); absolute(mount['target'])
        self._binding_shape(value, binding, auxiliary)
        if value['schema']==2:require(binding.get('indexed_host_generation')==2, 'indexed_binding_missing')
        require(type(value['daemon']) is str and 1<=len(value['daemon'])<=256, 'daemon_schema')
        if value['runroot'] is not None:absolute(value['runroot'])
        if 'owner_pid' in value:require(type(value['owner_pid']) is int and value['owner_pid']>0, 'owner_pid_shape')
        for field in ('created_at','qualification_cell','qualification_role','client_mode'):
            if field == 'created_at' and auxiliary:continue
            if field in value:require(type(value[field]) is str and 0<len(value[field])<=256
                and not any(ord(c)<32 for c in value[field]), 'metadata_string_shape')
        if 'application_helper' in value:require(type(value['application_helper']) is bool, 'helper_shape')
        if 'container_id' in value:require(value['container_id'] is None or sha(value['container_id']), 'CID_shape')
        if 'private_store' in value:absolute(value['private_store'])
        # Original all-released reconciliation never follows gateway_state.
        # Classify this operational reference lexically; no stat/read/hash of
        # its target is performed by the preflight or accepted SDK branch.
        if 'gateway_state' in value:absolute(value['gateway_state'])
        for field in ('gateway_ready','inference_uncertain'):
            if field in value:require(type(value[field]) is bool, 'gateway_flag_type')
        require(value.get('inference_uncertain') is not True, 'released_inference_uncertain')
        if 'code_identity' in value:
            require(type(value['code_identity']) is dict
                and set(value['code_identity']) in (CODE_KEYS, BROWSER_CODE_KEYS, CURRENT_CODE_KEYS)
                and all(sha(v) for v in value['code_identity'].values()), 'code_identity_keys')
        if 'diagnostic_entrypoint' in value:
            row=value['diagnostic_entrypoint'];require(type(row) is dict and set(row)=={'source','overlay','scope'}
                and row['overlay']=='/opt/pi-application/runtime/application_client_service.py'
                and row['scope']=='storage_primitive_only', 'diagnostic_metadata_schema');reference(row['source'])
        for name in ('qualification_service_cleanup', 'qualification_preworker_cleanup'):
            if name in value:
                ref = value[name]
                require(type(ref) is dict and set(ref) == {'path', 'sha256'}
                        and sha(ref['sha256']), 'attached_reference_schema')
                absolute(ref['path'])

    def _profile(self, value):
        if value.get('application_helper') is not True:
            require(value['launch_id'] not in self.profiles, 'known_owner_subtype_changed')
            return 'ordinary'
        subtype = ('preworker' if 'qualification_preworker_cleanup' in value else
                   'service' if (str(value.get('client_mode', '')).startswith('qualification-')
                       or 'qualification_role' in value
                       or 'qualification_service_cleanup' in value) else 'ordinary_helper')
        if subtype in ('service', 'preworker'):
            profile = self.profiles.get(value['launch_id'])
            field = 'qualification_' + ('preworker' if subtype == 'preworker' else 'service') + '_cleanup'
            if profile is None:
                marker_mask = ((1 if str(value.get('client_mode', '')).startswith('qualification-') else 0)
                    | (2 if 'qualification_role' in value else 0)
                    | (4 if 'qualification_service_cleanup' in value else 0)
                    | (8 if 'qualification_preworker_cleanup' in value else 0))
                if value['launch_id'] in self.policy['selected_task_records']:
                    error = AdmissionDenied('qualification_owner_missing_selected')
                else:
                    error = AdmissionDenied('qualification_owner_missing_outside_selected')
                # Classification inputs only; no owner/proof provenance or value
                # is copied. This remains the same primary missing-owner denial.
                error.qualification_profile_markers = (subtype, marker_mask)
                raise error
            require(profile['subtype'] == subtype, 'qualification_owner_subtype_mismatch')
            # The record reference already passed _shape; the policy reference
            # passed derive_read_closure. Exact path+digest equality therefore
            # preserves the previous dictionary predicate without target IO.
            require(field in value, 'qualification_cleanup_reference_missing')
            require(value[field]['path'] == profile['reference']['path'], 'qualification_cleanup_path_mismatch')
            require(value[field]['sha256'] == profile['reference']['sha256'], 'qualification_cleanup_digest_mismatch')
            if subtype=='service':require([m for m in value['mounts'] if m['target']=='/private']==[
                {'source':profile['private_mount_source'],'target':'/private','rw':False}], 'service_private_scope_changed')
        else:
            require(value['launch_id'] not in self.profiles, 'known_owner_subtype_changed')
        return subtype

    def _proof_headers(self):
        total=0;snapshots={}
        for text in self.closure['absent_paths']:
            require(self._absent(absolute(text)), 'classified_private_path_present')
        self._control_tree()
        for text,row in sorted(self.reads.items()):
            self._fence();path=absolute(text);fd=self._directory(path.parent)
            mask=0o077 if row['role'] in ('typed_service_owner_metadata','typed_preworker_owner_metadata') else 0o022
            try:
                parent=os.fstat(fd)
                require(parent.st_uid==os.getuid() and not stat.S_IMODE(parent.st_mode)&mask, 'proof_parent_not_classified')
                info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            finally:os.close(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
                and not stat.S_IMODE(info.st_mode)&mask and 0<=info.st_size<=row['maximum_bytes'], 'proof_header_not_classified')
            total+=info.st_size*row['read_multiplicity'];snapshots[text]={'leaf':signature(info),'parent':signature(parent)}
            require(total<=PROOF_AGGREGATE_BYTES, 'aggregate_proof_limit')
        return snapshots,total

    def _absent(self,path):
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                self._fence()
                try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                except FileNotFoundError:return True
                os.close(fd);fd=child
            self._fence()
            try:os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:return True
            return False
        finally:os.close(fd)

    def _control_tree(self):
        tree=self.closure['control_tree'];root=absolute(tree['path']);fd=self._directory(root)
        expected={'':set()}
        for relative in tree['directories']:
            path=Path(relative);require(not path.is_absolute() and '..' not in path.parts, 'control_relative_path')
            expected.setdefault(str(path.parent) if str(path.parent)!='.' else '',set()).add(path.name)
            expected.setdefault(relative,set())
        for text,row in self.reads.items():
            if row['role']=='classified_control_metadata':
                path=absolute(text);require(path.parent==root,'control_leaf_rerooted');expected[''].add(path.name)
        try:
            info=os.fstat(fd);require((info.st_dev,info.st_ino)==(tree['device'],tree['inode'])
                and info.st_uid==os.getuid() and not stat.S_IMODE(info.st_mode)&0o022, 'control_root_identity')
            for relative,wanted in sorted(expected.items()):
                dfd=self._directory(root/relative) if relative else os.dup(fd)
                try:
                    di=os.fstat(dfd);require(di.st_uid==os.getuid() and not stat.S_IMODE(di.st_mode)&0o022,
                        'control_directory_not_owner_owned_nonwritable')
                    seen=set()
                    with os.scandir(dfd) as entries:
                        for entry in entries:
                            self._fence();require(len(seen)<len(wanted),'control_namespace_overflow')
                            name=entry.name;require(name in wanted and name not in seen,'unclassified_control_entry');seen.add(name)
                    require(seen==wanted,'control_namespace_missing')
                finally:os.close(dfd)
        finally:os.close(fd)

    def _proof_conservation(self,snapshots):
        for text,expected in sorted(snapshots.items()):
            self._fence();path=absolute(text);fd=self._directory(path.parent)
            try:parent=os.fstat(fd);info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            finally:os.close(fd)
            require(signature(info)==expected['leaf'] and signature(parent)==expected['parent'], 'proof_header_changed')
        for text in self.closure['absent_paths']:
            require(self._absent(absolute(text)), 'private_path_reappeared')
        self._control_tree()

    def _read_exact(self,fd,name,maximum,lease_fd,registry_fd=None):
        self._fence();self._lease(lease_fd)
        if registry_fd is not None:self._registry(registry_fd)
        leaf=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(leaf,'rb',buffering=0) as stream:
            info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode)
                and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600
                and info.st_nlink==1 and 0<=info.st_size<=maximum, 'metadata_header')
            self._fence();body=stream.read(info.st_size);after=os.fstat(stream.fileno())
        named=os.stat(name,dir_fd=fd,follow_symlinks=False)
        require(signature(info)==signature(after)==signature(named) and len(body)==info.st_size,'metadata_drift')
        if registry_fd is not None:self._registry(registry_fd)
        return body,signature(info)

    def _final_records(self,fd,snapshots):
        self._registry(fd)
        for key,expected in sorted(snapshots.items()):
            self._fence();self._registry(fd)
            require(signature(os.stat(key+'.json',dir_fd=fd,follow_symlinks=False))==expected,
                'record_drift_before_constructor')
        self._registry(fd)

    def __call__(self, *, lease_fd, lock_path, registry_root):
        require(not self._called, 'preflight_already_used');self._called=True
        require(Path(lock_path) == self.lock_path and Path(registry_root) == self.registry_root
                and type(lease_fd) is int, 'callback_not_original_context')
        self._begin()
        lease_identity = self._lease(lease_fd)
        # This frozen policy has no authority to read the new ordinary-owner
        # proof graph. Presence is a namespace observation, never an implicit
        # policy extension or an all-released bypass.
        owner_store = self.registry_root.with_name(self.registry_root.name + '.owner-proofs')
        try:os.stat(owner_store, follow_symlinks=False)
        except FileNotFoundError:pass
        else:require(False, 'owner_cleanup_policy_extension_required')
        fd = self._directory(self.registry_root)
        total = self._initial_bytes; signatures = {}; kinds = {}; owners = set()
        try:
            ri = self._registry(fd);namespace_signature=signature(ri)
            require(ri.st_uid == os.getuid() and stat.S_IMODE(ri.st_mode) == 0o700,
                    'registry_not_owner_only')
            names = self._names(fd)
            for ordinal, (key, expected) in enumerate(sorted(self.expected.items())):
                self._lease(lease_fd);self._registry(fd)
                maximum = min(1048576, 33554432 - total)
                require(maximum > 0, 'aggregate_metadata_limit')
                leaf = os.open(key + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=fd)
                with os.fdopen(leaf, 'rb', buffering=0) as stream:
                    info = os.fstat(stream.fileno())
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                            and 0 <= info.st_size <= maximum, 'metadata_leaf_not_classified')
                    self._fence(); body = stream.read(info.st_size)
                    after = os.fstat(stream.fileno())
                named = os.stat(key + '.json', dir_fd=fd, follow_symlinks=False)
                require(signature(info) == signature(after) == signature(named)
                        and len(body) == info.st_size, 'metadata_changed')
                total += len(body)
                self._registry(fd)
                value = decode(body)
                self._shape(value, key)
                require(digest(value) == expected, 'canonical_record_changed')
                try:
                    kind = self._profile(value)
                except AdmissionDenied as error:
                    if type(error) is AdmissionDenied:
                        args = error.args
                        if (type(args) is tuple and len(args) == 1 and type(args[0]) is str
                                and args[0] == 'qualification_owner_missing_outside_selected'):
                            attributes = error.__dict__
                            if type(attributes) is dict:
                                markers = attributes.get('qualification_profile_markers')
                                if (type(markers) is tuple and len(markers) == 2
                                        and type(markers[0]) is str and markers[0] == 'service'
                                        and type(markers[1]) is int and markers[1] == 7):
                                    # This is the bounded, already-public expected
                                    # map, not the encountered record or its proof.
                                    error.qualification_baseline_selector = (
                                        ordinal, len(self.expected), digest(self.expected))
                    raise
                kinds[kind] = kinds.get(kind, 0) + 1
                if kind in ('service', 'preworker'): owners.add(key)
                signatures[key] = signature(info)
            require(owners == set(self.profiles), 'qualification_owner_set_changed')
            proof_snapshots,proof_bytes=self._proof_headers()
            self._final_records(fd,signatures);self._proof_conservation(proof_snapshots)
            require(self._names(fd) == names, 'registry_namespace_changed')
            require(signature(self._registry(fd))==namespace_signature, 'registry_directory_drift')
            require(8192 - len(names) >= 210, 'insufficient_original_registry_headroom')
            self._lease(lease_fd);self._registry(fd);self._fence()
            self._snapshots = signatures
            self._proof_snapshots=proof_snapshots
            self.witness = {'schema': 1, 'document_type': 'original_lease_sdk_preflight_witness',
                'lease_fd': lease_fd, 'lease_device': lease_identity[0], 'lease_inode': lease_identity[1],
                'registry_root': str(self.registry_root), 'registry_device': ri.st_dev,
                'registry_inode': ri.st_ino, 'namespace_sha256': digest(names),
                'canonical_map_sha256': digest(self.expected),
                'selected281_sha256': digest({k: self.expected[k] for k in
                                            sorted(self.policy['selected_task_records'])}),
                'readset_seal': digest(self.closure), 'records': len(names),
                'record_bytes': total, 'subtype_counts': kinds, 'headroom': 8192-len(names),
                'proof_header_bytes_with_multiplicity':proof_bytes,
                'original_reconcile_claimed': False, 'native_eligibility_claimed': False}
        finally:
            os.close(fd)


    def assert_after_yield(self, registry):
        require(self.witness is not None, 'missing_original_lease_witness')
        import ownership_registry
        require(ownership_registry.CURRENT.get() is registry and Path(registry.root)==self.registry_root
            and registry.lease_fd==self.witness['lease_fd'], 'original_sdk_context_mismatch')
        self._lease(registry.lease_fd);fd=self._directory(self.registry_root)
        try:
            self._registry(fd);self._final_records(fd,self._snapshots)
            require(digest(self._names(fd))==self.witness['namespace_sha256'], 'original_namespace_drift')
            self._proof_conservation(self._proof_snapshots);self._lease(registry.lease_fd);self._registry(fd)
        finally:os.close(fd)


def _intent_identity(record):
    return digest({k:v for k,v in record.items() if k not in (
        'status','container_id','qualification_service_cleanup','qualification_preworker_cleanup')})


def _role_weight(manifest,cell,role):
    browser=cell['image_id']==manifest['images']['browser-'+cell['release']]['id']
    if role in ('fixture','scripted-inference'):return {'cpu_millis':250,'memory_mib':128,'pids_limit':64}
    if role=='application-helper':return {'cpu_millis':2000,'memory_mib':2048,'pids_limit':512} if browser else {'cpu_millis':1000,'memory_mib':512,'pids_limit':128}
    return {'cpu_millis':2000,'memory_mib':2048,'pids_limit':512} if browser and cell['group']=='N01' else {'cpu_millis':1000,'memory_mib':1024,'pids_limit':256}


def extend_current_scope_policy(base_policy, *, lease_fd, lock_path, registry_root,
                                manifest, ledger_root, scope_root):
    """Under original flock, derive exact released, completed OWN additions.

    The immutable base comes from the external execution seal. The original
    instance.write producer commits fixed intent mirrors before its unchanged
    bound writer. No generic new global row, pending row or serialized extension
    assertion is admitted. Extension and Gate share ONE absolute entry budget.
    """
    gate=AdmissionGate(base_policy);gate._begin();gate._lease(lease_fd)
    require(Path(lock_path)==gate.lock_path and Path(registry_root)==gate.registry_root,'extension_original_context')
    root=absolute(str(scope_root));lr=absolute(str(ledger_root));current=gate.policy['current_scope']
    require(type(current) is dict and set(current)=={'scope_root','ledger_root','manifest_sha256',
        'maximum_container_records','maximum_network_records','repository_root','expected_carry'}
        and current['scope_root']==str(root) and current['ledger_root']==str(lr)
        and current['manifest_sha256']==digest(manifest) and current['maximum_container_records']==210
        and current['maximum_network_records']==24, 'extension_scope_unbound')
    repository=absolute(current['repository_root']);require(root.is_relative_to(repository/'reports'),'qualification_root_scope')
    require(manifest['limits']['container_launch_attempts']==520 and manifest['limits']['participant_segments']==45,
        'prepared_M20_limit_binding')
    row_fields={'key','cell','role','registry','generation','launch_id','container','image','resources',
        'physical','private_cleanup','pid','intent_sha256','container_id','cleanup_requests','launch_policy'}
    mirror_fields={'schema','launch_id','kind','intent_sha256','before_original_Registry_write',
        'registry','generation','daemon','runroot','qualification_id','source_scope_root'}
    used=0;mirrors={};mirror_sigs={};new_sigs={};new={};new_owners={};rows={};proof_sigs={}
    rfd=gate._directory(gate.registry_root);sfd=None;lfd=None
    try:
        sfd=gate._directory(root);lfd=gate._directory(lr)
        root_sig=signature(os.fstat(sfd));ledgerdir_sig=signature(os.fstat(lfd));gate._registry(rfd)
        count=0
        with os.scandir(sfd) as entries:
            for entry in entries:
                gate._fence();count+=1;require(count<=1024,'scope_namespace_overflow');name=entry.name
                if not name.startswith('intent-'):continue
                match=re.fullmatch(r'intent-([a-f0-9-]{36})\.json',name)
                require(match is not None and match[1] not in mirrors and len(mirrors)<234,'scope_mirror_name')
                body,sig=gate._read_exact(sfd,name,4096,lease_fd);used+=len(body);item=decode(body)
                require(type(item) is dict and set(item)==mirror_fields and type(item['schema']) is int and item['schema']==1
                    and item['launch_id']==match[1] and item['kind'] in ('container','network')
                    and sha(item['intent_sha256']) and item['before_original_Registry_write'] is True
                    and item['qualification_id']==manifest['qualification_id'] and item['source_scope_root']==str(root)
                    and item['registry']==hashlib.sha256(str(gate.registry_root).encode()).hexdigest()
                    and identifier(item['generation']) and type(item['daemon']) is str
                    and item['launch_id'] not in gate.expected,'scope_mirror_shape')
                if item['runroot'] is not None:absolute(item['runroot'])
                mirrors[item['launch_id']]=item;mirror_sigs[name]=sig
        require(sum(v['kind']=='container'for v in mirrors.values())<=210 and
            sum(v['kind']=='network'for v in mirrors.values())<=24,'scope_kind_count')
        wanted={k+'.json'for k in set(gate.expected)|set(mirrors)};gate._names(rfd,wanted)
        ledgerbody,lsig=gate._read_exact(lfd,'ledger.json',min(1048576,33554432-used),lease_fd)
        used+=len(ledgerbody);ledger=decode(ledgerbody)
        ledgerfields={'schema','manifest_sha256','daemon','daemon_capacity','started','deadline',
            'started_wall','deadline_wall','last_now','last_wall','poisoned','launches','carry'}
        require(type(ledger) is dict and set(ledger)==ledgerfields and type(ledger['schema']) is int and ledger['schema']==1
            and ledger['manifest_sha256']==digest(manifest) and ledger['poisoned'] is False
            and type(ledger['launches']) is list and len(ledger['launches'])<=210,'current_ledger_shape_or_poison')
        for field in ('started','deadline','started_wall','deadline_wall','last_now','last_wall'):
            require(type(ledger[field]) in (int,float) and math.isfinite(ledger[field]),'current_clock_type')
        require(ledger['deadline']-ledger['started']==14400 and ledger['deadline_wall']-ledger['started_wall']==14400
            and ledger['started']<=ledger['last_now']<ledger['deadline'] and ledger['started_wall']<=ledger['last_wall']<ledger['deadline_wall'], 'current_clock')
        predecessor=manifest['predecessor'];carry=ledger['carry'];expected_carry=current['expected_carry']
        require(type(carry) is dict and set(carry)=={'descriptor_sha256','attempts','participant_segments','qualification_id','planned_cells'}
            and carry==expected_carry and carry['descriptor_sha256']==digest(predecessor)
            and type(carry['attempts']) is int and 0<=carry['attempts']<=manifest['limits']['container_launch_attempts']
            and type(carry['participant_segments']) is int and 0<=carry['participant_segments']<=manifest['limits']['participant_segments'],'current_carry')
        cells={c['id']:c for c in manifest['cells']};counts={}
        for row in ledger['launches']:
            require(type(row) is dict and set(row)==row_fields and identifier(row['launch_id']) and row['launch_id'] not in rows
                and row['key']==digest({'registry':row['registry'],'launch_id':row['launch_id']})
                and identifier(row['generation']) and sha(row['intent_sha256']) and row['physical']=='absent'
                and row['private_cleanup'] is True and sha(row['container_id']) and row['cell'] in cells
                and row['role'] in cells[row['cell']]['role_limits'],'current_row_not_complete')
            require(row['launch_policy'] in ('explicit_pull_never_owned_id_5s','inserted_pull_never_owned_id_5s')
                and row['resources']==_role_weight(manifest,cells[row['cell']],row['role'])
                and row['image'] in cells[row['cell']]['allowed_images'] and (row['pid'] is None or type(row['pid']) is int and row['pid']>0),'current_row_source_resources')
            cleanup=row['cleanup_requests'];require(type(cleanup) is list and len(cleanup)<=16,'current_cleanup_requests')
            for request in cleanup:
                require(type(request) is dict and set(request)=={'operation','requested_target','effective_target'}
                    and request['operation'] in ('rm','stop','kill') and request['requested_target'] in ('name','immutable_id')
                    and request['effective_target'] in ('immutable_id','read_only_absence_check'),'current_cleanup_identity')
            pair=(row['cell'],row['role']);counts[pair]=counts.get(pair,0)+1
            require(counts[pair]<=cells[row['cell']]['role_limits'][row['role']],'current_role_limit')
            require(row['launch_id'] in mirrors and mirrors[row['launch_id']]['kind']=='container'
                and mirrors[row['launch_id']]['intent_sha256']==row['intent_sha256'],'current_row_mirror_mismatch')
            rows[row['launch_id']]=row
        require(len(rows)+carry['attempts']<=manifest['limits']['container_launch_attempts']
            and sum(r['role']=='participant'for r in rows.values())+carry['participant_segments']<=manifest['limits']['participant_segments'],
            'current_cumulative_limits')
        require(set(rows)=={k for k,v in mirrors.items()if v['kind']=='container'},'current_ledger_mirror_set')
        for key,mirror in sorted(mirrors.items()):
            body,sig=gate._read_exact(rfd,key+'.json',min(1048576,33554432-used),lease_fd,rfd)
            used+=len(body);value=decode(body);gate._shape(value,key)
            require(_intent_identity(value)==mirror['intent_sha256'] and all(value.get(k)==mirror[k]
                for k in ('registry','generation','daemon','runroot')) and value['daemon']==ledger['daemon'],'current_intent_or_daemon_changed')
            if mirror['kind']=='container':
                row=rows[key]
                require(all(value.get(k)==row[k]for k in ('registry','generation','launch_id','container','image'))
                    and value.get('container_id') in (None,row['container_id']) and value.get('kind','container')=='container'
                    and value['runroot'] is not None and absolute(value['runroot']).is_relative_to(root),'current_row_record_identity')
                if row['role'] in ('fixture','scripted-inference'):
                    require(sha(value.get('container_id')) and value['container_id']==row['container_id'], 'current_service_real_CID_required')
                    require(value.get('application_helper') is True and value.get('qualification_role')==row['role']
                        and value.get('client_mode')=='qualification-'+row['role'] and value.get('qualification_cell')==row['cell'],'current_service_identity')
                    targets={m['target']:m for m in value['mounts']}
                    require(len(targets)==len(value['mounts'])==4 and set(targets)=={'/opt/pi-skill','/qualification','/private','/observations'}
                        and targets['/opt/pi-skill']=={'source':str(repository/'skill'),'target':'/opt/pi-skill','rw':False}
                        and targets['/qualification']=={'source':str(repository/'tools/qualification'),'target':'/qualification','rw':False}
                        and targets['/private']['rw'] is False and targets['/observations']['rw'] is True
                        and absolute(targets['/observations']['source']).is_relative_to(root/'cells'/row['cell'])
                        and not absolute(targets['/private']['source']).is_relative_to(root),'current_service_mounts')
                    ref=reference(value.get('qualification_service_cleanup'));path=absolute(ref['path'])
                    require(path==root/'cells'/row['cell']/'service-cleanup-receipts'/(key+'.json'),'current_service_receipt_rerooted')
                    pfd=gate._directory(path.parent)
                    try:
                        parent=os.fstat(pfd);require(parent.st_uid==os.getuid() and not stat.S_IMODE(parent.st_mode)&0o077, 'current_service_parent_not_private')
                        proofbody,proofsig=gate._read_exact(pfd,path.name,min(65536,33554432-used),lease_fd)
                    finally:os.close(pfd)
                    used+=len(proofbody);proof=decode(proofbody)
                    identity={k:value[k]for k in ('launch_id','registry','generation','daemon','container','container_id','image','runroot','binding','client_mode','mounts')}
                    identity.update(role=row['role'],cell=row['cell'],intent_sha256=_intent_identity(value))
                    require(type(proof) is dict and set(proof)==set(identity)|{'schema','document_type','private_mount',
                        'physical_absence_confirmed','private_bootstrap_removed','terminal_available','startup_readied','qualification_eligible'}
                        and all(proof[k]==v for k,v in identity.items()) and type(proof['schema']) is int and proof['schema']==1
                        and proof['document_type']=='qualification_service_cleanup' and proof['physical_absence_confirmed'] is True
                        and proof['private_bootstrap_removed'] is True and all(type(proof[k]) is bool for k in
                        ('terminal_available','startup_readied','qualification_eligible')) and proof['qualification_eligible']==(
                        proof['terminal_available'] and proof['startup_readied']),'current_service_proof_fields')
                    private=proof['private_mount'];require(type(private) is dict and set(private)=={'source','device','inode'}
                        and type(private['device']) is int and 0<=private['device']<2**64 and type(private['inode']) is int and 0<private['inode']<2**64
                        and private['source']==targets['/private']['source'],'current_service_private_scope')
                    require(hashlib.sha256(proofbody).hexdigest()==ref['sha256'],'current_service_receipt_hash')
                    new_owners[key]={'subtype':'service','reference':ref,'private_mount_source':private['source']};proof_sigs[str(path)]=proofsig
                else:
                    require('qualification_preworker_cleanup'not in value and 'qualification_service_cleanup'not in value
                        and 'qualification_role'not in value and not str(value.get('client_mode','')).startswith('qualification-'),'new_unknown_helper_subtype')
                    for mount in value['mounts']:
                        require(absolute(mount['source']).is_relative_to(root) or mount['source'] in (
                            str(repository/'skill'),str(repository/'tools/qualification')),'current_mount_outside_scope')
            else:
                require(value.get('kind')=='network' and value['image'] is None and value['mounts']==[]
                    and value['runroot'] is None and 'owner_pid'not in value,'current_network_metadata')
                matches=[r for r in rows.values()if r['role']=='application-helper' and value['container']==r['container']+'-network'
                    and value['registry']==r['registry'] and value['generation']==r['generation']]
                require(len(matches)==1,'current_network_not_exact_helper')
            new[key]=digest(value);new_sigs[key]=sig
        gate._registry(rfd);gate._names(rfd,wanted);gate._final_records(rfd,new_sigs)
        for text,sig in proof_sigs.items():
            path=absolute(text);pfd=gate._directory(path.parent)
            try:require(signature(os.stat(path.name,dir_fd=pfd,follow_symlinks=False))==sig,'extension_service_drift')
            finally:os.close(pfd)
        require(signature(os.stat('ledger.json',dir_fd=lfd,follow_symlinks=False))==lsig
            and signature(os.fstat(sfd))==root_sig and signature(os.fstat(lfd))==ledgerdir_sig,'extension_namespace_or_ledger_drift')
        for name,sig in mirror_sigs.items():require(signature(os.stat(name,dir_fd=sfd,follow_symlinks=False))==sig,'mirror_drift')
        gate._lease(lease_fd);gate._registry(rfd);gate._fence()
        result=_CurrentPolicy(copy.deepcopy(gate.policy));result['expected_canonical_records'].update(new)
        result['qualification_owners'].update(new_owners);result['extension']={'container_records':len(rows),
            'network_records':len(mirrors)-len(rows),'scope_root':str(root),'ledger_root':str(lr),'manifest_sha256':digest(manifest)}
        result['activation']['proof_read_authority']=digest(derive_read_closure(result['qualification_owners'],result['preworker_projection']))
        result._ticket=_TICKET;result._bytes=used
        return result
    finally:
        if lfd is not None:os.close(lfd)
        if sfd is not None:os.close(sfd)
        os.close(rfd)

