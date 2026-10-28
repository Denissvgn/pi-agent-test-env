"""Finite, copy-only operational replay; never an original-runtime reader.

Original manifest/Ledger function code objects execute in a PRIVATE namespace.
Only their IO-bearing policy/claim dependencies are replaced with the explicit
copy validators below. No production global, class or clock is patched. This
replays structural accounting; it does not recreate lost waits, old RAM or a
fresh cleanup observation. Classification and historical cleanup reviews are
separate mandatory evidence, not invented by this implementation.
"""
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import types

from ast_compat import pinned_dump
import application_launch as launch
import application_scoped_retained_checks as scoped_checks

LAUNCH_SHA256 = '151a750a4aa076c84532525590634cee751c3c2144a0656871e565c1fd9b11fa'
HISTORICAL_POLICY = {9: {'source_path': 'tools/qualification/application_amendment.py',
     'source_sha256': 'ea50097ddd39602c7693f631aa581af88dcccd6fbbeb1cc8002d20d470a3b4a2',
     'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-002/matrix-009-authorization.json',
                       'sha256': '5c8576c3672968d5b429b52a4bfb26039b9eab2394f87d1e6d73f5f611807b92'},
     'authorization_id': 'e8a970b1-3e9e-4a52-a292-d0fdca25537e',
     'container_cap': 241,
     'participant_cap': 24,
     'deadline': 564055.688387708,
     'deadline_wall': 1792283647.187074},
 10: {'source_path': 'tools/qualification/application_successor.py',
      'source_sha256': '9c47136f782a7860c0fd4928d444f51ca76c216489811c56f05c065072c125e1',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-003/matrix-010-execution-authorization.json',
                        'sha256': 'b548df9507118531a8e6901d3cad065c7c1347ffb63c0b52ba8a4cfec0f4d406'},
      'authorization_id': '42f69b66-9201-4d94-b0d2-b2658aa0d88e',
      'container_cap': 249,
      'participant_cap': 24,
      'deadline': 604456.609015083,
      'deadline_wall': 1792324048.4343522},
 11: {'source_path': 'tools/qualification/application_followup.py',
      'source_sha256': '1349bfa1a907527a878d3e1944516c872649f39ff0cc9f51765a7b9e0333bc85',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-004/diagnostic-and-matrix-011-authorization.json',
                        'sha256': 'e656b42a94f76729e2f055b341b50d975bb338baa5219085c49b0faeed9a4320'},
      'authorization_id': 'e8bb8dd3-19c3-45fd-8200-5b628695a0a5',
      'container_cap': 262,
      'participant_cap': 24,
      'deadline': 604456.609015083,
      'deadline_wall': 1792324048.4343522},
 12: {'source_path': 'tools/qualification/application_requalification.py',
      'source_sha256': '778e8273d7b08d0739ea0e223eab35151954bdc31d6ddafc1e48c17078573de1',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-005/matrix-012-authorization.json',
                        'sha256': '7d6c3a9579a14829d5b76888bd83a503294ad8e47a20f17e2a8c323d70f913c8'},
      'authorization_id': '051bdc12-45f8-4900-b32a-5b359136e756',
      'container_cap': 265,
      'participant_cap': 24,
      'deadline': 616986.187410833,
      'deadline_wall': 1792336578.1072938},
 13: {'source_path': 'tools/qualification/application_matrix13.py',
      'source_sha256': '43a8f6e12f76111e2df88be3babe3d688d5e71cc56e82fc3daa7a32634254f73',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-006/matrix-013-authorization.json',
                        'sha256': 'c3f2d3add282f0b6fd4238f816725dd24d82a0f5080a852e15703965f2f44d2d'},
      'authorization_id': '5fbce9c5-b706-443a-ba65-7eee83e09855',
      'container_cap': 277,
      'participant_cap': 24,
      'deadline': 622229.374229125,
      'deadline_wall': 1792341821.30397},
 14: {'source_path': 'tools/qualification/application_matrix14.py',
      'source_sha256': '6d62297846ce8251018fce3bddcf1613319605e71b64975ce194505eadcc4cb2',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-008/matrix-014-authorization.json',
                        'sha256': '4849dd9eaab0b987d2f1390b7043b72766b62c247003fb512d0a18bbb03bad3d'},
      'authorization_id': 'de2cde66-cbc1-4e9a-87c5-a0ca9c3e79d3',
      'container_cap': 291,
      'participant_cap': 25,
      'deadline': 631372.105809541,
      'deadline_wall': 1792350964.132689},
 15: {'source_path': 'tools/qualification/application_matrix15.py',
      'source_sha256': 'bf09400c4287e4ae7034a3602b839a4b2901396a06d557ebbbe06f2119827a31',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-009/matrix-015-authorization.json',
                        'sha256': '5cae5efbbc88e6353a379d6a0562ec3818beb1f2d6b952dbca3367141fd688cf'},
      'authorization_id': '7cb6c30d-17ae-4c59-b7b4-3b207324d244',
      'container_cap': 305,
      'participant_cap': 26,
      'deadline': 642742.22091475,
      'deadline_wall': 1792362334.311112},
 16: {'source_path': 'tools/qualification/application_matrix16.py',
      'source_sha256': 'c1c24d489d8d08660fd4ded02e05a854254cbcf44b7ac4cd4a29a0160e7660a3',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-010/matrix-016-authorization.json',
                        'sha256': '77d461392127ee7bc434750438341d8fa21148bad54f7cc5af3ee2b2284fb057'},
      'authorization_id': '358e19b0-16d8-4a87-bd0a-df2f88dba017',
      'container_cap': 349,
      'participant_cap': 30,
      'deadline': 651380.227786125,
      'deadline_wall': 1792370972.352897},
 17: {'source_path': 'tools/qualification/application_matrix17.py',
      'source_sha256': 'd608a6d2dc880fd48df36879829ffb5a546a5be99fdea00ae36da4f610b1b101',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-011/matrix-017-authorization.json',
                        'sha256': '7d9fa918409e49249f674404144c1b308eebedede591a508b9e4a4f6148e9fcf'},
      'authorization_id': 'bc8f8aef-2110-4204-854e-28476caa7a9a',
      'container_cap': 380,
      'participant_cap': 33,
      'deadline': 684940.983177208,
      'deadline_wall': 1792409108.337437},
 18: {'source_path': 'tools/qualification/application_matrix18.py',
      'source_sha256': '9e0885be5b0cf95636cf3c14af60cdf9a1b9cc180b55883f607a811f1a39d94b',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-012/matrix-018-authorization-003.json',
                        'sha256': '67b10dc6abc60f2ba72adadba21c5d47530881a6bec83dffeebaf2bcdf91b9d4'},
      'authorization_id': '8f5ce6bf-a8a9-4c2b-84cc-c277af207548',
      'container_cap': 432,
      'participant_cap': 37,
      'deadline': 701325.524116416,
      'deadline_wall': 1792425492.976367},
 19: {'source_path': 'tools/qualification/application_matrix19.py',
      'source_sha256': '5c2d2cd89346441e3801a516047b873f8d026055b2c44e4bbae26f3bdea22cd6',
      'authorization': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-013/matrix-019-authorization.json',
                        'sha256': '07422f13dcb5f983e44e8d88dc374730fcddcf900d3b4d1def210ef0ba2b5142'},
      'authorization_id': 'ad5988fd-4c95-45a3-bcbc-e7ec1b609f52',
      'container_cap': 461,
      'participant_cap': 39,
      'deadline': 720821.978244583,
      'deadline_wall': 1792444989.542186}}

MATRIX_AST_SHA256 = '4123532bef7c60a02e6795ff46727df2cdf7054b403ded9a9ecc1639a7f3a7a5'

AUXILIARY_STAGES={'auxiliary-campaign':(7,3),'startup-failed':(10,1),'artifact-write-diagnostic':(16,1),'image-recovery':(17,12),'fixture-startup':(17,1),'helper-startup':(18,1),'D05':(19,0),'D06':(19,6)}

HISTORICAL_RUNTIME_ROOTS = ('/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-001/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-002/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-003/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-004/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-005/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-006/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-007/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-008/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-009/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-010/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-011/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-012/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-013/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-014/qualification-002', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-015/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-016/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-017/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification', '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/qualification')

MATRIX_CONSTANTS_SHA256 = 'd33d184169ab6de7ac04b69e98d762ae78e0dd86ba79db1961bb806834a60a65'

KINDS = frozenset(('manifest', 'state', 'ledger', 'candidate', 'authority',
                   'window', 'claim', 'source-review', 'cleanup-review',
                   'operational-projection', 'record', 'retained-predicate'))
FORBIDDEN = frozenset(('private', 'workspace', 'workspaces', 'children',
    'controls', 'application-helpers', 'application-evidence',
    'application-startup', '.aws', '.codex', '.local'))
FIELDS = ('id', 'group', 'release', 'image_id', 'allowed_images', 'role_limits',
          'container_launches_max', 'participant_segments_max')


def need(ok, reason='matrix20_operational_replay_invalid'):
    if not ok:
        raise launch.LaunchError(reason)


def refkey(ref):
    launch._exact(ref, {'path', 'sha256'})
    launch._canonical_root(ref['path']); launch._sha(ref['sha256'])
    return ref['path'], ref['sha256']


def safe_copy_json(reference, root):
    """Exact object path only, no glob, aliases, payload path or original read."""
    path, digest = refkey(reference); root = launch._canonical_root(str(root))
    expected = root / 'objects' / (digest + '.json')
    need(Path(path) == expected)
    parts=expected.parts[2:] if expected.parts[:2]==('/', 'private') else expected.parts
    need(not any(p.casefold() in FORBIDDEN for p in parts))
    folder = launch._dir(expected.parent)
    try:
        fd = launch._file(folder, expected.name, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno()); body = stream.read(launch.MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        named = os.stat(expected.name, dir_fd=folder, follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(after) == identity(named))
        need(len(body) <= launch.MAX_BYTES and hashlib.sha256(body).hexdigest() == digest)
        def pairs(rows):
            out = {}
            for k, v in rows:
                need(k not in out); out[k] = v
            return out
        return json.loads(body, object_pairs_hook=pairs,
                          parse_constant=lambda _: need(False))
    finally:
        os.close(folder)


class FiniteClosure:
    def __init__(self, root, entries, classification, *, read=safe_copy_json, approved_root=Path('/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-016/matrix20-operational-copies-35a70e32-d76d-4487-8eb0-920ef07cead9')):
        self.root = launch._canonical_root(str(root)); self.read = read
        need(self.root==launch._canonical_root(str(approved_root)))
        need(type(entries) is list and 1 <= len(entries) <= 4096)
        need(classification['status'] == 'PASS' and classification['unresolved_findings'] == [])
        need(classification['supports_exact_operational_metadata_closure'] is True)
        need(classification['closure_root'] == str(self.root))
        need(classification['entries_sha256'] == launch._digest(entries))
        need(classification['runtime_payload_files_included'] is False)
        need(classification['original_runtime_fallback_permitted'] is False)
        self.entries = {}
        for item in entries:
            launch._exact(item, {'original', 'copy', 'kind'})
            key = refkey(item['original']); copied = refkey(item['copy'])
            need(item['kind'] in KINDS and key not in self.entries)
            need(key[1] == copied[1])  # byte-identical, not an edited snapshot
            need(Path(copied[0]) == self.root / 'objects' / (copied[1] + '.json'))
            self.entries[key] = copy.deepcopy(item)

    def get(self, ref, kind):
        item = self.entries.get(refkey(ref))
        need(item is not None and item['kind'] == kind, 'matrix20_metadata_not_classified')
        return self.read(item['copy'], self.root)


class Kernel:
    """Execute unchanged source code objects with finite explicit dependencies."""
    def __init__(self, source_sha256=LAUNCH_SHA256):
        need(source_sha256 == LAUNCH_SHA256)
        need(hashlib.sha256(Path(launch.__file__).read_bytes()).hexdigest() == source_sha256)

    @staticmethod
    def manifest(value, limits):
        # This finite historical kernel has no retained-evidence dependencies.
        # Refuse the new mode before the copied validator can import its module.
        need(type(value) is dict and 'retained_requalification' not in value and 'browser_followup' not in value and 'browser_fixture_followup' not in value and 'settlement_diagnostic' not in value)
        namespace = dict(launch.validate_manifest.__globals__)
        def recorded_limits(subject):
            need(subject is value); return copy.deepcopy(limits)
        namespace['effective_limits'] = recorded_limits
        fn = types.FunctionType(launch.validate_manifest.__code__, namespace)
        return fn(value)

    @staticmethod
    def ledger(policy, state, root, prior, claim_check):
        namespace = dict(launch.LaunchLedger._validate.__globals__)
        namespace['_successor_claim'] = claim_check
        # Even if a malformed caller omits prevalidated carry, it cannot read history.
        namespace['_effective_carry'] = lambda *a, **k: need(False)
        fn = types.FunctionType(launch.LaunchLedger._validate.__code__, namespace)
        verifier = object.__new__(launch.LaunchLedger)
        verifier.root = Path(root) / 'launch-ledger'; verifier.manifest = policy
        verifier.expected_daemon = verifier.expected_capacity = None
        verifier._carry = None; verifier._prevalidated_carry = prior
        fn(verifier, state)


def same_typed(actual, expected):
    need(type(actual) is type(expected) and actual == expected)


def matrix_cells(images):
    """Only compile the exact pure original matrix function, never its module IO."""
    import ast
    path=Path(launch.__file__).with_name('application_client.py')
    tree=ast.parse(path.read_text())
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='matrix')
    need(hashlib.sha256(pinned_dump(fn).encode()).hexdigest()==MATRIX_AST_SHA256)
    constants={}
    for node in tree.body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name) and target.id in ('ROLES','RELEASES','NEGATIVES','SCRIPT_RESULTS','RESERVE_COUNTS','SENSITIVE_SCOPE'):
                    constants[target.id]=ast.literal_eval(node.value)
    need(set(constants)=={'ROLES','RELEASES','NEGATIVES','SCRIPT_RESULTS','RESERVE_COUNTS','SENSITIVE_SCOPE'})
    need(launch._digest(constants)==MATRIX_CONSTANTS_SHA256)
    code=compile(ast.Module(body=[fn],type_ignores=[]),str(path),'exec')
    namespace={'__builtins__':{'dict':dict,'range':range,'sum':sum,'list':list},**constants}
    exec(code,namespace)
    return namespace['matrix'](copy.deepcopy(images))


def negative_oracles():
    return {'tool_results':{'invalid-typed-request':1,'wrong-actor':1,'omitted-report':5,
        'multi-call-reserve-boundary':13,'publication-response-loss':6,'sensitive-participant-interruption':2},
        'reserve_counts':{'attempted':13,'charged':10,'blocked':3,'grants_consumed':10,'executed_known':10,
            'executed_unknown':0,'helper_verified':10,'worker_observed':0},'reserve_remaining':6,
        'scope':'expected negative failures are qualification assertions, never model task success'}


def retained_predicates(closure,review,event,names):
    """Explicit retained predicate delegation; never a current observation."""
    need(set(review['retained_predicates'])==set(names))
    for name,ref in review['retained_predicates'].items():
        proof=closure.get(ref,'retained-predicate')
        need(proof['predicate']==name and proof['status']=='PASS_SCOPED_RETAINED')
        need(proof['scope']=='original_terminal_evidence_only_not_current_global_clearance')
        need(proof['origin']==event['origin'])
        for key in ('manifest','state','ledger'): need(proof[key]==event[key])
        source=proof['original_validator']
        kind=source.get('evidence_kind','executed_original_validator')
        if kind==scoped_checks.KIND:
            scoped_checks.validate(closure, event, name, proof)
            continue
        need(kind=='executed_original_validator')
        launch._sha(source['sha256']); launch._canonical_root(source['path'])
        need(type(source['callable']) is str and source['callable'] in (
            'validate_predecessor','_validate_first_predecessor','_native_prior','_current_cleanup',
            '_replay_prior','verify','validate_qualification_preworker_cleanup'))
        need(type(proof['evidence']) is list and proof['evidence'])
        for item in proof['evidence']:
            # Evidence itself must be in the classified closure, and its body
            # is read/hash checked. No opaque 'reviewed=True' substitution.
            closure.get(item,'operational-projection')


def frozen_metadata(full,limits,source,closure,event):
    expected={k:v for k,v in limits.items() if k!='live'}
    expected.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
    need(full['limits']==expected and all(type(full['limits'][k]) is int for k in expected))
    need(full['schema']==1 and type(full['schema']) is int)
    base={'schema','document_type','qualification_id','created_at','prepared_root','session','endpoint',
        'endpoint_sha256','images','image_receipts','fixture_route','credential_references','host_admission',
        'secrets_dir','source','cells','limits','planned_container_launches','files','negative_oracles'}
    need(base<=set(full) and not set(full)-base-{'sensitive_negative_scope','predecessor','campaign_boundary','campaign_amendment'})
    need(full['negative_oracles']==negative_oracles())
    need(full['endpoint_sha256']==launch._digest(full['endpoint']))
    need(full['host_admission']==source['host_admission'])
    need(type(full['host_admission']['wait_seconds']) is int and full['host_admission']['wait_seconds']==30)
    launch._canonical_root(full['host_admission']['lock_file'])
    launch._sha(full['source']['runner']); need(type(full['source']['files']) is dict)
    for relative,digest in full['source']['files'].items():
        need(type(relative) is str and not Path(relative).is_absolute() and '..' not in Path(relative).parts)
        launch._sha(digest)
    need(full['source']['sha256']==launch._digest(full['source']['files']))
    need(full['files']==source['frozen_input_inventory'])
    need(type(full['files']) is dict and 1<=len(full['files'])<=8192)
    for relative,digest in full['files'].items():
        need(type(relative) is str and not Path(relative).is_absolute() and '..' not in Path(relative).parts)
        launch._sha(digest)
    expected_cells=matrix_cells(full['images'])
    need(len(full['cells'])==len(expected_cells))
    for actual,wanted in zip(full['cells'],expected_cells):
        need({k:actual.get(k) for k in wanted}==wanted)
        need(not set(actual)-set(wanted)-{'trial_id','plan_sha256'})
        if actual['group']=='N02': launch._uuid(actual['trial_id'])
        if actual['participant_segments_max']: launch._sha(actual['plan_sha256'])
    retained_predicates(closure,source,event,('original_endpoint_and_session_admission',
        'original_frozen_input_bytes_and_compiled_bindings','original_source_and_candidate_gate'))


def cells_projection(full, state):
    launch._exact(state, {'schema', 'phase', 'active_cell', 'cells', 'started_at'})
    same_typed(state['schema'], 1)
    need(state['phase'] in ('blocked', 'complete') and type(state['cells']) is dict)
    ids = {c['id'] for c in full['cells']}; need(not set(state['cells']) - ids)
    active = state['active_cell']
    if active is not None:
        launch._exact(active, {'id', 'pid', 'run_id', 'attempt_id'})
        need(active['id'] in ids); launch._integer(active['pid'], 1, 2**31 - 1)
        launch._uuid(active['run_id']); launch._uuid(active['attempt_id'])
        need(state['cells'][active['id']]['status'] == 'BLOCKED')
    rows = []
    for cell in full['cells']:
        item = state['cells'].get(cell['id'], {'status': 'NOT_RUN', 'attempts': 0})
        need(type(item) is dict and item['status'] in ('PASS','FAIL','BLOCKED','NOT_RUN'))
        launch._integer(item['attempts'], 0, 1)
        need((item['status'] == 'NOT_RUN') == (item['attempts'] == 0))
        rows.append({'qualification_id': full['qualification_id'], 'cell': cell['id'],
                     'status': item['status'], 'attempts': item['attempts']})
    return rows


def validate_claims(closure, origin, policy, prior):
    """Compare actual copied permanent claims to original expected field sets.

    Exact expected values are constructed here from the original source claim
    families and real manifest/carry/digests. The index supplies only references;
    neither a supplied expected dictionary nor a 'claim exists' flag is accepted.
    """
    claims = origin['claims']
    need(type(claims) is list)
    if prior is None:
        need(claims == [])  # no incoming successor claim exists for origin one
        return
    actual = [closure.get(ref, 'claim') for ref in claims]
    digest = launch._digest(policy)
    if 'campaign_amendment' in policy:
        need(len(actual) == 4)  # two permanent fence copies, candidate, launch
        fence = {'schema':1,'document_type':'qualification_matrix_amendment_claim',
            'amendment':policy['campaign_amendment'],'prior_root':prior['lineage'][-1]['root'],
            'prior_qualification_id':prior['qualification_id'],'final_root':origin['root']}
        candidate = {'schema':1,'amendment':policy['campaign_amendment'],
            'qualification_id':policy['qualification_id'],'full_manifest':origin['manifest'],
            'candidate':origin['candidate'],'launch_manifest_sha256':digest}
        binding = {'schema':1,'document_type':'qualification_matrix_amendment_launch_binding',
            'amendment':policy['campaign_amendment'],'qualification_id':policy['qualification_id'],
            'manifest_sha256':digest,'ledger_root':str(Path(origin['root'])/'launch-ledger'),
            'cumulative_attempts':prior['attempts'],'participant_segments':prior['participant_segments'],
            'candidate_binding':claims[2]}
        need(actual == [fence,fence,candidate,binding])
    elif 'campaign_boundary' in policy:
        need(len(actual) == 4)
        binding = closure.get(origin['boundary_binding'], 'operational-projection')
        need(binding['base_predecessor'] == policy['predecessor'] and binding['final_root'] == origin['root'])
        fence = {'schema':1,'document_type':'qualification_campaign_boundary_fence',
            'binding_sha256':launch._digest(binding),'auxiliary_root':binding['root'],
            'final_root':binding['final_root'],'authorization':binding['authorization'],
            'base_predecessor':binding['base_predecessor']}
        candidate = {'schema':1,'boundary':policy['campaign_boundary'],
            'qualification_id':policy['qualification_id'],'full_manifest':origin['manifest'],
            'candidate':origin['candidate'],'launch_manifest_sha256':digest}
        final = {'schema':1,'document_type':'qualification_boundary_final_binding',
            'boundary':policy['campaign_boundary'],'qualification_id':policy['qualification_id'],
            'manifest_sha256':digest,'ledger_root':str(Path(origin['root'])/'launch-ledger'),
            'base_attempts':51,'auxiliary_attempts':prior['attempts']-51,
            'cumulative_attempts':prior['attempts'],'candidate_binding':claims[2]}
        need(actual == [fence,fence,candidate,final])
    else:
        need(len(actual) == 1)
        expected = {'schema':1,'document_type':'qualification_campaign_successor',
            'predecessor_qualification_id':prior['qualification_id'],
            'predecessor_sha256':launch._digest(policy['predecessor']),
            'qualification_id':policy['qualification_id'],
            'ledger_root':str(Path(origin['root'])/'launch-ledger'),'manifest_sha256':digest}
        need(actual[0] == expected)


def record_scopes(closure,index):
    """Retained per-origin release facts and selected current281 are distinct.

    The current observation includes networks/auxiliaries and is not the whole
    historical309-container union. Neither projection claims unread current
    global statuses, positive host reaps or complete memory. Fresh SDK admission
    still independently checks the full current namespace under its actual lease.
    """
    observation=closure.get(index['record_observation'],'operational-projection')
    peer=closure.get(index['record_observation_review'],'operational-projection')
    need(observation['status']=='PASS_METADATA_ONLY' and peer['status']=='PASS_METADATA_ONLY')
    need(peer['subjects']['verification']==index['record_observation'])
    need(peer['unresolved_findings']==[] and peer['supports_selected_record_metadata_and_known_guest_absence'] is True)
    observed={r['launch_id']:r['canonical_body_sha256'] for r in observation['selected_records'] if r['status']=='released'}
    need(len(observed)==len(observation['selected_records']) and index['canonical_record_sha256']==observed)
    selected={}
    for ref in index.get('selected_record_bodies',[]):
        body=closure.get(ref,'record'); key=body['launch_id']
        need(key in observed and key not in selected and body['status']=='released')
        need(launch_digest(body)==observed[key]); selected[key]=body
    bindings={}
    for item in index['historical_record_bindings']:
        _exact(item,{'origin','launch_id','record','namespace','snapshot','provenance','capture'})
        _integer(item['origin'],1,19); _uuid(item['launch_id'])
        key=(item['origin'],item['launch_id']); need(key not in bindings)
        root=_canonical_root(item['namespace']); refkey(item['capture'])
        closure.get(item['capture'],'operational-projection')
        body=closure.get(item['record'],'record')
        snapshot=closure.get(item['snapshot'],'operational-projection')
        provenance=closure.get(item['provenance'],'operational-projection')
        need(body['launch_id']==item['launch_id'] and body['status']=='released')
        need(body['registry']==hashlib.sha256(str(root).encode()).hexdigest())
        need(snapshot['document_type']=='qualification_retained_released_record_snapshot')
        need(snapshot['namespace']==str(root) and snapshot['capture']==item['capture'])
        fact=snapshot['records'][item['launch_id']]
        need(fact['record']==item['record'] and fact['status']=='released')
        need(fact['canonical_body_sha256']==launch_digest(body))
        for field in ('registry','generation','daemon'): need(fact[field]==body[field])
        need(provenance['status']=='PASS_SCOPED_RELEASED_RECORD_SNAPSHOT' and provenance['unresolved_findings']==[])
        need(provenance['supports_retained_released_record_bindings'] is True)
        need(provenance['snapshot']==item['snapshot'] and provenance['namespace']==str(root))
        need(provenance['scope']=='retained_at_capture_not_current_global_liveness')
        need(type(provenance['evidence']) is list and provenance['evidence'])
        for evidence in provenance['evidence']: closure.get(evidence,'operational-projection')
        if item['launch_id'] in observed:
            if item['capture']==index['record_observation']:
                need(launch_digest(body)==observed[item['launch_id']])
            elif launch_digest(body)!=observed[item['launch_id']]:
                # A legitimate later status/proof attachment can change the
                # canonical body. It cannot change immutable intent or CID.
                current=selected.get(item['launch_id']); need(current is not None)
                need(_intent_identity(body)==_intent_identity(current))
                oldcid,newcid=body.get('container_id'),current.get('container_id')
                need(oldcid is None or newcid is None or oldcid==newcid)
        bindings[key]=(item,body)
    return observed,selected,bindings


# Explicit aliases keep the copied validator independent of live original
# readers while preserving the exact original primitive semantics.
from application_launch import _exact,_integer,_uuid,_canonical_root,_intent_identity
from application_launch import _digest as launch_digest



LATER_ABSENCE_SUBJECTS = {'manifest': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification/manifest.json', 'sha256': '9062fc6bfecdaf4a391d56239f172a6ec4394300493b9d82ee6f0647f702a0c2'}, 'state': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification/state.json', 'sha256': 'c4123bfa4f658d598af36badb459be2ecb49442a928ee09dd0bc8b32e18fc5fa'}, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification/launch-ledger/ledger.json', 'sha256': '32d3a3699480f37b96133e949c1e7e8ba32e1e1e06af5216cccd2f0effd58cf0'}, 'cleanup': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/final-cleanup.json', 'sha256': '7658e4ec3fc89d6dbafa6e5a6e5fabd938e406632ca964e5b4fb85114bf2faed'}, 'cleanup_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/final-cleanup-independent-review/review.json', 'sha256': '1bb29b29838af13c184d370390a0a7b485be089bb71cb028f66bbeea5d5cc5a1'}}
RETAINED_UNCERTAIN_ROWS = [{'origin': 9, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-009/qualification/launch-ledger/ledger.json', 'sha256': '0f2a0a849166c2183cbf7a24f41f80a3ff2fbdb2af94075357a24eb7ccee74b0'}, 'launch_id': '37e5db55-7801-491b-a39d-c91a96461163', 'role': 'fixture', 'container_id': '95d656f5f697068a865eb8f36a0fd130bf8396b26d7ddc78de507bb593a73cbb'}, {'origin': 10, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-010/qualification/launch-ledger/ledger.json', 'sha256': '727fc7e7fe74e0b21fbbf08ae4b74491382511a1d64823717e0bb81c734f6732'}, 'launch_id': '4b0231ad-cea4-460b-a545-1af199fa582b', 'role': 'fixture', 'container_id': '9c4e343bdc2a6ed2436f46f9daf9b7bd5d4fd2a0f10376d9f1c23dc5083c01f1'}, {'origin': 10, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-010/qualification/launch-ledger/ledger.json', 'sha256': '727fc7e7fe74e0b21fbbf08ae4b74491382511a1d64823717e0bb81c734f6732'}, 'launch_id': 'f707c0df-3517-4d80-8e9c-cede2eaa8696', 'role': 'application-helper', 'container_id': 'e3809a6e7b614f59d3584c3faa458bdfd744fa20661ac4011ef26ad3fc85e1b9'}, {'origin': 12, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-012/qualification/launch-ledger/ledger.json', 'sha256': 'b3c2dd5f2f21074bd051f9e0a929e3a3cd85e7e17bd33a0608edd501b58e66fd'}, 'launch_id': '00a19707-7faa-4367-9118-f6b9dd3220f0', 'role': 'fixture', 'container_id': 'cd6d9ff79eae6507ee246d0f57f43f74aaf43994d74265d7d23be36a2e253359'}, {'origin': 12, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-012/qualification/launch-ledger/ledger.json', 'sha256': 'b3c2dd5f2f21074bd051f9e0a929e3a3cd85e7e17bd33a0608edd501b58e66fd'}, 'launch_id': '03c973f8-72c0-4c85-8244-396f5cde932b', 'role': 'application-helper', 'container_id': '738ce5cfe43efd435c0b40f8b5a1f7fdc225bc8203e6161dc0f6f5645d3f3d54'}, {'origin': 13, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-013/qualification/launch-ledger/ledger.json', 'sha256': '043c8f7d6798805a87117c9324c4be137c0586f17b4e590e5ee6019fc67c0bbf'}, 'launch_id': '8306c1ce-3602-4d3d-824b-2252ed7920b2', 'role': 'fixture', 'container_id': '9d6505c2b853cadc0170bf07163f4008d4e30a32629c5e02f41f181d11b3aff5'}, {'origin': 14, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-014/qualification-002/launch-ledger/ledger.json', 'sha256': 'ee873dac04e06e2940e575b03e48717ac1870e9014d5446fe80aef69b4cee759'}, 'launch_id': 'de23cc46-bbed-4147-a020-c7a9f263d43e', 'role': 'fixture', 'container_id': '1ec794340c6bb28e0427a6230a501897c9a72ef8c8bdb3d22539c509196ef70d'}]


def later_retained_physical_absence(closure,index,event,row):
    """Resolve only seven exact retained raw-uncertain CIDs using known266.

    This is later historical guest absence, never a rewrite/current observation.
    The caller still completes every original Kernel/source/candidate/claim and
    retained predicate check for all19 origins, including incoming19's binding.
    """
    need(type(event.get('origin')) is int and row['physical']=='uncertain'
        and row['private_cleanup'] is False and row['container_id'] is not None)
    matches=[item for item in RETAINED_UNCERTAIN_ROWS
        if item['origin']==event['origin'] and item['launch_id']==row['launch_id']]
    need(len(matches)==1)
    fixed=matches[0]
    need(event['ledger']==fixed['ledger'] and row['role']==fixed['role']
        and row['container_id']==fixed['container_id'])
    events=index['events']
    need(type(events)is list and event in events)
    prior=[item for item in events if item.get('kind')=='matrix'and type(item.get('origin'))is int and item['origin']==18]
    incoming=[item for item in events if item.get('kind')=='matrix'and type(item.get('origin'))is int and item['origin']==19]
    need(len(prior)==len(incoming)==1)
    prior=prior[0];incoming=incoming[0]
    need(all(prior[k]==LATER_ABSENCE_SUBJECTS[k]for k in ('manifest','state','ledger')))
    need(all(incoming[k]==scoped_checks.SUBJECTS[k]for k in ('manifest','state','ledger')))
    raw=closure.get(event['ledger'],'ledger')
    witness=closure.get(prior['ledger'],'ledger')
    need(raw['poisoned']is True and any(item==row for item in raw['launches'])
        and raw['daemon']==witness['daemon'])
    for clock in (raw['last_wall'],witness['last_wall']):launch._number(clock)
    need(witness['last_wall']>raw['last_wall'])
    full=closure.get(prior['manifest'],'manifest')
    newfull=closure.get(incoming['manifest'],'manifest')
    rule=HISTORICAL_POLICY[19]
    need(newfull['campaign_amendment']==rule['authorization']
        and newfull['source']['files'][rule['source_path']]==rule['source_sha256'])
    cleanup=closure.get(LATER_ABSENCE_SUBJECTS['cleanup'],'operational-projection')
    peer=closure.get(LATER_ABSENCE_SUBJECTS['cleanup_review'],'operational-projection')
    need(cleanup['document_type']=='qualification_final_cleanup_and_safe_handoff'
        and cleanup['status']==peer['status']=='PASS'and peer['unresolved_findings']==[]
        and peer['supports_final_handoff']is True
        and peer['final_cleanup']==LATER_ABSENCE_SUBJECTS['cleanup'])
    need(cleanup['qualification_id']==full['qualification_id']
        and cleanup['raw_ledger']==prior['ledger']and cleanup['raw_state']==prior['state']
        and type(cleanup['cumulative_container_launches'])is int and cleanup['cumulative_container_launches']==274
        and type(cleanup['participant_segments'])is int and cleanup['participant_segments']==15
        and type(cleanup['real_model_participant_segments'])is int and cleanup['real_model_participant_segments']==0
        and type(cleanup['actual_immutable_container_id_count'])is int and cleanup['actual_immutable_container_id_count']==266
        and type(cleanup['live_owned_containers'])is int and cleanup['live_owned_containers']==0
        and cleanup['safe_to_continue']is False and cleanup['qualification_eligible']is False)
    for key in ('all_owned_container_ids_absent','all_known_container_ids_and_names_absent',
                'raw_poisoned_true_preserved','raw_private_cleanup_false_preserved'):
        need(cleanup[key]is True)
    identifiers=cleanup['all_owned_container_ids']
    need(type(identifiers)is list and len(identifiers)==len(set(identifiers))==266)
    for identifier in identifiers:launch._sha(identifier)
    need(row['container_id']in identifiers)
    return True

def replay(closure, index, *, kernel=None, expected_origins=19, expected_attempts=334,
           expected_segments=21):
    """Recompute every matrix row and every auxiliary canonical intent charge.

    Production callers must use defaults. Smaller explicit values are ONLY the
    pure synthetic fixture API. No live reader is chosen by these parameters.
    """
    kernel = kernel or Kernel()
    need(index['schema'] == 1 and index['document_type'] == 'matrix20_operational_carry_index')
    need(type(index['events']) is list and 1 <= len(index['events']) <= 64)
    observed,selected,record_bindings=record_scopes(closure,index)
    if expected_origins==19: need(len(observed)==281)

    attempts = segments = origins = 0; lineage = []; rows = []; keys = set(); ids = set()
    prior = None; daemon = None; capacity = None; roots=set(); auxiliaries=set()
    initial_window=None; base_carry=None; boundary_carry=None; auxiliary_refs={}; immutable_ids=set()
    for event in index['events']:
        if event['kind'] == 'auxiliary':
            summary = closure.get(event['summary'], 'operational-projection')
            review = closure.get(event['review'], 'cleanup-review')
            need(review['status'] == 'PASS' and review['unresolved_findings'] == [])
            need(review['supports_exact_auxiliary_intent_accounting'] is True and review['summary'] == event['summary'])
            diagnostic=summary['diagnostic']
            need(diagnostic in AUXILIARY_STAGES and diagnostic not in auxiliaries)
            auxiliaries.add(diagnostic)
            auxiliary_refs[diagnostic]={'summary':event['summary'],'review':event['review']}
            if diagnostic=='auxiliary-campaign': base_carry=copy.deepcopy(prior)
            need(AUXILIARY_STAGES[diagnostic][0]==origins)
            same_typed(summary['canonical_container_intents'],AUXILIARY_STAGES[diagnostic][1])
            same_typed(summary['matrix_origins_added'],0); same_typed(summary['planned_matrix_rows_added'],0)
            need(type(summary['intents']) is list and len(summary['intents']) <= 32)
            delegated = 0
            for intent in summary['intents']:
                launch._uuid(intent['launch_id']); need(intent['launch_id'] not in keys); keys.add(intent['launch_id'])
                need(type(intent['delegated']) is bool); delegated += intent['delegated']
                need(intent['role'] in launch.ROLES or intent['role'] == 'image-recovery')
                need(intent['role']!='participant')
                provenance=closure.get(intent['source_reference'],'operational-projection')
                need(provenance['launch_id']==intent['launch_id'] and provenance['role']==intent['role'])
                need(provenance['canonical_intent_counted'] is True and provenance['OS_delegate_returned'] is intent['delegated'])
            same_typed(summary['canonical_container_intents'], len(summary['intents']))
            same_typed(summary['native_OS_delegates'], delegated)
            attempts += len(summary['intents'])
            if summary['diagnostic'] in ('D05','D06'):
                need(summary['native_oracle_exercised'] is False)
                same_typed(summary['participant_segments'], 0)
                same_typed(summary['canonical_container_intents'], 0 if summary['diagnostic']=='D05' else 6)
                same_typed(summary['native_OS_delegates'], 0 if summary['diagnostic']=='D05' else 5)
            if prior is not None:
                prior = {**prior, 'attempts': attempts, 'participant_segments': segments}
            continue
        need(event['kind'] == 'matrix')
        launch._integer(event['origin'],1,19); need(event['origin'] == origins + 1)
        full = closure.get(event['manifest'], 'manifest')
        state = closure.get(event['state'], 'state'); ledger = closure.get(event['ledger'], 'ledger')
        review = closure.get(event['review'], 'cleanup-review')
        need(review['status'] == 'PASS' and review['unresolved_findings'] == [])
        need(review['supports_original_historical_operational_invariants'] is True)
        for k in ('manifest','state','ledger'): need(review[k] == event[k])
        need(review['raw_state_and_failure_flags_preserved'] is True)
        retained_predicates(closure,review,event,('original_controller_and_owner_terminal_provenance',
            'original_guest_and_owned_sensitive_file_cleanup','original_lineage_cleanup_proof_bindings'))
        need(full['prepared_root'] == event['root'] and full['document_type'] == 'application_client_qualification')
        currentroot=launch._canonical_root(event['root']); launch._uuid(full['qualification_id'])
        need(event['root'] not in roots and all(not currentroot.is_relative_to(Path(old)) and not Path(old).is_relative_to(currentroot) for old in roots))
        roots.add(event['root'])
        need(full['qualification_id'] not in ids); ids.add(full['qualification_id'])
        policy = {k: full[k] for k in ('qualification_id','images','planned_container_launches')}
        policy['cells'] = [{k:c[k] for k in FIELDS} for c in full['cells']]
        policy['limits'] = copy.deepcopy(event['effective_limits'])
        for k in ('predecessor','campaign_boundary','campaign_amendment'):
            if k in full: policy[k] = copy.deepcopy(full[k])
        limits = policy['limits']; same_typed(limits['global_seconds'],14400)
        same_typed(limits['cleanup_reserve_seconds'],30); same_typed(limits['live'],4)
        if origins == 0:
            need('predecessor' not in policy and limits == launch.LIMITS)
        else:
            descriptor = policy['predecessor']
            launch._integer(event['predecessor_origin'],1,origins)
            base = lineage[event['predecessor_origin']-1]
            need(descriptor['root'] == base['root'])
            for k in ('manifest','state','ledger'): need(descriptor[k+'_sha256'] == base[k+'_sha256'])
            if 'campaign_amendment' in policy:
                rule=HISTORICAL_POLICY[event['origin']]
                need(ledger['deadline']==rule['deadline'] and ledger['deadline_wall']==rule['deadline_wall'])
                need(ledger['started']==rule['deadline']-14400 and ledger['started_wall']==rule['deadline_wall']-14400)
                prior = {**prior, **{k:ledger[k] for k in ('started','deadline','started_wall','deadline_wall')}}
            elif 'campaign_boundary' in policy:
                binding=closure.get(event['boundary_binding'],'operational-projection')
                auth=closure.get(binding['authorization'],'authority')
                for key,field in (('started','started_monotonic'),('started_wall','started_wall'),('deadline','deadline_monotonic'),('deadline_wall','deadline_wall')):
                    need(ledger[key]==auth[field])
                prior = {**prior, **{k:ledger[k] for k in ('started','deadline','started_wall','deadline_wall')}}
            # Linear origins retain the previous exact window; do not project
            # attacker-controlled ledger clocks into the expected carry.
        if event['origin'] <= 8:
            need(limits==launch.LIMITS)
            need('campaign_amendment' not in policy)
        if event['origin'] >= 9:
            rule=HISTORICAL_POLICY[event['origin']]
            need(policy.get('campaign_amendment')==rule['authorization'])
            authority=closure.get(rule['authorization'],'authority')
            need(authority['authorization_id']==rule['authorization_id'])
            same_typed(authority['container_cap'],rule['container_cap'])
            if 'participant_cap' in authority: same_typed(authority['participant_cap'],rule['participant_cap'])
            need(limits=={**launch.LIMITS,'container_launch_attempts':rule['container_cap'],'participant_segments':rule['participant_cap']})
            need(full['source']['files'][rule['source_path']]==rule['source_sha256'])
            need(ledger['deadline']==rule['deadline'] and ledger['deadline_wall']==rule['deadline_wall'])
        source = closure.get(event['source_review'], 'source-review')
        need(source['status'] == 'PASS' and source['unresolved_findings'] == [])
        need(source['historical_source'] == full['source'] and source['effective_limits'] == limits)
        frozen_metadata(full,limits,source,closure,event)
        need(source['manifest'] == event['manifest'] and source['origin'] == event['origin'])
        need(source['predecessor'] == policy.get('predecessor'))
        need(source['original_claim_family'] == ('amendment' if 'campaign_amendment' in policy else 'boundary' if 'campaign_boundary' in policy else 'linear' if prior else 'initial'))
        candidate = closure.get(event['candidate'], 'candidate')
        need(candidate['scope'] == 'extracted_candidate' and candidate['runner_sha256'] == full['source']['runner'])
        launch._sha(candidate['archive_sha256']); launch._sha(candidate['runner_sha256'])
        if prior is not None:
            need(prior['attempts']+186<=limits['container_launch_attempts'])
            need(prior['participant_segments']+24<=limits['participant_segments'])
        policy = kernel.manifest(policy, limits)
        need(len(policy['cells']) == 28)
        need({g:sum(c['group']==g for c in policy['cells']) for g in ('N01','N02','N03','N04')} == {'N01':4,'N02':12,'N03':6,'N04':6})
        need(sum(c['participant_segments_max'] for c in policy['cells']) == 24)
        # Detached original Ledger validates exact carry, all rows/caps/resources,
        # PID/CID syntax, immutable intent keys, poison types and original clocks.
        kernel.ledger(policy, ledger, event['root'], prior,
                      lambda *a, **kw: validate_claims(closure,event,policy,prior))
        if prior is None: validate_claims(closure,event,policy,None)
        current_rows = cells_projection(full,state)
        record_refs=event['records']; need(type(record_refs) is list and len(record_refs)==len(ledger['launches']))
        records={}
        for ref in record_refs:
            record=closure.get(ref,'record'); key=record['launch_id']; launch._uuid(key)
            need(key not in records and record['status']=='released')
            retained=record_bindings.get((event['origin'],key)); need(retained is not None)
            need(retained[0]['record']==ref and retained[1]==record)
            need(retained[0]['namespace']==str(Path(full['host_admission']['lock_file']+'.registry')))
            records[key]=record
        need(set(records)=={row['launch_id'] for row in ledger['launches']})
        for row in ledger['launches']:
            record=records[row['launch_id']]
            need(record['registry']==row['registry'] and record['generation']==row['generation'])
            need(record['daemon']==ledger['daemon'] and record['container']==row['container'] and record['image']==row['image'])
            need(launch._intent_identity(record)==row['intent_sha256'])
            need(record.get('container_id') in (None,row['container_id']))
            if row['launch_id'] in selected:
                need(selected[row['launch_id']].get('container_id') in (None,row['container_id']))
            need(row['launch_id'] not in keys); keys.add(row['launch_id'])
            need(row['container_id'] is not None)
            if row['physical'] != 'absent':
                later_retained_physical_absence(closure,index,event,row)
            need(row['container_id'] not in immutable_ids); immutable_ids.add(row['container_id'])
            if row['role']=='participant':
                need(next(c for c in policy['cells'] if c['id']==row['cell'])['group']=='N02')
            need(next(r for r in current_rows if r['cell']==row['cell'])['attempts'] == 1)
        attempts += len(ledger['launches']); segments += sum(r['role']=='participant' for r in ledger['launches'])
        need(attempts <= limits['container_launch_attempts'] and segments <= limits['participant_segments'])
        if daemon is None:
            daemon = ledger['daemon']; capacity = ledger['daemon_capacity']
            initial_window={k:ledger[k] for k in ('started','deadline','started_wall','deadline_wall')}
        if 'campaign_boundary' in policy and 'campaign_amendment' not in policy:
            need(base_carry is not None)
            boundary_carry={'base_attempts':base_carry['attempts'],'auxiliary_attempts':3,
                'attempts':attempts-len(ledger['launches']),'participant_segments':segments-sum(r['role']=='participant' for r in ledger['launches']),
                'started_wall':ledger['started_wall'],'deadline_wall':ledger['deadline_wall'],'original_window':copy.deepcopy(initial_window)}
        need(daemon == ledger['daemon'])
        capacity = {k:min(capacity[k],ledger['daemon_capacity'][k]) for k in ('cpu_millis','memory_mib')}
        hashes = {k+'_sha256':event[k]['sha256'] for k in ('manifest','state','ledger')}
        lineage.append({'root':event['root'],'qualification_id':full['qualification_id'],**hashes})
        rows.extend(current_rows); origins += 1
        prior = {'attempts':attempts,'participant_segments':segments,'qualification_id':full['qualification_id'],
            'planned_cells':origins*28,'lineage':copy.deepcopy(lineage),'prior_rows':copy.deepcopy(rows),
            'daemon':daemon,'daemon_capacity':capacity,**hashes,
            **{k:ledger[k] for k in ('started','deadline','started_wall','deadline_wall')}}
    need(prior is not None and (origins,attempts,segments)==(expected_origins,expected_attempts,expected_segments))
    need(len(rows)==28*expected_origins)
    if expected_origins==19: need(auxiliaries==set(AUXILIARY_STAGES))
    used={(event['origin'],row['launch_id']) for event in index['events'] if event['kind']=='matrix'
        for row in closure.get(event['ledger'],'ledger')['launches']}
    need(set(record_bindings)==used)
    prior['prior_rows'] = rows; prior['lineage'] = lineage
    prior['base_predecessor']=copy.deepcopy(full.get('predecessor'))
    prior['original_window']=initial_window
    prior['historical_base_carry']=base_carry
    prior['historical_boundary_carry']=boundary_carry
    prior['historical_auxiliary_events']=auxiliary_refs
    prior['image_recovery']={'qualified_images':copy.deepcopy(full['images']),'accounting':auxiliary_refs.get('image-recovery')}
    prior['historical_primary_rows_reused_for_new_matrix'] = 0
    return prior
