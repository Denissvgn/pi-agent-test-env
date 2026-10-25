"""Explicitly activated application tool service; no task orchestration or repair.

Parent control selects an already frozen stage. Tool capabilities only spend its
ledger and perform one declared operation. Activation never sends application I/O.
"""
import copy
import os
from pathlib import Path
import secrets
import threading
import time

import application_contracts as c
import application_credentials as credentials
from application_client_service import CapabilityService, ServiceError, token, validate_scope
from application_budget import BudgetRouter
from application_api import APIClient
from application_evidence import open_directory, read_file
from native_budget_service import private_root
from tool_budgets import BudgetLedger, BINDING_FIELDS


class ApplicationService(CapabilityService):
    def __init__(self, configuration, *, clock=time.monotonic, browser_factory=None, files_factory=None):
        c.exact(configuration, {'schema', 'document_type', 'mode', 'authority', 'state_root',
                                'outputs_root', 'budget_grants', 'browser_admission', 'sealed_inputs', 'redaction_values'}, '')
        c.choice(configuration['schema'], (1,), '/schema')
        c.choice(configuration['document_type'], ('application_execution_private_bootstrap',), '/document_type')
        c.choice(configuration['mode'], ('application-execution',), '/mode')
        super().__init__(configuration['authority'])
        self.mode, self.clock = 'application-execution', clock
        self._state_root = private_root(configuration['state_root'])
        # Only fixed children of the already verified private evidence mount.
        if Path(configuration['outputs_root']) != self._evidence_root / 'outputs':
            raise ServiceError('evidence_unavailable')
        for name in ('raw', 'outputs'):
            (self._evidence_root / name).mkdir(mode=0o700, exist_ok=False)
        self.outputs_root = private_root(configuration['outputs_root'])
        self._evidence_root = private_root(self._evidence_root / 'raw')
        roots = [self._state_root, self.outputs_root, self._evidence_root]
        if any(a == b or a in b.parents or b in a.parents for i,a in enumerate(roots) for b in roots[i+1:]):
            raise ServiceError('evidence_unavailable')
        self._budget_grants = {}
        c.array(configuration['budget_grants'], '/budget_grants', 64, 1)
        issued = {self._control_token, *(g['token'] for g in self._grants)}
        for record in configuration['budget_grants']:
            c.exact(record, {'token', 'scope'}, '/budget_grants')
            capability = token(record['token']); validate_scope(record['scope'], self.plan)
            if (capability in issued or self.redactor.contains(c.canonical(record))
                    or not any(g['scope'] == record['scope'] for g in self._grants)):
                raise ServiceError()
            issued.add(capability)
            key = c.digest(record['scope'])
            if key in self._budget_grants: raise ServiceError()
            self._budget_grants[key] = capability
        if set(self._budget_grants) != {c.digest(g['scope']) for g in self._grants}:
            raise ServiceError()
        c.array(configuration['redaction_values'],'/redaction_values',1024)
        for value in configuration['redaction_values']:c.text(value,'/redaction_values',16384)
        # Tokens authenticate the transport and must not poison their own bearer
        # screening. Participant payloads screen every issued token separately.
        corpus=[value for value in configuration['redaction_values'] if value not in issued]
        self.redactor=credentials.Redactor([*(value for aliases in self._authorities.values()
            for value in aliases.values()),*corpus])
        self._issued, self._ledgers, self._segments = issued, {}, {}
        self._active, self._router, self._browser = None, None, None
        self._quarantined = False
        self._finished, self._sealed_inputs = set(), {}
        self._browser_admission = copy.deepcopy(configuration['browser_admission'])
        self._browser_factory = browser_factory
        self._files_factory = files_factory
        for name in ('home', 'tmp'):
            directory = self._state_root / name
            directory.mkdir(mode=0o700, exist_ok=False)
        self._load_sealed_inputs(configuration['sealed_inputs'])
        self.api = APIClient(self, self._evidence_root, self.outputs_root,
                             clock=clock, budget_verifier=self._verify_effect)
        self.files = None

    def _load_sealed_inputs(self, records):
        import hashlib
        c.array(records,'/sealed_inputs',64)
        declarations={(s['id'],a['id']):a for s in self.plan['stages'] for a in s['completion']['artifacts']}
        incoming={(a['stage_id'],a['artifact_id']) for s in self.plan['stages'] for a in s['input_artifacts']}
        total=0
        directory=self._state_root/'incoming';directory.mkdir(mode=0o700)
        private=credentials.Redactor(self._issued)
        for i,record in enumerate(records):
            c.exact(record,{'stage_id','artifact_id','content','sha256','bytes','media_type'},'/sealed_inputs')
            key=(record['stage_id'],record['artifact_id'])
            if key not in incoming or key not in declarations or key in self._sealed_inputs:raise ServiceError()
            item=declarations[key];body=record['content'].encode('utf-8')
            if (len(body)>item['max_bytes'] or record['bytes']!=len(body) or type(record['bytes']) is not int
                    or record['sha256']!=hashlib.sha256(body).hexdigest() or record['media_type']!=item['media_type']
                    or self.redactor.contains(body) or private.contains(body)):raise ServiceError()
            total+=len(body)
            if total>2*1024*1024:raise ServiceError()
            path=directory/str(i);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
            with os.fdopen(fd,'wb') as output:output.write(body);output.flush();os.fsync(output.fileno())
            self._sealed_inputs[key]={k:v for k,v in record.items() if k in ('sha256','bytes','media_type')}
            self._sealed_inputs[key]['path']=str(path)

    def __repr__(self):
        return '<ApplicationService private authority withheld>'

    def _verify_effect(self, grant, scope, native_id, name, arguments):
        self._require_active(scope)
        return self._router.verify_effect(grant, scope, native_id, name, arguments)

    def _require_active(self, scope):
        if self._quarantined or self._active is None or scope != self._active['scope'] or self._active['revoked']:
            raise ServiceError()

    def authorize(self, bearer, scope, operation_id=None):
        result = super().authorize(bearer, scope, operation_id)
        if operation_id is not None: self._require_active(scope)
        return result

    def _parent(self, bearer):
        valid = type(bearer) is str and len(bearer)==64 and all(ch in '0123456789abcdef' for ch in bearer)
        if not valid or not secrets.compare_digest(bearer, self._control_token): raise ServiceError()

    def _close_stage_adapters(self):
        try:
            if self._browser is not None:
                self._browser.close(); self._browser = None
        finally:
            if self.files is not None:
                self.files.close(); self.files = None

    def _terminal_failure(self):
        self._quarantined = True
        if self._active is not None:self._active['revoked'] = True
        self._active = None;self._router = None
        try:self._close_stage_adapters()
        except Exception:pass  # Parent still receives failure; never authorizes cleanup.

    def _open_stage_adapters(self, stage):
        from application_files import ApplicationFiles
        self.files = (self._files_factory or ApplicationFiles)(self, self.outputs_root,
            sealed_inputs=self._sealed_inputs, budget_verifier=self._verify_effect,
            forbidden_values=tuple(self._issued))
        if stage['browser_targets']:
            from application_browser import BrowserClient
            self._browser = (self._browser_factory or BrowserClient)(self.api, self._browser_admission)

    def _activate(self, body):
        c.exact(body, {'schema','action','capability','remaining_seconds'}, '')
        if self._quarantined or self._active is not None: raise ServiceError()
        grant = self._lookup(token(body['capability'])); scope = grant['scope']
        if scope['stage_id'] in self._finished or scope['stage_id'] in self._ledgers: raise ServiceError()
        stage = validate_scope(scope, self.plan)
        remaining = body['remaining_seconds']
        if type(remaining) not in (int,float) or not 0 < remaining <= stage['limits']['timeout_seconds']:
            raise ServiceError('request_invalid')
        binding = {key: scope[key] for key in BINDING_FIELDS - {'pi_release'}}
        binding['pi_release'] = self.plan['runtime']['pi_release']
        ledger = BudgetLedger.create(self._state_root / (scope['stage_id']+'.json'),
            binding=binding, limits={key:stage['limits'][key] for key in
                ('max_tool_calls','reporting_reserve_calls','reporting_reserve_seconds')},
            native_tools=stage['tool_schemas'], initial_segment_id=scope['segment_id'],
            deadline=self.clock()+remaining, completion=stage['completion'], clock=self.clock)
        self._ledgers[scope['stage_id']] = ledger; self._segments[scope['stage_id']] = [scope['segment_id']]
        self._active = grant
        self._router = BudgetRouter(self, {self._budget_grants[c.digest(scope)]:{'scope':scope,'ledger':ledger}})
        try: self._open_stage_adapters(stage)
        except BaseException:
            self._terminal_failure()
            raise
        return {'schema':1,'ok':True,'budget':ledger.snapshot()}

    def _seal_outputs(self, stage):
        # Copies become helper-private immutable predecessor inputs. Missing output
        # is left missing for independent completion diagnostics; never synthesized.
        import hashlib
        source = open_directory(self.outputs_root)
        sealed = self._state_root / ('sealed-'+self._active['scope']['stage_id']); sealed.mkdir(mode=0o700)
        try:
            for artifact in stage['completion']['artifacts']:
                try: body=read_file(source, artifact['path'], artifact['max_bytes'])
                except FileNotFoundError: continue
                if self.redactor.contains(body): raise ServiceError('credential_scope_invalid')
                destination=sealed/artifact['id'];fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
                with os.fdopen(fd,'wb') as target:target.write(body);target.flush();os.fsync(target.fileno())
                key=(stage['id'],artifact['id'])
                if any(item['stage_id']==key[0] and item['artifact_id']==key[1]
                       for consumer in self.plan['stages'] for item in consumer['input_artifacts']):
                    self._sealed_inputs[key]={'path':str(destination),
                        'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),'media_type':artifact['media_type']}
        finally:os.close(source)

    def request(self, path, bearer, body):
        with self._lock:
            if path == '/ipc':
                result=super().request(path,bearer,body)
                result['business_effects_enabled']=self._active is not None and body['scope']==self._active['scope']
                result['native_budget_enabled']=self._active is not None
                return result
            if path == '/control':
                self._parent(bearer)
                if type(body) is not dict or type(body.get('schema')) is not int or body['schema']!=1:raise ServiceError('request_invalid')
                action=body.get('action')
                if action=='activate':return self._activate(body)
                if action=='revoke':
                    result=super().request(path,bearer,body)
                    if self._active is not None and secrets.compare_digest(self._active['token'],body['capability']):
                        try:self._close_stage_adapters()
                        except BaseException:self._terminal_failure();raise
                        self._active=None;self._router=None
                    return result
                if self._active is None:raise ServiceError()
                scope=self._active['scope'];ledger=self._ledgers[scope['stage_id']]
                if action in ('status','checkpoint','receipt_index'):
                    c.exact(body,{'schema','action'},'')
                    if action=='receipt_index':
                        return {'schema':1,'ok':True,'receipts':self.api.receipt_index(scope,allowed_segment_ids=self._segments[scope['stage_id']])}
                    result=ledger.snapshot() if action=='status' else ledger.checkpoint(scope)
                    return {'schema':1,'ok':True,'budget':result}
                if action=='finish':
                    c.exact(body,{'schema','action','writers_confirmed'},'')
                    if body['writers_confirmed'] is not True:raise ServiceError('cleanup_unconfirmed')
                    diagnostic=None
                    try:
                        from application_files import validate_file_diagnostic
                        value=getattr(self.files,'file_diagnostic',None)
                        if value is not None:diagnostic=validate_file_diagnostic(value)
                    except (KeyboardInterrupt,SystemExit,GeneratorExit,TimeoutError):
                        # Preserve control flow, revoke business and close stage
                        # adapters. The parent still performs owned helper cleanup.
                        try:self._terminal_failure()
                        except BaseException:pass
                        raise
                    except Exception:pass  # Invalid optional telemetry stays unknown.
                    try:
                        budget=ledger.checkpoint(scope)
                        stage=validate_scope(scope,self.plan)
                        self._active['revoked']=True;self._router=None
                        self._close_stage_adapters();self._seal_outputs(stage)
                        receipts=self.api.receipt_index(scope,allowed_segment_ids=self._segments[scope['stage_id']])
                        self._finished.add(scope['stage_id']);self._active=None
                    except BaseException:self._terminal_failure();raise
                    return {'schema':1,'ok':True,'budget':budget,'receipts':receipts,
                            **({'file_diagnostic':diagnostic} if diagnostic is not None else {})}
                if action=='extend':
                    c.exact(body,{'schema','action','max_tool_calls','remaining_seconds'},'')
                    remaining=body['remaining_seconds']
                    if remaining is not None and (type(remaining) not in (int,float) or not 0 < remaining <=3600):raise ServiceError('request_invalid')
                    return {'schema':1,'ok':True,'budget':ledger.extend(max_tool_calls=body['max_tool_calls'],
                        deadline=None if remaining is None else self.clock()+remaining,authorized=True)}
                if action=='continue':
                    c.exact(body,{'schema','action','scope','capability','budget_token'},'')
                    new_scope=copy.deepcopy(body['scope']);validate_scope(new_scope,self.plan)
                    if (len(self._grants)>=64 or new_scope['segment_id'] in self._segments[scope['stage_id']]
                            or {k:v for k,v in new_scope.items() if k!='segment_id'} !=
                               {k:v for k,v in scope.items() if k!='segment_id'}):raise ServiceError()
                    capability,budget_token=token(body['capability']),token(body['budget_token'])
                    if (capability==budget_token or capability in self._issued or budget_token in self._issued
                            or self.redactor.contains(c.canonical(body))):raise ServiceError()
                    try:
                        ledger.checkpoint(scope)
                        self._active['revoked']=True;self._router=None
                        self._close_stage_adapters()
                        ledger.add_segment(new_scope['segment_id'])
                        grant={'token':capability,'scope':new_scope,'revoked':False}
                        self._grants.append(grant);self._issued.update((capability,budget_token))
                        self._budget_grants[c.digest(new_scope)]=budget_token
                        self._segments[scope['stage_id']].append(new_scope['segment_id'])
                        self._active=grant
                        self._router=BudgetRouter(self,{budget_token:{'scope':new_scope,'ledger':ledger}})
                        self._open_stage_adapters(validate_scope(new_scope,self.plan))
                    except BaseException:
                        self._terminal_failure();raise
                    return {'schema':1,'ok':True,'budget':ledger.snapshot()}
                raise ServiceError('request_invalid')
            if path not in ('/tool','/budget'):raise ServiceError('request_invalid')
            if type(body) is not dict or 'scope' not in body:raise ServiceError('request_invalid')
            self._require_active(body['scope'])
            private_redactor=credentials.Redactor(self._issued)
            if path=='/budget':
                # Authenticate first, then screen participant-controlled metadata
                # before it can enter the durable ledger. Auth tokens themselves
                # belong to the HTTP envelope and are never ledger payloads.
                selected=self._router._authenticated(bearer,body['scope'])
                if private_redactor.contains(c.canonical(body.get('payload'))):
                    self._router._poison(selected)
                return {'schema':1,'ok':True,'result':self._router.request(bearer,body)}
            c.exact(body,{'schema','scope','native_call_id','tool_name','input','budget_grant'},'')
            c.choice(body['schema'],(1,),'/schema')
            self.authorize(bearer,body['scope'])
            if private_redactor.contains(c.canonical({'native_call_id':body['native_call_id'],'input':body['input']})):
                self._ledgers[body['scope']['stage_id']].poison(body['scope'])
                raise ServiceError('credential_scope_invalid')
            stage=validate_scope(body['scope'],self.plan);name=body['tool_name']
            if name not in stage['tools'] or name=='budget_status':raise ServiceError()
            args=(bearer,body['scope'],body['native_call_id'],body['input'],body['budget_grant'])
            if name=='app_api':result=self.api.execute(*args)
            elif name=='app_browser':
                if self._browser is None:raise ServiceError()
                result=self._browser.execute(*args)
            else:result=self.files.execute(bearer,body['scope'],body['native_call_id'],name,body['input'],body['budget_grant'])
            return {'schema':1,'ok':True,'result':private_redactor.value(result)}

    def close(self):
        with self._lock:
            for grant in self._grants:grant['revoked']=True
            self._close_stage_adapters();self.api.close();self._active=None;self._router=None
