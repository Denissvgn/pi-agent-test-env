"""Reviewed execution opt-in on the credential-withholding authority.

The inherited authority-only path remains inert. This type binds bundled profile
bytes and distinct stage budget capabilities before any helper launch.
"""
import copy
from pathlib import Path
import secrets

import agent_profiles
import application_contracts as c
from application_client import Authority, ClientError
import application_client_service as service
import prompt_contract


class ReviewedAuthority(Authority):
    def __init__(self, *args, browser_admission=None, sealed_inputs=None, redaction_values=(), runner_files=None, **kwargs):
        super().__init__(*args, **kwargs)
        if type(redaction_values) not in (list,tuple) or len(redaction_values)>1024:raise ClientError('credential_scope_invalid')
        for value in redaction_values:c.text(value,'/redaction_values',16384)
        self._execution_redaction_values=list(dict.fromkeys(value for value in
            [*self._inference_values,*redaction_values] if value))
        c.array(self._execution_redaction_values,'/redaction_values',1024)
        if self.redactor().contains(c.canonical(self._plan)):raise ClientError('credential_scope_invalid')
        self._runner_files=copy.deepcopy(runner_files)
        if runner_files is not None:
            import provenance
            if type(runner_files) is not dict or provenance.digest(runner_files)!=self._plan['input_hashes']['runner']:
                raise ClientError('authority_changed')
            for path,digest in runner_files.items():c.relative(path,'/runner_files');c.sha256(digest,'/runner_files')
        self._budget_tokens = {}
        self._grant_digests = {}
        self._browser_admission = copy.deepcopy(browser_admission)
        self._sealed_inputs = []
        declared={(s['id'],a['id']):a for s in self._plan['stages'] for a in s['completion']['artifacts']}
        incoming={(a['stage_id'],a['artifact_id']) for s in self._plan['stages'] for a in s['input_artifacts']}
        if sealed_inputs is None:sealed_inputs={}
        if type(sealed_inputs) is not dict or set(sealed_inputs)-incoming:raise ClientError('authority_changed')
        for key,body in sorted(sealed_inputs.items()):
            if key not in declared or type(body) is not bytes or len(body)>declared[key]['max_bytes']:
                raise ClientError('authority_changed')
            try:content=body.decode('utf-8')
            except UnicodeError:raise ClientError('authority_changed') from None
            if self.redactor().contains(body):raise ClientError('credential_scope_invalid')
            self._sealed_inputs.append({'stage_id':key[0],'artifact_id':key[1],
                'content':content,'sha256':__import__('hashlib').sha256(body).hexdigest(),
                'bytes':len(body),'media_type':declared[key]['media_type']})
        if sum(item['bytes'] for item in self._sealed_inputs)>2*1024*1024:
            raise ClientError('authority_changed')
        release = self._plan['runtime']['pi_release']
        profile = agent_profiles.application(release)
        expected = {'id':'application-client','pi_release':release,
                    'sha256':agent_profiles.identity(profile),
                    'assets':{asset['target']:asset['sha256'] for asset in profile['assets']}}
        if any(stage['profile_binding'] != expected for stage in self._plan['stages']):
            raise ClientError('runtime_mismatch')
        if self._plan['runtime']['container_profile']=='browser':
            from application_browser import BrowserError, _admission, unsupported_browser_assets
            try:_admission(self._plan, browser_admission)
            except BrowserError:raise ClientError('runtime_mismatch') from None
            if any(unsupported_browser_assets(self._plan, s['id']) for s in self._plan['stages']):
                raise ClientError('runtime_mismatch')
        elif browser_admission is not None:
            raise ClientError('runtime_mismatch')
        self._admitted_identity = self._authority_identity()

    def _authority_identity(self):
        return c.digest({'plan':self._plan,'browser_admission':self._browser_admission,
                         'generation':self._generation,'control_token':self._control_token,
                         'sealed_inputs':self._sealed_inputs,'redaction_values':self._execution_redaction_values,
                         'runner_files':self._runner_files})

    def redactor(self):
        import application_credentials
        return application_credentials.Redactor([*self._inference_values,
            *(value for aliases in self._values.values() for value in aliases.values()),
            *getattr(self,'_execution_redaction_values',())])

    def revalidate(self):
        # Recheck immutable prepared authority before the first image probe and
        # again before the bootstrap is handed to the helper.
        if self._authority_identity() != self._admitted_identity:
            raise ClientError('authority_changed')
        if (set(self._budget_tokens) != {g.capability for g in self._grants}
                or any(self._grant_digests.get(g.capability) != c.digest({'scope':g.scope,
                       'budget_token':self._budget_tokens[g.capability]}) for g in self._grants)):
            raise ClientError('authority_changed')
        c.validate_ir(self._plan)
        profile=agent_profiles.application(self._plan['runtime']['pi_release'])
        expected={'id':'application-client','pi_release':self._plan['runtime']['pi_release'],
                  'sha256':agent_profiles.identity(profile),
                  'assets':{a['target']:a['sha256'] for a in profile['assets']}}
        if any(stage['profile_binding']!=expected for stage in self._plan['stages']):
            raise ClientError('authority_changed')
        if self._runner_files is not None:
            from application_client import PACKAGE_ROOT,TRUSTED_CODE
            import hashlib
            for relative in TRUSTED_CODE:
                body=agent_profiles.read_asset(PACKAGE_ROOT/relative)
                if hashlib.sha256(body).hexdigest()!=self._runner_files.get(relative):raise ClientError('authority_changed')
        return super().revalidate()

    def verify_code_identity(self,identity):
        from application_client import TRUSTED_CODE
        if self._runner_files is None or identity!={path:self._runner_files.get(path) for path in TRUSTED_CODE}:
            raise ClientError('authority_changed')

    def preflight_bootstrap(self):
        from application_client import PACKAGE_ROOT, TRUSTED_CODE
        import hashlib
        identity={name:hashlib.sha256(agent_profiles.read_asset(PACKAGE_ROOT/name)).hexdigest()
                  for name in TRUSTED_CODE}
        self.verify_code_identity(identity)
        self._bootstrap('/pi-client/evidence',identity,state_root='/pi-client/state')

    def grant(self, stage_name, binding):
        grant = super().grant(stage_name, binding)
        issued = {self._control_token, *(g.capability for g in self._grants), *self._budget_tokens.values()}
        value = secrets.token_hex(32)
        while value in issued: value=secrets.token_hex(32)
        self._budget_tokens[grant.capability] = value
        self._grant_digests[grant.capability] = c.digest({'scope':grant.scope,'budget_token':value})
        return grant

    def launch_spec(self):
        result = super().launch_spec();result['mode']='application-execution'
        return result

    def _bootstrap(self, evidence_root, code_identity, mode='application-execution', state_root=None):
        if mode!='application-execution' or not state_root:raise ClientError('runtime_mismatch')
        base=c.loads(super()._bootstrap(evidence_root,code_identity,mode='authority-only'))
        required={(item['stage_id'],item['artifact_id']) for g in self._grants
                  for s in self._plan['stages'] if s['id']==g.scope['stage_name'] for item in s['input_artifacts']}
        provided={(item['stage_id'],item['artifact_id']) for item in self._sealed_inputs}
        if not required<=provided:raise ClientError('authority_changed')
        result={'schema':1,'document_type':'application_execution_private_bootstrap',
                'mode':mode,'authority':base,'state_root':str(state_root),
                'outputs_root':str(Path(evidence_root)/'outputs'),
                'budget_grants':[{'token':self._budget_tokens[g.capability],'scope':copy.deepcopy(g.scope)} for g in self._grants],
                'browser_admission':self._browser_admission,
                'redaction_values':self._execution_redaction_values,
                'sealed_inputs':[copy.deepcopy(item) for item in self._sealed_inputs
                                 if (item['stage_id'],item['artifact_id']) in required]}
        body=c.canonical(result)
        if len(body)>service.MAX_CONFIG_BYTES:raise ClientError('credential_scope_invalid')
        return body

    def application_context(self, grant, extension_order_sha256):
        self.revalidate()
        if grant not in self._grants or grant.capability in self._revoked:raise ClientError('operation_not_granted')
        c.sha256(extension_order_sha256,'/extension_order_sha256')
        stage=next(s for s in self._plan['stages'] if s['id']==grant.scope['stage_name'])
        schemas=prompt_contract.tool_schemas(stage)
        budget={'schema':1,'pi_release':self._plan['runtime']['pi_release'],
                'scope':copy.deepcopy(grant.scope),'allowed_tools':list(stage['tools']),
                'prepare_arguments':{name:'none' for name in stage['tools']},
                'extension_order_sha256':extension_order_sha256,
                'tool_schema_sha256':c.digest(sorted(schemas,key=lambda t:t['name'])),
                'base_url':'http://pi-application:8081/budget','capability':self._budget_tokens[grant.capability]}
        return {'schema':1,'scope':copy.deepcopy(grant.scope),'capability':grant.capability,
                'base_url':'http://pi-application:8081/tool','tool_schemas':schemas,'budget_context':budget}
