"""Parent-only preparation for explicitly budgeted builtin/fixture stages.

This reuses the owned helper lifecycle. It grants no application operations and
does not reinterpret or add limits to an unbudgeted legacy task.
"""
import copy
from pathlib import Path
import secrets

import application_contracts as c
import application_credentials as credentials
from application_client import ClientError, Grant, _binding
import native_budget_controls
import resources


class NativeBudgetAuthority:
    def __init__(self, *, runtime, task, plan_sha256, project, runroot, profile='builtin', redaction_values=()):
        import native_tool_contracts
        self.runtime = copy.deepcopy(runtime)
        c.exact(self.runtime, {'pi_release', 'image_id', 'platform', 'container_profile', 'resources'}, '/runtime')
        c.choice(self.runtime['pi_release'], c.RELEASES, '/runtime/pi_release')
        c.choice(self.runtime['platform'], ('linux/arm64',), '/runtime/platform')
        c.choice(self.runtime['container_profile'], ('core', 'browser'), '/runtime/container_profile')
        if type(self.runtime['image_id']) is not str or not self.runtime['image_id'].startswith('sha256:'):
            raise ClientError('runtime_mismatch')
        c.sha256(self.runtime['image_id'][7:], '/runtime/image_id')
        self.runtime['resources'] = resources.validate_policy(self.runtime['resources'])
        c.sha256(plan_sha256, '/plan_sha256'); self.plan_sha256 = plan_sha256
        self.task, self.profile = copy.deepcopy(task), profile
        c.choice(profile, ('builtin', 'fixture-lookup'), '/profile')
        self.limits = native_budget_controls.native_limits({key: task[key] for key in
            ('max_tool_calls', 'reporting_reserve_calls', 'reporting_reserve_seconds') if key in task},
            timeout_seconds=task['timeout_seconds'], required=True)
        if 'budget_status' not in task['tools']:
            raise ClientError('runtime_mismatch')
        self.tools = native_tool_contracts.selected_tools(self.runtime['pi_release'], task['tools'])
        self.preparation = native_tool_contracts.prepare_arguments(self.runtime['pi_release'], task['tools'])
        if ('fixture_lookup' in task['tools']) != (profile == 'fixture-lookup'):
            raise ClientError('runtime_mismatch')
        self.project, self.runroot = Path(project).resolve(), Path(runroot).resolve()
        if (self.project == self.runroot or self.project in self.runroot.parents or self.runroot in self.project.parents):
            raise ClientError('credential_scope_invalid')
        if type(redaction_values) not in (list, tuple) or len(redaction_values) > 1024:
            raise ClientError('credential_scope_invalid')
        for value in redaction_values:
            c.text(value, '/redaction_values', 16384, empty=True)
        self._values = tuple(dict.fromkeys(value for value in redaction_values if value))
        if credentials.Redactor(self._values).contains(c.canonical({'runtime':self.runtime,'task':self.task,'profile':profile})):
            raise ClientError('credential_scope_invalid')
        self._control_token = secrets.token_hex(32)
        self._grants, self._revoked, self._budget_tokens = [], set(), {}
        self._grant_digests = {}
        self._launched = False
        self._frozen = c.digest({'runtime': self.runtime, 'task': self.task, 'tools': self.tools,
                                 'preparation': self.preparation, 'limits': self.limits, 'profile': profile})

    def __repr__(self):
        return '<NativeBudgetAuthority private capabilities withheld>'

    def launch_spec(self):
        return {'runtime': copy.deepcopy(self.runtime), 'plan_sha256': self.plan_sha256,
                'mode': 'budget-only', 'browser': False, 'actors': []}

    def revalidate(self):
        import native_tool_contracts
        current = {'runtime': self.runtime, 'task': self.task,
                   'tools': self.tools, 'preparation': self.preparation,
                   'limits': self.limits, 'profile': self.profile}
        if (c.digest(current) != self._frozen
                or self.tools != native_tool_contracts.selected_tools(self.runtime['pi_release'], self.task['tools'])
                or self.preparation != native_tool_contracts.prepare_arguments(self.runtime['pi_release'], self.task['tools'])):
            raise ClientError('authority_changed')
        if any(self._grant_digests.get(grant.capability) != c.digest(grant.scope) for grant in self._grants):
            raise ClientError('authority_changed')

    def ensure_snapshot_clean(self):
        workspace = self.runroot / 'workspace'
        if (workspace.is_symlink() or not workspace.is_dir()
                or not credentials.workspace_inspected_clean(workspace, self.redactor())):
            raise ClientError('credential_scope_invalid')

    def redactor(self):
        return credentials.Redactor([*self._values, self._control_token,
                                     *(grant.capability for grant in self._grants), *self._budget_tokens.values()])

    def grant(self, stage_name, binding):
        if self._launched or self._grants or stage_name != self.task['name']:
            raise ClientError('operation_not_granted')
        _binding(binding, self.plan_sha256)
        scope = {**copy.deepcopy(binding), 'stage_name': stage_name, 'pi_release': self.runtime['pi_release']}
        if credentials.Redactor(self._values).contains(c.canonical(scope)):
            raise ClientError('credential_scope_invalid')
        grant = Grant(scope, secrets.token_hex(32)); self._grants.append(grant)
        self._grant_digests[grant.capability] = c.digest(scope)
        self._budget_tokens[scope['segment_id']] = secrets.token_hex(32)
        return grant

    def budget_context(self, grant, extension_order_sha256):
        self.revalidate()
        if grant not in self._grants or grant.capability in self._revoked:
            raise ClientError('operation_not_granted')
        c.sha256(extension_order_sha256, '/extension_order_sha256')
        return {'schema': 1, 'pi_release': self.runtime['pi_release'], 'scope': copy.deepcopy(grant.scope),
                'allowed_tools': [tool['name'] for tool in self.tools],
                'prepare_arguments': copy.deepcopy(self.preparation), 'extension_order_sha256': extension_order_sha256,
                'tool_schema_sha256': c.digest(sorted(self.tools, key=lambda tool: tool['name'])),
                'base_url': 'http://pi-application:8081/budget',
                'capability': self._budget_tokens[grant.scope['segment_id']]}

    def _bootstrap(self, evidence_root, code_identity, mode='budget-only', state_root=None):
        if mode != 'budget-only' or len(self._grants) != 1 or state_root is None:
            raise ClientError('operation_not_granted')
        self.revalidate(); grant = self._grants[0]
        body = c.canonical({'schema': 1, 'document_type': 'native_budget_private_bootstrap', 'mode': mode,
            'pi_release': self.runtime['pi_release'], 'control_token': self._control_token,
            'code_identity': copy.deepcopy(code_identity), 'state_root': str(state_root),
            'evidence_root': str(evidence_root), 'redaction_values': list(self._values),
            'stage': {'scope': copy.deepcopy(grant.scope), 'authority_token': grant.capability,
                'budget_token': self._budget_tokens[grant.scope['segment_id']], 'limits': self.limits,
                'tools': self.tools, 'prepare_arguments': self.preparation, 'profile': self.profile,
                'remaining_seconds': self.task['timeout_seconds']}})
        if len(body) > 2 * 1024 * 1024:
            raise ClientError('evidence_unavailable')
        return body
