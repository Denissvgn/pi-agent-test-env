"""Synthetic artifact-family replay through the actual isolated consumer worker."""
import copy
import os
from pathlib import Path
from unittest import TestCase, mock

from tests import test_application_owner_consumer_graph as graphs
from tests import test_application_owner_legacy_namespace as shapes
from tests.test_application_owner_legacy_support import AcceptanceFixture
import application_owner_legacy as legacy


def artifact_fixture(case):
    """Use inert fixed source fixtures, never a production catalog entry."""
    case.build = lambda name='case', **kw: AcceptanceFixture(
        case.root/name, registry_id=case.owner.registry_id, generation=case.owner.generation, **kw)
    case.artifact = lambda name='artifact': shapes.LegacyNamespaceTests.artifact(case, name)
    fixture = shapes.LegacyNamespaceTests.full_artifact(case)
    family = fixture.family()
    next(iter(family.values())).update(execution_rule='absolute_owned_host_paths_v1',
        public_source_roles=('producer','emitter','supervisor','probe','prior_validator'),
        readable_metadata_parent_roles=('inputs','source_binding','authority'))
    fixture.family = lambda: copy.deepcopy(family)
    return fixture


class ArtifactConsumerTests(TestCase):
    def setUp(self):
        text = os.environ.get('PI_SYNTHETIC_ARTIFACT_PROVIDER')
        if not text:self.skipTest('Requires the distinct read-only synthetic artifact catalog in Docker')
        self.holder=graphs.IsolatedGraphTests('test_complete_standard_graph_replays_in_a_fresh_readonly_provider')
        self.holder.setUp(); self.addCleanup(self.holder.doCleanups)
        self.holder.provider=Path(text)
        case=self.holder.case; case.fixture=artifact_fixture(case); case.owner.write(case.fixture.record)
        self.catalog=mock.patch.dict(legacy.SOURCE_FAMILIES,case.fixture.family(),clear=True)
        self.catalog.start(); self.addCleanup(self.catalog.stop)
        # The real producer separates its readable source directory from private
        # proof inputs. Model that topology rather than weakening other grants.
        keep={'controller-driver.py','supervisor.py','emission_source.py',
              'probe.py','prior.py','emission-inputs.json','source-bindings.json','legacy-evidence.json'}
        fixture=case.fixture
        for name, ref in list(fixture.refs.items()):
            path=Path(ref['path'])
            if path.parent==fixture.originals and name not in keep:
                new=fixture.put_retained(name,fixture.root/'private-inputs'/name,fixture.body(name))
                fixture._rebind(ref,new)
        commitment=shapes.digest(fixture.body('runtime-manifest.json'))
        fixture.rewrite('ledger.json',lambda body:body.update(manifest_sha256=commitment))
        fixture.rewrite('claim.json',lambda body:body.update(manifest_sha256=commitment))
        fixture.rewrite('supervisor-stdout.json',lambda body:body.update(terminal=fixture.refs['diagnostic-terminal.json']))
        fixture.put_retained('legacy-evidence.json',fixture.root/'private-inputs/legacy-evidence.json',fixture.envelope)
        self.terminal=case.graph()
        # Match the legitimate installed family: private metadata with readable
        # parents, plus a later nonsensitive tool observation. Never chmod originals.
        for name in ('emission-inputs.json','source-bindings.json'):
            Path(case.fixture.refs[name]['path']).parent.chmod(0o755)
        self.observer=Path(case.fixture.refs['tool-terminal.json']['path'])
        self.observer.chmod(0o644)
        self.value=self.holder.approval(self.terminal)
        readable={case.fixture.refs[name]['path'] for name in ('emission-inputs.json','source-bindings.json')}
        sources={case.fixture.refs[name]['path'] for name in ('controller-driver.py','supervisor.py','probe.py','prior.py')}
        for row in self.value['read_scope']['files']:
            if row['path'] in readable:row['private_parent']=False
            if row['path'] in sources:row.update(role='source',private=False,private_parent=False)
            if row['path']==str(self.observer):
                row.update(role='artifact_tool_observation',private=False,maximum_bytes=16384)
        self.value['read_scope']['files'].sort(key=lambda row:(row['path'],row['role']))

    def test_complete_artifact_graph_preserves_readable_source_metadata_classification(self):
        result=self.holder.reader(self.value).evaluate('replay')
        self.assertEqual((result['decision'],result['condition']),('proof_accepted','replayed'),result)
        self.assertTrue(result['history_read']);self.assertFalse(result['admission_authorized'])

    def test_blanket_private_parent_is_a_real_refusal(self):
        value=copy.deepcopy(self.value)
        for row in value['read_scope']['files']:
            if Path(row['path']).name in ('emission-inputs.json','source-bindings.json'):
                row['private_parent']=True
        result=self.holder.reader(value).evaluate('replay')
        self.assertEqual(result['decision'],'invalid_proof')

    def test_public_observer_never_allows_foreign_writes_or_missing_read_grant(self):
        self.observer.chmod(0o666)
        self.assertEqual(self.holder.reader(self.value).evaluate('replay')['decision'],'invalid_proof')
        self.observer.chmod(0o644)
        value=copy.deepcopy(self.value)
        value['read_scope']['files']=[r for r in value['read_scope']['files']if r['path']!=str(self.observer)]
        self.assertEqual(self.holder.reader(value).evaluate('replay')['decision'],'invalid_proof')
