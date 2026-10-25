"""Pure indexed variant selection admission from real frozen experiment artifacts.

The catalog/session fixtures use disposable keys; tested admission is the pure
binding view, with no broker, container, model, or application request.
"""
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_experiments as experiments
import application_preparation as preparation
import indexed_contract
import indexed_execution
from inference_catalog import Catalog
import pi_lab as lab
import test_application_experiments as experiment_fixture


def independent_selection(variant_id,entry):
    entry={key:value for key,value in entry.items() if key!='authority_id'}
    body=json.dumps({'variant_id':variant_id,'binding':entry},sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
    return {'owner':'experiment_variant','id':hashlib.sha256(body).hexdigest()}


class IndexedApplicationVariantTests(unittest.TestCase):
    def setUp(self):
        self.fixture=experiment_fixture.ApplicationExperimentTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.catalog=self.fixture.indexed();self.fixture.prepare(catalog=self.catalog,session='fixture-session')
        self.root=self.fixture.root/'prepared';self.metadata,self.matrix=experiments.verify(self.root,lab)
        self.cell=next(cell for cell in self.matrix['cells'] if cell['variant']=='candidate')
        self.compiled=preparation.load_compiled(self.root/self.cell['compiled_plan'])
        self.args=experiments.trial_args(self.root,self.metadata,self.cell,lab,'fixture-session')
        self.args._indexed_application=True;self.args._application_plan=copy.deepcopy(self.compiled['plan'])
        self.bindings=copy.deepcopy(self.args._indexed_bindings)

    def view(self,args=None,bindings=None):
        with mock.patch.object(socket,'socket',side_effect=AssertionError('No network in binding admission')),\
             mock.patch.object(subprocess,'Popen',side_effect=AssertionError('No child in binding admission')),\
             mock.patch.object(Catalog,'select',side_effect=AssertionError('Use frozen entry only')),\
             mock.patch.object(Catalog,'admit',side_effect=AssertionError('Pure binding view does not authorize session')):
            return indexed_execution.application_admission_view(args or self.args,lab,self.bindings if bindings is None else bindings)

    def rehash_plan(self,args):
        plan=args._application_plan;plan['plan_sha256']=c.digest({key:value for key,value in plan.items() if key!='plan_sha256'})

    def test_variant_context_recomputes_exact_selection_from_frozen_entry(self):
        before=copy.deepcopy((self.args._application_plan,self.bindings,self.args._application_variant_context))
        stage=self.args._application_plan['stages'][0];entry=self.bindings[stage['id']]
        self.assertEqual(stage['inference_binding']['selection'],independent_selection(self.cell['variant'],entry))
        self.assertNotEqual(stage['inference_binding']['selection']['id'],entry['id'])
        view,names=self.view()
        self.assertEqual(names,[stage['id']]);self.assertEqual(view['application_plan'],self.compiled['plan'])
        self.assertEqual((self.args._application_plan,self.bindings,self.args._application_variant_context),before)

    def test_missing_or_foreign_variant_context_rejects_even_with_same_configuration(self):
        for context in (None,{}, {'variant_id':'baseline'}, {'variant_id':self.bindings['participant']['id']}):
            args=copy.deepcopy(self.args);args._application_variant_context=context
            with self.subTest(context=context),self.assertRaises(indexed_contract.IndexedError):self.view(args)

    def test_catalog_label_or_digest_cannot_replace_variant_selection_identity(self):
        entry=self.bindings['participant']
        for identity in (entry['id'],entry['fingerprint'],c.digest(entry['configuration'])):
            args=copy.deepcopy(self.args);args._application_plan['stages'][0]['inference_binding']['selection']['id']=identity;self.rehash_plan(args)
            with self.subTest(identity=identity),self.assertRaises(indexed_contract.IndexedError):self.view(args)

    def test_same_configuration_under_different_immutable_entry_rejects(self):
        for field,value in [('id','other-environment'),('incarnation',str(uuid.uuid4())),('revision',2)]:
            bindings=copy.deepcopy(self.bindings);bindings['participant'][field]=value
            self.assertEqual(c.digest(bindings['participant']['configuration']),self.args._application_plan['stages'][0]['inference_binding']['configuration_sha256'])
            with self.subTest(field=field),self.assertRaises(indexed_contract.IndexedError):self.view(bindings=bindings)

    def test_session_authority_uuid_is_excluded_from_pure_immutable_selection(self):
        bindings=copy.deepcopy(self.bindings);bindings['participant']['authority_id']=str(uuid.uuid4())
        self.assertEqual(independent_selection(self.cell['variant'],bindings['participant']),
            self.args._application_plan['stages'][0]['inference_binding']['selection'])
        view,names=self.view(bindings=bindings)
        self.assertEqual(names,['participant']);self.assertEqual(view['application_plan'],self.compiled['plan'])
        # This is only structural admission. Actual Catalog.admit, tested elsewhere,
        # separately rejects an authority UUID without the current session receipt.
        with self.assertRaises(indexed_contract.IndexedError):self.catalog.admit(bindings['participant'],'fixture-session')


if __name__=='__main__':unittest.main()
