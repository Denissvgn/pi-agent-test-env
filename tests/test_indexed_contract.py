"""Offline indexed contracts; no model, Docker or actual credential reads."""
import copy
from pathlib import Path
import sys
import unittest
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import indexed_contract as contract


def normalize(raw):
    raw=copy.deepcopy(raw);raw.setdefault('host_base_url',raw['base_url']);return raw


def config():
    return {'api':contract.API,'adapter_contract':contract.ADAPTER,
        'endpoint':{'base_url':'http://synthetic.invalid/v1','model':'fixture-model','context_window':32768,'max_tokens':8192},
        'credential':{'source':'store','name':'SYNTHETIC_REFERENCE'},'capacity_group':'shared'}


class ContractTests(unittest.TestCase):
    def test_configuration_and_stored_identity_bind_source_and_routes(self):
        c=contract.configuration(config(),normalize)
        e={'id':'alpha','incarnation':str(uuid.uuid4()),'revision':1,'configuration':c,'fingerprint':contract.digest(c)}
        self.assertEqual(contract.entry(e,normalize),e)
        e['configuration']['credential']['source']='env'
        with self.assertRaises(contract.IndexedError):contract.entry(e,normalize)
    def test_unknown_api_keys_literal_credentials_and_unbounded_fields_reject(self):
        for field,value in [('api','anthropic-messages'),('adapter_contract','unknown'),('credential',{'source':'store','name':'SECRET','value':'synthetic-value'}),('capacity_group','../escape')]:
            bad=config();bad[field]=value
            with self.subTest(field=field),self.assertRaises(contract.IndexedError):contract.configuration(bad,normalize)
        for value in [True,0,33,601]:
            with self.subTest(value=value),self.assertRaises(contract.IndexedError):contract.limits({'queue_wait_seconds':value,'request_timeout_seconds':30})
    def test_none_does_not_allow_a_hidden_credential_reference(self):
        c=config();c['credential']={'source':'none'}
        self.assertEqual(contract.configuration(c,normalize)['endpoint']['api_key_env'],'PI_LAB_NOAUTH')
        c['credential']['name']='HIDDEN'
        with self.assertRaises(contract.IndexedError):contract.configuration(c,normalize)
    def test_stage_and_case_ownership_is_exhaustive(self):
        self.assertEqual(contract.stage_map({'implementer':'alpha','reviewer':'beta'},['implementer','reviewer']),{'implementer':'alpha','reviewer':'beta'})
        for mapping in ({'implementer':'alpha'},{'implementer':'alpha','reviewer':'beta','setup':'alpha'}):
            with self.assertRaises(contract.IndexedError):contract.stage_map(mapping,['implementer','reviewer'])
        with self.assertRaises(contract.IndexedError):contract.case_maps({'foreign':{'a':'alpha'}},{'case':['a']})
    def test_catalog_bounds_tombstones_and_default_integrity(self):
        c=contract.configuration(config(),normalize);e={'id':'alpha','incarnation':str(uuid.uuid4()),'revision':1,'configuration':c,'fingerprint':contract.digest(c)}
        document={'schema':1,'revision':1,'default_id':'alpha','entries':[e],'tombstones':[]}
        self.assertEqual(contract.catalog(document,normalize),document)
        for mutation in ('duplicate','default','tombstone','boolean'):
            bad=copy.deepcopy(document)
            if mutation=='duplicate':bad['entries'].append(copy.deepcopy(e))
            if mutation=='default':bad['default_id']='missing'
            if mutation=='tombstone':bad['tombstones']=[{k:e[k] for k in ('id','incarnation','revision')}]
            if mutation=='boolean':bad['revision']=True
            with self.subTest(mutation=mutation),self.assertRaises(contract.IndexedError):contract.catalog(bad,normalize)
    def test_stored_parameter_expansion_cannot_be_repeated(self):
        c=contract.configuration(config(),normalize);c['endpoint']['model']='${MUTABLE_MODEL}'
        e={'id':'alpha','incarnation':str(uuid.uuid4()),'revision':1,'configuration':c,'fingerprint':contract.digest(c)}
        with self.assertRaises(contract.IndexedError):contract.entry(e,normalize)
    def test_public_diagnostics_are_whitelisted_and_bounded(self):
        err=contract.IndexedError('unknown synthetic secret/url')
        self.assertEqual(err.reason,'catalog-invalid');self.assertNotIn('synthetic',str(err.public()))
    def test_route_preflight_uses_selected_deadlines(self):
        self.assertEqual(contract.preflight({'queue_wait_seconds':180,'request_timeout_seconds':180}),{'request_timeout_seconds':360,'container_timeout_seconds':390})

    def test_profile_strings_and_context_are_bounded_before_storage(self):
        for field,value in (('model','m'*513),('base_url','http://'+('a'*4096)+'.invalid/v1'),('context_window',2**31)):
            raw=config();raw['endpoint'][field]=value
            with self.subTest(field=field),self.assertRaises(contract.IndexedError):contract.configuration(raw,normalize)
        raw=config();raw['credential']['name']='A'*129
        with self.assertRaises(contract.IndexedError):contract.configuration(raw,normalize)


if __name__=='__main__':unittest.main()
