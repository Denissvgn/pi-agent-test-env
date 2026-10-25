"""Offline-only compiler preparation for one explicitly controlled settlement case.

There is no execute/server/admission backend in this module. A compiled artifact
never opens a fresh clock, bypasses the original ownership gate, or resumes a
failed qualification. Scripted responses are synthetic, not real model evidence.
"""
import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit

REPO=Path(__file__).resolve().parents[2]
SKILL=REPO/'skill'
EXAMPLE=SKILL/'examples/authenticated-application'
sys.path[:0]=[str(SKILL/'scripts'),str(SKILL/'runtime')]
import application_contracts as c
import application_preparation as preparation
import application_scripted as scripted

MODEL='application-settlement-script-0.87.1'
SCRIPT_KEY_REFERENCE='PI_SETTLEMENT_SCRIPT_KEY'
PARTICIPANT={'application_id':'diagnostic-app','tenant_id':'team-1','actor_id':'actor-alice','role':'participant'}
IMAGE_IDS={'core':'sha256:a622aa853e0203b6768411c21dbc3d79b76b40c239fffef1aaaa1b095231e8ec',
 'browser':'sha256:1cfc7604742b05ef213564d290e887fed7f342ab6e4bf967f2177963091d20f0'}
NORMAL_LOCK='/home/piqual/.local/state/pi-agent-test-env/operation.lock'
PRESERVED_SCOPE='/home/piqual/a15-qualification-062'
CURRENT_USE={'containers':501,'participants':42}
PLAN_MAX={'containers':7,'participants':1}
POST_MAX={'containers':508,'participants':43}
CAPS={'containers':537,'participants':47}
LIVE={'containers':4,'active_trials':1,'inference_slots':1}
LIMITS={'timeout_seconds':180,'max_turns':8,'max_total_tokens':16000,'max_tool_calls':16,
        'reporting_reserve_calls':6,'reporting_reserve_seconds':30}
ROLES=('fixture','probe','boundary','preflight','application-helper','participant','scorer')
CALLS=('app_api','app_browser','app_browser','app_browser','artifact_write','report_write')
REQUIRED_TOOLS=('app_api','app_browser','artifact_read','artifact_write','report_write','budget_status')
SETTLEMENT_CODES=frozenset(('UNKNOWN','WRITERS_UNCONFIRMED','FINISH_ALREADY_ATTEMPTED','FINISH_RPC_FAILED',
 'FINISH_DIAGNOSTIC_FAILED','FINISH_BUDGET_INVALID','RECEIPT_INDEX_INVALID','RECEIPT_REDACTION_REJECTED',
 'COMPLETION_BINDING_INVALID','REDACTION_STATE_FAILED','HELPER_CLEANUP_FAILED','STARTUP_CLEANUP_UNCONFIRMED',
 'FINISH_UNCONFIRMED','HELPER_RECEIPT_INVALID','CONTEXT_UNCONFIRMED','CONTEXT_PURGE_FAILED'))
UNRESOLVED='controlled_diagnostic_partial_pagination_no_publication'
CONTROLLED_PROMPT='One controlled scripted cleanup diagnostic. Execute only the six frozen explicit tool calls from the scripted provider. The partial report is intentional, no publication or repair. Settle once; this is not model qualification.'
TASK_BYTES=b'Controlled settlement diagnostic only. Intentional partial artifact/report; no native acceptance credit.\n'


class DiagnosticError(ValueError):
    def __init__(self):super().__init__('Controlled settlement preparation refused')


def need(value):
    if not value:raise DiagnosticError()


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


def settlement_projection(value):
    """Consume only the exact approved closed process field; never error text."""
    if (type(value)is dict and set(value)=={'schema','code'}and type(value['schema'])is int and value['schema']==1
            and type(value['code'])is str and value['code']in SETTLEMENT_CODES):return dict(value)
    return {'schema':1,'code':'UNKNOWN'}


def endpoint(value):
    need(type(value)is dict and set(value)=={'base_url','model','api_key_env','context_window','max_tokens','input','reasoning'})
    need(value['model']==MODEL and value['api_key_env']==SCRIPT_KEY_REFERENCE
      and type(value['context_window'])is int and value['context_window']==262144
      and type(value['max_tokens'])is int and value['max_tokens']==8192
      and value['input']==['text']and canonical(value['reasoning'])==canonical({'enabled':False}))
    parsed=urlsplit(value['base_url'])
    need(parsed.scheme=='http'and parsed.path=='/v1'and not parsed.query and not parsed.fragment
      and parsed.username is None and parsed.password is None and parsed.hostname is not None)
    try:address=ipaddress.ip_address(parsed.hostname);port=parsed.port
    except ValueError:raise DiagnosticError() from None
    need(address.version==4 and address.is_private and not address.is_loopback and not address.is_unspecified
      and type(port)is int and 1024<=port<=65535
      and value['base_url']=='http://172.17.0.1:19081/v1')
    return copy.deepcopy(value)


def route(value):
    need(type(value)is dict and set(value)=={'origin','allowed_addresses'})
    parsed=urlsplit(value['origin'])
    need(parsed.scheme=='http'and parsed.path==''and not parsed.query and not parsed.fragment
      and parsed.username is None and parsed.password is None and type(parsed.port)is int and 1024<=parsed.port<=65535)
    addresses=value['allowed_addresses'];need(type(addresses)is list and len(addresses)==1)
    try:address=ipaddress.ip_address(addresses[0])
    except ValueError:raise DiagnosticError() from None
    need(address.version==4 and address.is_private and not address.is_loopback and not address.is_unspecified
      and parsed.hostname==str(address)and value['origin']=='http://'+str(address)+':'+str(parsed.port))
    return copy.deepcopy(value)


def contract(inference,fixture,credential_reference='CONTROLLED_ACTOR_REFERENCE'):
    inference=endpoint(inference);fixture=route(fixture)
    need(type(credential_reference)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,127}',credential_reference)is not None
      and credential_reference!=SCRIPT_KEY_REFERENCE)
    need(inference['base_url'].rsplit('/v1',1)[0]!=fixture['origin'])
    return {'schema':1,'document_type':'controlled_settlement_diagnostic_contract','status':'DISABLED_PREPARATION_ONLY',
      'case_id':'controlled-browser-artifact-settlement-0.87.1','pi_release':'0.87.1','platform':'linux/arm64',
      'actor_credential_reference':credential_reference,
      'inference':{'kind':'SCRIPTED_PARENT_HTTP','configuration':inference,'synthetic_usage':dict(scripted.WIRE_USAGE),
        'usage_accounting':'synthetic_fixed_16_16','real_model_calls':0,'bind_only_reviewed_guest_bridge_address':True,
        'fresh_owned_returned_process_handle_required':True,'max_lifetime_seconds':900,'port_kill_or_rebind_retry':False},
      'fixture':fixture,'image_ids':dict(IMAGE_IDS),'roles_upper_bounds':dict.fromkeys(ROLES,1),
      'resource_limits':dict(LIVE),'stage_limits':dict(LIMITS),'overall_seconds':900,'cleanup_reserve_seconds':30,
      'max_primary_attempts':1,'max_tool_calls_planned':6,'max_assistant_responses_planned':7,
      'native_tool_sequence':list(CALLS),'reported_tokens_are_synthetic':True,
      'current_charged':dict(CURRENT_USE),'additional_upper_bound':dict(PLAN_MAX),'cumulative_upper_bound':dict(POST_MAX),
      'current_caps':dict(CAPS),'automatic_retries':0,'continuations':0,'report_repair':False,'fallback':False,
      'task_oracle':{'partial_first_page_only':True,'publication_attempts':0,'expected_completion':'incomplete',
        'expected_task_verdict':'FAIL_OR_NOT_EVALUATED','original_scorer_and_check_retained':True,
        'scorer_may_be_skipped_by_original_SDK':True,'all_seven_roles_required_to_launch':False,
        'task_failure_is_distinct_from_settlement_diagnostic':True,'native_qualification_credit':False},
      'prerequisites':{'fresh_specific_grant':'REQUIRED_NOT_CREATED','exact_qualified_source_candidate':'REQUIRED_NOT_BOUND',
        'reviewed_execution_backend':'REQUIRED_EXTERNAL_CONTROLLER_BINDING','original_ownership_gate':'REQUIRED_UNRESOLVED',
        'scripted_endpoint_is_reviewed_guest_bridge':'REQUIRED_UNPROVEN',
        'normal_lock_file':NORMAL_LOCK,'override_or_alternate_registry_namespace':False,
        'preserve_failed_scope':PRESERVED_SCOPE,'preserve_poison_and_four_private_flags':True},
      'automatic_evidence_contract':{'parent_process_field':'application_settlement_failure',
        'field_schema':1,'code_enum':sorted(SETTLEMENT_CODES),'unclassified_failure':'UNKNOWN',
        'parent_and_terminal_code_capture_included_in_future_grant':True,
        'relative_metadata_roles':['result.json','summary.json_IF_RESULT_ABSENT','agent-1-participant/process.json',
          'child-completion.json','services-cleanup.json','phase-terminal.json','launch-ledger/ledger.json','state.json'],
        'path_binding':'Single fresh primary run/attempt + exact parent phase, frozen before dispatch.',
        'raw_exception_args_paths_credentials_or_modeltext_exported':False,
        'new_private_read_request_after_failure_required':False},
      'activation_created':False,'dispatch_ready':False,'native_dispatch_supported_by_this_module':False}


class SettlementScript:
    """Pure seven-response conversation; no service constructor or tool dispatch."""
    def __init__(self):
        self.sent={};self.results={};self.pending=None;self.step=0;self.finished=False
        self.identity_succeeded=False;self.unexpected_results=0;self.page_receipt=None;self.content=None;self.artifact=None
    def __repr__(self):return '<ControlledSettlementScript payloads withheld>'
    def _call(self,name,args):
        need(len(self.sent)<6 and name==CALLS[len(self.sent)])
        identifier='settlement-call-'+str(len(self.sent)+1)
        call={'id':identifier,'name':name,'arguments':copy.deepcopy(args)};self.sent[identifier]=call;self.pending=identifier
        return call
    def _accept(self,messages):
        need(type(messages)is list and 1<=len(messages)<=128)
        seen=set()
        for message in messages:
            need(type(message)is dict and message.get('role')in('system','developer','user','assistant','tool'))
            if message['role']!='tool':continue
            ident=message.get('tool_call_id');need(type(ident)is str and ident in self.sent and ident not in seen);seen.add(ident)
            if 'name'in message:need(message['name']==self.sent[ident]['name'])
            value=scripted.parse_tool_result(message.get('content'))
            if ident in self.results:need(self.results[ident]==value)
            else:self.results[ident]=value
        need(set(self.results)==seen)
        if self.pending is None:need(not self.results);return None
        need(self.pending in self.results);value=self.results[self.pending];self.pending=None;return value
    def _snapshot_content(self,value):
        need(value.get('ok')is True and type(value.get('dom'))is str and len(value['dom'].encode())<=262144)
        dom=scripted.strict(value['dom'])
        need(type(dom)is dict and set(dom)=={'url','page_identity','html','form_state','text_content','inner_text'}
          and dom['page_identity']==['diagnostic-summary-v1']and type(dom['html'])is str)
        # Read only the exact fixture pre element, never script text or arbitrary
        # model-generated summary values. HTML entities decode through the parser.
        from html.parser import HTMLParser
        class Records(HTMLParser):
            def __init__(self):super().__init__(convert_charrefs=True);self.depth=0;self.parts=[];self.matches=0
            def handle_starttag(self,tag,attrs):
                if tag=='pre'and ('data-testid','records')in attrs:
                    need(self.depth==0);self.depth=1;self.matches+=1
                elif self.depth:self.depth+=1
            def handle_endtag(self,tag):
                if self.depth:self.depth-=1
            def handle_data(self,data):
                if self.depth:self.parts.append(data)
        parser=Records();parser.feed(dom['html']);parser.close();need(parser.matches==1 and parser.depth==0)
        page=scripted.strict(''.join(parser.parts));need(type(page)is dict and set(page)=={'items','next_cursor','snapshot_id'})
        items=page['items'];need(type(items)is list and len(items)==2 and [r.get('id')for r in items]==['r1','r2'])
        for item in items:
            need(type(item)is dict and set(item)=={'id','text'}and type(item['text'])is str and 1<=len(item['text'])<=512)
        need(type(page['next_cursor'])is str and re.fullmatch('[a-f0-9]{64}',page['next_cursor'])is not None)
        return '# Controlled settlement diagnostic\n\n'+''.join('- '+r['id']+': '+r['text']+'\n'for r in items)
    def respond(self,messages,available_tools):
        need(not self.finished and type(available_tools)in(set,list,tuple)and set(available_tools)==set(REQUIRED_TOOLS))
        value=self._accept(messages);calls=[]
        try:
            if self.step==0:
                calls=[self._call('app_api',scripted.api_input('identity'))]
            else:
                need(type(value)is dict and value.get('ok')is True)
                if self.step==1:
                    need(all(value.get(k)==v for k,v in PARTICIPANT.items()));scripted._receipt(value.get('receipt_id'))
                    self.identity_succeeded=True;calls=[self._call('app_browser',{'action':'navigate','target_id':'summary-page'})]
                elif self.step==2:calls=[self._call('app_browser',{'action':'click','target_id':'records-button'})]
                elif self.step==3:
                    ids=value.get('operation_receipt_ids');need(type(ids)is list and len(ids)==1);self.page_receipt=scripted._receipt(ids[0])
                    calls=[self._call('app_browser',{'action':'snapshot','target_id':'summary-page'})]
                elif self.step==4:
                    self.content=self._snapshot_content(value);calls=[self._call('artifact_write',{'artifact_id':'summary','content':self.content})]
                elif self.step==5:
                    need(value.get('artifact_id')=='summary'and type(value.get('bytes'))is int
                      and value['bytes']==len(self.content.encode())and value.get('sha256')==hashlib.sha256(self.content.encode()).hexdigest())
                    self.artifact={'sha256':value['sha256'],'bytes':value['bytes']}
                    report={'schema':1,'document_type':'application_completion_report','contract_id':'participant-report',
                      'participant':dict(PARTICIPANT),'artifacts':[{'id':'summary','path':'outputs/summary.md',**self.artifact}],
                      'pagination':{'list-records':[self.page_receipt]},'publications':[],'unresolved':[UNRESOLVED]}
                    calls=[self._call('report_write',{'report':report})]
                else:self.finished=True
        except (ValueError,TypeError,KeyError,IndexError,AttributeError):
            self.unexpected_results+=1;self.finished=True;self.pending=None;calls=[]
        self.step+=1;need(self.step<=7)
        return {'calls':calls,'hold':False,'finished':self.finished,
          'text':'CONTROLLED_SETTLEMENT_DIAGNOSTIC_SETTLED'if self.finished else''}


def response_frames(decision,prompt_bytes=1):
    """Reuse the bounded existing synthetic SSE wire; never open HTTP here."""
    need(type(decision)is dict and set(decision)=={'calls','hold','finished','text'}and decision['hold']is False
      and type(decision['finished'])is bool and decision['text']==('CONTROLLED_SETTLEMENT_DIAGNOSTIC_SETTLED'if decision['finished']else''))
    need(type(decision['calls'])is list and len(decision['calls'])<=1)
    for call in decision['calls']:
        need(type(call)is dict and set(call)=={'id','name','arguments'}and type(call['id'])is str
          and re.fullmatch('settlement-call-[1-6]',call['id'])is not None
          and call['name']==CALLS[int(call['id'][-1])-1]and type(call['arguments'])is dict)
        c.safe_json(call['arguments'])
    return scripted.sse_frames(MODEL,decision,prompt_bytes)


def _configure_module():
    spec=importlib.util.spec_from_file_location('settlement_original_configure',EXAMPLE/'configure.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def controlled_source(browser_receipt_path,frozen):
    """Reconstruct the exact case from its current reviewed public producer."""
    configure=_configure_module();fixture=frozen['fixture']
    source=configure.source_for(browser_receipt_path,fixture['origin'],fixture['allowed_addresses'],frozen['actor_credential_reference'],'browser')
    need(source['runtime']['image_id']==IMAGE_IDS['browser']and source['runtime']['pi_release']=='0.87.1')
    source['stages'][0]['limits']=dict(LIMITS);source['stages'][0]['prompt']=CONTROLLED_PROMPT
    return c.validate_source(source)


def module_identity():
    return hashlib.sha256(preparation._read(Path(__file__),262144)).hexdigest()


def prepare(output,*,image_receipts,scripted_endpoint,fixture_route,credential_reference):
    """Offline original compilation only. Explicit public inputs; no saved config."""
    need(type(image_receipts)is dict and set(image_receipts)=={'core','browser'})
    inference=endpoint(preparation._json(scripted_endpoint));fixture=route(fixture_route)
    frozen=contract(inference,fixture,credential_reference);configure=_configure_module()
    source=controlled_source(image_receipts['browser'],frozen)
    core=configure.source_for(image_receipts['core'],fixture['origin'],fixture['allowed_addresses'],credential_reference,'api')
    need(source['runtime']['image_id']==IMAGE_IDS['browser']and core['runtime']['image_id']==IMAGE_IDS['core']
      and source['runtime']['pi_release']==core['runtime']['pi_release']=='0.87.1')
    need(len(source['checks'])==1)
    core_receipt=preparation._runtime(core,preparation._json(image_receipts['core']))
    output=Path(output).absolute();need(not output.exists()and not output.is_symlink())
    need(str(output)!=PRESERVED_SCOPE and Path(PRESERVED_SCOPE)not in output.parents and output not in Path(PRESERVED_SCOPE).parents)
    files={}
    with tempfile.TemporaryDirectory(prefix='controlled-settlement-compile-')as tmp:
        tmp=Path(tmp).resolve();spec_path=tmp/'source.json';spec_path.write_bytes(c.canonical(source))
        for name in ('content_scorer.py','expected.json'):
            body=preparation._read(EXAMPLE/name);(tmp/name).write_bytes(body);preparation._add(files,name,body)
        compiled=preparation.compile_artifact(spec_path,tmp/'compiled',image_receipts['browser'],endpoint_path=scripted_endpoint)
        need(compiled['plan']['stages'][0]['limits']==LIMITS and len(compiled['plan']['checks'])==1)
        for path in sorted((tmp/'compiled').rglob('*')):
            if path.is_file():preparation._add(files,'compiled/'+str(path.relative_to(tmp/'compiled')),preparation._read(path,4*1024*1024))
        for name,value in (('source.json',source),('CONTRACT.json',frozen),('core-runtime-receipt.json',core_receipt)):
            preparation._add(files,name,canonical(value))
        preparation._add(files,'project/TASK.md',TASK_BYTES)
        document={'schema':1,'document_type':'controlled_settlement_diagnostic_preparation','status':'DISABLED_PREPARED',
          'script_module_sha256':module_identity(),'compiled_plan_sha256':compiled['plan']['plan_sha256'],'contract_sha256':hashlib.sha256(canonical(frozen)).hexdigest(),
          'files':{name:hashlib.sha256(body).hexdigest()for name,body in files.items()},
          'activation_created':False,'dispatch_ready':False,'native_clock_created':False,'reservation_consumed':False,
          'prerequisites':copy.deepcopy(frozen['prerequisites'])}
        preparation._add(files,'PREPARATION.json',canonical(document));preparation._publish(output,files)
    verify(output);return document


def verify(root):
    root=Path(root).absolute();document=preparation._json(root/'PREPARATION.json')
    need(type(document)is dict and set(document)=={'schema','document_type','status','compiled_plan_sha256','contract_sha256',
      'files','activation_created','dispatch_ready','native_clock_created','reservation_consumed','prerequisites','script_module_sha256'}
      and type(document['files'])is dict and 1<=len(document['files'])<=1024)
    need(document['schema']==1 and type(document['schema'])is int
      and document['document_type']=='controlled_settlement_diagnostic_preparation'and document['status']=='DISABLED_PREPARED'
      and document['activation_created']is False and document['dispatch_ready']is False and document['native_clock_created']is False
      and document['reservation_consumed']is False and document['script_module_sha256']==module_identity())
    for name,sha in document['files'].items():
        c.relative(name,'');c.sha256(sha,'');need(hashlib.sha256(preparation._read(root/name,4*1024*1024)).hexdigest()==sha)
    frozen=preparation._json(root/'CONTRACT.json')
    need(canonical(frozen)==canonical(contract(frozen['inference']['configuration'],frozen['fixture'],frozen['actor_credential_reference'])))
    need(document['contract_sha256']==digest(frozen)and canonical(document['prerequisites'])==canonical(frozen['prerequisites']))
    bundle=preparation.load_compiled(root/'compiled/plan.json',verify_runner=True);compiled=bundle['plan']
    expected_names={'source.json','CONTRACT.json','core-runtime-receipt.json','project/TASK.md','content_scorer.py','expected.json',
      'compiled/input-manifest.json'}|{'compiled/'+name for name in bundle['manifest']['files']}
    need(set(document['files'])==expected_names)
    expected_source=controlled_source(root/'compiled/runtime-receipt.json',frozen)
    need(canonical(preparation._json(root/'source.json'))==canonical(expected_source)
      and canonical(preparation._json(root/'compiled/source.json'))==canonical(expected_source))
    core=_configure_module().source_for(root/'core-runtime-receipt.json',frozen['fixture']['origin'],
      frozen['fixture']['allowed_addresses'],frozen['actor_credential_reference'],'api')
    need(core['runtime']['image_id']==IMAGE_IDS['core']and core['runtime']['pi_release']=='0.87.1')
    selected=preparation._json(root/'compiled/inference.json')
    normalized=preparation.pi_lab.normalize_endpoint(frozen['inference']['configuration'])
    need(canonical(selected)==canonical({'kind':'legacy','selection':{'owner':'compiler_input','id':'explicit-endpoint'},
      'configuration':normalized,'catalog_entry':None}))
    need(compiled['plan_sha256']==document['compiled_plan_sha256']and len(compiled['stages'])==1
      and canonical(compiled['stages'][0]['limits'])==canonical(LIMITS)
      and compiled['runtime']['pi_release']=='0.87.1'and compiled['runtime']['image_id']==IMAGE_IDS['browser']
      and compiled['runtime']['container_profile']=='browser'and compiled['runtime']['platform']=='linux/arm64'
      and compiled['runtime']['browser_sandbox_policy']=='chromium-userns'
      and set(compiled['stages'][0]['tools'])==set(REQUIRED_TOOLS)and len(compiled['stages'][0]['tools'])==len(REQUIRED_TOOLS))
    # Original load_compiled already recompiles every IR field against the exact
    # reconstructed source and its compiler/profile/inference/scorer commitments.
    need(preparation._read(root/'project/TASK.md')==TASK_BYTES)
    for name in ('content_scorer.py','expected.json'):
        need(preparation._read(root/name)==preparation._read(EXAMPLE/name))
    for check in expected_source['checks']:
        for asset in check.get('scorer',{}).get('assets',[]):
            need(preparation._read(root/'compiled/scorers'/check['id']/asset['target'])==preparation._read(EXAMPLE/asset['source']))
    return document


def require_execution(*unused,**kwargs):
    raise DiagnosticError()  # No dispatch/backend/admission authority exists here.


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare')
    for name in ('output','core-receipt','browser-receipt','scripted-endpoint','fixture-route','credential-reference'):p.add_argument('--'+name,required=True)
    p=sub.add_parser('verify');p.add_argument('--root',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='prepare':document=prepare(args.output,image_receipts={'core':args.core_receipt,'browser':args.browser_receipt},
          scripted_endpoint=args.scripted_endpoint,fixture_route=preparation._json(args.fixture_route),credential_reference=args.credential_reference)
        else:document=verify(args.root)
        print(json.dumps({'status':document['status'],'native_dispatch_supported':False}));return 0
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        print(json.dumps({'status':'DISABLED_OR_REFUSED','raw_exception_exported':False}));return 2


if __name__=='__main__':raise SystemExit(main())
