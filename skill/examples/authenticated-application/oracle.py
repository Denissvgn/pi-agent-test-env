#!/usr/bin/env python3
"""Key-free, read-only external oracle for stopped authenticated application runs.

The trusted parent supplies a sealed stop/cleanup receipt and its digest. Model
claims and the normal content scorer are never evidence of identity or effects.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import stat
import uuid

HERE=Path(__file__).resolve().parent
MAX_TOTAL=33554432


def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def sha(body):return hashlib.sha256(body).hexdigest()
def exact(value,keys):
    if type(value) is not dict or set(value)!=set(keys):raise ValueError()
def strict(body):
    def pairs(items):
        value={}
        for key,item in items:
            if key in value:raise ValueError()
            value[key]=item
        return value
    return json.loads(body,object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in ()).throw(ValueError()))
def identifier(value):
    if type(value) is not str or str(uuid.UUID(value))!=value:raise ValueError()
def digest(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value):raise ValueError()
def _path(value):
    value=os.fspath(value);path=PurePosixPath(value)
    if not path.is_absolute() or str(path)!=value or '..' in path.parts:raise ValueError()
    return path


def read(root,relative,maximum=2097152):
    root=_path(root);path=PurePosixPath(relative)
    if not relative or path.is_absolute() or str(path)!=relative or any(part in ('.','..') for part in relative.split('/')):raise ValueError()
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in [*root.parts[1:],*path.parts[:-1]]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_size>maximum:raise ValueError()
            body=stream.read(maximum+1);after=os.fstat(stream.fileno())
            if len(body)>maximum or any(getattr(before,key)!=getattr(after,key) for key in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')):raise ValueError()
            return body
    finally:os.close(parent)


def stop_gate(parent):
    try:
        exact(parent,{'schema','document_type','run','fixture'})
        if type(parent['schema']) is not int or parent['schema']!=1 or parent['document_type']!='authenticated_application_parent_receipt':return False
        exact(parent['run'],{'run_id','attempt_id','result_sha256','writers_stopped','cleanup_confirmed'})
        exact(parent['fixture'],{'fixture_id','terminal_sha256','writers_stopped','cleanup_confirmed'})
        for item in (parent['run'],parent['fixture']):
            if item['writers_stopped'] is not True or item['cleanup_confirmed'] is not True:return False
        identifier(parent['run']['run_id']);identifier(parent['run']['attempt_id']);identifier(parent['fixture']['fixture_id'])
        digest(parent['run']['result_sha256']);digest(parent['fixture']['terminal_sha256']);return True
    except (ValueError,TypeError,AttributeError):return False


def cleaned(result):
    agents=result.get('agents')
    if result.get('sealed') is not True or type(agents) is not list or len(agents)!=1:return False
    process=agents[0].get('process',{});helper=process.get('application_helper_cleanup',{});credentials=process.get('application_credentials',{})
    denied=('cancelled','application_credential_cleanup','cleanup_error')
    if (result.get('termination',{}).get('reason') in denied or process.get('cancelled') is True
            or 'cancelled' in process and type(process['cancelled']) is not bool
            or process.get('termination_reason') in denied or process.get('exit_code')==130
            or 'exit_code' in process and type(process['exit_code']) is not int
            or process.get('application_completion',{}).get('status')=='not_evaluated'
            or any(stage.get('status')=='not_evaluated' for stage in result.get('application_completion',{}).get('stages',[]))):return False
    return (process.get('cleanup_confirmed') is True and type(helper.get('schema')) is int and helper['schema']==1 and helper.get('status')=='removed'
        and helper.get('workspace')=='clean' and helper.get('safe_to_continue') is True
        and type(credentials.get('schema')) is int and credentials['schema']==1 and credentials.get('status')=='removed' and credentials.get('workspace')=='clean')


def fixture_stopped(terminal):
    try:
        exact(terminal,{'schema','document_type','fixture_id','journal','process'})
        exact(terminal['process'],{'exit_code','cleanup_confirmed','writers_stopped'})
        process=terminal['process'];identifier(terminal['fixture_id'])
        return (type(terminal['schema']) is int and terminal['schema']==1 and terminal['document_type']=='application_fixture_terminal_receipt'
            and type(process['exit_code']) is int and process['exit_code']==0
            and process['cleanup_confirmed'] is True and process['writers_stopped'] is True)
    except (ValueError,TypeError,AttributeError):return False


def _relative(root,value):
    path=_path(value);base=_path(root)
    result=path.relative_to(base)
    if not result.parts:raise ValueError()
    return result.as_posix()


def evaluate(run_root,journal_dir,parent_receipt,expected_path=None):
    codes=[];assertions={}
    def check(name,passed,code):
        assertions[name]=bool(passed)
        if not passed and code not in codes:codes.append(code)
    def result(status=None):return {'schema':1,'document_type':'authenticated_application_oracle',
        'status':status or ('PASS' if not codes else 'FAIL'),'diagnostics':codes,'assertions':assertions}
    # Crucially, no expected/run/journal/report/evidence read precedes this gate.
    if not stop_gate(parent_receipt):
        codes.append('writers_unconfirmed');return result('NOT_EVALUATED')
    try:
        expected_path=Path(expected_path or HERE/'expected.json').absolute()
        expected=strict(read(expected_path.parent,expected_path.name,16384));participant=expected['participant']
        result_body=read(run_root,'result.json');check('sealed_result_sha',sha(result_body)==parent_receipt['run']['result_sha256'],'terminal_receipt_invalid')
        if codes:return result()
        run=strict(result_body)
        check('sealed_run_identity',run.get('sealed') is True and all(run.get(key)==parent_receipt['run'][key] for key in ('run_id','attempt_id')),'run_identity_invalid')
        if not cleaned(run):codes.append('writers_unconfirmed');return result('NOT_EVALUATED')
        terminal_body=read(journal_dir,'terminal-receipt.json',16384)
        check('fixture_terminal_sha',sha(terminal_body)==parent_receipt['fixture']['terminal_sha256'],'terminal_receipt_invalid')
        if codes:return result()
        terminal=strict(terminal_body);exact(terminal,{'schema','document_type','fixture_id','journal','process'})
        check('fixture_stopped',fixture_stopped(terminal) and terminal['fixture_id']==parent_receipt['fixture']['fixture_id'],'writers_unconfirmed')
        if codes:return result('NOT_EVALUATED')
        exact(terminal['journal'],{'path','sha256','bytes'})
        if terminal['journal']['path']!='journal.json':raise ValueError()
        journal_body=read(journal_dir,'journal.json',262144)
        check('journal_sealed_sha',sha(journal_body)==terminal['journal']['sha256'] and len(journal_body)==terminal['journal']['bytes'],'fixture_journal_integrity')
        if codes:return result()
        journal=strict(journal_body)
        check('fixture_closed',journal.get('closed') is True and journal.get('fixture_id')==terminal['fixture_id'],'writers_unconfirmed')
        if codes:return result('NOT_EVALUATED')
        plan=strict(read(run_root,'plan.json'));plan_hash=plan.get('plan_sha256')
        check('frozen_plan_identity',sha(canonical({key:value for key,value in plan.items() if key!='plan_sha256'}))==plan_hash,'run_identity_invalid')
        stage=plan['stages'][0];contract=stage['completion'];process=run['agents'][0]['process'];context=process['application_completion_context']
        check('expected_participant',stage['participant']==participant and contract['participant']==participant,'participant_mismatch')
        check('single_stage',len(plan['stages'])==1 and run['agents'][0]['name']==stage['id'],'run_identity_invalid')
        exact(context,{'binding','parent_receipts','evidence_root','report_root','authorized_segment_ids'})
        binding=context['binding'];segments=context['authorized_segment_ids']
        check('parent_binding',binding['run_id']==run['run_id'] and binding['attempt_id']==run['attempt_id'] and binding['plan_sha256']==plan_hash
            and binding['profile_sha256']==stage['profile_binding']['sha256'] and binding['report_contract_sha256']==sha(canonical(contract)), 'receipt_integrity_failed')
        if type(segments) is not list or not 1<=len(segments)<=8 or len(set(segments))!=len(segments) or binding['segment_id'] not in segments:raise ValueError()
        for segment in segments:identifier(segment)
        report_root=_relative(run_root,context['report_root']);evidence_root=_relative(run_root,context['evidence_root'])
        expected_content=expected['content'].encode();content_hash=sha(expected_content)
        try:artifact=read(run_root,report_root+'/'+expected['summary_path'],16384)
        except FileNotFoundError:artifact=None
        check('artifact_present',artifact is not None,'artifact_missing');check('exact_summary_content',artifact==expected_content,'content_mismatch')
        try:report=strict(read(run_root,report_root+'/'+expected['report_path'],65536))
        except FileNotFoundError:report=None;check('report_present',False,'report_missing')
        if report is not None:
            exact(report,{'schema','document_type','contract_id','participant','artifacts','pagination','publications','unresolved'})
            check('report_identity',report['schema']==1 and type(report['schema']) is int and report['document_type']=='application_completion_report'
                and report['contract_id']==contract['id'] and report['participant']==participant and report['unresolved']==[],'report_invalid')
            check('report_artifact',report['artifacts']==[{'id':expected['artifact_id'],'path':expected['summary_path'],
                'sha256':content_hash,'bytes':len(expected_content)}],'artifact_hash_mismatch')
            if artifact is not None:
                check('artifact_report_binding',len(report['artifacts'])==1 and report['artifacts'][0]['sha256']==sha(artifact)
                    and report['artifacts'][0]['bytes']==len(artifact),'artifact_hash_mismatch')
        index=context['parent_receipts']
        if type(index) is not dict or not 1<=len(index)<=128:raise ValueError()
        if report is not None:
            reported=[receipt_id for page in report['pagination'].values() for receipt_id in page]+[row['receipt_id'] for row in report['publications']]
            check('reported_receipts_available',all(type(receipt_id) is str and receipt_id in index for receipt_id in reported),'receipt_missing')
        receipts={};responses={};total=0;sequences=set();instances=set();paths=set()
        for ordinal,(receipt_id,reference) in enumerate(index.items()):
            if type(receipt_id) is not str or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',receipt_id):raise ValueError()
            exact(reference,{'path','sha256'});body=read(run_root,evidence_root+'/'+reference['path'],65536);total+=len(body)
            label=str(ordinal)
            if sha(body)!=reference['sha256']:check('receipt_'+label,False,'receipt_integrity_failed');continue
            receipt=strict(body);actual=receipt['binding'];expected_binding={**binding,'segment_id':actual['segment_id']}
            valid=(receipt.get('schema')==1 and receipt.get('document_type')=='application_operation_receipt' and receipt['receipt_id']==receipt_id
                and actual==expected_binding and actual['segment_id'] in segments and receipt['participant']==participant)
            check('receipt_binding_'+label,valid,'participant_mismatch' if receipt['participant']!=participant else 'receipt_integrity_failed')
            check('receipt_unique_'+label,receipt['sequence'] not in sequences and (receipt['operation_instance_id'] is None or receipt['operation_instance_id'] not in instances),'receipt_integrity_failed')
            sequences.add(receipt['sequence']);instances.add(receipt['operation_instance_id'])
            response=None
            for evidence in receipt['evidence']:
                if evidence['path'] in paths:raise ValueError()
                paths.add(evidence['path']);raw=read(run_root,evidence_root+'/'+evidence['path'],min(MAX_TOTAL-total,1048576));total+=len(raw)
                check('evidence_'+sha(evidence['path'].encode())[:12],len(raw)==evidence['bytes'] and sha(raw)==evidence['sha256'],'receipt_integrity_failed')
                if evidence['kind']=='response' and receipt['outcome']=='succeeded' and receipt['effect'] in ('identity','read','publication'):
                    response=strict(raw.split(b'\r\n\r\n',1)[1])
            if total>MAX_TOTAL:raise ValueError()
            receipts[receipt_id]=receipt;responses[receipt_id]=response
        identity=[r for r in receipts.values() if r['effect']=='identity' and r['outcome']=='succeeded']
        check('identity_receipt',len(identity)==1 and responses.get(identity[0]['receipt_id'])==participant,'participant_mismatch')
        page_receipts=sorted((r for r in receipts.values() if r['operation_id']=='list-records' and r['pagination'] is not None),key=lambda r:r['sequence'])
        check('two_page_receipts',len(page_receipts)==2,'pagination_incomplete')
        pages=journal.get('pages',[])
        check('fixture_pages',[(p['actor_id'],p['page_index'],p['record_ids'],p['snapshot_id']) for p in pages]==[
            (participant['actor_id'],1,['r1','r2'],expected['snapshot_id']),(participant['actor_id'],2,['r3'],expected['snapshot_id'])],'pagination_incomplete')
        if len(page_receipts)==2:
            first,second=page_receipts
            check('receipt_page_chain',first['outcome']==second['outcome']=='succeeded' and first['pagination']['state']=='more'
                and second['pagination']['state']=='exhausted' and first['pagination']['chain_id']==second['pagination']['chain_id']
                and first['pagination']['snapshot_id']==second['pagination']['snapshot_id']==expected['snapshot_id']
                and first['pagination']['page']==1 and second['pagination']['page']==2
                and first['pagination']['total_items']==2 and second['pagination']['total_items']==3,'pagination_incomplete')
            check('raw_page_records',[responses.get(r['receipt_id'],{}).get('items') for r in page_receipts]==[expected['records'][:2],expected['records'][2:]],'pagination_incomplete')
            if report is not None:check('reported_page_receipts',report['pagination']=={'list-records':[r['receipt_id'] for r in page_receipts]},'pagination_incomplete')
        publications=[r for r in receipts.values() if r['effect']=='publication']
        committed=journal.get('publications',[]);posts=[r for r in journal['requests'] if r['method']=='POST']
        check('single_committed_publication',len(committed)==1 and len(posts)==1,'publication_missing')
        if len(committed)==1:
            actual=committed[0]
            check('fixture_publication_binding',actual['actor_id']==participant['actor_id'] and actual['target_id']==expected['target_id']
                and actual['artifact_id']==expected['artifact_id'] and actual['artifact_sha256']==actual['content_sha256']==content_hash
                and actual['content_bytes']==len(expected_content),'publication_binding_mismatch')
        if any(r['outcome']=='outcome_unknown' for r in publications):check('publication_response_confirmed',False,'publication_outcome_unknown')
        successful=[r for r in publications if r['outcome']=='succeeded']
        check('publication_receipt',len(successful)==1,'publication_missing' if not publications else 'publication_outcome_unknown')
        if stage['browser_targets']:
            business=[r for r in receipts.values() if r['operation_id'] in ('list-records','publish-summary') and r['outcome']=='succeeded']
            check('declared_browser_operations',len(business)==3 and all(r['transport']=='browser' and type(r['action_id']) is str and r['action_id'] for r in business),'browser_evidence_missing')
        if len(successful)==1 and len(committed)==1:
            receipt=successful[0];pub=receipt['publication'];commit=committed[0]
            check('publication_binding',pub=={'id':expected['publication_requirement_id'],'artifact_id':expected['artifact_id'],
                'target_id':expected['target_id'],'publication_id':commit['publication_id'],'artifact_sha256':content_hash,'state':'published'},'publication_binding_mismatch')
            check('raw_publication_response',responses[receipt['receipt_id']]=={'actor_id':participant['actor_id'],'target_id':expected['target_id'],
                'publication_id':commit['publication_id'],'artifact_sha256':content_hash,'state':'published'},'publication_binding_mismatch')
            if report is not None:check('reported_publication',report['publications']==[{'id':expected['publication_requirement_id'],'receipt_id':receipt['receipt_id']}],'publication_binding_mismatch')
        return result()
    except FileNotFoundError:codes.append('receipt_missing');return result()
    except (OSError,ValueError,KeyError,IndexError,TypeError,AttributeError,RecursionError):codes.append('evidence_invalid');return result()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--run-root',required=True);parser.add_argument('--journal-dir',required=True)
    parser.add_argument('--parent-receipt',required=True);parser.add_argument('--parent-sha256',required=True);args=parser.parse_args()
    path=Path(args.parent_receipt).absolute();body=read(path.parent,path.name,16384)
    if sha(body)!=args.parent_sha256:raise SystemExit('Parent receipt digest mismatch')
    result=evaluate(Path(args.run_root).absolute(),Path(args.journal_dir).absolute(),strict(body))
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
