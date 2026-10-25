#!/usr/bin/env python3
"""Compile one explicit authenticated API/browser example without live effects."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

HERE=Path(__file__).resolve().parent
SKILL=HERE.parents[1]
sys.path[:0]=[str(SKILL/'scripts'),str(SKILL/'runtime')]
import application_contracts as c
import application_preparation as preparation
import release_contracts


def _prompt(variant):
    common=(
        'Act only as diagnostic-app / team-1 / actor-alice / participant. '
        'Call app_api identity once with operation_id identity, path_params {}, query {}, body null and cursor null; '
        'verify all four returned identity fields before business actions. '
    )
    if variant=='api':
        common+=(
            'Call app_api list-records with path_params {}, query {}, body null and cursor null. '
            'Read that page and save its receipt_id. Then make a second explicit app_api list-records call '
            'using ONLY the returned helper cursor in cursor; leave query {}. Save both page receipt IDs. '
            'Require exactly three distinct records and exhausted pagination. '
        )
    else:
        common+=(
            'Call app_browser navigate target_id summary-page, then snapshot summary-page. '
            'Call app_browser click target_id records-button once for the first page, then snapshot summary-page to read it. '
            'Click records-button once again for page two, then snapshot summary-page to read it; '
            'each click and snapshot is a separate native call. Save the two list-records network receipt IDs from those actions. '
            'Read the actual DOM snapshots; require exactly three distinct records and exhausted pagination. '
        )
    common+=(
        'Create the summary as UTF-8 Markdown: heading "# Team summary", one blank line, '
        'then one "- <id>: <text>" line per record in r1,r2,r3 order, ending with a newline. '
        'Call artifact_write with artifact_id summary and those exact content bytes. Save its returned bytes and sha256. '
    )
    if variant=='api':
        common+=(
            'Before reporting-only mode, call app_api publish-summary exactly once, path_params {}, query {}, cursor null, '
            'body {"target_id":"team-summary","artifact_id":"summary","artifact_sha256":<the artifact hash>}. '
            'The helper reads the declared artifact and supplies its content; do not add content or raw headers. '
        )
    else:
        common+=(
            'Call app_browser fill target_id summary-editor with value equal to the summary text. '
            'Call app_browser fill target_id summary-hash with value equal to the actual artifact_write sha256. '
            'Call app_browser snapshot target_id summary-page and verify its DOM form_state summary text and hash exactly match the written artifact. '
            'Before reporting-only mode, call app_browser click target_id publish-button exactly once. '
            'The reviewed template binds the declared summary artifact hash; the helper supplies its content. '
            'Use snapshot summary-page to inspect the resulting page. No arbitrary JavaScript, raw URL or fallback click is allowed. '
        )
    return common+(
        'Require a succeeded publication receipt attesting actor-alice, team-summary, the exact artifact sha256 and published state. '
        'Do not retry publication after failure, timeout or outcome_unknown. '
        'Finally call report_write once with report exactly: schema 1, document_type application_completion_report, '
        'contract_id participant-report, participant the four assigned identity fields, '
        'artifacts [{id:"summary",path:"outputs/summary.md",sha256:<actual hash>,bytes:<actual byte count>}], '
        'pagination {"list-records":[<first page receipt_id>,<second page receipt_id>]}, '
        'publications [{id:"summary-publication",receipt_id:<publication receipt_id>}], unresolved []. '
        'Use actual tool receipts and hashes; never invent them or claim completion when a required step failed. '
        'If incomplete, write the truthful partial report with unresolved declared failures, then settle. '
        'Every listed operation/action/artifact/report is an explicit native tool call. '
        'Use budget_status only when needed; 32 calls include a six-call/30-second reporting reserve. '
        'No automatic continuation, hidden workflow or report repair is authorized.'
    )


def source_for(runtime_receipt,origin,allowed_addresses,credential_reference,variant):
    if variant not in ('api','browser'):raise preparation.PreparationError()
    receipt=preparation._json(runtime_receipt)
    image=receipt.get('image') if receipt.get('document_type') in ('application_runtime_receipt','browser_admission') else receipt
    if type(image) is not dict or image.get('platform')!='linux/arm64':raise preparation.PreparationError()
    if variant=='api' and (receipt.get('document_type')=='browser_admission' or receipt.get('browser_admission') is not None):
        raise preparation.PreparationError()
    source_profile='browser' if variant=='browser' else 'core'
    if image.get('profile',source_profile)!=source_profile:
        raise preparation.PreparationError()
    release=release_contracts.image_identity(image)['release']
    source=preparation._json(HERE/'source.template.json')
    source['name']='authenticated-application-'+variant
    source['runtime'].update(pi_release=release,image_id=image['id'],container_profile='browser' if variant=='browser' else 'core',
        browser_sandbox_policy='chromium-userns' if variant=='browser' else None)
    source['application']['origins']['fixture'].update(url=origin,allowed_addresses=list(allowed_addresses))
    source['application']['credentials']['persona']=credential_reference
    stage=source['stages'][0];stage['prompt']=_prompt(variant)
    if variant=='browser':
        for operation in source['application']['operations']:
            if operation['effect']!='identity':operation['transport']='browser'
        empty={'type':'object','properties':{},'required':[],'additionalProperties':False}
        common={'page_identity':'diagnostic-summary-v1','url':origin+'/summary','credential_alias':'persona',
            'static_resources':[],'request_body_template':None,'input_schema':empty}
        source['application']['browser_targets']=[
            dict(common,id='summary-page',locator=None,actions=['navigate','snapshot','screenshot'],allowed_operation_ids=[],
                static_resources=[{'method':'GET','origin':'fixture','path':'/summary','media_type':'text/html','max_bytes':16384}]),
            dict(common,id='records-button',locator='[data-testid="load-records"]',actions=['click'],allowed_operation_ids=['list-records']),
            dict(common,id='summary-editor',locator='[data-testid="summary-editor"]',actions=['fill'],allowed_operation_ids=[],
                input_schema={'type':'object','properties':{'value':{'type':'string','maxLength':4096}},'required':['value'],'additionalProperties':False}),
            dict(common,id='summary-hash',locator='[data-testid="summary-hash"]',actions=['fill'],allowed_operation_ids=[],
                input_schema={'type':'object','properties':{'value':{'type':'string','minLength':64,'maxLength':64,'pattern':'^[a-f0-9]{64}$'}},'required':['value'],'additionalProperties':False}),
            dict(common,id='publish-button',locator='[data-testid="publish-summary"]',actions=['click'],allowed_operation_ids=['publish-summary'],
                request_body_template={'target_id':'team-summary','artifact_id':'summary','artifact_sha256':'${artifact.summary.sha256}'})]
        stage['browser_targets']=[target['id'] for target in source['application']['browser_targets']]
    source=c.validate_source(source)
    preparation._runtime(source,receipt)
    return source


def configure(*,runtime_receipt,origin,allowed_addresses,credential_reference,variant,output_dir,endpoint=None,inference_env=None,catalog_dir=None):
    if (endpoint is None)==(inference_env is None):raise preparation.PreparationError()
    if (inference_env is None)!=(catalog_dir is None):raise preparation.PreparationError()
    target=preparation._path(output_dir)
    if target.exists() or target.is_symlink():raise preparation.PreparationError()
    source=source_for(runtime_receipt,origin,allowed_addresses,credential_reference,variant)
    files={}
    with tempfile.TemporaryDirectory(prefix='pi-authenticated-application-') as temporary:
        scratch=Path(temporary).resolve()
        (scratch/'source.json').write_bytes(c.canonical(source))
        for name in ('content_scorer.py','expected.json'):
            body=preparation._read(HERE/name);(scratch/name).write_bytes(body);preparation._add(files,name,body)
        compiled=preparation.compile_artifact(scratch/'source.json',scratch/'compiled',runtime_receipt,
            endpoint_path=endpoint,inference_env_id=inference_env,catalog_root=catalog_dir)
        for path in sorted((scratch/'compiled').rglob('*')):
            if path.is_file():preparation._add(files,'compiled/'+str(path.relative_to(scratch/'compiled')),preparation._read(path,4*1024*1024))
        preparation._add(files,'source.json',c.canonical(source))
        preparation._add(files,'project/TASK.md',preparation._read(HERE/'project/TASK.md'))
        preparation._add(files,'configuration.json',c.canonical({'schema':1,'variant':variant,'plan_sha256':compiled['plan']['plan_sha256'],
            'image':source['runtime']['image_id'],'pi_release':source['runtime']['pi_release'],'platform':'linux/arm64',
            'profile':source['runtime']['container_profile'],'qualification':'not performed'}))
        preparation._publish(target,files)
    return {'configured':str(target),'compiled_plan':str(target/'compiled/plan.json'),'project':str(target/'project'),
        'plan_sha256':compiled['plan']['plan_sha256'],'qualification':'not performed'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-receipt',required=True);parser.add_argument('--origin',required=True)
    parser.add_argument('--allowed-address',action='append',required=True);parser.add_argument('--credential-reference',required=True)
    parser.add_argument('--variant',choices=('api','browser'),required=True);parser.add_argument('--output-dir',required=True)
    selection=parser.add_mutually_exclusive_group(required=True);selection.add_argument('--endpoint');selection.add_argument('--inference-env')
    parser.add_argument('--catalog-dir')
    args=parser.parse_args(argv)
    try:result=configure(runtime_receipt=args.runtime_receipt,origin=args.origin,allowed_addresses=args.allowed_address,
        credential_reference=args.credential_reference,variant=args.variant,output_dir=args.output_dir,
        endpoint=args.endpoint,inference_env=args.inference_env,catalog_dir=args.catalog_dir)
    except (OSError,ValueError,KeyError,TypeError):parser.error('Configuration rejected; check explicit runtime, origin, reference, inference selection and fresh output')
    print(json.dumps(result,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
