#!/usr/bin/env python3
"""Render opt-in indexed definitions offline; no credential values or requests."""
import argparse,copy,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
SKILL=HERE.parents[1]
sys.path[:0]=[str(SKILL/'scripts'),str(SKILL/'runtime')]
import indexed_contract,release_contracts


def definitions(image,release='0.87.1',a='builder-local',b='reviewer-local'):
    release_contracts.contract(release);indexed_contract.identifier(a);indexed_contract.identifier(b)
    gateway={'resources':{'cpu_millis':250,'memory_mib':128,'pids_limit':64},'max_inflight':1,'max_pending':4,'queue_wait_seconds':180,'request_timeout_seconds':180}
    execution={'contract':'indexed-inference-v1','host_generation':2,'max_workers':1,
        'aggregate':{'cpu_millis':2500,'memory_mib':3328,'pids_limit':1152},'gateway':gateway}
    common={'schema':3,'name':'indexed-serial','mode':'serial','baseline':'baseline','repetitions':3,
        'cases':[{'name':'slug','project':str(SKILL/'examples/application-baseline/project'),'plan':str(SKILL/'examples/application-baseline/application.plan.json')}],
        'variants':[{'name':'baseline','inference_env':a},{'name':'candidate','inference_env':b}],
        'budgets':{'timeout_seconds':600,'max_turns':12,'max_total_tokens':128000},
        'execution':{'image':image,'platform':'linux/arm64','resources':str(SKILL/'assets/resources/indexed-workers.json'),'network':'bridge'},
        'indexed_execution':execution,'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'stop','max_attempts':1}}
    parallel=copy.deepcopy(common);parallel.update(name='indexed-parallel',mode='parallel')
    parallel['indexed_execution']['max_workers']=2
    parallel['concurrency']={'scheduler':'parallel-trials-v2','host_generation':2,'registry_aware_cohort':True,
        'max_trials':2,'max_stages':2,'max_pending':16,'queue_wait_seconds':3600,'collection_timeout_seconds':14400,
        'aggregate':execution['aggregate'],'gateway':gateway}
    roles=copy.deepcopy(common);roles['name']='indexed-roles';roles['cases'][0]['plan']=str(HERE/'external.plan.json')
    for variant,pair in zip(roles['variants'],((a,b),(b,a))):
        variant.pop('inference_env');variant['inference_bindings']={'slug':dict(zip(('implementer','reviewer'),pair))}
    return {'serial.json':common,'parallel.json':parallel,'roles.json':roles}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image-receipt',required=True);parser.add_argument('--output-dir',required=True)
    parser.add_argument('--a',default='builder-local');parser.add_argument('--b',default='reviewer-local');args=parser.parse_args()
    receipt=json.loads(Path(args.image_receipt).read_text());release=release_contracts.image_identity(receipt)['release']
    if receipt.get('platform')!='linux/arm64':parser.error('Native ARM64 receipt required')
    destination=Path(args.output_dir)
    if destination.exists() or destination.is_symlink():parser.error('Use a fresh output directory')
    destination.mkdir(parents=True)
    for name,value in definitions(receipt['id'],release,args.a,args.b).items():(destination/name).write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps({'definitions':str(destination),'scope':'Offline inputs; catalog authorization and native qualification remain required'}))

if __name__=='__main__':main()
