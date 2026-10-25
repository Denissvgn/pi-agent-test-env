"""Pure compilation of reviewed application sources into validated frozen IR.

All asset bytes and configuration bindings are explicit inputs. Filesystem,
credential resolution, runtime qualification and dispatch belong to admission.
"""
import copy
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).absolute().parents[1] / 'runtime'))
import application_contracts as c
import application_runtime_contracts as runtime_contracts
import prompt_contract


def _maps(value, names, pointer):
    c.exact(value,set(names),pointer)


def compile_plan(source, *, profile_bindings, inference_bindings, prompt_policy,
                 input_assets, runner_sha256):
    """Return a new final representation, without reading mutable external state."""
    source=c.validate_source(source)
    c.sha256(runner_sha256,'/compiler_inputs/runner_sha256')
    names=[stage['id'] for stage in source['stages']]
    _maps(profile_bindings,names,'/compiler_inputs/profile_bindings')
    _maps(inference_bindings,names,'/compiler_inputs/inference_bindings')
    c.exact(prompt_policy,{'system_instructions','profile_instructions','variant_instructions',
                           'framing_upper_bounds','bound_source_sha256','byte_bound_reviewed'},'/compiler_inputs/prompt_policy')
    c.text(prompt_policy['system_instructions'],'/compiler_inputs/prompt_policy/system_instructions',16384)
    c.choice(prompt_policy['byte_bound_reviewed'],(True,),'/compiler_inputs/prompt_policy/byte_bound_reviewed')
    c.sha256(prompt_policy['bound_source_sha256'],'/compiler_inputs/prompt_policy/bound_source_sha256')
    _maps(prompt_policy['profile_instructions'],names,'/compiler_inputs/prompt_policy/profile_instructions')
    _maps(prompt_policy['variant_instructions'],names,'/compiler_inputs/prompt_policy/variant_instructions')
    release=source['runtime']['pi_release']
    c.exact(prompt_policy['framing_upper_bounds'],{release},'/compiler_inputs/prompt_policy/framing_upper_bounds')
    framing=c.integer(prompt_policy['framing_upper_bounds'][release],'/compiler_inputs/prompt_policy/framing_upper_bounds/'+release,1,65536)
    if type(input_assets) is not dict or not 1<=len(input_assets)<=256:
        c.fail('/compiler_inputs/input_assets','Bounded explicit asset byte map required')
    total=0
    for locator,body in input_assets.items():
        c.relative(locator,'/compiler_inputs/input_assets')
        if type(body) is not bytes:c.fail('/compiler_inputs/input_assets/'+c.escape(locator),'Asset bytes required')
        total+=len(body)
    if total>32*1024*1024:c.fail('/compiler_inputs/input_assets','Asset byte limit')
    used=set()
    def asset(locator,maximum):
        if locator not in input_assets:c.fail('/compiler_inputs/input_assets/'+c.escape(locator),'Missing explicit asset')
        body=input_assets[locator]
        if len(body)>maximum:c.fail('/compiler_inputs/input_assets/'+c.escape(locator),'Asset byte limit')
        used.add(locator)
        return body
    output=copy.deepcopy(source)
    output['runtime']['resources']=c.resources.validate_policy(source['runtime']['resources'])
    output['document_type']='application_execution_plan'
    output['compiler_contract']=runtime_contracts.compiler_identity()
    lookup={s['id']:s for s in source['stages']}
    output['stages']=[]
    for name in c.stage_order(source['stages']):
        stage=copy.deepcopy(lookup[name]);p='/compiler_inputs/profile_bindings/'+name
        profile=copy.deepcopy(profile_bindings[name])
        c.exact(profile,{'id','pi_release','sha256','assets'},p)
        c.choice(profile['id'],('application-client',),p+'/id')
        c.choice(profile['pi_release'],(release,),p+'/pi_release')
        c.sha256(profile['sha256'],p+'/sha256')
        if type(profile['assets']) is not dict or not {'instructions.md','application-client.mjs'}<=set(profile['assets']) or len(profile['assets'])>16:
            c.fail(p+'/assets','Reviewed client assets and instructions required')
        for target,expected in profile['assets'].items():
            c.relative(target,p+'/assets');c.sha256(expected,p+'/assets/'+c.escape(target))
            body=asset('profiles/'+name+'/'+target,1048576)
            if hashlib.sha256(body).hexdigest()!=expected:c.fail(p+'/assets/'+c.escape(target),'Profile asset identity mismatch')
        instructions=prompt_policy['profile_instructions'][name]
        c.text(instructions,'/compiler_inputs/prompt_policy/profile_instructions/'+name,8192)
        if instructions.encode()!=input_assets['profiles/'+name+'/instructions.md']:
            c.fail(p+'/assets/instructions.md','Rendered instructions differ from frozen asset')
        variant=prompt_policy['variant_instructions'][name]
        c.text(variant,'/compiler_inputs/prompt_policy/variant_instructions/'+name,16384,empty=True)
        stage['profile_binding']=profile
        stage['inference_binding']=copy.deepcopy(inference_bindings[name])
        binding=stage['inference_binding'];q='/compiler_inputs/inference_bindings/'+name
        c.exact(binding,{'kind','configuration_sha256','context_window','max_tokens','input_modalities','selection'},q)
        c.choice(binding['kind'],('legacy','indexed'),q+'/kind')
        c.sha256(binding['configuration_sha256'],q+'/configuration_sha256')
        c.integer(binding['context_window'],q+'/context_window',2049,100000000)
        c.integer(binding['max_tokens'],q+'/max_tokens',1,binding['context_window']-1)
        if binding['input_modalities']!=['text']:c.fail(q+'/input_modalities','Reviewed text input only')
        c.exact(binding['selection'],{'owner','id'},q+'/selection')
        c.choice(binding['selection']['owner'],(source['runtime']['inference_owner'],),q+'/selection/owner')
        c.text(binding['selection']['id'],q+'/selection/id',128)
        stage['tools']=[tool for tool in c.APP_TOOLS if tool!='app_browser' or stage['browser_targets']]
        stage['resolved_operations']=[copy.deepcopy(op) for op in source['application']['operations'] if op['id'] in stage['operations']]
        stage['_resolved_browser_targets']=[copy.deepcopy(t) for t in source['application']['browser_targets'] if t['id'] in stage['browser_targets']]
        prompt=prompt_contract.render(stage,system_instructions=prompt_policy['system_instructions'],
                                      profile_instructions=instructions,variant_instructions=variant)
        stage.pop('_resolved_browser_targets');stage.pop('prompt')
        prompt_bytes=len(prompt.encode())
        if prompt_bytes>131072:c.fail('/stages/'+name+'/effective_prompt','Complete rendered prompt exceeds 128 KiB')
        stage['effective_prompt']=prompt
        stage['tool_schemas']=prompt_contract.tool_schemas(stage)
        tool_bytes=len(c.canonical(stage['tool_schemas']))
        admission={'method':'conservative_bytes','prompt_bytes':prompt_bytes,'tool_schema_bytes':tool_bytes,
                   'framing_upper_bound':framing,'reply_tokens':binding['max_tokens'],
                   'history_reserve_tokens':2048,'context_window':binding['context_window']}
        admission['total_upper_bound']=sum(admission[k] for k in ('prompt_bytes','tool_schema_bytes','framing_upper_bound','reply_tokens','history_reserve_tokens'))
        if admission['total_upper_bound']>admission['context_window']:
            c.fail('/stages/'+name+'/prompt_admission','Complete prompt, tools, reply and reserve do not fit selected context')
        stage['prompt_admission']=admission
        output['stages'].append(stage)
    for i,check in enumerate(output['checks']):
        check.setdefault('cwd','.')
        if 'scorer' in check:
            frozen=[];size=0
            for declaration in check['scorer']['assets']:
                body=asset(declaration['source'],16*1024*1024);size+=len(body)
                if size>16*1024*1024:c.fail('/checks/'+str(i)+'/scorer/assets','Scorer asset byte limit')
                frozen.append({'target':declaration['target'],'sha256':hashlib.sha256(body).hexdigest()})
            check['scorer']['assets']=frozen
    if set(input_assets)!=used:c.fail('/compiler_inputs/input_assets','Unreferenced asset inputs are not permitted')
    output['input_hashes']={
        'source':c.digest(source),'profiles':c.digest(profile_bindings),
        'prompt_renderer':c.digest({'renderer':prompt_contract.identity(),'policy':prompt_policy}),
        'operations':c.digest({'operations':source['application']['operations'],'browser_targets':source['application']['browser_targets']}),
        'completion':c.digest([{'stage_id':s['id'],'completion':s['completion'],'input_artifacts':s['input_artifacts']} for s in source['stages']]),
        'scorers':c.digest(output['checks']),
        'release_contract':c.digest({'legacy':runtime_contracts.contract(release)['legacy_release_identity'],
                                     'application':runtime_contracts.identity(release)}),
        'runner':runner_sha256}
    output['plan_sha256']=c.digest(output)
    return c.validate_ir(output)
