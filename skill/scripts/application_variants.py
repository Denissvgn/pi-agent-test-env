"""Pure experiment variant transforms through the shared application compiler.

All byte observations and reviewed bindings are explicit inputs. This module
does not select mutable catalogs, read credentials/assets, or dispatch a plan.
Current bundled-byte authority and session confirmation remain admission gates.
"""
import copy

import agent_profiles
import application_compiler
import application_contracts as c
import application_runtime_contracts
import indexed_contract
import pi_lab
import resources as resource_policy

BUDGET_FIELDS={'timeout_seconds','max_turns','max_total_tokens','max_tool_calls',
               'reporting_reserve_calls','reporting_reserve_seconds'}
RUNTIME_FIELDS={'pi_release','image_id','platform','container_profile','browser_sandbox_policy'}


class VariantError(ValueError):
    def __init__(self):super().__init__('Invalid explicit application variant inputs')


def _literal(value):
    # Normalizers may expand endpoint templates; variant compilation never does.
    if type(value) is str and '${' in value:raise VariantError()
    if type(value) is dict:
        for key,child in value.items():_literal(key);_literal(child)
    elif type(value) is list:
        for child in value:_literal(child)


def _binding(kind,binding):
    try:
        if type(binding) is not dict or len(c.canonical(binding))>1024*1024:raise VariantError()
        _literal(binding)
        if kind=='indexed':
            canonical=copy.deepcopy(binding)
            if 'authority_id' in canonical:indexed_contract.identity(canonical.pop('authority_id'))
            canonical=indexed_contract.entry(canonical,pi_lab.normalize_endpoint)
            configuration=canonical['configuration'];endpoint=configuration['endpoint']
        elif kind=='legacy':
            configuration=copy.deepcopy(binding)
            if pi_lab.normalize_endpoint(configuration)!=configuration:raise VariantError()
            canonical=configuration;endpoint=configuration
            for field,limit in (('base_url',4096),('host_base_url',4096),('model',512),('api_key_env',128)):
                c.text(endpoint[field],'/variant/binding/'+field,limit)
        else:raise VariantError()
        if endpoint.get('input',['text'])!=['text']:raise VariantError()
        return canonical,configuration,endpoint
    except (ValueError,TypeError,KeyError,AttributeError,RecursionError,pi_lab.LabError):raise VariantError() from None


def variant_selection(variant_id,kind,binding):
    """Return exact IR selection; indexed session authority_id is excluded.

    The immutable entry incarnation/revision/configuration/ref all bind identity.
    Parent admission must recompute this from its trusted frozen variant ID/map,
    never guess from the model or a mutable catalog default.
    """
    try:c.slug(variant_id,'/variant/id')
    except ValueError:raise VariantError() from None
    canonical,_,_=_binding(kind,binding)
    return {'owner':'experiment_variant','id':c.digest({'variant_id':variant_id,'binding':canonical})}


def _profiles(bindings,names,release):
    # Bind the fixed reviewed profile layout, release and explicit asset hashes.
    # No filesystem check is hidden here; the owning admission path compares
    # these same hashes against the installed reviewed bundle before effects.
    c.exact(bindings,set(names),'/variant/profile_bindings')
    for name in names:
        profile=bindings[name];c.exact(profile,{'id','pi_release','sha256','assets'},'/variant/profile_binding')
        c.exact(profile['assets'],agent_profiles.APPLICATION_TARGETS,'/variant/profile_binding/assets')
        for digest in profile['assets'].values():c.sha256(digest,'/variant/profile_binding/assets')
        declaration={'schema':1,'document_type':'agent_profile','id':'application-client','kind':'application-client',
            'components':[application_runtime_contracts.profile_component(release)],
            'tools':list(agent_profiles.APPLICATION_TOOLS),'required_tools':[],
            'assets':[{'target':target,'sha256':profile['assets'][target]}
                      for target in ('application-client.mjs','instructions.md')],
            'service_endpoints':[agent_profiles.APPLICATION_ENDPOINT]}
        if (profile['id']!='application-client' or profile['pi_release']!=release
                or profile['sha256']!=agent_profiles.identity(declaration)):raise VariantError()


def build_variant_inputs(source,*,variant_id,bindings,profile_bindings,prompt_policy,input_assets,
                         runner_sha256,runtime=None,resources=None,budgets=None,prompt_suffix=''):
    """Return {source, compiler_kwargs} for shared compilation/frozen artifacts.

    bindings is an exhaustive uniform stage map of either
    {kind:'indexed',entry:<Catalog entry, optional authority_id>} or
    {kind:'legacy',endpoint:<fully normalized endpoint>}. No endpoint path,
    catalog selector, default lookup or credential value argument is accepted.
    Resources overrides are full explicit policies; budget overrides are all six
    app limit fields. Runtime transforms cannot change inference ownership.
    """
    effective=c.validate_source(source)
    if effective['runtime']['inference_owner']!='experiment_variant':raise VariantError()
    c.slug(variant_id,'/variant/id');c.text(prompt_suffix,'/variant/prompt_suffix',16384,empty=True)
    if runtime is not None:
        if type(runtime) is not dict or set(runtime)-RUNTIME_FIELDS:raise VariantError()
        effective['runtime'].update(copy.deepcopy(runtime))
    if resources is not None:
        if (type(resources) is not dict or set(resources)!=set(resource_policy.DEFAULTS)
                or type(resources['schema']) is not int or resources['schema']!=1):raise VariantError()
        for section in ('runtime','build','host_budget'):
            if type(resources[section]) is not dict or set(resources[section])!=set(resource_policy.DEFAULTS[section]):raise VariantError()
        effective['runtime']['resources']=resource_policy.validate_policy(resources)
    if budgets is not None:
        c.exact(budgets,BUDGET_FIELDS,'/variant/budgets')
        for stage in effective['stages']:stage['limits']=copy.deepcopy(budgets)
    # Validate again after every explicit transform, before final prompt sizing.
    effective=c.validate_source(effective);names=[stage['id'] for stage in effective['stages']]
    c.exact(bindings,set(names),'/variant/bindings')
    _profiles(profile_bindings,names,effective['runtime']['pi_release'])
    selected={};kinds=set()
    for name in names:
        item=bindings[name]
        if type(item) is not dict or type(item.get('kind')) is not str:raise VariantError()
        kind=item['kind'];key='entry' if kind=='indexed' else 'endpoint' if kind=='legacy' else None
        if key is None or set(item)!={'kind',key}:raise VariantError()
        kinds.add(kind);_,configuration,endpoint=_binding(kind,item[key])
        selected[name]={'kind':kind,'configuration_sha256':c.digest(configuration),
            'context_window':endpoint['context_window'],'max_tokens':endpoint['max_tokens'],'input_modalities':['text'],
            'selection':variant_selection(variant_id,kind,item[key])}
    if len(kinds)!=1:raise VariantError()
    policy=copy.deepcopy(prompt_policy)
    if type(policy) is not dict or type(policy.get('variant_instructions')) is not dict:raise VariantError()
    c.exact(policy['variant_instructions'],set(names),'/variant/prompt_policy/variant_instructions')
    for name in names:
        current=policy['variant_instructions'][name]
        c.text(current,'/variant/prompt_policy/variant_instructions',16384,empty=True)
        policy['variant_instructions'][name]=current+('\n' if current and prompt_suffix else '')+prompt_suffix
    return {'source':effective,'compiler_kwargs':{'profile_bindings':copy.deepcopy(profile_bindings),
        'inference_bindings':selected,'prompt_policy':policy,'input_assets':copy.deepcopy(input_assets),
        'runner_sha256':runner_sha256}}


def compile_variant(source,*,variant_id,bindings,profile_bindings,prompt_policy,input_assets,
                    runner_sha256,runtime=None,resources=None,budgets=None,prompt_suffix=''):
    prepared=build_variant_inputs(source,variant_id=variant_id,bindings=bindings,
        profile_bindings=profile_bindings,prompt_policy=prompt_policy,input_assets=input_assets,
        runner_sha256=runner_sha256,runtime=runtime,resources=resources,budgets=budgets,prompt_suffix=prompt_suffix)
    return application_compiler.compile_plan(prepared['source'],**prepared['compiler_kwargs'])
