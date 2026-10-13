"""Reviewed Pi 0.87.1/1.2.0 mappings; server enforcement needs live receipts."""
import copy
import math
import release_contracts

PI_RELEASE='0.87.1'
LEVELS=('off','minimal','low','medium','high')


def reasoning_settings(config,release):
    selected = release_contracts.contract(release)
    value=config.get('reasoning',False)
    if not isinstance(value,(bool,dict)):raise ValueError('Reasoning must be a boolean or explicit settings object')
    enabled=value if isinstance(value,bool) else value.get('enabled',True)
    if type(enabled) is not bool:raise ValueError('reasoning.enabled must be boolean')
    if isinstance(value,dict) and not enabled and value.get('level','off')!='off':raise ValueError('Disabled reasoning conflicts with a non-off level')
    level=('low' if enabled else 'off') if isinstance(value,bool) else value.get('level','low' if enabled else 'off')
    budget=None if isinstance(value,bool) else value.get('budget_tokens')
    if not enabled:level='off'
    if level not in selected['reasoning_levels']:raise ValueError('Unsupported thinking level; supported runner levels are off/minimal/low/medium/high')
    if budget is not None:
        raise ValueError('Numeric reasoning budgets are unsupported for the reviewed Pi CLI contracts: omit budget_tokens or qualify a separate ingestion/request route. No budget is silently dropped.')
    settings={'packages':[],'extensions':[],'defaultThinkingLevel':level,
              'retry':{'enabled':False,'provider':{'maxRetries':0}},'compaction':{'enabled':False},'cacheWarming':'off'}
    receipt={'requested':copy.deepcopy(value),'pi_configuration':{'model_reasoning':bool(enabled),'thinking_level':level},
             'ingestion':'unverified','server_enforcement':'unverified','budget_enforcement':'unsupported' if budget else 'not_requested',
             'release':release,'release_contract':release_contracts.identity(release)}
    return bool(enabled),level,settings,receipt


SAMPLING_RANGES={'temperature':(0,2),'top_p':(0,1),'min_p':(0,1),'top_k':(0,10000),
                 'repetition_penalty':(0.1,2),'seed':(0,4294967295)}


def sampling_settings(config,release=None):
    value=config.get('sampling',{})
    if not isinstance(value,dict) or set(value)-set(SAMPLING_RANGES):raise ValueError('Unsupported sampling controls; allowed: '+', '.join(SAMPLING_RANGES))
    for key,number in value.items():
        low,high=SAMPLING_RANGES[key]
        if type(number) not in (int,float) or not math.isfinite(number) or not low<=number<=high or (key in ('top_k','seed') and type(number) is not int):
            raise ValueError(f'Invalid sampling.{key}: bounded numeric value required ({low}..{high})')
    if release is not None: release_contracts.contract(release)
    return copy.deepcopy(value)


def model_configuration(config,release):
    enabled,level,settings,receipt=reasoning_settings(config,release)
    sampling=sampling_settings(config,release)
    if sampling and release is None:raise ValueError('Sampling ingestion cannot be qualified with unknown Pi release')
    receipt['sampling']={'requested':sampling,'pi_configuration':sampling,'ingestion':'unverified','server_enforcement':'unverified'}
    model={'id':config['model'],'name':config['model'],'input':config.get('input',['text']),
           'contextWindow':config['context_window'],'maxTokens':config['max_tokens'],
           'compat':{'maxTokensField':'max_tokens',**config.get('compat',{})},'reasoning':enabled}
    if sampling:model['samplingParams']=sampling
    return {'providers':{'local-lab':{'baseUrl':config['base_url'],'api':'openai-completions',
                                    'apiKey':'$PI_LAB_API_KEY','models':[model]}}},settings,['--thinking',level],receipt
