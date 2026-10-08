"""Deterministic application comparisons with explicit cohorts and denominators."""
import copy
import hashlib
import json
import math
from pathlib import Path
import statistics

import provenance


def stats(values):
    known=[x for x in values if type(x) in (int,float) and math.isfinite(x)]
    return {'observed':len(known),'missing':len(values)-len(known),'mean':statistics.mean(known) if known else None,
            'min':min(known) if known else None,'max':max(known) if known else None,
            'sample_stddev':statistics.stdev(known) if len(known)>1 else None}


def rate(numerator,denominator):
    return {'numerator':numerator,'denominator':denominator,'value':numerator/denominator if denominator else None}


def assessment(record,expected,configuration_digest):
    if record is None:return {'completed':False,'scorable':False,'artifact_correct':False,'eligible':False,'successful':False,'reason':'result_missing'}
    completed=record.get('sealed') is True and record.get('schema')==2 and record.get('document_type')=='run_result'
    scoring=record.get('scoring',{});task=record.get('task_result',{})
    results=scoring.get('results',[]);scorer=results[0] if len(results)==1 else {}
    oracle=expected['scorer']
    comparable=all(scorer.get(k)==oracle[k] for k in ('scorer_id','scorer_version','scorer_sha256','score_domain'))
    score=task.get('score');domain=oracle['score_domain']
    numeric=type(score) in (int,float) and math.isfinite(score) and domain['min']<=score<=domain['max']
    scorable=completed and scoring.get('status')=='completed' and scorer.get('status')=='completed' and comparable and numeric and task.get('status') in ('pass','fail','partial') and scorer.get('score')==score and scorer.get('task_status')==task.get('status')
    matched=(record.get('configuration_digest')==configuration_digest and record.get('provenance',{}).get('configuration_sha256')==expected['endpoint_sha256']
             and record.get('provenance',{}).get('snapshot_sha256')==expected['snapshot_sha256']
             and record.get('provenance',{}).get('plan_sha256')==expected['plan_sha256']
             and record.get('provenance',{}).get('runner_content_sha256')==expected['runner_content_sha256']
             and record.get('image',{}).get('id')==expected['image'] and record.get('image',{}).get('platform')==expected['platform'])
    if expected.get('profile_explicit'):
        observations=record.get('agent_profile',{}).get('observed_stages',[])
        matched=matched and record.get('provenance',{}).get('agent_profile',{}).get('sha256')==expected['agent_profile_sha256']
        matched=matched and bool(observations) and all(row.get('segments') and all(s.get('loading')=='observed' and (expected['agent_profile_id']=='builtin' or s.get('use')=='observed') for s in row['segments']) for row in observations)
    eligible=(scorable and matched and record.get('infrastructure',{}).get('status')=='ready' and record.get('invocation',{}).get('status')=='verified'
              and record.get('assistance',{}).get('status')=='autonomous' and record.get('protected_inputs',{}).get('status')=='unchanged'
              and record.get('termination',{}).get('reason') not in ('cancelled','cleanup_error'))
    correct=scorable and task['status']=='pass'
    successful=eligible and correct and record.get('termination',{}).get('reason')=='completed' and record.get('status')=='PASS'
    reason=('result_unsealed_or_unsupported' if not completed else 'scorer_unscorable' if not scorable else
            'configuration_or_runner_mismatch' if not matched else 'invocation_unverified' if record.get('invocation',{}).get('status')!='verified' else
            'assisted' if record.get('assistance',{}).get('status')!='autonomous' else 'protected_inputs_unverified' if record.get('protected_inputs',{}).get('status')!='unchanged' else
            'cancelled_or_cleanup_error' if record.get('termination',{}).get('reason') in ('cancelled','cleanup_error') else None)
    return {'completed':completed,'scorable':scorable,'artifact_correct':correct,'eligible':eligible,'successful':successful,'reason':reason}


def summarize_group(rows,expected):
    primary=[];all_attempts=[];details=[]
    for row in rows:
        attempts=row['attempts'];record=attempts[0]['result'] if attempts else None
        a=assessment(record,expected[row['trial_id']],row['configuration_digest'])
        primary.append((row,record,a));all_attempts.extend((row,attempt) for attempt in attempts)
        details.append({'trial_id':row['trial_id'],'repetition':row['repetition'],'primary_attempt_id':row['primary_attempt_id'],
                        'status':record.get('status') if record else 'planned' if not attempts else 'incomplete',
                        'task_status':record.get('task_result',{}).get('status') if record else 'unknown',
                        'score':record.get('task_result',{}).get('score') if a['scorable'] else None,**a,
                        'attempts':[{'attempt_id':x['attempt_id'],'attempt_index':x['attempt_index'],'retry_of_attempt_id':x['retry_of_attempt_id'],
                                     'result_path':x.get('evidence_path',x['result_path']),'status':x['result'].get('status') if x['result'] else 'incomplete'} for x in attempts]})
    counts={'planned':len(rows),'started':sum(bool(row['attempts']) for row in rows),
            'completed':sum(a['completed'] for _,_,a in primary),'scorable':sum(a['scorable'] for _,_,a in primary),
            'artifact_correct':sum(a['artifact_correct'] for _,_,a in primary),'eligible':sum(a['eligible'] for _,_,a in primary),
            'successful':sum(a['successful'] for _,_,a in primary),
            'blocked':sum(bool(r and r.get('status')=='BLOCKED') for _,r,_ in primary),
            'cancelled':sum(bool(r and r.get('termination',{}).get('reason')=='cancelled') for _,r,_ in primary),
            'controller_lost':sum(bool(r and r.get('controller_interruption',{}).get('kind')=='controller_lost') for _,r,_ in primary),
            'assisted_primaries':sum(bool(r and r.get('assistance',{}).get('status')=='assisted') for _,r,_ in primary),
            'retries':sum(max(0,len(row['attempts'])-1) for row in rows),'attempts':len(all_attempts)}
    counts['not_started']=counts['planned']-counts['started'];counts['incomplete']=counts['started']-counts['completed']
    counts['unscorable']=counts['planned']-counts['scorable'];counts['completed_unscorable']=counts['completed']-counts['scorable']
    counts['ineligible']=counts['planned']-counts['eligible']
    usage={name:stats([r.get('measurement',{}).get('usage',{}).get('categories',{}).get(name,{}).get('reported') if r else None for _,r,_ in primary]) for name in ('input','output','cache_read','cache_write','total')}
    timings=stats([r.get('measurement',{}).get('agent_process_seconds') if r else None for _,r,_ in primary])
    cohorts={}
    for name,predicate in [('retries',lambda x:x['attempt_index']>1),('assisted',lambda x:bool(x['result'] and x['result'].get('assistance',{}).get('status')=='assisted'))]:
        members=[(row,attempt) for row,attempt in all_attempts if predicate(attempt)]
        measurements=[(row,attempt,assessment(attempt['result'],expected[row['trial_id']],row['configuration_digest'])) for row,attempt in members]
        cohorts[name]={'attempts':len(members),'scorable':sum(a['scorable'] for _,_,a in measurements),'artifact_correct':sum(a['artifact_correct'] for _,_,a in measurements),
                       'scores':stats([x['result']['task_result']['score'] if a['scorable'] else None for _,x,a in measurements]),
                       'members':[{'trial_id':row['trial_id'],'attempt_id':x['attempt_id'],'attempt_index':x['attempt_index']} for row,x in members]}
    return {'counts':counts,'rates':{'primary_success_planned':rate(counts['successful'],counts['planned']),
                                   'artifact_success_scored':rate(counts['artifact_correct'],counts['scorable']),
                                   'completion_planned':rate(counts['completed'],counts['planned']),
                                   'score_coverage_planned':rate(counts['scorable'],counts['planned']),
                                   'eligibility_planned':rate(counts['eligible'],counts['planned'])},
            'artifact_scores':stats([r['task_result']['score'] if a['scorable'] else None for _,r,a in primary]),
            'attributable_scores':stats([r['task_result']['score'] if a['eligible'] else None for _,r,a in primary]),
            'primary_reported_usage':usage,'primary_agent_end_to_end_seconds':timings,'inference_seconds':None,'cohorts':cohorts,'trials':details}


def comparison(metadata,rows,expected):
    cases=[]
    for case in dict.fromkeys(row['case'] for row in rows):
        variants={}
        for variant in dict.fromkeys(row['variant'] for row in rows if row['case']==case):
            subset=[row for row in rows if row['case']==case and row['variant']==variant]
            variants[variant]=summarize_group(subset,expected)
        baseline=variants[metadata['baseline']]
        pairs=[]
        for candidate,group in variants.items():
            if candidate==metadata['baseline']:continue
            b={x['repetition']:x for x in baseline['trials']};c={x['repetition']:x for x in group['trials']}
            members=[]
            for repetition in range(metadata['repetitions']):
                left=b.get(repetition);right=c.get(repetition)
                compatible=bool(left and right and expected[left['trial_id']]['scorer']==expected[right['trial_id']]['scorer']
                                and expected[left['trial_id']]['snapshot_sha256']==expected[right['trial_id']]['snapshot_sha256']
                                and expected[left['trial_id']]['runner_content_sha256']==expected[right['trial_id']]['runner_content_sha256'])
                eligible=bool(compatible and left['eligible'] and right['eligible'])
                members.append({'repetition':repetition,'baseline_trial_id':left['trial_id'] if left else None,
                                'candidate_trial_id':right['trial_id'] if right else None,'compatible':compatible,'eligible':eligible,
                                'candidate_minus_baseline':right['score']-left['score'] if eligible else None})
            pairs.append({'candidate':candidate,'planned_pairs':metadata['repetitions'],'eligible_pairs':sum(x['eligible'] for x in members),
                          'score_differences':stats([x['candidate_minus_baseline'] for x in members]),'members':members})
        cases.append({'case':case,'baseline':metadata['baseline'],'variants':variants,'pairs':pairs})
    totals={key:sum(group['counts'][key] for case in cases for group in case['variants'].values()) for key in ('planned','started','completed','scorable','artifact_correct','eligible','successful','blocked','cancelled','controller_lost','unscorable','retries','attempts','not_started','incomplete','completed_unscorable')}
    return {'schema':1,'document_type':'experiment_comparison','experiment_id':metadata['experiment_id'],'name':metadata['name'],
            'primary_policy':'first; retries never replace it','evidence_scope':'contains_synthetic_fixtures' if any(a.get('result',{}).get('fixture_origin') for row in rows for a in row['attempts'] if a.get('result')) else 'recorded_attempts; live qualification requires matching receipts','scope':metadata.get('profile','builtin-only'),'counts_totals':totals,'cases':cases,
            'relationships':['planned = started + not_started','started = completed + incomplete','planned = scorable + unscorable',
                             'completed = scorable + completed_unscorable','successful <= eligible <= scorable <= completed <= started <= planned',
                             'blocked/cancelled/assisted are subsets of terminal primaries, not additive partitions'],
            'limits':['Artifact correctness does not establish model invocation.','Unknown values remain null; observed denominators accompany statistics.',
                      'Retries and assisted cohorts can overlap and never inflate primary counts.','Cases with different scorers are not averaged together.',
                      'No significance or improvement is inferred from these small samples.']}


def markdown(report):
    lines=[f"# {report['name']} application comparison",'',f"Experiment: `{report['experiment_id']}`. Primary selection: first attempt.",'',
           f"Evidence scope: {report['evidence_scope']}.",'',
           'Counts describe primary trials. Artifact success is diagnostic; verified autonomous success has its own planned denominator.','']
    for case in report['cases']:
        lines += [f"## Case: {case['case']}",'', '| Variant | Planned | Started | Terminal | Scored | Eligible | Clean success/planned | Artifact success/scored | Unscorable | Retries |',
                  '|---|---:|---:|---:|---:|---:|---|---|---:|---:|']
        for name,group in case['variants'].items():
            c=group['counts'];r=group['rates'];s=r['primary_success_planned'];a=r['artifact_success_scored']
            lines.append(f"| {name} | {c['planned']} | {c['started']} | {c['completed']} | {c['scorable']} | {c['eligible']} | {s['numerator']}/{s['denominator']} | {a['numerator']}/{a['denominator']} | {c['unscorable']} | {c['retries']} |")
        lines.append('')
        for pair in case['pairs']:
            lines.append(f"{pair['candidate']} vs {case['baseline']}: {pair['eligible_pairs']}/{pair['planned_pairs']} eligible pairs; mean paired score difference {pair['score_differences']['mean'] if pair['score_differences']['mean'] is not None else 'unknown'}.")
        lines += ['', '| Trial | Variant | Repeat | Primary status | Task | Score | Eligible | Evidence |','|---|---|---:|---|---|---|---|---|']
        for name,group in case['variants'].items():
            for trial in group['trials']:
                evidence=' '.join(f"[attempt {a['attempt_index']}]({a['result_path']})" for a in trial['attempts']) or 'unexecuted'
                lines.append(f"| {trial['trial_id']} | {name} | {trial['repetition']} | {trial['status']} | {trial['task_status']} | {trial['score'] if trial['score'] is not None else 'unknown'} | {trial['eligible']} | {evidence} |")
        lines.append('')
    lines += ['No significance or improvement claim is made. Inference timing and unknown usage remain unknown. Retries and assistance are separate from primary comparison.','']
    return '\n'.join(lines)


def expected_contracts(root,metadata,rows,lab):
    expected={}
    for row in rows:
        path=Path(root)/row['plan']
        import agent_profiles
        profile=agent_profiles.load(Path(root)/row['agent_profile']) if row.get('agent_profile') else agent_profiles.builtin()
        plan=lab.validate_plan(json.loads(path.read_text()),path.parent,profile)
        contract=plan['checks'][0]['scorer'];hashes={x['target']:hashlib.sha256(Path(x['source']).read_bytes()).hexdigest() for x in contract['assets']}
        oracle={'scorer_id':contract['id'],'scorer_version':contract['version'],'scorer_sha256':hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest(),'score_domain':contract['score_domain']}
        endpoint=lab.load_endpoint(Path(root)/row['endpoint'])
        expected[row['trial_id']]={'scorer':oracle,'endpoint_sha256':provenance.digest({k:v for k,v in endpoint.items() if k!='api_key_env'}),
                                  'snapshot_sha256':metadata['source_receipts'][row['case']]['snapshot_sha256'],
                                  'plan_sha256':row['plan_sha256'],'runner_content_sha256':metadata['runner_content_sha256'],
                                  'image':metadata['execution']['image'],'platform':metadata['execution']['platform'],
                                  'profile_explicit':row.get('profile_explicit',False),'agent_profile_id':row.get('agent_profile_id','builtin'),'agent_profile_sha256':row.get('agent_profile_sha256')}
    return expected
