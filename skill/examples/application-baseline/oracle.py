#!/usr/bin/env python3
"""Independent eight-group oracle. Untrusted application runs in short child interpreters."""
import json
import os
from pathlib import Path
import subprocess
import sys

# Expected values are parsed only in this parent, which never imports the subject.
cases=json.loads(Path(__file__).with_name('cases.json').read_text())
bridge=Path(__file__).with_name('subject_call.py')


def call(value=None,kind='json'):
    result=subprocess.run([sys.executable,str(bridge)],input=json.dumps({'kind':kind,'value':value}),
                          capture_output=True,text=True,timeout=2)
    if result.returncode or len(result.stdout.encode())>16384:raise AssertionError('Application response failed/oversized')
    response=json.loads(result.stdout)
    if not isinstance(response,dict):raise AssertionError('Application response is not an object')
    return response


assertions=[]
for case in cases:
    passed=False
    try:
        for example in case.get('examples',[]):assert call(example['input'])=={'kind':'return','value':example['expected']}
        for invalid in case.get('invalid',[]):assert call(invalid)=={'kind':'exception','type':'TypeError'}
        if case['id']=='types':assert call(kind='bytes')=={'kind':'exception','type':'TypeError'}
        for value in case.get('values',[]):
            normalized=call(value)
            assert normalized.get('kind')=='return' and call(normalized['value'])==normalized
        passed=True
    except Exception as exc:print(case['id']+': '+type(exc).__name__,file=sys.stderr)
    assertions.append({'id':case['id'],'passed':passed})
passed=sum(x['passed'] for x in assertions);discovered=len(assertions)
success=discovered>0 and passed==discovered
print(json.dumps({'schema':1,'scorer_id':'ascii-slug-oracle','scorer_version':'1',
 'run_id':os.environ['PI_LAB_RUN_ID'],'attempt_id':os.environ['PI_LAB_ATTEMPT_ID'],
 'task_status':'pass' if success else 'fail','score':passed/discovered if discovered else 0,
 'test_counts':{'discovered':discovered,'passed':passed,'failed':discovered-passed,'skipped':0},'assertions':assertions}))
