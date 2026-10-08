#!/usr/bin/env python3
"""Independent artifact oracle; never imports/evaluates application or extension code."""
import json
import os
from pathlib import Path
expected=json.loads(Path(__file__).with_name('expected.json').read_text())
try:
    file=Path.cwd()/'answer.json'
    if file.is_symlink() or file.stat().st_size>16384:raise ValueError('Unsafe/oversized answer')
    actual=json.loads(file.read_text())
except (OSError,ValueError):actual=None
assertions=[{'id':'shape','passed':isinstance(actual,dict) and set(actual)==set(expected)}]
assertions.extend({'id':key,'passed':isinstance(actual,dict) and actual.get(key)==value} for key,value in expected.items())
passed=sum(x['passed'] for x in assertions);success=passed==len(assertions)
print(json.dumps({'schema':1,'scorer_id':'fixture-answer','scorer_version':'1','run_id':os.environ['PI_LAB_RUN_ID'],'attempt_id':os.environ['PI_LAB_ATTEMPT_ID'],
 'task_status':'pass' if success else 'fail','score':passed/len(assertions),'test_counts':{'discovered':len(assertions),'passed':passed,'failed':len(assertions)-passed,'skipped':0},'assertions':assertions}))
