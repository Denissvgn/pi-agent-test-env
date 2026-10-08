#!/usr/bin/env python3
"""Example parent-approved scorer. Exit 0 means measurement completed, not task pass."""
import json
import os
from pathlib import Path

value=Path('/workspace/answer.txt')
passed=value.is_file() and not value.is_symlink() and value.read_text().strip()=='42'
print(json.dumps({'schema':1,'scorer_id':'answer-artifact','scorer_version':'1',
    'run_id':os.environ['PI_LAB_RUN_ID'],'attempt_id':os.environ['PI_LAB_ATTEMPT_ID'],
    'task_status':'pass' if passed else 'fail','score':1 if passed else 0,'test_counts':None,
    'assertions':[{'id':'answer','passed':passed}]}))
