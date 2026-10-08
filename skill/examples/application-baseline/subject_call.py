#!/usr/bin/env python3
"""One application call in a disposable interpreter; reports data, never a grade."""
import json
from pathlib import Path
import sys

request=json.loads(sys.stdin.read(16384))
sys.path.insert(0,str(Path.cwd()))
try:
    from slug import slugify
    value=b'bytes' if request['kind']=='bytes' else request['value']
    result={'kind':'return','value':slugify(value)}
except Exception as exc:result={'kind':'exception','type':type(exc).__name__}
print(json.dumps(result))
