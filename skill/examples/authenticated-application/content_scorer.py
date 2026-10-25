#!/usr/bin/env python3
"""Content-only structured scorer; identity/effects/report proof belong to oracle."""
import json
import os
from pathlib import Path
import stat


def score(workspace,expected_path=None):
    expected_path=Path(expected_path or Path(__file__).with_name('expected.json'))
    expected=json.loads(expected_path.read_text(encoding='utf-8'))
    path=Path(workspace)/expected['summary_path'];passed=False
    try:
        root=os.open(Path(workspace),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            parent=os.open('outputs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
            try:
                fd=os.open('summary.md',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                with os.fdopen(fd,'rb') as stream:
                    before=os.fstat(stream.fileno());body=stream.read(16385);after=os.fstat(stream.fileno())
                    passed=(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=16384
                        and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                        and body==expected['content'].encode('utf-8'))
            finally:os.close(parent)
        finally:os.close(root)
    except OSError:pass
    return {'schema':1,'scorer_id':'authenticated-summary-content','scorer_version':'1',
        'run_id':os.environ.get('PI_LAB_RUN_ID',''),'attempt_id':os.environ.get('PI_LAB_ATTEMPT_ID',''),
        'task_status':'pass' if passed else 'fail','score':int(passed),
        'test_counts':{'discovered':1,'passed':int(passed),'failed':int(not passed),'skipped':0},
        'assertions':[{'id':'content','passed':passed}]}


if __name__=='__main__':print(json.dumps(score(Path.cwd())))
