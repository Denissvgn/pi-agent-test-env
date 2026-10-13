#!/usr/bin/env python3
"""Render explicit definitions from a user-reviewed native image capability receipt."""
import argparse
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
SKILL=HERE.parents[1]
sys.path.insert(0, str(SKILL/'runtime'))
import release_contracts


def definitions(image, release='0.87.1'):
    release_contracts.contract(release)
    common={'schema':1,'name':'slug-baseline','baseline':'baseline','repetitions':2,
            'cases':[{'name':'slug','project':str(HERE/'project'),'plan':str(HERE/'application.plan.json')},
                     {'name':'cutoff','project':str(HERE/'project'),'plan':str(HERE/'cutoff.plan.json'),
                      'budgets':{'timeout_seconds':5,'max_turns':12,'max_total_tokens':60000}}],
            'variants':[{'name':'baseline'},{'name':'candidate','prompt_suffix':'Before editing, reason through input type errors, Unicode lowercase versus casefold, ASCII filtering, separator runs, empty input and idempotence. Implement the general rules and verify the provided tests.'}],
            'budgets':{'timeout_seconds':120,'max_turns':12,'max_total_tokens':60000},
            'execution':{'image':image,'platform':'linux/arm64','resources':str(SKILL/'assets/resources/low-impact.json')},
            'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'continue','max_attempts':2}}
    resume=json.loads(json.dumps(common));resume.update(name='slug-resume-demonstration',repetitions=1,cases=[common['cases'][0]])
    return {'baseline.experiment.json':common,'resume.experiment.json':resume}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image-receipt',required=True);p.add_argument('--output-dir',required=True)
    args=p.parse_args();receipt=json.loads(Path(args.image_receipt).read_text())
    try: release = release_contracts.image_identity(receipt)['release']
    except ValueError as exc: p.error(str(exc))
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',receipt.get('id','')) or receipt.get('platform')!='linux/arm64':
        p.error('Requires a reviewed native ARM64 Pi capability receipt; no release/image substitution')
    target=Path(args.output_dir).expanduser().absolute()
    if target.exists():p.error('Use a new output directory; existing definitions are preserved')
    target.mkdir(parents=True)
    for name,value in definitions(receipt['id'], release).items():(target/name).write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps({'definitions':str(target),'image':receipt['id'],'trust':'Receipt identifies the selected image; review provenance and qualify it before execution.'},indent=2))

if __name__=='__main__':main()
