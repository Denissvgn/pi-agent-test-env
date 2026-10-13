#!/usr/bin/env python3
"""Render fixed built-in versus explicitly selected fixture integration definitions."""
import argparse
import json
from pathlib import Path
import re
import sys
HERE=Path(__file__).resolve().parent
SKILL=HERE.parents[1]
sys.path.insert(0, str(SKILL/'runtime'))
import release_contracts


def definition(image, release='0.87.1'):
    release_contracts.contract(release)
    profile = 'profile.json' if release == '0.87.1' else 'profile.pi-1.2.0.json'
    return {'schema':1,'name':'fixture-integration','baseline':'builtin','repetitions':2,
            'cases':[{'name':'lookup','project':str(HERE/'project'),'plan':str(HERE/'lookup.plan.json')}],
            'variants':[{'name':'builtin','agent_profile':str(SKILL/'assets/profiles/builtin.json')},
                        {'name':'fixture','agent_profile':str(SKILL/'assets/profiles/fixture-lookup'/profile)}],
            'budgets':{'timeout_seconds':90,'max_turns':12,'max_total_tokens':60000},
            'execution':{'image':image,'platform':'linux/arm64','resources':str(SKILL/'assets/resources/low-impact.json')},
            'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'continue','max_attempts':1}}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image-receipt',required=True);p.add_argument('--output',required=True);args=p.parse_args()
    receipt=json.loads(Path(args.image_receipt).read_text())
    try: release = release_contracts.image_identity(receipt)['release']
    except ValueError as exc: p.error(str(exc))
    if not re.fullmatch('sha256:[a-f0-9]{64}',receipt.get('id','')) or receipt.get('platform')!='linux/arm64':p.error('Reviewed native ARM64 Pi receipt required')
    output=Path(args.output)
    if output.exists() or output.is_symlink():p.error('Output must be new; existing definitions preserved')
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(definition(receipt['id'], release),indent=2)+'\n')
    print(json.dumps({'definition':str(output),'image':receipt['id'],'scope':'one explicit fixture lookup integration; receipt is not a signature'}))
if __name__=='__main__':main()
