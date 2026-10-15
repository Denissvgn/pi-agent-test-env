"""Maintainer-only prelaunch counters and deadline clipping for the frozen intent."""
import fcntl,json,os,subprocess,sys,time
from pathlib import Path


def charge(root,phase,argv,now=None):
    root=Path(root);now=time.monotonic() if now is None else now
    fd=os.open(root/'budget.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        value=json.loads((root/'budget.json').read_text());policy=json.loads((root/'manifest.json').read_text())['launch_derivation']
        if phase!=value['phase']:raise ValueError('Qualification phase mismatch')
        if now>=min(value['whole_deadline'],value['phase_deadline']):raise TimeoutError('Frozen qualification deadline')
        kind='containers' if argv[:1]==['run'] else 'networks' if argv[:2]==['network','create'] else None
        if argv[:1] in (['build'],['buildx'],['pull']):raise ValueError('Qualification admits reused images only')
        if kind and value.get('cleanup'):raise ValueError('No launch during cleanup')
        if kind:
            if kind=='containers' and ('--platform' not in argv or argv[argv.index('--platform')+1]!='linux/arm64'):raise ValueError('Native ARM64 launch required')
            kinds=[kind]
            if kind=='containers' and '/opt/pi-lab/worker.py' in argv and argv[argv.index('/opt/pi-lab/worker.py')+1:][:1]==['agent']:kinds.append('segments')
            for charge_kind in kinds:
                if value['counts'][phase].get(charge_kind,0)>=policy[phase][charge_kind] or sum(v.get(charge_kind,0) for v in value['counts'].values())>=policy['whole'][charge_kind]:raise ValueError('Frozen launch ceiling exhausted')
            for charge_kind in kinds:value['counts'][phase][charge_kind]=value['counts'][phase].get(charge_kind,0)+1
            temporary=root/'.budget-next';temporary.write_text(json.dumps(value));os.replace(temporary,root/'budget.json')
        return max(.01,min(value['whole_deadline'],value['phase_deadline'])-now),value['docker']
    finally:os.close(fd)


def main():
    remaining,docker=charge(os.environ['PI_INDEXED_QUALIFICATION_ROOT'],os.environ['PI_INDEXED_QUALIFICATION_PHASE'],sys.argv[1:])
    try:return subprocess.run([docker,*sys.argv[1:]],timeout=remaining).returncode
    except subprocess.TimeoutExpired:return 124

if __name__=='__main__':sys.exit(main())
