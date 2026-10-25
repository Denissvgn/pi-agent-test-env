"""Key-free immutable configuration identities and bounded, untrusted emission receipts."""
import hashlib
import json
import os
from pathlib import Path
import stat
import application_credentials
import release_contracts


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def execution(endpoint,image,root):
    runner={}
    for folder in ('scripts','runtime'):
        for path in sorted((root/folder).rglob('*')):
            if path.is_file() and not path.is_symlink() and '__pycache__' not in path.parts:
                runner[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    safe={k:v for k,v in endpoint.items() if k!='api_key_env'}
    observed_pi = image.get('capabilities', {}).get('pi')
    selected = release_contracts.identity(observed_pi) if observed_pi in release_contracts.RELEASES else None
    return {'schema':1,'configuration_sha256':digest(safe),'credential_identity':'excluded',
            'release_contract':selected,
            'runner_content_sha256':digest(runner),'runner_files':runner,
            'image':{k:image.get(k) for k in ('id','platform','repo_digests')},
            'pi_version':image.get('capabilities',{}).get('pi'),
            'server':{'origin':'user_declared' if endpoint.get('server_provenance') else 'unknown',
                      'values':{k:endpoint.get('server_provenance',{}).get(k) for k in ('engine','version','weights','quantization','configuration_digest')}},
            'effective_prompts':'per-segment provenance.emitted; worker-reported, not server attestation',
            'seed_replay':'not_guaranteed'}


def collect_emitted(runtime,logs,secret='',application_secrets=(),*,application=False):
    """After cleanup only. No-follow each ancestor; no authority is derived from child files."""
    artifacts={}
    names=('effective-prompt.txt','effective-configuration.json','agent/models.json','agent/settings.json')
    if application:names+=('application-prompt.json',)
    for name in names:
        parent=None
        try:
            parent=os.open(runtime,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            parts=Path(name).parts
            for part in parts[:-1]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=child
            fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            with os.fdopen(fd,'rb') as handle:
                info=os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>2*1024*1024:raise ValueError('unsafe emission file')
                body=handle.read(2*1024*1024+1)
            redactor = application_credentials.Redactor([secret, *application_secrets])
            if redactor.contains(body):raise ValueError('credential found in emission')
            path=logs/('emitted-'+name.replace('/','-'));path.write_bytes(body)
            artifacts[name]={'sha256':hashlib.sha256(body).hexdigest(),'path':str(path),'origin':'worker_reported'}
        except (OSError,ValueError):artifacts[name]={'status':'unavailable_or_unsafe'}
        finally:
            if parent is not None:os.close(parent)
    return artifacts
