"""Versioned attempt records and one-way finalization, independent of Docker."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

import stage_control as controls


def initial():
    return {'schema':2,'document_type':'run_result','run_id':str(uuid.uuid4()),
            'attempt_id':str(uuid.uuid4()),'experiment_id':None,'trial_id':None,
            'attempt_index':1,'retry_of_attempt_id':None,'status':'RUNNING',
            'started_at':controls.now(),'run_dir':None,'workspace':None,
            'infrastructure':{'status':'not_started','phase':'evidence_destination','reason':None},
            'invocation':{'status':'not_started','attempted_stages':0},
            'termination':{'reason':'not_started','trigger':None,'process_exit_code':None},
            'scoring':{'status':'not_started','reason':None,'results':[]},
            'task_result':{'status':'unknown','score':None,'test_counts':None},
            'assistance':{'status':'autonomous','intervention_ids':[]},
            'protected_inputs':{'status':'unknown'},'agents':[],'checks':[],'sealed':False}


def status(record):
    if record['termination']['reason']=='cancelled':return 'INTERRUPTED',2
    if record['infrastructure']['status']!='ready' and record['invocation']['status']=='not_started':return 'BLOCKED',2
    gates=(record['infrastructure']['status']=='ready' and record['termination']['reason']=='completed'
           and record['invocation']['status'] in ('verified','recovered')
           and record['scoring']['status']=='completed' and record['task_result']['status']=='pass'
           and record['protected_inputs']['status']=='unchanged')
    if not gates:return 'FAIL',1
    if record['invocation']['status']=='recovered':return 'RECOVERED',1
    if record['assistance']['status']=='assisted':return 'ASSISTED',1
    return 'PASS',0


class Attempt:
    def __init__(self,args,record=None):
        self.record=record or initial();self.root=None;self.sealed=None
        # Validate lexical and canonical placement before creating any evidence.
        destination=Path(args.results_dir).expanduser().absolute()
        project=Path(args.project).expanduser().absolute() if getattr(args,'project',None) else None
        canonical=destination.resolve()
        if project:
            project_root=project.resolve()
            if any(p==project_root or project_root in p.parents or p==project or project in p.parents for p in (destination,canonical)):
                raise ValueError('unsafe-evidence-destination')
        # Resolve trusted host aliases once; every subsequent component is opened no-follow.
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in canonical.parts[1:]:
                try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                except FileNotFoundError:
                    os.mkdir(part,0o700,dir_fd=parent)
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                os.close(parent);parent=child
            name=self.record['run_id']
            os.mkdir(name,0o700,dir_fd=parent)
            self.root=canonical/name;self.record['run_dir']=str(self.root)
        finally:os.close(parent)
        controls.atomic(self.root/'identity.json',{k:self.record[k] for k in ('schema','run_id','attempt_id')})
        self.persist()
        latest=canonical/'latest'
        try:
            if latest.is_symlink():latest.unlink()
            if not latest.exists():latest.symlink_to(self.root)
        except OSError:pass

    @classmethod
    def attach_unsealed(cls,root,record):
        """Parent recovery only, after exclusive leases and independently confirmed cleanup."""
        root=Path(root)
        if root.is_symlink() or (root/'result.json').exists():raise controls.ControlError('Cannot attach sealed/linked attempt')
        identity=controls.read(root/'identity.json')
        if any(identity.get(k)!=record.get(k) for k in ('run_id','attempt_id')):raise controls.ControlError('Recovery identity mismatch')
        result=cls.__new__(cls);result.root=root;result.record=copy.deepcopy(record);result.sealed=None
        result.record['sealed']=False
        return result

    def persist(self):
        if self.sealed is None:controls.atomic(self.root/'summary.json',self.record)

    def cause(self,reason,exit_code=None):
        term=self.record['termination']
        if term['reason'] in ('not_started','completed') or reason in ('cleanup_error','cancelled'):
            if term['reason'] not in ('not_started','completed',reason):term['trigger']=term['reason']
            term['reason']=reason
        if exit_code is not None:term['process_exit_code']=exit_code

    def process(self,result):
        reason=result.get('termination_reason') or ('completed' if result.get('exit_code')==0 else 'process_error')
        if reason=='cleanup_error' and result.get('termination_trigger'):self.cause(result['termination_trigger'],result.get('exit_code'))
        if result.get('exit_code') or reason!='completed':self.cause(reason,result.get('exit_code'))
        if result.get('cleanup_confirmed') is False:self.cause('cleanup_error')

    def fail(self,exc):
        self.record['infrastructure']['status']='failed'
        self.record['infrastructure']['reason']=getattr(exc,'reason','') or type(exc).__name__
        # Keep diagnostic identifiers, never raw exception text/keys/URLs.
        if getattr(exc,'remedy',''):self.record['infrastructure']['remedy']=exc.remedy
        self.record['infrastructure']['error_digest']=hashlib.sha256(str(exc).encode()).hexdigest()
        if self.record['scoring']['status']=='not_started':
            self.record['scoring'].update(status='skipped',reason='infrastructure_failure')
        elif self.record['scoring']['status']=='running':
            self.record['scoring'].update(status='error',reason='scorer_execution_failed')

    def cancel(self):
        self.cause('cancelled')
        scoring=self.record['scoring']
        if scoring['status']=='running':scoring.update(status='cancelled',reason='user_cancelled')
        elif scoring['status']=='not_started':scoring.update(status='skipped',reason='user_cancelled')

    def finalize(self):
        if self.sealed is not None:return copy.deepcopy(self.sealed)
        path=self.root/'result.json'
        with controls.lock(self.root):
            if path.exists():
                saved=controls.read(path)
                if saved.get('attempt_id')!=self.record['attempt_id'] or not saved.get('sealed'):
                    raise controls.ControlError('Invalid sealed result identity')
                self.sealed=saved
                return copy.deepcopy(self.sealed)
            self.record['assistance']=controls.assistance(self.root)
            self.record['status'],self.record['exit_code']=status(self.record)
            self.record.update(sealed=True,finished_at=controls.now())
            encoded=(json.dumps(self.record,ensure_ascii=False,indent=2)+'\n').encode()
            temp=path.with_name('.result-'+uuid.uuid4().hex)
            published=False
            try:
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as f:f.write(encoded);f.flush();os.fsync(f.fileno())
                os.rename(temp,path);published=True
                parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent)
                finally:os.close(parent)
            except Exception:
                if published:path.unlink()
                self.record['sealed']=False
                raise
            finally:temp.unlink(missing_ok=True)
            self.sealed=copy.deepcopy(self.record)
        # The sealed result is authoritative even if the compatibility view fails.
        try:controls.atomic(self.root/'summary.json',self.sealed)
        except (OSError,ValueError,controls.ControlError):
            import sys
            print(json.dumps({'schema':2,'attempt_id':self.record['attempt_id'],
                              'reason':'progress_view_unavailable','result_persisted':True}),file=sys.stderr)
        return copy.deepcopy(self.sealed)


def fallback(record,phase,reason):
    result=copy.deepcopy(record)
    result.update(status='BLOCKED',exit_code=2,sealed=False,persistence='unavailable')
    result['infrastructure'].update(status='failed',phase=phase,reason=reason)
    result['scoring'].update(status='skipped',reason='evidence_unavailable')
    # An ID and sanitized dimensions are retained even if no file could be saved.
    return {k:result[k] for k in ('schema','document_type','run_id','attempt_id','status','exit_code',
                                 'infrastructure','invocation','termination','scoring','task_result','persistence')}
