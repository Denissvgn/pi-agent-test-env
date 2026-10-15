"""Parent-owned two-trial collection, deterministic records and sibling cancellation."""
import copy
import hashlib
from pathlib import Path
import signal
import time

import experiments
import stage_control as controls
from parallel_contract import ParallelError
from parallel_dispatch import Peer,launch_worker


def finalize(root,intent,path,lab):
    result=experiments.sealed_result(root,intent)
    if result is None:raise ParallelError('Worker exited without a sealed attempt')
    relative='runs/'+intent['run_id']+'/result.json'
    intent.update(status='finalized',result=relative,result_sha256=hashlib.sha256((root/relative).read_bytes()).hexdigest())
    controls.atomic(path,intent)
    return result


def collect(root,metadata,matrix,work,lab,registry,pool,session,inference,network_factory,network_cleanup,
            spawn=launch_worker,clock=time.monotonic):
    root=Path(root);contract=metadata['concurrency']
    state={'schema':2,'status':'running','active_attempts':{},'started_at':controls.now(),'controller_generation':registry.generation}
    controls.atomic(root/'state.json',state)
    experiments.directory(root,'runs');experiments.directory(root,'logs')
    active={};queued=list(work);completed=0;deadline=clock()+contract['collection_timeout_seconds'];cancel_started=None
    for cell in work:
        authorities=inference.get('authorities',{}).get(cell['trial_id'],[])
        pool.request(cell['trial_id'],{'credential_authorities':authorities},inference['worker_resources'],contract['queue_wait_seconds'])
    stopped=False;exit_code=0
    def persist():controls.atomic(root/'state.json',state)
    def stop(kind):
        nonlocal stopped,cancel_started,exit_code
        if stopped:return
        stopped=True;cancel_started=clock();pool.stop()
        state['status']=kind;exit_code=1 if kind=='halted' else 2
        if kind=='interrupted':state['interruption_kind']='explicit_controller_cancel'
        persist()
        for item in active.values():
            try:item['channel'].send({'op':'cancel'})
            except OSError:pass
    try:
        while active or queued and not stopped:
            if clock()>=deadline:stop('interrupted')
            while queued and len(active)<contract['max_trials'] and not stopped:
                if inference.get('admit'):inference['admit']()
                cell=queued[0];identity=cell['trial_id']
                binding={'generation':registry.generation,'trial_id':identity,'image':metadata['execution']['image'],
                         'release_contracts':metadata['release_contracts'],'daemon':getattr(registry,'daemon',None)}
                reservation=pool.records[identity]
                grants=pool.dispatch()
                if reservation.state=='expired':
                    raise ParallelError('Frozen trial queue deadline exceeded')
                if reservation.state!='reserved':break
                binding['credential_authorities']=reservation.binding.get('credential_authorities',[])
                previous=experiments.attempt_intents(root,cell)
                intent,path=experiments.reserve_attempt(root,metadata,cell,len(previous)+1,previous[-1]['attempt_id'] if previous else None)
                binding.update(run_id=intent['run_id'],attempt_id=intent['attempt_id'],workspace=str(root/'runs'/intent['run_id']/'workspace'))
                # The reference inside the parent reservation was copied on request.
                reservation.binding=copy.deepcopy(binding)
                state['active_attempts'][intent['attempt_id']]={'trial_id':identity,'run_id':intent['run_id']};persist()
                runroot=root/'runs'/intent['run_id']
                network=network_factory(intent)
                bootstrap={'experiment':str(root),'intent':intent,'session':session,'network':network,
                           'capability':reservation.capability,'inference':inference['trial'](intent),
                           'credentials':inference.get('credentials',{}).get(identity,{})}
                if inference.get('indexed'):
                    bootstrap['indexed']=inference['indexed'](cell,intent)
                    bootstrap['secret_variable_names']=inference.get('secret_variable_names',[])
                output=(root/'logs'/(intent['attempt_id']+'.txt')).open('w')
                peer=Peer(bootstrap,registry,pool,reservation,metadata,runroot)
                if inference.get('stage_admission'):
                    peer.indexed_stage=lambda name,renew=False,identity=identity:inference['stage_admission'](identity,name,renew)
                    peer.indexed_release=lambda identity=identity:inference['stage_release'](identity)
                try:process,channel=spawn(bootstrap,output,registry.lease_fd)
                except BaseException:output.close();raise
                active[identity]={'intent':intent,'path':path,'process':process,'channel':channel,'peer':peer,'output':output,'network':network}
                queued.pop(0)
            for identity,item in list(active.items()):
                channel=item['channel']
                # Authoritative launch/cleanup writes are serialized here, not in children.
                if channel.ready():
                    try:message=channel.receive(.2)
                    except EOFError:message=None
                    if message is not None:
                        rejected=False
                        try:reply=item['peer'].handle(message)
                        except (ParallelError,ValueError,OSError) as exc:
                            import indexed_contract
                            diagnostic=indexed_contract.diagnostic(exc)
                            reply={'op':'rejected',**({'reason':diagnostic['reason']} if diagnostic else {})};rejected=True
                        try:channel.send(reply)
                        except OSError:pass
                        if rejected:stop('blocked')
                if item['process'].poll() is None:continue
                if inference.get('stage_release'):inference['stage_release'](identity)
                try:
                    result=finalize(root,item['intent'],item['path'],lab)
                    known=experiments.cleanup_known(root,item['intent'],result)
                    physical=all(r['status']=='absent' for r in item['peer'].records) and item['peer'].active is None
                    network_cleanup(item['network'])
                    if not pool.release(identity,physical,known):stop('blocked')
                    else:
                        for record in item['peer'].records:registry.release(record,True)
                    completed+=1
                    if result['status']=='INTERRUPTED':stop('interrupted')
                    elif result['status']!='PASS' and metadata['policies']['on_failure']=='stop':stop('halted')
                except (ParallelError,ValueError,OSError):
                    stop('blocked')
                finally:
                    item['output'].close();channel.sock.close();state['active_attempts'].pop(item['intent']['attempt_id'],None)
                    del active[identity];persist()
            if cancel_started is not None and clock()-cancel_started>=30:
                for item in active.values():
                    item['process'].kill()
                    item['process'].wait(timeout=5)
                # Crash reconciliation will independently match/stop every writer.
                registry.reconcile()
            if active or queued and not stopped:time.sleep(.02)
    except KeyboardInterrupt:
        stop('interrupted')
        cancellation_deadline=clock()+30
        for item in active.values():item['process'].send_signal(signal.SIGINT)
        while active and clock()<cancellation_deadline:
            for identity,item in list(active.items()):
                if item['channel'].ready():
                    try:
                        message=item['channel'].receive(.2);reply=item['peer'].handle(message)
                        item['channel'].send(reply)
                    except (EOFError,OSError,ValueError):pass
                if item['process'].poll() is None:continue
                if inference.get('stage_release'):inference['stage_release'](identity)
                try:
                    result=finalize(root,item['intent'],item['path'],lab)
                    physical=all(r['status']=='absent' for r in item['peer'].records) and item['peer'].active is None
                    known=experiments.cleanup_known(root,item['intent'],result)
                    network_cleanup(item['network'])
                    if pool.release(identity,physical,known):
                        for record in item['peer'].records:registry.release(record,True)
                    completed+=1;state['active_attempts'].pop(item['intent']['attempt_id'],None)
                except (ValueError,OSError):state['status']='blocked'
                finally:item['output'].close();item['channel'].sock.close();del active[identity]
            if active:time.sleep(.02)
        if active:
            for item in active.values():
                item['process'].kill();item['process'].wait(timeout=5);item['output'].close();item['channel'].sock.close()
            registry.reconcile()
    except BaseException:
        stop('blocked')
        for identity,item in active.items():
            if inference.get('stage_release'):inference['stage_release'](identity)
            item['process'].kill();item['process'].wait(timeout=5);item['output'].close();item['channel'].sock.close()
        registry.reconcile()
        raise
    if not stopped:state['status']='completed'
    persist()
    return {'schema':2,'experiment_id':metadata['experiment_id'],'status':state['status'],'planned':len(matrix['cells']),
            'completed_this_call':completed,'exit_code':exit_code}
