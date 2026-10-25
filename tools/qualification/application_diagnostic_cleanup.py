"""One retained FAILED startup diagnostic, with separately reviewed hygiene.

No terminal is repaired and no process, container, credential or cleanup action
is performed here. The late metadata release is reporting, not continued timed
execution. Every call rereads the sealed proof graph and current Registry/PID/
private-path witnesses; dispatch still performs its existing fresh daemon check.
"""
import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path
import stat
import time
import zipfile

import application_launch as launch
import application_campaign as campaign
import application_amendment as amendment
import ownership_registry as ownership

REPO = Path(__file__).resolve().parents[2]
CAMPAIGN = REPO/'reports/application-agent-enhancements/A15/campaign-004'
ROOT = CAMPAIGN/'startup-diagnostic-001'
KNOWN_ROOT = CAMPAIGN/'diagnostic-known-cleanup-001'
KNOWN_PATH = KNOWN_ROOT/'known-cleanup.json'
REVIEW_PATH = KNOWN_ROOT/'independent-review.json'
REVIEW_CLASSIFICATION = 'failed diagnostic hygiene overlay reviewed; no native success or timed accounting completion'
QUALIFICATION_ID = '923bfc8b-594b-4df9-ae80-b7d0ebcdb945'
LAUNCH_ID = 'e049b004-7407-4e08-9f4a-a928856d0685'
NETWORK_ID = '7a2cd3b5-7f41-49d3-8c55-39b5c0d7bf98'
CONTAINER_ID = '45a0f924449c680cd17e147c7a7d8895741828ca29a993e3cf4610b01c9cb198'
MARKER_MTIME_NS = 1792316177310682056
NETWORK_MTIME_NS = 1792316204042725639
NETWORK_CTIME_NS = 1792316204042815806
ARCHIVE = REPO/'reports/application-agent-enhancements/A14/attempt-016/build-candidate/archives/pi-agent-test-env-source-4.5.0.zip'
ARCHIVE_SHA = 'a9430ecb2bd6ca5603cd4cf10ebfb76346b82581fd2f09806a23aaaebb0f61e4'
FROZEN_SOURCES = {
    'tools/qualification/application_startup_diagnostic.py': 'a32c0aa691329a12308ae51a902053433707c9a933954438e7daf467b3c3c505',
    'tools/qualification/application_launch.py': 'e78310aea9fed2e5d2d673ea2fd62fe1cf2b00a3a04eb871b298f1bdc70fbcf1',
    'skill/scripts/application_client.py': '15319a5e798cd3f392f53eceda377fb8015c83f68fb00753232597fef516efe6',
    'skill/scripts/ownership_registry.py': '0a64ab2d51e9acc86d047ca2398a61e5e96e2085efb9e373346b253a071ef0b8',
}
STATIC = {
    'manifest': (ROOT/'manifest.json', 'e3557ce0afa152d0bf735b3aa740b30bfb183c5ad7787a783a7c90e02bb2ea1a'),
    'ledger': (ROOT/'launch-ledger/ledger.json', 'a20560d07bee8af7d671dba4598502a8beb1baa4da8395d1443fa9ca320d31f2'),
    'failure': (ROOT/'failure.json', '9a91d13ea3637f3ee7bd69831a623335f08ded096e724132a598850c0c14defc'),
    'timing': (ROOT/('identity-timing-'+LAUNCH_ID+'.json'), '68fa71a154bd5933fe316d082dd7c50dd927744bffc3aef71d62f654d86dc021'),
    'command': (CAMPAIGN/'startup-diagnostic-command-002/verification.json', '18bf8e4e7e868bf35dd944a2817091dffd02a42c5ab718d9f39d6f77a5ad6dde'),
    'observation': (CAMPAIGN/'diagnostic-terminal-observation-001/proof.json', '0270f82bd83c2ac589de98e876756af1fb9f1d8887984455a12ebf0d5a836f97'),
    'claim': (CAMPAIGN/'startup-diagnostic-claim/claim.json', 'e2bb8a7a22c9f526813b383a5bf678e7271ee334c34aea3ca57ae63e8dd549c6'),
    'marker': (ROOT/'run/application-startup/pi-application-a3ae1471e6c84133.json', 'c89810cf9f20aef0acc1a421e49f298d7f492858ecc2d856dd05048ad4b6ceb7'),
}
KNOWN_FIELDS = {'schema','document_type','authorization','qualification_id','manifest','ledger','failure','timing','command','observation',
    'metadata_release','startup_marker','network_record_before','driver_status','cleanup_accounting','native_success_attested',
    'diagnostic_terminal_absent','raw_ledger_preserved'}
RELEASE_FIELDS = {'schema','document_type','status','authorization','qualification_id','program','source_review','observation','bounds_review',
    'manifest','ledger','original_helper_record','released_helper_record','helper_registry_record','released_network_record','network_registry_record',
    'container_id','host_pid','host_pid_absent','private_absence','docker_observations','original_lease_held','lease_inode_unchanged','new_container_launches',
    'participant_segments','cumulative_container_launches','resource_mutations','registry_status_changes','raw_ledger_preserved',
    'driver_terminal_absent','metadata_only_reporting','elapsed_seconds','completed_wall'}


def require(value):
    if not value:
        raise launch.LaunchError('qualification_diagnostic_cleanup_invalid')


def _ref(path, sha):
    return {'path':str(path),'sha256':sha}


def _public(reference):
    launch._exact(reference, {'path','sha256'});launch._sha(reference['sha256'])
    path=launch._canonical_root(reference['path'])
    require(path.is_relative_to(REPO/'reports/application-agent-enhancements'))
    value=amendment._reference(reference)
    def finite(item,depth=0):
        require(depth<=64)
        if type(item) is float:require(math.isfinite(item))
        elif type(item) is dict:
            for child in item.values():finite(child,depth+1)
        elif type(item) is list:
            for child in item:finite(child,depth+1)
    finite(value)
    return value


def _public_ref(path):
    # Public review/proof publication may legitimately use0644. The strict
    # public reader below still requires owner/no022 and stable nofollow FDs.
    return _ref(path,hashlib.sha256(_bytes(path,launch.MAX_BYTES)[0]).hexdigest())


def _bytes(path, maximum=64*1024*1024):
    parent=launch._dir(Path(path).parent,False)
    try:
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid()
                and not stat.S_IMODE(before.st_mode)&0o022 and before.st_size<=maximum)
            body=stream.read(maximum+1);after=os.fstat(stream.fileno());named=os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(len(body)==before.st_size and identity(before)==identity(after)==identity(named))
        return body,before
    finally:
        os.close(parent)


def _terminal_absent():
    # lexists semantics: an invalid or dangling terminal is never an exception.
    parent=launch._dir(ROOT,False)
    try:
        try:os.stat('terminal.json',dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:return
        require(False)
    finally:os.close(parent)


def _source_order():
    body,_=_bytes(ARCHIVE)
    require(hashlib.sha256(body).hexdigest()==ARCHIVE_SHA)
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        for name,expected in FROZEN_SOURCES.items():
            require(hashlib.sha256(archive.read('pi-agent-test-env-source/'+name)).hexdigest()==expected)


def _metadata(info):
    return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),
        'nlink':info.st_nlink,'size':info.st_size,'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}


def _proofs(value):
    result={}
    for name,(path,sha) in STATIC.items():
        reference=_ref(path,sha)
        if name not in ('claim','marker'):require(value[name]==reference)
        result[name]=_public(reference)
    _source_order()
    return result


def _validate_history(value, proofs, carry, authority, base, clock, wall):
    import application_followup as followup
    manifest,ledger,command,observation=map(proofs.get,('manifest','ledger','command','observation'))
    require(value['schema']==1 and type(value['schema']) is int and value['document_type']=='qualification_failed_startup_diagnostic_known_cleanup'
        and value['authorization']==authority and value['qualification_id']==QUALIFICATION_ID
        and value['driver_status']=='BLOCKED' and value['cleanup_accounting']=='FAILED' and value['native_success_attested'] is False
        and value['diagnostic_terminal_absent'] is True and value['raw_ledger_preserved'] is True)
    require(proofs['failure']=={'continuation_authorized':False,'diagnostic_outcome':'startup_failed','qualification_eligible':False,
        'raw_evidence_preserved':True,'schema':1,'status':'BLOCKED'})
    followup.validate_diagnostic_manifest(manifest)
    require(manifest['qualification_id']==QUALIFICATION_ID and manifest['predecessor']==base and manifest['campaign_amendment']==authority)
    verifier=object.__new__(launch.LaunchLedger);verifier.root=ROOT/'launch-ledger';verifier.manifest=manifest
    verifier.expected_daemon=None;verifier.expected_capacity=None;verifier._carry=None;verifier._prevalidated_carry=carry;verifier.clock=clock;verifier.wall=wall
    verifier._validate(ledger)
    require(ledger['poisoned'] is True and len(ledger['launches'])==1 and ledger['daemon']==carry['daemon'])
    row=ledger['launches'][0]
    require(row['role']=='application-helper' and row['cell']==followup.DIAGNOSTIC_CELL and row['launch_id']==LAUNCH_ID
        and row['container_id']==CONTAINER_ID and row['physical']=='uncertain' and row['private_cleanup'] is False
        and row['cleanup_requests']==[{'effective_target':'immutable_id','operation':'rm','requested_target':'immutable_id'}])
    require(type(command['actual_exit']) is int and command['actual_exit']==2 and command['expected_exit']==0
        and command['cwd']==str(REPO) and command['argv'][:3]==['python3','-B','tools/qualification/application_startup_diagnostic.py'])
    launch._number(command['started_wall']);elapsed=launch._number(command['elapsed_seconds'])
    require(0<elapsed<=120 and command['started_wall']<=manifest['diagnostic']['started_wall']
        and command['started_wall']+elapsed>=ledger['last_wall'])
    timing=proofs['timing']
    require(timing['terminal'] is True and timing['native_success_attested'] is False and timing['deadline_changed'] is False
        and type(timing['extra_dispatches']) is int and timing['extra_dispatches']==0
        and timing['runtime_identity_seconds']==5 and timing['guard_capture_seconds']==5
        and timing['identity_deadline_already_expired_at_entry'] is True and timing['identity_bind_outcome']=='raised'
        and launch._number(timing['identity_bind_remaining_seconds_at_entry'])<0
        and timing['identity']=={'cell_id':followup.DIAGNOSTIC_CELL,'kind':'startup_diagnostic','launch_id':LAUNCH_ID,'scope_id':QUALIFICATION_ID}
        and timing['source_hashes']=={'guard':FROZEN_SOURCES['tools/qualification/application_launch.py'],
            'runtime':FROZEN_SOURCES['skill/scripts/application_client.py'],'orchestrator':FROZEN_SOURCES['tools/qualification/application_startup_diagnostic.py']})
    require(observation['manifest']==value['manifest'] and observation['raw_ledger_sha256']==value['ledger']['sha256']
        and observation['original_lease_held'] is True and observation['cumulative_container_launches']==76
        and observation['participant_segments']==0 and observation['new_container_launches']==0 and observation['raw_ledger_unchanged'] is True
        and observation['host_pid']==row['pid'] and observation['host_pid_absent'] is True)
    now,wallnow=launch._number(clock()),launch._number(wall())
    require(now>=ledger['last_now'] and wallnow>=observation['observed_wall'] and wallnow>=command['started_wall']+elapsed)
    return row


def _validate_resource_order(value, proofs):
    marker=value['startup_marker'];launch._exact(marker,{'path','sha256','device','inode','uid','mode','nlink','size','mtime_ns','ctime_ns'})
    path,sha=STATIC['marker'];require({k:marker[k] for k in ('path','sha256')}==_ref(path,sha))
    body,info=_bytes(path,4096);require(hashlib.sha256(body).hexdigest()==sha)
    require({k:marker[k] for k in _metadata(info)}==_metadata(info)
        and marker['mtime_ns']==marker['ctime_ns']==MARKER_MTIME_NS and marker['mode']==0o600 and marker['nlink']==1)
    before=value['network_record_before'];launch._exact(before,{'path','sha256','mtime_ns','ctime_ns'})
    records=proofs['observation']['registry_records'];require(type(records) is list and len(records)==2)
    network=next(r for r in records if r['record'].get('kind')=='network')
    require(before=={k:network[k] for k in ('path','sha256','mtime_ns','ctime_ns')}
        and before['mtime_ns']==NETWORK_MTIME_NS and before['ctime_ns']==NETWORK_CTIME_NS
        and network['record']['status']=='released' and network['record']['launch_id']==NETWORK_ID)
    bound=(max(before['mtime_ns'],before['ctime_ns'])-marker['mtime_ns'])/1e9
    require(0<=bound<30)


def _validate_release(value, proofs, row, authority, carry, wall):
    release=_public(value['metadata_release']);launch._exact(release,RELEASE_FIELDS)
    require(type(release['schema']) is int and release['schema']==1 and release['document_type']=='qualification_diagnostic_metadata_release'
        and release['status']=='PASS' and release['authorization']==authority and release['qualification_id']==QUALIFICATION_ID
        and all(release[k]==value[k] for k in ('observation','manifest','ledger')) and release['container_id']==CONTAINER_ID
        and release['host_pid']==row['pid'])
    for name in ('host_pid_absent','original_lease_held','lease_inode_unchanged','raw_ledger_preserved','driver_terminal_absent','metadata_only_reporting'):
        require(release[name] is True)
    for name,expected in (('new_container_launches',0),('participant_segments',0),('cumulative_container_launches',76),('resource_mutations',0),('registry_status_changes',1)):
        require(type(release[name]) is int and release[name]==expected)
    require(0<=launch._number(release['elapsed_seconds'])<=30 and proofs['observation']['observed_wall']<=launch._number(release['completed_wall'])<=wall())
    program=release['program'];launch._exact(program,{'path','sha256'});launch._sha(program['sha256'])
    require(launch._canonical_root(program['path']).is_relative_to(CAMPAIGN) and Path(program['path']).suffix=='.py')
    require(hashlib.sha256(_bytes(program['path'])[0]).hexdigest()==program['sha256'])
    source_review=_public(release['source_review']);bounds=_public(release['bounds_review'])
    require(source_review['status']=='PASS' and source_review['unresolved_findings']==[] and bounds['status']=='PASS' and bounds['unresolved_findings']==[])
    require(source_review.get('program')==program or source_review.get('program_sha256')==program['sha256'])
    before=_public(release['original_helper_record']);after=_public(release['released_helper_record']);network=_public(release['released_network_record'])
    originals=proofs['observation']['registry_records'];original=next(r for r in originals if r['record'].get('application_helper') is True)
    old_network=next(r for r in originals if r['record'].get('kind')=='network')
    require(before==original['record'] and release['original_helper_record']['sha256']==original['sha256'] and before['status']=='absent'
        and after=={**before,'status':'released'} and network==old_network['record'] and release['released_network_record']['sha256']==old_network['sha256'])
    registry_root=Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
    for name,identifier,record in (('helper_registry_record',LAUNCH_ID,after),('network_registry_record',NETWORK_ID,network)):
        reference=release[name];launch._exact(reference,{'path','sha256'});require(reference['path']==str(registry_root/(identifier+'.json')))
        require(reference['sha256']==release['released_helper_record' if name=='helper_registry_record' else 'released_network_record']['sha256'])
        require(launch._bound_json(reference['path'],reference['sha256'])==record)
    require(after['launch_id']==row['launch_id'] and after['container_id']==CONTAINER_ID and launch._intent_identity(after)==row['intent_sha256']
        and all(after[k]==row[k] for k in ('registry','generation','image','container')) and after['daemon']==carry['daemon']
        and network['daemon']==carry['daemon'] and network['registry']==after['registry'] and network['generation']==after['generation']
        and network['container']==after['container']+'-network')
    paths=release['private_absence'];require(paths==proofs['observation']['private_absence'] and len(paths)==3)
    expected={str(ROOT/'private'),after['private_store'],str(ROOT/'run/application-evidence'/after['container']/'private')}
    require({item['path'] for item in paths}==expected)
    for item in paths:
        launch._exact(item,{'path','absent'});require(item['absent'] is True and ownership._qualification_absent(item['path']))
    # This immutable wrapper uses started_wall; the common PID-reuse verifier
    # uses started_at. Normalize a detached view, preserving actual elapsed/end.
    terminal={**proofs['command'],'started_at':proofs['command']['started_wall']}
    for pid in (row['pid'],after['owner_pid']):
        launch._integer(pid,1,2**31-1);require(launch._historical_controller_absent(pid,terminal,wall()))
    observations=release['docker_observations'];require(type(observations) is list and len(observations)==3)
    observed={item['kind']:item for item in observations};require(set(observed)=={'daemon','container','network'})
    for item in observations:launch._exact(item,{'kind','target','exit','stdout','stderr'})
    daemon=observed['daemon'];require(daemon['target']==carry['daemon'] and type(daemon['exit']) is int and daemon['exit']==0
        and daemon['stdout'].strip()==carry['daemon'] and daemon['stderr']=='')
    for kind,target in (('container',CONTAINER_ID),('network',network['container'])):
        item=observed[kind];require(item['target']==target and type(item['exit']) is int and item['exit']!=0 and item['stdout'].strip()=='[]')
        reply=type('Absence',(),{'returncode':item['exit'],'stderr':item['stderr']})()
        require(launch.LaunchGuard._absent(reply,target) if kind=='container' else ownership.network_absent(reply,target))
    return release


def validate_known_cleanup(authority,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    """Return76/0 carry for this failed diagnostic only; never a native pass."""
    import application_followup as followup
    try:
        _terminal_absent()
        carry=followup._current_carry(authority,base_predecessor,clock=clock,wall=wall,window=window)
        require((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage']))==(75,0,280,10))
        reference=_public_ref(KNOWN_PATH);value=_public(reference);launch._exact(value,KNOWN_FIELDS)
        review=_public(_public_ref(REVIEW_PATH));launch._exact(review,{'schema','status','unresolved_findings','known_cleanup','validator_sha256','classification'})
        require(type(review['schema']) is int and review['schema']==1 and review['status']=='PASS' and review['unresolved_findings']==[]
            and review['known_cleanup']==reference and review['classification']==REVIEW_CLASSIFICATION
            and review['validator_sha256']==hashlib.sha256(_bytes(Path(__file__))[0]).hexdigest())
        proofs=_proofs(value);row=_validate_history(value,proofs,carry,authority,base_predecessor,clock,wall)
        _validate_resource_order(value,proofs);_validate_release(value,proofs,row,authority,carry,wall)
        _terminal_absent()
        return {**copy.deepcopy(carry),'attempts':76,'startup_diagnostic':{'reference':reference,'attempts':1,'participant_segments':0,'native_rows':0,
            'root':str(ROOT),'outcome':'startup_failed','driver_status':'BLOCKED','cleanup_accounting':'FAILED','native_success_attested':False}}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,StopIteration,zipfile.BadZipFile,RecursionError):
        raise launch.LaunchError('qualification_diagnostic_cleanup_invalid') from None
