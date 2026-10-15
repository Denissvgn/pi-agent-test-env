"""Bounded named-profile diagnostic and preflight entry points."""
import copy
from pathlib import Path

import indexed_contract as contract
from indexed_contract import IndexedError
import indexed_execution
import outcomes


def preflight(args,lab):
    if getattr(args,'endpoint',None) is not None:raise IndexedError('selection-conflict')
    attempt=outcomes.Attempt(args)
    try:
        with lab.admission_lock(args.lock_file,args.lock_wait_seconds) as registry:
            registry.runroot=attempt.root;registry.command=lambda argv:lab.command(argv,timeout=15,required=False)
            with indexed_execution.admission(lab,args,attempt,registry):
                code=lab.preflight_only(args)
        return code
    except Exception as exc:
        attempt.fail(exc);report=attempt.finalize()
        import json
        print(json.dumps(report));return 2


def health(args,catalog):
    import pi_lab as lab
    # The caller supplies the trusted image/resource contract explicitly.
    if not getattr(args,'image',None) or not getattr(args,'resources',None):raise IndexedError('selection-conflict')
    cli=lab.parser().parse_args(['preflight','--image',args.image,'--resources',args.resources,
        '--platform',args.platform or 'linux/arm64','--inference-env',args.id,'--session',args.session,
        '--catalog-dir',str(catalog.root),'--secrets-dir',str(catalog.store)])
    import contextlib,io,json
    output=io.StringIO()
    with contextlib.redirect_stdout(output):code=preflight(cli,lab)
    return {'state':'ready' if code==0 else 'blocked','health':'observed' if code==0 else 'failed','scope':'Bounded broker preflight; tool use remains separately qualified'}


def doctor(args,lab):
    from inference_catalog import Catalog
    catalog=Catalog(lab.normalize_endpoint,args.catalog_dir,args.secrets_dir)
    status=catalog.status(args.inference_env,args.session)
    if status['state']!='ready' or args.skip_network:
        import json
        print(json.dumps(status));return 0 if status['state']=='ready' else 2
    selected=copy.deepcopy(args);selected.id=args.inference_env
    value=health(selected,catalog)
    import json
    print(json.dumps(value));return 0 if value['state']=='ready' else 2
