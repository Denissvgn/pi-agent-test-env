"""Internal host worker entry point. Requires an inherited private channel and lease."""
import os
import signal
import socket
import sys


def main():
    import experiments
    import pi_lab as lab
    from parallel_dispatch import Channel,RemoteAdmission
    from parallel_contract import ParallelError
    if len(sys.argv)!=3:raise ParallelError('No public standalone parallel-worker entry point')
    fd,lease_fd=map(int,sys.argv[1:]);os.fstat(lease_fd)
    channel=Channel(socket.socket(fileno=fd));bootstrap=channel.receive()
    if bootstrap.get('op')!='bootstrap':raise ParallelError('Private bootstrap missing')
    signal.signal(signal.SIGTERM,lambda *unused:(_ for _ in ()).throw(KeyboardInterrupt()))
    root=bootstrap['experiment'];metadata,matrix=experiments.verify(root,lab)
    cell=next(c for c in matrix['cells'] if c['trial_id']==bootstrap['intent']['trial_id'])
    args=experiments.trial_args(root,metadata,cell,lab,bootstrap.get('session'))
    args.network=bootstrap['network'];args.host_gateway=True
    args._parallel_session=RemoteAdmission(channel,bootstrap,lambda argv:lab.command(argv,timeout=15,required=False))
    args._parallel_inference_key=bootstrap['inference']['token']
    try:return lab.run_suite(args,initial_record=bootstrap['intent']['initial_record'])
    finally:
        channel.sock.close();os.close(lease_fd)


if __name__=='__main__':sys.exit(main())
