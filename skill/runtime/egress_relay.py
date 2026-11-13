#!/usr/bin/env python3
"""Fixed-destination TCP relay and reachability probes for the endpoint-only network mode.

Python standard library only. Three operations, each started by the host runner:

relay   Listen on one port of this container's address inside one allowed
        network, accept connections only from that network and forward the bytes
        to one fixed host and port. The stream is never parsed, logged or stored:
        TLS stays end to end and no key, prompt or reply is recorded. It is not a
        proxy: a client cannot choose another destination.
canary  Listen on one port and answer every connection with a short token.
probe   Report which of the named destinations can be reached or resolved.

Only connection counts and error classes are printed, never stream content.
"""
import argparse
import errno
import ipaddress
import json
import signal
import socket
import sys
import threading
import time

BUFFER = 64 * 1024
MAX_CONNECTIONS = 32
CONNECT_SECONDS = 10
# Longer than the longest stage (3600 seconds plus grace): a silent stream is
# closed only after no byte moved in either direction for this long.
IDLE_SECONDS = 3900
# Longer than the failure of address resolution on a link (about three seconds),
# so an address that no host owns reads as unreachable and not as a timeout.
PROBE_SECONDS = 6
BANNER_SECONDS = 3
RESOLVE_SECONDS = 8


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def local_address(network):
    """This container's address inside `network`, read from the routing decision.

    Connecting a datagram socket sends nothing. The relay binds to this address
    only, so nothing on another attached network can reach its listener.
    """
    target = next(network.hosts(), network.network_address)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((str(target), 9))
        address = ipaddress.ip_address(sock.getsockname()[0])
    if address not in network:
        raise RuntimeError('No interface inside the allowed network')
    return str(address)


def inside(peer, network):
    """Whether a peer address belongs to the one allowed network."""
    try:
        return ipaddress.ip_address(peer) in network
    except ValueError:
        return False


def copy(source, destination):
    """Forward one direction until end of stream; never inspect the bytes."""
    try:
        while True:
            data = source.recv(BUFFER)
            if not data:
                break
            destination.sendall(data)
        destination.shutdown(socket.SHUT_WR)
    except OSError:
        for item in (source, destination):
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def relay(args):
    allowed = ipaddress.ip_network(args.allow)
    if allowed.version != 4 or not 0 < args.listen_port < 65536 or not 0 < args.upstream_port < 65536:
        raise RuntimeError('Relay needs an IPv4 allowed network and valid ports')
    address = local_address(allowed)
    counters = {'accepted': 0, 'rejected_peers': 0, 'over_capacity': 0, 'upstream_failures': 0}
    lock = threading.Lock()
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
    stop = threading.Event()

    def count(name):
        with lock:
            counters[name] += 1

    def serve(client):
        upstream = None
        try:
            try:
                upstream = socket.create_connection((args.upstream_host, args.upstream_port), timeout=CONNECT_SECONDS)
            except OSError:
                count('upstream_failures')
                return
            for item in (client, upstream):
                item.settimeout(IDLE_SECONDS)
                item.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            back = threading.Thread(target=copy, args=(upstream, client), daemon=True)
            back.start()
            copy(client, upstream)
            back.join()
        finally:
            for item in (client, upstream):
                if item is not None:
                    try:
                        item.close()
                    except OSError:
                        pass
            slots.release()

    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda signum, frame: stop.set())
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, args.listen_port))
    listener.listen(64)
    listener.settimeout(0.5)
    emit({'egress_relay': 'ready', 'listen': f'{address}:{args.listen_port}', 'allow': str(allowed),
          'upstream_host': args.upstream_host, 'upstream_port': args.upstream_port})
    while not stop.is_set():
        try:
            client, peer = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        if not inside(peer[0], allowed):
            count('rejected_peers')
            client.close()
            continue
        if not slots.acquire(blocking=False):
            count('over_capacity')
            client.close()
            continue
        count('accepted')
        threading.Thread(target=serve, args=(client,), daemon=True).start()
    listener.close()
    with lock:
        emit({'egress_relay': 'stopped', **counters})
    return 0


def canary(args):
    token = args.token.encode('ascii')
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', args.port))
    listener.listen(16)
    emit({'egress_canary': 'ready', 'port': args.port})
    while True:
        client, unused = listener.accept()
        try:
            client.settimeout(BANNER_SECONDS)
            client.sendall(token + b'\n')
        except OSError:
            pass
        finally:
            client.close()


def target(value):
    name, separator, rest = value.partition('=')
    host, colon, port = rest.rpartition(':')
    if not name or not separator or not host or not colon or not port.isdigit():
        raise argparse.ArgumentTypeError('expected NAME=HOST:PORT')
    return name, host, int(port)


def attempt(host, port, banner):
    """One bounded TCP connection. `refused` still means the destination answered."""
    try:
        connection = socket.create_connection((host, port), timeout=PROBE_SECONDS)
    except socket.gaierror:
        return {'outcome': 'unresolved'}
    except ConnectionRefusedError:
        return {'outcome': 'refused'}
    except socket.timeout:
        return {'outcome': 'timeout'}
    except OSError as exc:
        unreachable = exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.EHOSTDOWN)
        return {'outcome': 'unreachable' if unreachable else 'error', 'errno': errno.errorcode.get(exc.errno, 'unknown')}
    result = {'outcome': 'connected'}
    with connection:
        if banner:
            connection.settimeout(BANNER_SECONDS)
            try:
                result['banner'] = connection.recv(128).decode('ascii', 'replace').strip()
            except OSError:
                result['banner'] = ''
    return result


def resolve(name):
    """Bounded name resolution; a resolver that never answers counts as a timeout."""
    result = {}

    def work():
        try:
            result['addresses'] = len({item[4][0] for item in socket.getaddrinfo(name, 443)})
        except OSError:
            result['addresses'] = 0

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(RESOLVE_SECONDS)
    if 'addresses' not in result:
        return {'outcome': 'timeout'}
    return {'outcome': 'resolved' if result['addresses'] else 'unresolved'}


def interfaces():
    """Non-loopback IPv6 interfaces and whether any default route exists."""
    ipv6 = []
    try:
        with open('/proc/net/if_inet6', encoding='ascii') as stream:
            ipv6 = sorted({line.split()[-1] for line in stream if line.split() and line.split()[-1] != 'lo'})
    except OSError:
        pass
    default = None
    try:
        with open('/proc/net/route', encoding='ascii') as stream:
            rows = [line.split() for line in stream.read().splitlines()[1:]]
        default = any(len(row) > 7 and row[1] == '00000000' and row[7] == '00000000' for row in rows)
    except OSError:
        pass
    return ipv6, default


def probe(args):
    started = time.monotonic()
    ipv6, default = interfaces()
    report = {'egress_probe': 1, 'tcp': {}, 'resolve': {}, 'ipv6_interfaces': ipv6, 'default_route': default}
    for name, host, port in args.tcp:
        report['tcp'][name] = attempt(host, port, False)
    for name, host, port in args.banner:
        report['tcp'][name] = attempt(host, port, True)
    for name in args.resolve:
        report['resolve'][name] = resolve(name)
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    emit(report)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    r = sub.add_parser('relay')
    r.add_argument('--listen-port', type=int, required=True)
    r.add_argument('--upstream-host', required=True)
    r.add_argument('--upstream-port', type=int, required=True)
    r.add_argument('--allow', required=True, help='The only network whose peers are accepted, as CIDR')
    c = sub.add_parser('canary')
    c.add_argument('--port', type=int, required=True)
    c.add_argument('--token', required=True)
    p = sub.add_parser('probe')
    p.add_argument('--tcp', type=target, action='append', default=[], metavar='NAME=HOST:PORT')
    p.add_argument('--banner', type=target, action='append', default=[], metavar='NAME=HOST:PORT')
    p.add_argument('--resolve', action='append', default=[], metavar='NAME')
    args = parser.parse_args(argv)
    return {'relay': relay, 'canary': canary, 'probe': probe}[args.operation](args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(f'PI_LAB_ERROR: {type(exc).__name__}: {exc}', file=sys.stderr)
        sys.exit(2)
