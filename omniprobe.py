#!/usr/bin/env python3
"""
OmniProbe — Network scanning tool for Consumer Internet Services

Main entry point for both client and server modes. Parses command-line arguments.

Usage:
    # Client: connect to a running OmniProbe server and request a scan
    python omniprobe.py --client --host probe.example.com
    python omniprobe.py --client --host 192.168.1.1 --ports 22,80,443
    python omniprobe.py --client --host probe.example.com --top 500 --timeout 15

    # Server: listen for incoming client connections
    python omniprobe.py --server
    python omniprobe.py --server --bind 0.0.0.0 --control 9000
"""

import argparse
import sys

from core import config
from core.ports import parse_port_range, get_nmap_top_ports


def build_parser():
    parser = argparse.ArgumentParser(
        prog='omniprobe',
        description='Network scanning tool for Consumer Internet Services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # running mode, client or server (mutually exclusive)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        '--client', action='store_true',
        help='Run in client mode (connect to a server)')
    mode.add_argument(
        '--server', action='store_true',
        help='Run in server mode (listen for clients)')

    parser.add_argument(
        '--control', '-c', type=int, default=config.DEFAULT_CONTROL_PORT,
        metavar='PORT',
        help='Control port used by both client and server')

    client_opts = parser.add_argument_group(title='client options',
                                            description=f'''Options when running in client mode. Specifying host IP is required.
Ports will default to scan nmap's top {config.DEFAULT_TOP_PORTS} ports if not specified.\nProtocol defaults to TCP.''')
    client_opts.add_argument(
        '--host', '-H', metavar='HOST',
        help='[client] Server hostname or IP address to connect to')

    port_group = client_opts.add_mutually_exclusive_group()
    port_group.add_argument(
        '--ports', metavar='RANGE',
        help='[client] Ports to request scanning, e.g. "22,80,443" or "1-1024"')
    port_group.add_argument(
        '--top', type=int, default=config.DEFAULT_TOP_PORTS,
        metavar='N',
        help=f'[client] Use top N most common ports from nmap-services (default: {config.DEFAULT_TOP_PORTS})')

    client_opts.add_argument(
        '--protocol', choices=['tcp', 'udp'], default='tcp',
        help='[client] Protocol to request scanning (default: tcp)')
    client_opts.add_argument(
        '--timeout', type=int, default=config.DEFAULT_TIMEOUT,
        metavar='SEC',
        help=f'[client] Per-probe timeout in seconds (default: {config.DEFAULT_TIMEOUT}s)')
    client_opts.add_argument(
        '--delay', type=float, default=config.DEFAULT_DELAY,
        metavar='SEC',
        help=f'[client] Delay between probes in seconds (default: {config.DEFAULT_DELAY}s)')

    # server options
    server_opts = parser.add_argument_group(title='server options',
                                            description='''Options when running in server mode.
By default, the server binds to all interfaces and accepts connections from any client.''')
    server_opts.add_argument(
        '--bind', '-b', metavar='ADDRESS', default=config.DEFAULT_ADDRESS,
        help=f'[server] Address to bind to (default: {config.DEFAULT_ADDRESS})')

    server_opts.add_argument(
        '--whitelist', '-w', metavar='ADDRESS', nargs='+',
        help='[server] Whitelist of expected clients IPs (separated by a space); if not set any connection is accepted')

    return parser


def resolve_ports(args):
    """Return a sorted list of port numbers based on CLI flags."""
    if args.ports:
        return parse_port_range(args.ports)
    return get_nmap_top_ports(config.NMAP_SERVICES_PATH, top_n=args.top)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.client:
        if not args.host:
            parser.error("--host is required in client mode")

        ports = resolve_ports(args)
        if not ports:
            print("Error: could not resolve port list.", file=sys.stderr)
            sys.exit(1)

        scan_config = {
            "direction": "inbound",
            "protocol": args.protocol,
            "ports": ports,
            "timeout": args.timeout,
            "delay": args.delay,
        }

        print(f"Host      : {args.host}:{args.control}")
        print(f"Protocol  : {args.protocol.upper()}")
        print(f"Ports     : {len(ports)} ports")
        print(f"Timeout   : {args.timeout}s")
        print(f"Delay     : {args.delay}s")

        from client.listener import connect
        connect(args.host, args.control, scan_config=scan_config)

    elif args.server:
        from server.listener import start
        start(host=args.bind, port=args.control, whitelist=args.whitelist)


if __name__ == '__main__':
    main()
