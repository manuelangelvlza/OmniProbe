#!/usr/bin/env python3
"""
Usage:
    python omniprobe.py --server <host> [options]

Examples:
    python omniprobe.py --server probe.example.com
    python omniprobe.py --server 192.168.1.1 --ports 22,80,443
    python omniprobe.py --server probe.example.com --top 500 --timeout 15
"""

import argparse
import socket
import sys

from core import config
from core.ports import parse_port_range, get_nmap_top_ports
from core.protocol import send_message, recv_message, MSG_TYPE_SCAN_REQUEST, MSG_TYPE_ERROR

# arg parsing

def build_parser():
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog='omniprobe',
        description='Measure inbound TCP reachability through NAT and ISP filtering',
    )

    # which server to talk to
    parser.add_argument(
        '--server', '-s', required=True,
        metavar='HOST',
        help='Measurement server hostname or IP address',
    )
    parser.add_argument(
        '--server-port', '-p', type=int, default=config.DEFAULT_SERVER_PORT,
        metavar='PORT',
        help=f'Measurement server control port (default: {config.DEFAULT_SERVER_PORT})',
    )

    # pick one method for port selection
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        '--ports',
        metavar='RANGE',
        help='Ports to test, e.g. "22,80,443" or "1-1024"',
    )
    port_group.add_argument(
        '--top', type=int, default=config.DEFAULT_TOP_PORTS,
        metavar='N',
        help=f'Use top N most common ports from nmap-services (default: {config.DEFAULT_TOP_PORTS})',
    )

    # Protocol and timeout
    parser.add_argument(
        '--protocol', choices=['tcp', 'udp'], default='tcp',
        help='Protocol to test (default: tcp)',
    )
    parser.add_argument(
        '--timeout', type=int, default=config.DEFAULT_TIMEOUT,
        metavar='SEC',
        help=f'Per-connection timeout in seconds (default: {config.DEFAULT_TIMEOUT})',
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    print(f'Server     : {args.server}:{args.server_port}')
    print(f'Protocol   : {args.protocol}')
    print(f'Timeout    : {args.timeout}s')

    if args.ports:
        print(f'Ports      : {args.ports}')
    else:
        print(f'Top ports  : {args.top}')

    # Resolve port list
    if args.ports:
        ports = parse_port_range(args.ports)
    else:
        ports = get_nmap_top_ports(filepath=config.NMAP_SERVICES_PATH, top_n=args.top)

    if not ports:
        print('Error: No valid ports resolved. Exiting.', file=sys.stderr)
        sys.exit(1)

    print(f'Ports      : {len(ports)} ports resolved')

    # Connect to measurement server
    print(f'Connecting to {args.server}:{args.server_port}...')
    try:
        sock = socket.create_connection((args.server, args.server_port), timeout=args.timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f'Error: Could not connect to server: {e}', file=sys.stderr)
        sys.exit(1)

    print('Connected.')

    # Send scan request & receive results
    try:
        request = {
            'type': MSG_TYPE_SCAN_REQUEST,
            'protocol': args.protocol,
            'ports': ports,
            'timeout': args.timeout,
        }
        if not send_message(sock, request):
            print('Error: Failed to send scan request.', file=sys.stderr)
            sys.exit(1)

        print('Scan request sent. Waiting for results...')

        response = recv_message(sock)
        if response is None:
            print('Error: No response received from server.', file=sys.stderr)
            sys.exit(1)

        if response.get('type') == MSG_TYPE_ERROR:
            print(f'Server error: {response.get("message", "unknown error")}', file=sys.stderr)
            sys.exit(1)

        print('Results:')
        print(response)
    finally:
        sock.close()


if __name__ == '__main__':
    main()