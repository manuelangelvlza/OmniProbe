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
import sys

from core import config

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

    # TODO: resolve port list
    # TODO: connect to measurement server
    # TODO: send scan request & receive results


if __name__ == '__main__':
    main()