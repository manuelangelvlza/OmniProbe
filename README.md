# OmniProbe

Network scanning tool for consumer ISP networks.

## Overview

OmniProbe is a two-instance model program to test a consumer ISP network.
It's designed to reveal what ports/protocols are blocked or filtered by default by an ISP (both inbound and outbound), whether IP options survive the path between client and server, and whether end-to-end IPv6 connectivity is available from the consumer network.

- **Client** — runs on any machine inside the consumer network that is going to be tested.
- **Server** — runs outside the ISP network (On a cloud server ideally).

The client connects to the server over a persistent TCP port, we may call this, the ***control channel or control port***.
All communication is done via the ***control channel***: what to scan, how to scan (timeout & delay) and results, the exchange is done with length-prefixed JSON messages.
The ***control channel*** is used for coordination and reporting only as especified in (`core/protocol.py`). 

The actual port scanning is done with scapy raw sockets (`core/scanner.py`), which requires root privileges for crafting and sending raw packets. 
Therefore, OmniProbe (viewed from client perspective): requires root privileges on the server side for `inbound` scans and on the client side for `outbound` scans. The default scan direction is `inbound` (server scans client), which is the most common use case for testing ISP filtering of incoming traffic to the consumer network.

## How it works

### 1. Control channel handshake

The client initiates a TCP connection to the server on the control port (default `9000`). Once connected, the client identifies itself and the server acknowledges:

```
Client                            Server
  |                                 |
  |---- CONNECT (OS info) --------->|
  |<--- CONNECT_ACK (version) ------|
```

### 2. Scan round (inbound from client)

The client requests a scan, specifying all parameters. The server acknowledges and executes it:

```
Client                            Server
  |                                 |
  |---- SCAN_REQUEST -------------->| (direction, protocol, ports, timeout, delay)
  |<--- SCAN_ACK -------------------|
  |         [inbound loop]          |
  |<--- SYN (TCP) / UDP datagram ---| Probe with: SYN if TCP, empty UDP datagram if UDP
  |---- SYN-ACK (TCP open) -------->| TCP port open
  |---- RST (TCP closed) ---------->| TCP port closed
  |---- UDP reply (UDP open) ------>| UDP port open
  |---- ICMP unreachable ---------->| UDP port closed or TCP filtered
  |<--- RST (if SYN-ACK received) --| RST if TCP port was open
  |     [inbound loop finished]     |
  |<--- RESULT ---------------------|
  |                                 |
```

**Inbound** (`direction=inbound`): the server sends raw probes to the client's IP.

**Outbound** (`direction=outbound`): the client sends raw probes to the server's IP.

### 3. Port scanning (scapy)

All probing is done with scapy raw sockets (`core/scanner.py`).

- **TCP** — A SYN is sent; a SYN-ACK means `open` (RST sent to close it), a RST means `closed`, no response or ICMP unreachable means `filtered`.
- **UDP** — An empty UDP datagram is sent; UDP reply means `open`, an ICMP port-unreachable means `closed`, no response means `open|filtered`.

Optional inter-probe delay (`--delay`) paces the probes to avoid triggering firewalls (similar to nmap's `-T` timing flag).

### 4. IP Options testing

OmniProbe can test whether the network path supports specific IP options by comparing against a baseline scan. Use `--ip-option` with a specific option or `all` to test every option in one run.

A baseline scan (no IP options) runs first, then each selected option is tested. Results are compared per-port to determine support:

| Baseline | With option | Verdict |
|----------|------------|---------|
| open | open | **supported** — option passed through, service responded normally |
| open | closed | **supported** — option passed through, host rejected at application level |
| open | filtered | **blocked** — option caused packet to be dropped in transit |
| closed | closed | **supported** — option passed through, host sent RST |
| closed | open | **supported** — option passed through |
| closed | filtered | **blocked** — option caused packet to be dropped in transit |
| filtered | open | **supported** — option got a response where baseline did not |
| filtered | closed | **supported** — got a definitive response, likely reached destination |
| filtered | filtered | **inconclusive** — cannot determine if option or firewall caused the drop |

Supported IP options: `record_route`, `timestamp`, `router_alert`.

```bash
# Test a single IP option
sudo python3 omniprobe.py --client --host <server-ip> --ports 22,80 --ip-option router_alert

# Test all IP options in one run
sudo python3 omniprobe.py --client --host <server-ip> --ports 22,80 --ip-option all
```

### 5. IPv6 connectivity test

OmniProbe can test whether end-to-end IPv6 reachability exists between the client and the server during a scan session. The test is enabled by passing the `--ipv6` flag on the client.

How it works:

- Both endpoints discover their own public IPv6 address using a UDP-connect trick (the OS picks a source address for a route to a well-known IPv6 host; no packet is actually sent).
- The two addresses are exchanged over the IPv4 control channel during the handshake.
- If both sides have a public IPv6 address, the client opens an `AF_INET6` TCP socket to the server's IPv6 address and exchanges an `IPV6_PING` / `IPV6_PONG` message pair over IPv6.
- A successful exchange indicates that an end-to-end v6 path exists between the client's network and the server. A failure (timeout, connection refused, no route to host) means the v6 path is broken somewhere on the route. If either side lacks a public IPv6 address, the test is skipped and the reason is reported.

```
Client                            Server
  |                                 |
  |---- (IPv6 addr in CONNECT) ---->|
  |<--- (IPv6 addr in CONNECT_ACK)--|
  |                                 |
  |==== open AF_INET6 TCP ==========|   (only if both sides have v6)
  |---- IPV6_PING ----------------->|
  |<--- IPV6_PONG ------------------|
  |==== close AF_INET6 TCP =========|
  |                                 |
```

This test reflects IPv6 *deployment* on the consumer network: whether the ISP has assigned the client a public IPv6 address at all, and whether that address can reach the open IPv6 Internet. In our measurement runs, IPv6 was available on residential ISPs that have deployed v6 (e.g., Spectrum) and unavailable on most public wifi, small-town, university, and business networks tested. The IPv6 feature is best understood as a proof-of-concept connectivity check; it does not test v6-specific behaviors such as extension header survival, ICMPv6 filtering, or fragmentation handling.

```bash
# Add an IPv6 connectivity test alongside the port scan
sudo python3 omniprobe.py --client --host <server-ip> --ipv6
```

## Usage

The side crafting and sending raw packets (server for inbound scans, client for outbound scans) requires root privileges.

Example for an inbound scan.

```bash
# Server — bind on all interfaces accept any client (no white-list)
sudo python3 omniprobe.py --server

# Client — connect and request inbound TCP scan of the top 100 ports with 10s timeout and .1s delay between probes
python3 omniprobe.py --client --host <server-ip>

# Client — custom port list, UDP, slower timing
python3 omniprobe.py --client --host <server-ip> --ports 53,67,123,161 --protocol udp --delay 0.5

# Client — full session: TCP scan + all IP options + IPv6 connectivity test
sudo python3 omniprobe.py --client --host <server-ip> --top 500 --ip-option all --ipv6
```

## File layout

```
omniprobe.py            # entry point: argument parsing, launches client or server
README.md
LICENSE

core/                   # shared logic used by both client and server
  __init__.py
  config.py             # shared config constants (default ports, timeouts, paths)
  protocol.py           # message types, framed JSON messaging, IPv6 address discovery
  scanner.py            # scapy-based TCP SYN / UDP scanning, IP-option-bearing probes,
                        # and the differential IP options test (scan_with_ip_options)
  ports.py              # port range parsing and nmap-services top-N selection

server/                 # server-side: listens for clients, executes inbound scans
  __init__.py
  listener.py           # TCP server: accepts connections, spawns ControlSession threads
  control.py            # ControlSession: handshake, scan dispatch, IPv6 ping/pong,
                        # response framing and result return
  scanner.py            # thin re-export of core.scanner.scan_ports

client/                 # client-side: connects to a server and requests scans
  __init__.py
  listener.py           # connects to server, performs handshake, sends scan requests,
                        # runs IPv6 connectivity test, and renders per-port results

data/
  nmap-services         # Nmap services file used to select the top-N most common ports

results/                # session logs from the six networks tested in our paper
  cox-tcp-72_206_92_24_SD-CA.txt
  cox-udp-72_206_92_24_SD-CA.txt
  lvl3-tcp-64-157-159-170_SD-CA.txt
  lvl3-udp-64-157-159-179_SD-CA.txt
  att-tcp_Parsons-KS.txt
  att-udp_Parsons-KS.txt
  results_columbia_tcp.txt
  results_columbia_udp.txt
  spectrum-tcp_74-71-2-248_NY.txt
  granite telecoms-tcp-104-218-183-194.txt
  granite telecoms-udp-104-218-183-194.txt
```
