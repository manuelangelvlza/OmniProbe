# OmniProbe

Network scanning tool for consumer ISP networks.

## Overview

OmniProbe is a two-instance model program to test a consumer ISP network.
It's designed to reveal what ports/protocols are blocked or filtered by default by an ISP, both inbound and outbound. As well as if the consumer network have support for IP options and IPV6 **(To be implemented)**.

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
```

## File layout

```
omniprobe.py        # entry point, argument parsing, launches client or server
core/
  config.py         # shared config constants
  protocol.py       # message types and framed JSON messaging
  scanner.py        # scapy-based TCP SYN and UDP scanning
  ports.py          # port range parsing and nmap-services file top-N selection
server/
  listener.py       # TCP server — accepts connections, spawns ControlSession threads
  control.py        # ControlSession — handles handshake, responds and executes scan requests
  scanner.py        # re-exports core.scanner.scan_ports
client/
  listener.py       # connects to server, initiates handshake and sends scan requests
```
