from time import sleep
from core.config import DEFAULT_TIMEOUT, DEFAULT_DELAY
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, RandShort  # type: ignore
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def scan_ports(target_ip, protocol, ports, timeout=DEFAULT_TIMEOUT, delay=DEFAULT_DELAY):
    """
    Scan a list of ports on target_ip.
    Returns a list of dicts: {port, protocol, state}.
    Requires root/admin privileges.
    """
    results = []

    if protocol == "tcp":
        for port in ports:
            state = _tcp_syn_scan(target_ip, port, timeout)
            sleep(delay)
            results.append({"port": port, "protocol": "tcp", "state": state})

    elif protocol == "udp":
        for port in ports:
            state = _udp_scan(target_ip, port, timeout)
            sleep(delay)
            results.append({"port": port, "protocol": "udp", "state": state})

    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    return results


def _tcp_syn_scan(target_ip, port, timeout):
    pkt = IP(dst=target_ip) / TCP(dport=port,
                                  sport=int(RandShort()), flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return "filtered"

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags & 0x12 == 0x12:  # SYN-ACK
            # Reset the half-open connection
            send(IP(dst=target_ip) / TCP(dport=port,
                 flags="R", seq=resp[TCP].ack), verbose=0)
            return "open"
        if flags & 0x04:  # RST
            return "closed"

    if resp.haslayer(ICMP):
        # Type 3 = Destination Unreachable; codes 1,2,3,9,10,13 indicate filtering
        if resp[ICMP].type == 3 and resp[ICMP].code in (1, 2, 3, 9, 10, 13):
            return "filtered"

    return "filtered"


def _udp_scan(target_ip, port, timeout):
    pkt = IP(dst=target_ip) / UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return "open|filtered"

    if resp.haslayer(UDP):
        return "open"

    if resp.haslayer(ICMP):
        if resp[ICMP].type == 3:       # Destination Unreachable
            if resp[ICMP].code == 3:
                return "closed"
            return "filtered"          # Other unreachable codes -> filtered

    return "open|filtered"
