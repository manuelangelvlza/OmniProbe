from time import sleep
from core.config import FALLBACK_TIMEOUT, DEFAULT_DELAY
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, RandShort, IPOption_RR, IPOption_Timestamp, IPOption_Router_Alert  # type: ignore
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

IP_OPTIONS = {
    "record_route": IPOption_RR,
    "timestamp": IPOption_Timestamp,
    "router_alert": IPOption_Router_Alert,
}


def _extract_ip_option_data(resp, ip_option):
    """Extract IP option fields from a scapy response packet. Returns dict or None."""
    if resp is None or ip_option is None:
        return None
    if not resp.haslayer(IP):
        return None

    for opt in resp[IP].options:
        if ip_option == "record_route" and isinstance(opt, IPOption_RR):
            routers = [r for r in opt.routers if r != "0.0.0.0"]
            return {"routers": routers}
        if ip_option == "timestamp" and isinstance(opt, IPOption_Timestamp):
            return {
                "timestamp": opt.timestamp,
                "pointer": opt.pointer,
                "flag": opt.flg,
            }
        if ip_option == "router_alert" and isinstance(opt, IPOption_Router_Alert):
            return {"alert": str(opt.alert)}
    return None


def format_option_data(ip_option, data):
    """Format extracted IP option data for display."""
    if ip_option == "record_route":
        hops = data.get("routers", [])
        return f"route: {' -> '.join(hops)}" if hops else "route: (empty)"
    if ip_option == "timestamp":
        return f"ts={data.get('timestamp')} ptr={data.get('pointer')} flg={data.get('flag')}"
    if ip_option == "router_alert":
        return f"alert: {data.get('alert')}"
    return str(data)


def scan_ports(target_ip, protocol, ports, timeout=FALLBACK_TIMEOUT, delay=DEFAULT_DELAY, ip_option=None):
    """
    Scan a list of ports on target_ip.
    Returns a list of dicts: {port, protocol, state, ip_option_data (optional)}.
    Requires root/admin privileges.
    """
    results = []

    if ip_option is not None and ip_option not in IP_OPTIONS:
        raise ValueError(f"Unsupported IP option: {ip_option}. Valid options: {list(IP_OPTIONS.keys())}")

    if protocol == "tcp":
        for port in ports:
            state, option_data = _tcp_syn_scan(target_ip, port, timeout, ip_option)
            sleep(delay)
            entry = {"port": port, "protocol": "tcp", "state": state}
            if option_data is not None:
                entry["ip_option_data"] = option_data
            results.append(entry)

    elif protocol == "udp":
        for port in ports:
            state, option_data = _udp_scan(target_ip, port, timeout, ip_option)
            sleep(delay)
            entry = {"port": port, "protocol": "udp", "state": state}
            if option_data is not None:
                entry["ip_option_data"] = option_data
            results.append(entry)

    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    return results


def scan_with_ip_options(target_ip, protocol, ports, ip_options, timeout=FALLBACK_TIMEOUT, delay=DEFAULT_DELAY):
    """
    Run a baseline scan (no IP options), then scan with each specified IP option.
    Compares results against baseline to determine support.

    Returns:
        {
            "baseline": [{"port": ..., "protocol": ..., "state": ...}, ...],
            "options": {
                "record_route": {"results": [...], "supported": bool},
                ...
            }
        }
    """
    print(f"  Running baseline scan (no IP options)...")
    baseline = scan_ports(target_ip, protocol, ports, timeout=timeout, delay=delay, ip_option=None)

    baseline_states = {r["port"]: r["state"] for r in baseline}

    options_results = {}
    for opt_name in ip_options:
        print(f"  Running scan with {opt_name}...")
        results = scan_ports(target_ip, protocol, ports, timeout=timeout, delay=delay, ip_option=opt_name)

        # Determine support:
        #   supported    — at least one port got a response (open/closed) with the option
        #   blocked      — a reachable baseline port (open/closed) became filtered
        #   inconclusive — everything filtered in both baseline and option scan
        has_response = False
        has_blocked = False
        for r in results:
            base_state = baseline_states.get(r["port"])
            if r["state"] in ("open", "closed"):
                has_response = True
            if base_state in ("open", "closed") and r["state"] == "filtered":
                has_blocked = True

        if has_response:
            support = "supported"
        elif has_blocked:
            support = "blocked"
        else:
            support = "inconclusive"

        options_results[opt_name] = {
            "results": results,
            "support": support,
        }

    return {
        "baseline": baseline,
        "options": options_results,
    }


def _tcp_syn_scan(target_ip, port, timeout, ip_option=None):
    options = [IP_OPTIONS[ip_option]()] if ip_option else []
    pkt = IP(dst=target_ip, options=options) / TCP(dport=port,
                                  sport=int(RandShort()), flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return ("filtered", None)

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags & 0x12 == 0x12:  # SYN-ACK
            # Reset the half-open connection
            send(IP(dst=target_ip) / TCP(dport=port,
                 flags="R", seq=resp[TCP].ack), verbose=0)
            return ("open", _extract_ip_option_data(resp, ip_option))
        if flags & 0x04:  # RST
            return ("closed", _extract_ip_option_data(resp, ip_option))

    if resp.haslayer(ICMP):
        # Type 3 = Destination Unreachable; codes 1,2,3,9,10,13 indicate filtering
        if resp[ICMP].type == 3 and resp[ICMP].code in (1, 2, 3, 9, 10, 13):
            return ("filtered", _extract_ip_option_data(resp, ip_option))

    return ("filtered", _extract_ip_option_data(resp, ip_option))


def _udp_scan(target_ip, port, timeout, ip_option=None):
    options = [IP_OPTIONS[ip_option]()] if ip_option else []
    pkt = IP(dst=target_ip, options=options) / UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return ("open|filtered", None)

    if resp.haslayer(UDP):
        return ("open", _extract_ip_option_data(resp, ip_option))

    if resp.haslayer(ICMP):
        if resp[ICMP].type == 3:       # Destination Unreachable
            if resp[ICMP].code == 3:
                return ("closed", _extract_ip_option_data(resp, ip_option))
            return ("filtered", _extract_ip_option_data(resp, ip_option))

    return ("open|filtered", _extract_ip_option_data(resp, ip_option))
