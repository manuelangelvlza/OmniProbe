import socket
import platform
import time
import uuid
from core.config import DEFAULT_CONTROL_PORT, DEFAULT_DELAY, DEFAULT_PROTOCOL
from core.protocol import (
    send_message, recv_message,
    get_public_ipv6,
    MSG_TYPE_CONNECT, MSG_TYPE_CONNECT_ACK,
    MSG_TYPE_SCAN_REQUEST, MSG_TYPE_SCAN_ACK,
    MSG_TYPE_RESULT, MSG_TYPE_ERROR,
    MSG_TYPE_IPV6_PING, MSG_TYPE_IPV6_PONG,
)
from core.scanner import scan_ports, scan_with_ip_options, format_option_data, IP_OPTIONS


def connect(server_host, server_port=DEFAULT_CONTROL_PORT, scan_config=None):
    """
    Connect to OmniProbe server, complete the handshake (sending scan
    preferences), process scan requests until the server closes the connection.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_host, server_port))
    print(f"[Client] Connected to {server_host}:{server_port}")

    try:
        _run_session(sock, server_host, server_port, scan_config or {})
    finally:
        sock.close()
        print("[Client] Disconnected.")


def _run_session(sock, server_host, server_port, scan_config):
    client_ipv6 = get_public_ipv6()

    # --- Handshake: client initiates ---
    t0 = time.monotonic()
    send_message(sock, {
        "type": MSG_TYPE_CONNECT,
        "info": {
            "os": platform.system(),
            "os_version": platform.release(),
            "ipv6": client_ipv6,
        },
    })

    msg = recv_message(sock)
    rtt = time.monotonic() - t0

    if not msg or msg.get("type") != MSG_TYPE_CONNECT_ACK:
        print("[Client] Expected CONNECT_ACK from server.")
        return
    msg_version = msg.get("version", "?")
    server_ipv6 = msg.get("server_ipv6")
    print(f"[Client] Server version: {msg_version}, IPv6: {server_ipv6 or 'N/A'}")
    print("[Client] Handshake complete.")

    # Calculate dynamic timeout
    if scan_config.get("timeout") == "auto":
        timeout = max(rtt * 4, 0.5)
        print(f"[Client] RTT {rtt*1000:.0f}ms — timeout set to {timeout:.2f}s")
    else:
        timeout = scan_config.get("timeout")

    # --- IPv6 connectivity test (only when --ipv6 flag is set) ---
    if scan_config.get("ipv6"):
        _ipv6_test(server_ipv6, server_port, client_ipv6)

    # --- Send scan request ---
    scan_id = str(uuid.uuid4())[:8]
    direction = scan_config.get("direction", "inbound")
    protocol = scan_config.get("protocol", DEFAULT_PROTOCOL)
    ports = scan_config.get("ports", [])
    delay = scan_config.get("delay", DEFAULT_DELAY)
    ip_option = scan_config.get("ip_option")
    ipv6 = scan_config.get("ipv6")

    send_message(sock, {
        "type": MSG_TYPE_SCAN_REQUEST,
        "scan_id": scan_id,
        "direction": direction,
        "protocol": protocol,
        "ports": ports,
        "timeout": timeout,
        "delay": delay,
        "ip_option": ip_option,
        "ipv6": ipv6,
    })
    print(
        f"[Client] Scan request [{scan_id}]: {direction} {protocol.upper()}, {len(ports)} ports")

    # --- Wait for SCAN_ACK ---
    ack = recv_message(sock)
    if not ack or ack.get("type") != MSG_TYPE_SCAN_ACK:
        print(f"[Client] Expected SCAN_ACK, got: {ack}")
        return

    if direction == "inbound":
        # Server scans and sends the result
        msg = recv_message(sock)
        if not msg:
            print("[Client] Server disconnected before sending results.")
        elif msg.get("type") == MSG_TYPE_RESULT:
            _print_results(msg)
        elif msg.get("type") == MSG_TYPE_ERROR:
            print(f"[Client] Server error: {msg.get('message')}")

    elif direction == "outbound":
        # Client scans the server and reports back
        print(f"[Client] Running {protocol.upper()} scan toward server...")

        if ip_option:
            ip_options_list = list(IP_OPTIONS.keys()) if ip_option == "all" else [ip_option]
            comparison = scan_with_ip_options(server_host, protocol, ports,
                                             ip_options_list, timeout=timeout, delay=delay)
            result_msg = {
                "type": MSG_TYPE_RESULT,
                "scan_id": scan_id,
                "direction": direction,
                "ip_option": ip_option,
                "comparison": comparison,
            }
        else:
            results = scan_ports(server_host, protocol, ports,
                                 timeout=timeout, delay=delay)
            result_msg = {
                "type": MSG_TYPE_RESULT,
                "scan_id": scan_id,
                "direction": direction,
                "results": results,
            }

        send_message(sock, result_msg)
        _print_results(result_msg)


def _ipv6_test(server_ipv6, port, client_ipv6):
    """Attempt an IPv6 TCP connection to the server"""
    if not client_ipv6:
        print("[Client] IPv6 test: skipped — no public IPv6 on this machine.")
        return
    if not server_ipv6:
        print("[Client] IPv6 test: skipped — server has no public IPv6.")
        return
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        s.settimeout(5)
        s.connect((server_ipv6, port))
        send_message(s, {"type": MSG_TYPE_IPV6_PING})
        reply = recv_message(s)
        if reply and reply.get("type") == MSG_TYPE_IPV6_PONG:
            print(f"[Client] IPv6 test: OK ({client_ipv6} -> {server_ipv6})")
        else:
            print("[Client] IPv6 test: unexpected reply from server.")
    except Exception as e:
        print(f"[Client] IPv6 test: FAILED — {e}")
    finally:
        s.close()


def _print_results(msg):
    scan_id = msg.get("scan_id", "?")
    direction = msg.get("direction", "?")
    comparison = msg.get("comparison")

    if comparison:
        _print_comparison_results(scan_id, direction, comparison)
    else:
        results = msg.get("results", [])
        print(f"\n  Scan [{scan_id}] — {direction}:")
        for r in results:
            print(f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}")


def _print_comparison_results(scan_id, direction, comparison):
    baseline = comparison.get("baseline", [])
    options = comparison.get("options", {})

    baseline_states = {r["port"]: r["state"] for r in baseline}

    print(f"\n  Scan [{scan_id}] — {direction}:")

    print(f"\n  Baseline (no IP options):")
    for r in baseline:
        print(f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}")

    for opt_name, opt_data in options.items():
        results = opt_data.get("results", [])
        print(f"\n  With {opt_name}:")
        for r in results:
            line = f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}"
            base_state = baseline_states.get(r["port"])
            if base_state and r["state"] != base_state:
                line += f"   [was {base_state}]"
            opt_info = r.get("ip_option_data")
            if opt_info:
                line += f"   {format_option_data(opt_name, opt_info)}"
            print(line)

    print(f"\n  IP Options Support:")
    for opt_name, opt_data in options.items():
        print(f"    {opt_name:<16} — {opt_data.get('support', 'unknown')}")
