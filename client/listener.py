import socket
import platform
import uuid
from core.config import DEFAULT_CONTROL_PORT, DEFAULT_TIMEOUT, DEFAULT_DELAY, DEFAULT_PROTOCOL
from core.protocol import (
    send_message, recv_message,
    get_public_ipv6,
    MSG_TYPE_CONNECT, MSG_TYPE_CONNECT_ACK,
    MSG_TYPE_SCAN_REQUEST, MSG_TYPE_SCAN_ACK,
    MSG_TYPE_RESULT, MSG_TYPE_ERROR,
    MSG_TYPE_IPV6_PING, MSG_TYPE_IPV6_PONG,
)
from core.scanner import scan_ports


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
    send_message(sock, {
        "type": MSG_TYPE_CONNECT,
        "info": {
            "os": platform.system(),
            "os_version": platform.release(),
            "ipv6": client_ipv6,
        },
    })

    msg = recv_message(sock)
    if not msg or msg.get("type") != MSG_TYPE_CONNECT_ACK:
        print("[Client] Expected CONNECT_ACK from server.")
        return
    msg_version = msg.get("version", "?")
    server_ipv6 = msg.get("server_ipv6")
    print(
        f"[Client] Server version: {msg_version}, IPv6: {server_ipv6 or 'N/A'}")
    print("[Client] Handshake complete.")

    # --- IPv6 connectivity test (only when --ipv6 flag is set) ---
    if scan_config.get("ipv6"):
        _ipv6_test(server_ipv6, server_port, client_ipv6)

    # --- Send scan request ---
    scan_id = str(uuid.uuid4())[:8]
    direction = scan_config.get("direction", "inbound")
    protocol = scan_config.get("protocol", DEFAULT_PROTOCOL)
    ports = scan_config.get("ports", [])
    timeout = scan_config.get("timeout", DEFAULT_TIMEOUT)
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
        results = scan_ports(server_host, protocol, ports,
                             timeout=timeout, delay=delay, ip_option=ip_option)
        send_message(sock, {
            "type": MSG_TYPE_RESULT,
            "scan_id": scan_id,
            "direction": direction,
            "results": results,
        })
        _print_results(
            {"scan_id": scan_id, "direction": direction, "results": results})


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
    results = msg.get("results", [])
    scan_id = msg.get("scan_id", "?")
    direction = msg.get("direction", "?")
    print(f"\n  Scan [{scan_id}] — {direction}:")
    for r in results:
        print(f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}")
