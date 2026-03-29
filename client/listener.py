import socket
import platform
from core.config import DEFAULT_CONTROL_PORT, DEFAULT_TIMEOUT, DEFAULT_DELAY
from core.protocol import (
    send_message, recv_message,
    MSG_TYPE_CONNECT, MSG_TYPE_CONNECT_ACK,
    MSG_TYPE_SCAN_REQUEST, MSG_TYPE_SCAN_ACK,
    MSG_TYPE_RESULT, MSG_TYPE_ERROR,
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
        _run_session(sock, server_host, scan_config or {})
    finally:
        sock.close()
        print("[Client] Disconnected.")


def _run_session(sock, server_host, scan_config):
    msg = recv_message(sock)
    if not msg or msg.get("type") != MSG_TYPE_CONNECT:
        print("[Client] Expected CONNECT from server.")
        return

    send_message(sock, {
        "type": MSG_TYPE_CONNECT_ACK,
        "info": {
            "os": platform.system(),
            "os_version": platform.release(),
        },
        "scan_config": scan_config,
    })
    print(f"[Client] Handshake complete. Requested: "
          f"{scan_config.get('protocol', 'tcp').upper()}, "
          f"{len(scan_config.get('ports', []))} ports")

    # --- Main control loop ---
    while True:
        msg = recv_message(sock)
        if msg is None:
            print("[Client] Server closed the connection.")
            break

        msg_type = msg.get("type")

        if msg_type == MSG_TYPE_SCAN_REQUEST:
            _handle_scan_request(sock, msg, server_host)
        elif msg_type == MSG_TYPE_RESULT:
            _print_results(msg)
        elif msg_type == MSG_TYPE_ERROR:
            print(f"[Client] Server error: {msg.get('message')}")
            break
        else:
            print(f"[Client] Unknown message type: {msg_type!r}")


def _handle_scan_request(sock, msg, server_host):
    scan_id = msg.get("scan_id")
    direction = msg.get("direction")
    protocol = msg.get("protocol")
    ports = msg.get("ports", [])
    timeout = msg.get("timeout", DEFAULT_TIMEOUT)
    delay = msg.get("delay", DEFAULT_DELAY)

    print(f"[Client] Scan request [{scan_id}]: {direction} {protocol.upper()}, {len(ports)} ports")

    send_message(sock, {
        "type": MSG_TYPE_SCAN_ACK,
        "scan_id": scan_id,
        "status": "ready",
    })

    if direction == "outbound":
        # Client scans the server and reports back
        print(f"[Client] Running {protocol.upper()} scan toward server...")
        results = scan_ports(server_host, protocol, ports, timeout=timeout, delay=delay)
        send_message(sock, {
            "type": MSG_TYPE_RESULT,
            "scan_id": scan_id,
            "direction": direction,
            "results": results,
        })


def _print_results(msg):
    results = msg.get("results", [])
    scan_id = msg.get("scan_id", "?")
    direction = msg.get("direction", "?")
    print(f"\n  Scan [{scan_id}] — {direction}:")
    for r in results:
        print(f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}")
