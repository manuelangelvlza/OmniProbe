import socket
import threading
from core.config import DEFAULT_CONTROL_PORT
from server.control import ControlSession


def start(host="0.0.0.0", port=DEFAULT_CONTROL_PORT, whitelist=None):
    """
    Start the OmniProbe control server.
    Blocks until KeyboardInterrupt; each accepted client runs in its own thread.
    Scan parameters are negotiated per-session via client's CONNECT_ACK.

    whitelist: optional list of allowed client IP strings. If None, all IPs are accepted.
    """
    allowed = set(whitelist) if whitelist else None
    if allowed:
        print(f"[Server] IP whitelist active: {', '.join(sorted(allowed))}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    print(f"[Server] Listening on {host}:{port}")

    try:
        while True:
            conn, addr = server_sock.accept()
            client_ip = addr[0]

            if allowed is not None and client_ip not in allowed:
                print(f"[Server] Rejected connection from {client_ip} (not whitelisted)")
                conn.close()
                continue

            print(f"[Server] Connection from {client_ip}:{addr[1]}")
            session = ControlSession(conn, addr)
            threading.Thread(target=session.run, daemon=True).start()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
    finally:
        server_sock.close()
