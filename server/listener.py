import socket
import threading
from core.config import DEFAULT_CONTROL_PORT
from core.protocol import get_public_ipv6, recv_message, send_message, MSG_TYPE_IPV6_PING, MSG_TYPE_IPV6_PONG
from server.control import ControlSession


def _ipv6_test_handler(conn, addr):
    """Accept an IPV6_PING and reply with IPV6_PONG, then close."""
    try:
        msg = recv_message(conn)
        if msg and msg.get("type") == MSG_TYPE_IPV6_PING:
            send_message(conn, {"type": MSG_TYPE_IPV6_PONG})
            print(f"[Server] IPv6 test from {addr[0]} — OK")
    except Exception:
        pass
    finally:
        conn.close()


def _ipv6_test_listener(port, stop_event):
    """Background thread: listens on IPv6 for connectivity test connections."""
    try:
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock6.bind(("::", port))
        sock6.listen(5)
        sock6.settimeout(1.0)
    except Exception as e:
        print(f"[Server] IPv6 test listener failed to start: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = sock6.accept()
            threading.Thread(target=_ipv6_test_handler,
                             args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break

    sock6.close()


def start(host="0.0.0.0", port=DEFAULT_CONTROL_PORT, whitelist=None):
    """
    Start the OmniProbe control server.
    Blocks until KeyboardInterrupt; each accepted client runs in its own thread.
    Control channel is IPv4 only. A separate IPv6 test listener runs in the background.

    whitelist: optional list of allowed client IP strings. If None, all IPs are accepted.
    """
    allowed = set(whitelist) if whitelist else None
    if allowed:
        print(f"[Server] IP whitelist active: {', '.join(sorted(allowed))}")

    server_ipv6 = get_public_ipv6()

    stop_event = threading.Event()
    if server_ipv6:
        t = threading.Thread(target=_ipv6_test_listener,
                             args=(port, stop_event), daemon=True)
        t.start()
        print(
            f"[Server] IPv6 test listener active on [::]:{port} ({server_ipv6})")
    else:
        print("[Server] No public IPv6 detected — IPv6 test unavailable.")

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
                print(
                    f"[Server] Rejected connection from {client_ip} (not whitelisted)")
                conn.close()
                continue

            print(f"[Server] Connection from {client_ip}:{addr[1]}")
            session = ControlSession(conn, addr, server_ipv6=server_ipv6)
            threading.Thread(target=session.run, daemon=True).start()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
    finally:
        stop_event.set()
        server_sock.close()
