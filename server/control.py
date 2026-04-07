import uuid
from core.protocol import * # type: ignore
from server.scanner import scan_ports
from core.config import * # type: ignore


class ControlSession:
    """
    Manages a single client connection on the control channel.

    1. Client sends CONNECT with its metadata.
    2. Server replies CONNECT_ACK.
    3. Client sends SCAN_REQUEST with desired scan parameters.
    4. Server replies SCAN_ACK and executes the scan.
    5. Connection closes when the session ends.
    """

    def __init__(self, sock, addr):
        self.sock = sock
        self.client_ip = addr[0]
        self.client_port = addr[1]
        self.client_info = {}

    def run(self):
        try:
            if self._handshake():
                self._scan_loop()
        except Exception as e:
            print(f"[Session {self.client_ip}] Error: {e}")
        finally:
            self.sock.close()
            print(f"[Session {self.client_ip}] Connection closed.")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _handshake(self):
        msg = recv_message(self.sock)
        if not msg or msg.get("type") != MSG_TYPE_CONNECT:
            print(f"[Session {self.client_ip}] Handshake failed — expected CONNECT, got: {msg}")
            return False

        self.client_info = msg.get("info", {})

        send_message(self.sock, {
            "type": MSG_TYPE_CONNECT_ACK,
            "version": "0.1",
        })

        print(f"[Session {self.client_ip}] Handshake OK. OS: {self.client_info.get('os', '?')}")
        return True

    def _scan_loop(self):
        msg = recv_message(self.sock)
        if not msg or msg.get("type") != MSG_TYPE_SCAN_REQUEST:
            print(f"[Session {self.client_ip}] Expected SCAN_REQUEST, got: {msg}")
            return

        scan_id  = msg.get("scan_id")
        direction = msg.get("direction")
        protocol  = msg.get("protocol")
        ports     = msg.get("ports", [])
        timeout   = msg.get("timeout", DEFAULT_TIMEOUT)
        delay     = msg.get("delay", DEFAULT_DELAY)
        ip_option = msg.get("ip_option")

        send_message(self.sock, {
            "type": MSG_TYPE_SCAN_ACK,
            "scan_id": scan_id,
        })

        if direction == "inbound":
            print(f"[Session {self.client_ip}] Scanning ({protocol.upper()}, {len(ports)} ports)...")
            results = scan_ports(self.client_ip, protocol, ports, timeout=timeout, delay=delay, ip_option=ip_option)
            send_message(self.sock, {
                "type": MSG_TYPE_RESULT,
                "scan_id": scan_id,
                "direction": direction,
                "results": results,
            })
            self._print_results(scan_id, direction, protocol, results)

        elif direction == "outbound":
            result_msg = recv_message(self.sock)
            if not result_msg or result_msg.get("type") != MSG_TYPE_RESULT:
                print(f"[Session {self.client_ip}] Expected RESULT, got: {result_msg}")
                return
            self._print_results(scan_id, direction, protocol, result_msg.get("results", []))

    def _print_results(self, scan_id, direction, protocol, results):
        print(f"\n  Scan [{scan_id}] — {direction} {protocol.upper()}:")
        for r in results:
            print(f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}")
