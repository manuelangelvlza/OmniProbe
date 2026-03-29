import uuid
from core.protocol import * # type: ignore
from server.scanner import scan_ports
from core.config import * # type: ignore

# Defaults used when the client doesn't specify scan parameters
_DEFAULT_SCAN_CONFIG = {
    "direction": "inbound",
    "protocol": DEFAULT_PROTOCOL,
    "ports": [22, 80, 443, 8080, 8443],
    "timeout": DEFAULT_TIMEOUT,
    "delay": DEFAULT_DELAY,
}


class ControlSession:
    """
    Manages a single client connection on the control channel.

    1. Server sends CONNECT with version info.
    2. Client replies CONNECT_ACK with the metadata and desired scan_config.
    3. Server drives one or more scan rounds using the client's scan_config.
    4. Connection closes when the session ends.
    """

    def __init__(self, sock, addr):
        self.sock = sock
        self.client_ip = addr[0]
        self.client_port = addr[1]
        self.client_info = {}
        self.scan_config = dict(_DEFAULT_SCAN_CONFIG)

    def run(self):
        try:
            if self._handshake():
                self._scan_loop()
        except Exception as e:
            print(f"[Session {self.client_ip}] Error: {e}")
        finally:
            self.sock.close()
            print(f"[Session {self.client_ip}] Connection closed.")

    def _handshake(self):
        send_message(self.sock, {
            "type": MSG_TYPE_CONNECT,
            "version": "0.1",
        })

        msg = recv_message(self.sock)
        if not msg or msg.get("type") != MSG_TYPE_CONNECT_ACK:
            print(f"[Session {self.client_ip}] Handshake failed — expected CONNECT_ACK, got: {msg}")
            return False

        self.client_info = msg.get("info", {})

        # Merge client-supplied scan preferences over the defaults
        client_scan = msg.get("scan_config", {})
        self.scan_config.update({k: v for k, v in client_scan.items() if v is not None})

        print(f"[Session {self.client_ip}] Handshake OK. "
              f"OS: {self.client_info.get('os', '?')}, "
              f"scan: {self.scan_config['protocol'].upper()} "
              f"{len(self.scan_config['ports'])} ports")
        return True

    def _scan_loop(self):
        self.request_scan(
            direction=self.scan_config["direction"],
            protocol=self.scan_config["protocol"],
            ports=self.scan_config["ports"],
            timeout=self.scan_config["timeout"],
            delay=self.scan_config["delay"],
        )
    
    # ----------------
    # API

    def request_scan(self, direction, protocol, ports, timeout=DEFAULT_TIMEOUT, delay=DEFAULT_DELAY):
        """
        Send a SCAN_REQUEST to the client and handle the result.

        direction="inbound"  -> server scans the client, sends RESULT back.
        direction="outbound"  -> client scans the server, sends RESULT back.
        """
        scan_id = str(uuid.uuid4())[:8] # short unique ID for this scan round

        send_message(self.sock, {
            "type": MSG_TYPE_SCAN_REQUEST,
            "scan_id": scan_id,
            "direction": direction,
            "protocol": protocol,
            "ports": ports,
            "timeout": timeout,
            "delay": delay,
        })

        ack = recv_message(self.sock)
        if not ack or ack.get("type") != MSG_TYPE_SCAN_ACK:
            self._send_error("Expected SCAN_ACK")
            return

        if direction == "inbound":
            print(f"[Session {self.client_ip}] Scanning ({protocol.upper()}, {len(ports)} ports)...")
            results = scan_ports(self.client_ip, protocol, ports, timeout=timeout, delay=delay)
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
            self._print_results(
                scan_id, direction, protocol,
                result_msg.get("results", []),
            )

    def _send_error(self, message):
        send_message(self.sock, {"type": MSG_TYPE_ERROR, "message": message})

    def _print_results(self, scan_id, direction, protocol, results):
        print(f"\n  Scan [{scan_id}] — {direction} {protocol.upper()}:")
        for r in results:
            print(f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}")
