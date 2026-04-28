import uuid
from core.protocol import * # type: ignore
from server.scanner import scan_ports
from core.scanner import scan_with_ip_options, format_option_data, IP_OPTIONS
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

    def __init__(self, sock, addr, server_ipv6=None):
        self.sock = sock
        self.client_ip = addr[0]
        self.client_port = addr[1]
        self.client_info = {}
        self.server_ipv6 = server_ipv6

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
            "server_ipv6": self.server_ipv6,
        })

        print(f"[Session {self.client_ip}] Handshake OK. OS: {self.client_info.get('os', '?')}")
        return True

    def _scan_loop(self):
        msg = recv_message(self.sock)
        if not msg or msg.get("type") != MSG_TYPE_SCAN_REQUEST:
            print(f"[Session {self.client_ip}] Expected SCAN_REQUEST, got: {msg}")
            return

        scan_id   = msg.get("scan_id")
        direction = msg.get("direction")
        protocol  = msg.get("protocol")
        ports     = msg.get("ports", [])
        timeout   = msg.get("timeout", FALLBACK_TIMEOUT)
        delay     = msg.get("delay", DEFAULT_DELAY)
        ip_option = msg.get("ip_option")

        send_message(self.sock, {
            "type": MSG_TYPE_SCAN_ACK,
            "scan_id": scan_id,
        })

        if direction == "inbound":
            print(f"[Session {self.client_ip}] Scanning ({protocol.upper()}, {len(ports)} ports)...")

            if ip_option:
                ip_options_list = list(IP_OPTIONS.keys()) if ip_option == "all" else [ip_option]
                comparison = scan_with_ip_options(self.client_ip, protocol, ports,
                                                  ip_options_list, timeout=timeout, delay=delay)
                result_msg = {
                    "type": MSG_TYPE_RESULT,
                    "scan_id": scan_id,
                    "direction": direction,
                    "ip_option": ip_option,
                    "comparison": comparison,
                }
            else:
                results = scan_ports(self.client_ip, protocol, ports,
                                     timeout=timeout, delay=delay)
                result_msg = {
                    "type": MSG_TYPE_RESULT,
                    "scan_id": scan_id,
                    "direction": direction,
                    "results": results,
                }

            send_message(self.sock, result_msg)
            self._print_results(result_msg)

        elif direction == "outbound":
            result_msg = recv_message(self.sock)
            if not result_msg or result_msg.get("type") != MSG_TYPE_RESULT:
                print(f"[Session {self.client_ip}] Expected RESULT, got: {result_msg}")
                return
            self._print_results(result_msg)

    def _print_results(self, msg):
        scan_id = msg.get("scan_id", "?")
        direction = msg.get("direction", "?")
        comparison = msg.get("comparison")

        if comparison:
            self._print_comparison_results(scan_id, direction, comparison)
        else:
            results = msg.get("results", [])
            protocol = results[0]["protocol"].upper() if results else "?"
            print(f"\n  Scan [{scan_id}] — {direction} {protocol}:")
            for r in results:
                print(f"    {r['protocol'].upper()}/{r['port']:<5}  {r['state']}")

    def _print_comparison_results(self, scan_id, direction, comparison):
        baseline = comparison.get("baseline", [])
        options = comparison.get("options", {})
        protocol = baseline[0]["protocol"].upper() if baseline else "?"

        baseline_states = {r["port"]: r["state"] for r in baseline}

        print(f"\n  Scan [{scan_id}] — {direction} {protocol}:")

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
