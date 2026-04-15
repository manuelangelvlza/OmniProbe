import json
import socket
import struct

# standard message types
MSG_TYPE_CONNECT = "CONNECT"
MSG_TYPE_CONNECT_ACK = "CONNECT_ACK"
MSG_TYPE_SCAN_REQUEST = "SCAN_REQUEST"
MSG_TYPE_SCAN_ACK = "SCAN_ACK"
MSG_TYPE_RESULT = "RESULT"
MSG_TYPE_ERROR = "ERROR"
MSG_TYPE_IPV6_PING = "IPV6_PING"
MSG_TYPE_IPV6_PONG = "IPV6_PONG"

def get_public_ipv6():
    """
    Returns this machine's public IPv6 address, or None if unavailable.
    Uses a UDP connect trick: no packets sent, OS selects the source address.
    """
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect(("2001:4860:4860::8888", 80))  # Google IPv6 DNS — nothing is sent
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

def send_message(sock, message_dict):
    """
    converts a dictionary to a JSON string, calculates its byte length, 
    and sends it over the socket with a 4-byte length prefix.
    """
    try:
        # convert message -> JSON -> bytes
        json_data = json.dumps(message_dict).encode('utf-8')
        
        # pack the length into 4 bytes ('!I' = big-endian unsigned int (same as C unsigned int)))
        length_prefix = struct.pack('!I', len(json_data))

        sock.sendall(length_prefix + json_data)
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

def recv_message(sock):
    """
    Reads the 4-byte length prefix, then reads the exact amount of 
    subsequent JSON data. Returns the parsed dictionary.
    """
    # 1. Read the 4-byte length prefix
    raw_length = _recv_exactly(sock, 4)
    if not raw_length:
        return None
        
    # Unpack the 4 bytes back into an integer
    message_length = struct.unpack('!I', raw_length)[0]
    
    # 2. Read the actual JSON payload based on the length
    json_data = _recv_exactly(sock, message_length)
    if not json_data:
        return None
        
    try:
        return json.loads(json_data.decode('utf-8'))
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON payload: {e}")
        return None

def _recv_exactly(sock, num_bytes):
    """
    Helper function to ensure we receive exactly 'num_bytes'.
    TCP streams can fragment, so we loop until we have all the data.
    """
    data = b''
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            # The socket was closed by the other side
            return None 
        data += packet
    return data
