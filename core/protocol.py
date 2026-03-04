import json
import struct

# standard messages types
MSG_TYPE_SCAN_REQUEST = "SCAN_REQUEST"
MSG_TYPE_SCAN_ACK = "SCAN_ACK"
MSG_TYPE_RESULT = "RESULT"
MSG_TYPE_ERROR = "ERROR"

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

# --- Quick Test Block ---
if __name__ == "__main__":
    import socket
    import threading
    import time

    # A quick local test to prove the framing works
    def mock_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 9999))
        server.listen(1)
        conn, addr = server.accept()
        
        print("Server: Waiting for message...")
        msg = recv_message(conn)
        print(f"Server received: {msg}")
        
        reply = {"type": MSG_TYPE_SCAN_ACK, "status": "Ready"}
        send_message(conn, reply)
        conn.close()
        server.close()

    # Start the dummy server in the background
    threading.Thread(target=mock_server, daemon=True).start()
    time.sleep(0.5) # Give it a moment to start

    # Act as the client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 9999))
    
    test_msg = {
        "type": MSG_TYPE_SCAN_REQUEST, 
        "direction": "incoming",
        "protocol": "udp",
        "ports": [53, 67, 123]
    }
    print(f"Client sending: {test_msg}")
    send_message(client, test_msg)
    
    response = recv_message(client)
    print(f"Client received reply: {response}")
    
    client.close()