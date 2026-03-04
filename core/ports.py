import os

def parse_port_range(port_string):
    """
    parse a user-defined port string into a list of unique integers.
    supports single ports, comma separation and ranges.
    """
    ports = set()
    
    parts = port_string.split(',')

    for part in parts:
        part = part.strip()
        if not part:
            continue

        if '-' in part: # recieved range
            # handle ranges
            try:
                start, end = map(int, part.split('-', 1))
                if start <= end:
                    ports.update(range(start, end + 1))
                else:
                    print(f"Warning: Invalid range '{part}' (start > end). Ignoring.")
            except ValueError:
                print(f"Warning: Could not parse range '{part}'. Ignoring.")
        else:
            # handle single ports
            try:
                ports.add(int(part))
            except ValueError:
                print(f"Warning: Could not parse port '{part}'. Ignoring.")
                
    # return a sorted list of valid ports
    return sorted([p for p in ports if 1 <= p <= 65535])

def get_nmap_top_ports(filepath='data/nmap-services', top_n=1000):
    """
    parses Nmap services file, sorts by open frequency, 
    and returns the top N unique port numbers.
    """
    if not os.path.exists(filepath):
        print(f"Error: Nmap services file not found at {filepath}")
        return []

    ports_data = []
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.split('#', 1)[0].strip() # comment handling

            if not line:
                continue

            parts = line.split()

            # verify it has service_name, port and frequency
            if len(parts) >= 3:
                try:
                    port_proto = parts[1]
                    frequency = float(parts[2])

                    port_str = port_proto.split('/')[0]
                    port_num = int(port_str)
                    
                    ports_data.append((port_num, frequency))
                except ValueError:
                    continue

    # sort by frequency in descending order (highest frequency first)
    ports_data.sort(key=lambda x: x[1], reverse=True)
    
    # extract top N unique port numbers
    unique_ports = []
    for port, freq in ports_data:
        if port not in unique_ports:
            unique_ports.append(port)
        if len(unique_ports) == top_n:
            break

    return sorted(unique_ports)

if __name__ == "__main__":
    print("Testing custom range '22, 80, 100-105':")
    print(parse_port_range("22, 80, 100-105"))
    
    # test nmap-services file
    print("\nTesting Nmap top 10 ports:")
    print(get_nmap_top_ports(top_n=1000))