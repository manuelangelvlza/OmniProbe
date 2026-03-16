import os

# Measurement server defaults
DEFAULT_SERVER_PORT = 9000

# Scan defaults
DEFAULT_TIMEOUT = 10        # seconds per connection attempt
DEFAULT_TOP_PORTS = 100     # top N nmap ports when --top is used

# Path to nmap-services file (relative to repo root, resolved from this file's location)
NMAP_SERVICES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'nmap-services')