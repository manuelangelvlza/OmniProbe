import os

# Measurement server defaults
DEFAULT_CONTROL_PORT = 9000

# Server defaults
DEFAULT_ADDRESS = '0.0.0.0'

# Scan defaults
FALLBACK_TIMEOUT = 10.0        # seconds per connection attempt
DEFAULT_TOP_PORTS = 100     # top N nmap ports when --top is used
# delay between scan attempts in seconds (if the probing is done to fast some firewalls may drop packets), similar to nmap's timing (-T option)
DEFAULT_DELAY: float = .1
DEFAULT_PROTOCOL = "tcp"

# Path to nmap-services file (relative to repo root, resolved from this file's location)
NMAP_SERVICES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'nmap-services')