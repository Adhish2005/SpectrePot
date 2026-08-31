import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_PATH = DATA_DIR / "spectrepot.db"
SSH_HOST_KEY = DATA_DIR / "ssh_host_rsa.key"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Network Configuration
HOST = "0.0.0.0"
WEB_PORT = 8000
SSH_PORT = 2222
HTTP_PORT = 8080
TELNET_PORT = 2323
SCAN_PORTS = [2121, 3306, 3389, 5900, 6379]

# Honeypot Station Geo-Coordinates (Home Base Node on 3D Globe)
# Update this to reflect your actual AWS EC2 region and Elastic IP before deployment.
HONEYPOT_NODE = {
    "name": "AttackMe",
    "ip": "51.21.145.102",   # <-- Replace with your Elastic IP before deploying
    "lat": 59.3327,
    "lon": 18.0648,
    "city": "Stockholm",
    "country": "SE",
    "country_code": "SE"
}
