# SpectrePot

**SpectrePot** is a Python-based multi-protocol honeypot and real-time cyber threat visualization platform. It simulates vulnerable services, captures attacker activity, classifies threats using the MITRE ATT&CK framework, and displays attacks on an interactive 3D globe.

## How It Works

SpectrePot uses multiple decoy services to detect different types of malicious activity:

* **SSH Honeypot (Port 2222):** Simulates a Linux shell and records authentication attempts and attacker commands.
* **HTTP Honeypot (Port 8080):** Detects common attacks such as directory traversal, SQL injection, command injection, and credential harvesting.
* **Telnet/IoT Honeypot (Port 2323):** Emulates a vulnerable IoT device to detect Mirai-style activity.
* **Port Scan Detection:** Monitors commonly targeted ports such as FTP, MySQL, RDP, VNC, and Redis for reconnaissance attempts.

Detected events are enriched with GeoIP information, classified according to MITRE ATT&CK techniques, assigned a severity level, and stored in SQLite. The backend then streams events to the frontend using WebSockets.

## Architecture

```text
Incoming Network Traffic
          |
          v
   +--------------+
   | Decoy Services|
   +--------------+
          |
          v
   Attack Detection
          |
          v
 +--------------------+
 | Threat Processing  |
 |--------------------|
 | GeoIP Enrichment   |
 | MITRE Classification|
 | Severity Analysis  |
 | Session Recording  |
 +--------------------+
          |
          v
     SQLite Database
          |
          v
       WebSocket
          |
          v
   SOC Web Dashboard
          |
     +----+----+
     |         |
   3D Globe  Analytics
```

## Tech Stack

| Technology            | Purpose                         |
| --------------------- | ------------------------------- |
| Python                | Core honeypot and backend       |
| AsyncIO               | Asynchronous network operations |
| FastAPI               | REST API and WebSocket server   |
| Uvicorn               | ASGI application server         |
| Paramiko              | SSH honeypot                    |
| SQLite / aiosqlite    | Event and session storage       |
| WebSockets            | Real-time event streaming       |
| Three.js              | 3D rendering                    |
| Globe.gl              | Interactive threat globe        |
| JavaScript, HTML, CSS | Frontend dashboard              |
| MITRE ATT&CK          | Attack classification           |

## Installation

> **Warning:** SpectrePot intentionally exposes simulated vulnerable services. Run it only in an environment you control. Using it on an internet-facing system may attract real attackers. A dedicated VM or isolated test environment is strongly recommended. You are responsible for securing and monitoring the system.

### 1. Clone the Repository

```bash
git clone https://github.com/Adhish2005/SpectrePot.git
cd SpectrePot
```

### 2. Create a Virtual Environment

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows:

```powershell
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start SpectrePot

```bash
python3 run.py
```

Open the dashboard at:

```text
http://localhost:8000
```

## Security Notice

SpectrePot is intended for **educational, research, and controlled security-testing purposes**. Do not expose it to the public internet unless you understand the associated risks and have properly isolated the host and configured its firewall/network controls.


