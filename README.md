# SpectrePot — Cybersecurity Honeypot & Threat Visualizer

SpectrePot is a Python-based honeypot that detects and records different types of cyber attacks and displays them on an interactive 3D globe.

It uses Python, AsyncIO, WebSockets, Three.js, and Globe.gl to simulate vulnerable services, collect attacker activity, map IP addresses, and classify attacks using the MITRE ATT&CK framework.

## Key Features

* **3D Threat Globe:** Displays attacker locations and attack paths in real time.
* **SSH Honeypot (2222):** Simulates a Linux shell and records attacker commands and keystrokes.
* **Web Honeypot (8080):** Detects attacks such as `.env`/`.git` scans, command injection, directory traversal, and SQL injection.
* **Telnet/IoT Honeypot (2323):** Simulates a vulnerable IoT device commonly targeted by botnets.
* **Port Scan Detection:** Detects reconnaissance attempts against common services such as FTP, MySQL, RDP, VNC, and Redis.
* **MITRE ATT&CK Classification:** Categorizes attacks and assigns severity levels.
* **Session Replay:** Replays recorded SSH sessions for analysis.
* **Local Attack Simulation:** Includes tools for testing the honeypot with different attack scenarios.

## Architecture

```text
SpectrePot/
├── backend/
│   ├── config.py
│   ├── server.py
│   ├── decoys/
│   │   ├── ssh_decoy.py
│   │   ├── http_decoy.py
│   │   ├── telnet_decoy.py
│   │   └── scan_decoy.py
│   └── engine/
│       ├── database.py
│       ├── geo_enricher.py
│       ├── classifier.py
│       └── session_recorder.py
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   └── js/
├── tools/
│   └── attack_sim.py
├── run.py
├── requirements.txt
└── README.md
```

## Quick Start

Install the dependencies:

```bash
pip install -r requirements.txt
```

Start the honeypot:

```bash
python3 run.py
```

Open `http://localhost:8000` in your browser.

To test the honeypot:

```bash
python3 tools/attack_sim.py --mode all
```

Individual attack simulations are also available:

```bash
python3 tools/attack_sim.py --mode ssh
python3 tools/attack_sim.py --mode http
python3 tools/attack_sim.py --mode telnet
python3 tools/attack_sim.py --mode scan
```

## Concepts Used

* TCP socket programming and asynchronous I/O
* SSH and PTY-based terminal emulation
* HTTP request parsing and attack detection
* Honeypot and deception techniques
* MITRE ATT&CK threat classification
* GeoIP and threat mapping
* WebSockets for real-time event streaming
* Three.js/WebGL for 3D visualization
* Session recording and attack analysis
