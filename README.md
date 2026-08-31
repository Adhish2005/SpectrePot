# ⚡ SpectrePot 3D — Global Threat Operations & Interactive Decoy Honeypot

An interactive, multi-protocol cyber security honeypot and real-time **3D Cyber Threat Intelligence Visualizer** built in Python, AsyncIO, WebSockets, Three.js, and Globe.gl.

SpectrePot lures attackers into simulated vulnerable environments (SSH, HTTP Admin & APIs, Telnet/IoT, and Port Scans), enriches attacker IPs with Geo-coordinates and MITRE ATT&CK taxonomies, and projects glowing ballistic trajectories onto a real-time 3D Earth globe.

---

## 🌟 Key Features

* 🌐 **Interactive 3D WebGL Threat Globe**: High-FPS rotating Earth globe with glowing parabolic projectile arcs connecting attacking origins to your honeypot station, impact ripple rings, and threat heatmaps.
* 🔑 **Interactive Fake SSH Shell (Port 2222)**: Complete SSH server decoy with interactive pseudo-terminal (PTY), Linux shell command emulation (`uname`, `cat /etc/passwd`, `wget`, `whoami`, `ps aux`), and keystroke logging.
* 🛡 **Vulnerable Web Traps (Port 8080)**: Catches environment credential harvesters (`.env`, `.git`), command injection exploits (`/api/ping?host=127.0.0.1;id`), directory traversal (`../../etc/passwd`), and SQL injection attempts.
* 🤖 **Telnet IoT / Mirai Botnet Trap (Port 2323)**: Emulates BusyBox router shells targeted by Mirai and IoT malware.
* 🔍 **Multi-Port Reconnaissance Trap**: Intercepts TCP port sweeps on unadvertised ports (FTP: 21, MySQL: 3306, RDP: 3389, VNC: 5900, Redis: 6379).
* 🎯 **MITRE ATT&CK & Threat Classifier**: Automatically tags attacks with MITRE IDs (e.g. `T1110` Brute Force, `T1059` Command Execution, `T1190` Exploit Public-Facing App) and severity ratings (*Low, Medium, High, Critical*).
* 📼 **Attacker Session Replayer**: Watch recorded attacker interactive terminal sessions replay keystroke-by-keystroke with speed controls.
* 🔊 **Synthesized Web Audio Alerts**: Sci-fi cyber audio feedback for high-severity intrusions using the browser's native Web Audio API.
* 🚀 **Smart Local Geo-Mapping**: Test seamlessly on `localhost` or private LANs — the engine dynamically maps local tests to realistic global threat actors so your 3D globe lights up instantly.

---

## 🏗 Architecture

```
Cyber Proj/
├── backend/
│   ├── config.py                 # Network configuration & honeypot node coordinates
│   ├── server.py                 # FastAPI Web & WebSocket stream server
│   ├── decoys/
│   │   ├── ssh_decoy.py          # Interactive SSH honeypot with simulated Linux shell
│   │   ├── http_decoy.py         # Vulnerable web traps (.env, RCE, LFI, SQLi)
│   │   ├── telnet_decoy.py       # Mirai IoT decoy
│   │   └── scan_decoy.py         # Multi-port TCP connect trap
│   └── engine/
│       ├── database.py           # SQLite asynchronous event store
│       ├── geo_enricher.py       # GeoIP lookup & smart LAN simulation engine
│       ├── classifier.py         # MITRE ATT&CK taxonomy & severity engine
│       └── session_recorder.py   # Keystroke session recording
├── frontend/
│   ├── index.html                # SOC Cyber Operations Center UI
│   ├── css/style.css             # Cyberpunk/Dark-mode SOC stylesheet
│   └── js/
│       ├── sound.js              # Synthesized Web Audio alert engine
│       ├── globe_view.js         # Globe.gl & Three.js 3D threat visualizer
│       ├── charts.js             # Telemetry & SOC metrics
│       ├── replayer.js           # Attacker terminal playback engine
│       └── app.js                # Core controller & WebSocket client
├── tools/
│   └── attack_sim.py             # Penetration testing & botnet attack generator
├── run.py                        # Master single-command launcher
├── requirements.txt              # Python dependencies
└── README.md
```

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch SpectrePot 3D
```bash
python3 run.py
```
Open your browser at **[http://localhost:8000](http://localhost:8000)** to view the live 3D Cyber Operations Center.

### 3. Launch Simulated Attacks
Open a new terminal and run the built-in multi-vector attack generator:

* **Full Multi-Vector Suite**:
  ```bash
  python3 tools/attack_sim.py --mode all
  ```
* **Simulated Cyber War (Continuous Botnet Stream)**:
  ```bash
  python3 tools/attack_sim.py --mode botnet --duration 45
  ```
* **Targeted Attacks**:
  ```bash
  python3 tools/attack_sim.py --mode ssh      # SSH dictionary brute-force + shell
  python3 tools/attack_sim.py --mode http     # Web scans, LFI, and RCE
  python3 tools/attack_sim.py --mode telnet   # Mirai botnet IoT handshake
  python3 tools/attack_sim.py --mode scan     # Multi-port reconnaissance sweep
  ```

---

## 🧠 Networking & Security Concepts Learned

1. **Socket Programming & Asynchronous I/O (`asyncio`, `paramiko`)**:
   - Understanding TCP handshakes, socket state management, non-blocking stream readers/writers.
   - Managing multiplexed connections across multiple concurrent decoy ports.
2. **SSH Protocol & PTY Virtual Terminals**:
   - Implementing SSH key exchange, user authentication negotiation, and emulating ANSI/VT100 terminal escape sequences.
3. **HTTP Protocol Exploitation**:
   - Parsing raw HTTP request lines, headers, query parameters, and form-encoded payloads.
   - Detecting common web attack signatures (SQLi, Local File Inclusion, Remote Code Execution).
4. **Threat Intelligence & MITRE ATT&CK Framework**:
   - Mapping real-world adversary behaviors to standardized tactics and techniques.
5. **Real-time Event Streaming & 3D WebGL**:
   - Streaming binary/JSON event frames over WebSockets.
   - Projecting spherical latitude/longitude coordinates onto 3D geodesics with Three.js.

