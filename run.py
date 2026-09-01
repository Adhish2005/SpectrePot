#!/usr/bin/env python3
import os
import sys
import site

# Ensure user site packages are accessible
user_site = os.path.expanduser("~/.local/lib/python3.12/site-packages")
if os.path.exists(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)

import asyncio
import signal
import uvicorn
from backend.config import HOST, WEB_PORT, SSH_PORT, HTTP_PORT, TELNET_PORT, SCAN_PORTS, HONEYPOT_NODE
from backend.engine.database import db
from backend.decoys.ssh_decoy import SSHDecoyServer
from backend.decoys.http_decoy import HTTPDecoyServer
from backend.decoys.telnet_decoy import TelnetDecoyServer
from backend.decoys.scan_decoy import PortScanDecoy
import backend.server as server_module

BANNER = r"""
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗██████╗  ██████╗ ████████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██╔═══██╗╚══██╔══╝
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  ██████╔╝██║   ██║   ██║   
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║   ██║   
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗██║     ╚██████╔╝   ██║   
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝    ╚═╝   
                       3D Cyber Threat Intelligence & Decoy System
"""

async def main():
    print("\033[1;36m" + BANNER + "\033[0m")
    print(f"\033[1;32m[+] Initializing SpectrePot Engine...\033[0m")
    
    # 1. Initialize SQLite Database
    await db.init_db()
    print(f"[*] SQLite Database: Initialized")

    # 2. Store event loop reference for sync thread callbacks
    server_module.event_loop = asyncio.get_running_loop()

    # 3. Instantiate Decoys
    ssh_decoy = SSHDecoyServer(
        host=HOST,
        port=SSH_PORT,
        on_event=server_module.process_raw_event
    )
    http_decoy = HTTPDecoyServer(
        host=HOST,
        port=HTTP_PORT,
        on_event=lambda e: asyncio.create_task(server_module.handle_incoming_attack(e))
    )
    telnet_decoy = TelnetDecoyServer(
        host=HOST,
        port=TELNET_PORT,
        on_event=lambda e: asyncio.create_task(server_module.handle_incoming_attack(e))
    )
    scan_decoy = PortScanDecoy(
        ports=SCAN_PORTS,
        host=HOST,
        on_event=lambda e: asyncio.create_task(server_module.handle_incoming_attack(e))
    )

    # 4. Start Decoy Services
    ssh_decoy.start()
    print(f"[*] SSH Decoy:        \033[1;32mRUNNING\033[0m on port {SSH_PORT}")

    await http_decoy.start()
    print(f"[*] HTTP Decoy:       \033[1;32mRUNNING\033[0m on port {HTTP_PORT}")

    await telnet_decoy.start()
    print(f"[*] Telnet IoT Decoy: \033[1;32mRUNNING\033[0m on port {TELNET_PORT}")

    await scan_decoy.start()
    print(f"[*] Port Scan Traps:  \033[1;32mRUNNING\033[0m on ports {SCAN_PORTS}")

    print("-" * 75)
    print(f"\033[1;35m[★] Cyber SOC Dashboard & 3D Threat Globe:\033[0m \033[1;37mhttp://localhost:{WEB_PORT}\033[0m")
    print(f"\033[1;35m[★] Honeypot Station Node:\033[0m {HONEYPOT_NODE['name']} ({HONEYPOT_NODE['city']}, {HONEYPOT_NODE['country']})")
    print("-" * 75)

    # 5. Start Uvicorn Web Server
    config = uvicorn.Config(
        app=server_module.app,
        host=HOST,
        port=WEB_PORT,
        log_level="warning",
        loop="asyncio"
    )
    server = uvicorn.Server(config)

    # Graceful shutdown handler
    stop_event = asyncio.Event()
    def signal_handler():
        print("\n\033[1;33m[!] Shutting down SpectrePot services gracefully...\033[0m")
        ssh_decoy.stop()
        asyncio.create_task(http_decoy.stop())
        asyncio.create_task(telnet_decoy.stop())
        asyncio.create_task(scan_decoy.stop())
        server.should_exit = True
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            pass

    await server.serve()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("[*] SpectrePot shutdown complete.")
        sys.exit(0)
