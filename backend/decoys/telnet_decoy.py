import asyncio
import time
import uuid
from typing import Callable, Optional
from backend.config import TELNET_PORT, HOST
from backend.engine.session_recorder import session_recorder

class TelnetDecoyServer:
    def __init__(self, host=HOST, port=TELNET_PORT, on_event: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.on_event = on_event or (lambda e: None)
        self.server = None

    async def start(self):
        """Start listening for Telnet connections."""
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info("peername")
        client_ip = client_addr[0] if client_addr else "0.0.0.0"
        client_port = client_addr[1] if client_addr else 0
        session_id = str(uuid.uuid4())

        username = ""
        password = ""

        try:
            # Telnet Banner
            banner = "\r\n--- RouterOS v6.48.6 (MIPS) ---\r\n\r\n"
            writer.write(banner.encode("ascii"))
            await writer.drain()

            # Username Prompt
            writer.write(b"login: ")
            await writer.drain()
            raw_user = await asyncio.wait_for(reader.readline(), timeout=15)
            username = raw_user.decode("ascii", errors="ignore").strip()

            # Password Prompt (hide echo or prompt)
            writer.write(b"Password: ")
            await writer.drain()
            raw_pass = await asyncio.wait_for(reader.readline(), timeout=15)
            password = raw_pass.decode("ascii", errors="ignore").strip()

            # Fire Auth telemetry event
            self.on_event({
                "session_id": session_id,
                "source_ip": client_ip,
                "source_port": client_port,
                "target_port": self.port,
                "protocol": "TELNET",
                "service": "telnet",
                "username": username,
                "password": password,
                "payload": f"Telnet Auth Attempt: {username}:{password}"
            })

            # Grant interactive shell access
            welcome = (
                "\r\n\r\nBusyBox v1.22.1 (2018-04-12 14:22:10 CST) built-in shell (ash)\r\n"
                "Enter 'help' for a list of built-in commands.\r\n\r\n"
            )
            writer.write(welcome.encode("ascii"))
            await writer.drain()

            session_recorder.start_session(
                session_id=session_id,
                protocol="TELNET",
                source_ip=client_ip,
                username=username,
                password=password
            )
            session_recorder.record_event(session_id, "out", welcome)

            prompt = "# "
            writer.write(prompt.encode("ascii"))
            await writer.drain()

            # Interactive Shell Loop
            while True:
                line_bytes = await asyncio.wait_for(reader.readline(), timeout=60)
                if not line_bytes:
                    break

                cmd = line_bytes.decode("ascii", errors="ignore").strip()
                if not cmd:
                    writer.write(prompt.encode("ascii"))
                    await writer.drain()
                    continue

                session_recorder.record_event(session_id, "in", cmd)

                self.on_event({
                    "session_id": session_id,
                    "source_ip": client_ip,
                    "source_port": client_port,
                    "target_port": self.port,
                    "protocol": "TELNET",
                    "service": "telnet",
                    "username": username,
                    "password": password,
                    "payload": cmd
                })

                if cmd in ["exit", "quit", "logout"]:
                    writer.write(b"Goodbye.\r\n")
                    await writer.drain()
                    break

                output = self._handle_iot_cmd(cmd)
                writer.write((output + "\r\n" + prompt).encode("ascii"))
                await writer.drain()
                session_recorder.record_event(session_id, "out", output + "\r\n" + prompt)

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await session_recorder.end_session(session_id)

    def _handle_iot_cmd(self, cmd: str) -> str:
        parts = cmd.split()
        prog = parts[0].lower() if parts else ""

        if prog in ["/bin/busybox", "busybox"]:
            return "BusyBox v1.22.1 (2018-04-12) multi-call binary.\nCurrently defined functions:\n  cat, chmod, cp, echo, kill, ls, mkdir, ps, pwd, rm, sh, wget"
        elif prog == "cat" and len(parts) > 1 and "cpuinfo" in parts[1]:
            return "processor\t: 0\ncpu model\t: MIPS 24KEc V5.0\nBogoMIPS\t: 385.84\nFeatures\t: mips16 dsp"
        elif prog == "cat" and len(parts) > 1 and "passwd" in parts[1]:
            return "admin:$1$xyz$ABC123:0:0:root:/root:/bin/sh\nguest:*:1000:1000:guest:/home/guest:/bin/sh"
        elif prog == "ps":
            return "  PID USER       VSZ STAT COMMAND\n    1 admin     1088 S    init\n   45 admin      784 S    /sbin/klogd\n  102 admin     1240 S    /usr/sbin/telnetd\n  150 admin     1450 S    /bin/mips-daemon"
        elif prog in ["ls", "dir"]:
            return "bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var"
        elif prog == "uname" or prog == "uname -a":
            return "Linux Router 3.10.14 #1 Wed Mar 28 10:44:12 CST 2018 mips GNU/Linux"
        elif prog in ["wget", "tftp", "curl"]:
            return "Connecting to server... Download complete."
        elif prog in ["chmod", "rm", "kill", "mkdir", "cp", "echo", "sh"]:
            return ""  # Silent success
        elif prog == "help":
            return "Available commands: cat, chmod, cp, echo, kill, ls, mkdir, ps, pwd, rm, sh, uname, wget"
        return f"/bin/sh: {prog}: not found"

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

