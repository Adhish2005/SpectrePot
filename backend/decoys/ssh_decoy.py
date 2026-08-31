import asyncio
import os
import socket
import threading
import time
import uuid
import paramiko
from pathlib import Path
from typing import Callable, Optional

from backend.config import SSH_HOST_KEY, SSH_PORT, HOST, QUARANTINE_DIR
from backend.engine.session_recorder import session_recorder

# Ensure RSA Host Key exists for Paramiko
def ensure_host_key():
    if not SSH_HOST_KEY.exists():
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(SSH_HOST_KEY))
    return paramiko.RSAKey(filename=str(SSH_HOST_KEY))

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:System Administrator,,,:/home/admin:/bin/bash
ubuntu:x:1001:1001:Ubuntu Default User,,,:/home/ubuntu:/bin/bash
postgres:x:1002:1002:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
"""

class DecoySSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, on_event_callback: Callable):
        self.client_ip = client_ip
        self.client_port = client_port
        self.on_event_callback = on_event_callback
        self.session_id = str(uuid.uuid4())
        self.username = "unknown"
        self.password = ""
        self.auth_attempts = 0
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.auth_attempts += 1
        
        # Fire attack telemetry event for auth attempt
        self.on_event_callback({
            "session_id": self.session_id,
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "target_port": SSH_PORT,
            "protocol": "SSH",
            "service": "ssh",
            "username": username,
            "password": password,
            "payload": f"SSH Auth Attempt: {username}:{password}"
        })

        # Allow login on common creds or after 2 attempts to entice deeper interaction
        if self.auth_attempts >= 2 or username in ["root", "admin", "ubuntu", "user", "guest"]:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.on_event_callback({
            "session_id": self.session_id,
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "target_port": SSH_PORT,
            "protocol": "SSH",
            "service": "ssh",
            "username": self.username,
            "password": self.password,
            "payload": f"SSH Direct Exec: {command.decode(errors='ignore')}"
        })
        self.event.set()
        return True


class SSHDecoyServer:
    def __init__(self, host=HOST, port=SSH_PORT, on_event: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.on_event = on_event or (lambda e: None)
        self.host_key = ensure_host_key()
        self.running = False
        self.sock = None

    def start(self):
        """Start listening for incoming SSH connections."""
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(100)
        
        thread = threading.Thread(target=self._listen_loop, daemon=True, name="SSH-Decoy-Listener")
        thread.start()

    def _listen_loop(self):
        while self.running:
            try:
                client_sock, (client_ip, client_port) = self.sock.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_ip, client_port),
                    daemon=True
                ).start()
            except Exception:
                if not self.running:
                    break

    def _handle_client(self, client_sock: socket.socket, client_ip: str, client_port: int):
        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self.host_key)
            
            server = DecoySSHServer(client_ip, client_port, self.on_event)
            transport.start_server(server=server)
            
            chan = transport.accept(20)
            if chan is None:
                return

            server.event.wait(10)
            if not server.event.is_set():
                chan.close()
                return

            # Start interactive shell session recording
            session_recorder.start_session(
                session_id=server.session_id,
                protocol="SSH",
                source_ip=client_ip,
                username=server.username,
                password=server.password
            )

            # Interactive Fake Linux Shell
            self._run_fake_shell(chan, server)

        except Exception:
            pass
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass
            asyncio.run(session_recorder.end_session(server.session_id))

    def _run_fake_shell(self, chan, server: DecoySSHServer):
        prompt = f"\033[1;32mroot@prod-srv-01\033[0m:\033[1;34m~#\033[0m "
        banner = (
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)\r\n\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/pro\r\n\r\n"
            "System load:  0.12, 0.08, 0.02\r\n"
            "Processes:    128\r\n"
            "Memory usage: 14%\r\n"
            "Swap usage:   0%\r\n\r\n"
            "Last login: Mon Aug 25 10:14:22 2026 from 10.0.0.1\r\n"
        )
        chan.send(banner)
        chan.send(prompt)
        session_recorder.record_event(server.session_id, "out", banner + prompt)

        cmd_buffer = ""
        while self.running:
            try:
                data = chan.recv(1024)
                if not data:
                    break

                text = data.decode(errors="ignore")
                for char in text:
                    if char in ('\r', '\n'):
                        chan.send("\r\n")
                        full_cmd = cmd_buffer.strip()
                        cmd_buffer = ""

                        if full_cmd:
                            # Record and fire event
                            session_recorder.record_event(server.session_id, "in", full_cmd)
                            self.on_event({
                                "session_id": server.session_id,
                                "source_ip": server.client_ip,
                                "source_port": server.client_port,
                                "target_port": SSH_PORT,
                                "protocol": "SSH",
                                "service": "ssh",
                                "username": server.username,
                                "password": server.password,
                                "payload": full_cmd
                            })

                            if full_cmd in ["exit", "logout", "quit"]:
                                chan.send("logout\r\nConnection to prod-srv-01 closed.\r\n")
                                return

                            output = self._execute_fake_cmd(full_cmd)
                            if output:
                                chan.send(output + "\r\n")
                                session_recorder.record_event(server.session_id, "out", output + "\r\n")

                        chan.send(prompt)
                        session_recorder.record_event(server.session_id, "out", prompt)

                    elif char == '\x03':  # Ctrl+C
                        chan.send("^C\r\n" + prompt)
                        cmd_buffer = ""
                    elif char in ('\x08', '\x7f'):  # Backspace
                        if len(cmd_buffer) > 0:
                            cmd_buffer = cmd_buffer[:-1]
                            chan.send("\b \b")
                    else:
                        cmd_buffer += char
                        chan.send(char)  # Echo back
            except Exception:
                break

    def _execute_fake_cmd(self, cmd: str) -> str:
        parts = cmd.split()
        if not parts:
            return ""
        prog = parts[0].lower()
        args = parts[1:]

        if prog == "whoami":
            return "root"
        elif prog == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        elif prog in ["uname", "uname -a"] or (prog == "uname" and "-a" in args):
            return "Linux prod-srv-01 5.15.0-101-generic #111-Ubuntu SMP Tue Jan 16 11:22:33 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
        elif prog in ["ls", "dir"]:
            if "-la" in args or "-l" in args or "-a" in args:
                return (
                    "total 48\r\n"
                    "drwx------  6 root root 4096 Aug 25 10:14 .\r\n"
                    "drwxr-xr-x 19 root root 4096 Aug 20 08:30 ..\r\n"
                    "-rw-------  1 root root  892 Aug 25 11:02 .bash_history\r\n"
                    "-rw-r--r--  1 root root 3106 Oct 15  2023 .bashrc\r\n"
                    "drwx------  2 root root 4096 Aug 18 14:20 .cache\r\n"
                    "-rw-r--r--  1 root root  161 Jul  9  2023 .profile\r\n"
                    "drwx------  2 root root 4096 Aug 21 09:15 .ssh\r\n"
                    "-rw-r--r--  1 root root  384 Aug 25 09:44 backup.sh\r\n"
                    "drwxr-xr-x  3 root root 4096 Aug 22 17:30 database_backups"
                )
            return "backup.sh  database_backups  logs"
        elif prog == "pwd":
            return "/root"
        elif prog == "cat":
            target = " ".join(args)
            if "passwd" in target:
                return FAKE_PASSWD.replace("\n", "\r\n")
            elif "shadow" in target:
                return "root:$6$vQ9j039a$9h4n...:19000:0:99999:7:::\r\nadmin:$6$7Fk12..:19000:0:99999:7:::"
            elif "backup.sh" in target:
                return "#!/bin/bash\r\nmysqldump -u root -p'SecurePass2026!' prod_db > /root/database_backups/backup.sql"
            elif any(f in target for f in ["issue", "os-release"]):
                return "Ubuntu 22.04.3 LTS \\n \\l"
            return f"cat: {target}: No such file or directory"
        elif prog in ["wget", "curl"]:
            url = args[-1] if args else "unknown"
            return f"--2026-08-27 10:20:01--  {url}\r\nResolving payload host... 200 OK\r\nSaving to: 'payload.bin'\r\n100%[===================>] 24.5K  --.-KB/s    in 0.02s"
        elif prog == "chmod":
            return ""  # Silent success
        elif prog in ["ps", "top"]:
            return (
                "PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\r\n"
                "  1 root      20   0  169300  13200   8400 S   0.0   0.2   0:04.12 systemd\r\n"
                "612 root      20   0   14200   6100   4800 S   0.0   0.1   0:01.05 sshd\r\n"
                "890 www-data  20   0  245000  32100  12400 S   0.0   0.5   0:12.44 nginx\r\n"
                "940 mysql     20   0 1850000 350000  28000 S   0.2   4.5   1:45.30 mysqld"
            )
        elif prog in ["ifconfig", "ip"]:
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                "        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
                "        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)"
            )
        elif prog == "history":
            return (
                "  1  cd /var/www/html\r\n"
                "  2  git pull origin main\r\n"
                "  3  systemctl restart nginx\r\n"
                "  4  mysql -u root -p\r\n"
                "  5  crontab -e\r\n"
                "  6  ./backup.sh"
            )
        elif prog in ["cd", "mkdir", "rm", "cp", "mv", "touch", "sudo"]:
            return ""  # Fake silent success
        return f"bash: {prog}: command not found"

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

