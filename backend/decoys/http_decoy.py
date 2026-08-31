import asyncio
import re
import urllib.parse
from typing import Callable, Optional
from backend.config import HTTP_PORT, HOST

FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CorpNet Enterprise Gateway — Internal Portal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 360px; border: 1px solid #334155; }
        h2 { text-align: center; color: #38bdf8; margin-top: 0; }
        .input-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 6px; font-size: 14px; color: #94a3b8; }
        input { width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; box-sizing: border-box; }
        input:focus { outline: none; border-color: #38bdf8; }
        button { width: 100%; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        .notice { font-size: 12px; text-align: center; color: #64748b; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>CorpVault Internal SSO</h2>
        <form method="POST" action="/login">
            <div class="input-group">
                <label>Corporate Username / Email</label>
                <input type="text" name="username" placeholder="user@corp.internal" required>
            </div>
            <div class="input-group">
                <label>Access Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Authenticate</button>
        </form>
        <div class="notice">UNAUTHORIZED ACCESS IS STRICTLY MONITORED AND LOGGED.</div>
    </div>
</body>
</html>"""

FAKE_ENV = """# Production Environment Variables - CorpNet Gateway
NODE_ENV=production
PORT=8080

# Database Configuration
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=corp_production_db
DB_USER=postgres
DB_PASSWORD=SuperSecretPass2026!

# Cloud & API Secrets
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SECRET_KEY=9a8d7f6e5c4b3a210fedcba9876543210
STRIPE_API_KEY=sk_live_51HzT1239857129038571293847192837
REDIS_URL=redis://:RedisAdminAuth2026@127.0.0.1:6379/0
"""

class HTTPDecoyServer:
    def __init__(self, host=HOST, port=HTTP_PORT, on_event: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.on_event = on_event or (lambda e: None)
        self.server = None

    async def start(self):
        """Start listening for HTTP requests."""
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info("peername")
        client_ip = client_addr[0] if client_addr else "0.0.0.0"
        client_port = client_addr[1] if client_addr else 0

        try:
            request_data = await asyncio.wait_for(reader.read(4096), timeout=10)
            if not request_data:
                writer.close()
                await writer.wait_closed()
                return

            raw_text = request_data.decode("utf-8", errors="ignore")
            lines = raw_text.split("\r\n")
            if not lines:
                return

            # Parse Request Line: e.g. "GET /.env HTTP/1.1"
            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 2:
                return
            
            method, raw_path = parts[0], parts[1]
            parsed_url = urllib.parse.urlparse(raw_path)
            path = parsed_url.path
            query = parsed_url.query

            # Extract User-Agent and Headers
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            user_agent = headers.get("user-agent", "Unknown")
            
            # Parse POST body for credentials if applicable
            body = ""
            if "\r\n\r\n" in raw_text:
                body = raw_text.split("\r\n\r\n", 1)[1]

            username, password = "", ""
            if method == "POST" and body:
                parsed_post = urllib.parse.parse_qs(body)
                username = parsed_post.get("username", parsed_post.get("user", [""]))[0]
                password = parsed_post.get("password", parsed_post.get("pass", [""]))[0]

            # Construct Payload identifier
            full_payload = f"{method} {raw_path}"
            if body:
                full_payload += f" | Body: {body[:150]}"

            # Dispatch attack event
            self.on_event({
                "source_ip": client_ip,
                "source_port": client_port,
                "target_port": self.port,
                "protocol": "HTTP",
                "service": "http-alt",
                "username": username,
                "password": password,
                "payload": full_payload
            })

            # Route response based on decoy trap triggers
            response_bytes = self._generate_response(method, path, query, raw_path, body)
            writer.write(response_bytes)
            await writer.drain()

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _generate_response(self, method: str, path: str, query: str, raw_path: str, body: str) -> bytes:
        p_lower = path.lower()
        q_lower = query.lower()

        # 1. Environment & Config exposure trap
        if any(f in p_lower for f in [".env", ".git", "wp-config", "id_rsa", "config.json"]):
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Server: nginx/1.22.1\r\n"
                b"Connection: close\r\n\r\n" + FAKE_ENV.encode("utf-8")
            )

        # 2. Command Injection Trap: e.g. /api/ping?host=127.0.0.1;id or /diagnostics
        if "ping" in p_lower or "diagnostics" in p_lower or "exec" in p_lower:
            cmd_match = re.search(r"[;&|`$]\s*(.*)", query + body)
            fake_rce_out = "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.041 ms\n"
            if cmd_match:
                fake_rce_out += "uid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux prod-web-01 5.15.0-generic"
            
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Server: Apache/2.4.52\r\n"
                b"Connection: close\r\n\r\n" + fake_rce_out.encode("utf-8")
            )

        # 3. Directory Traversal / LFI Trap: e.g. /view?file=../../etc/passwd
        if any(token in raw_path for token in ["../", "..\\", "/etc/passwd", "win.ini"]):
            from backend.decoys.ssh_decoy import FAKE_PASSWD
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Server: nginx/1.22.1\r\n"
                b"Connection: close\r\n\r\n" + FAKE_PASSWD.encode("utf-8")
            )

        # 4. phpMyAdmin / WordPress traps
        if "phpmyadmin" in p_lower:
            pma_html = "<html><head><title>phpMyAdmin</title></head><body style='background:#f3f3f3;font-family:sans-serif;'><h2>phpMyAdmin 5.2.1</h2><p>Access restricted: Host not allowed.</p></body></html>"
            return (
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Type: text/html\r\n"
                b"Server: Apache/2.4.52\r\n"
                b"Connection: close\r\n\r\n" + pma_html.encode("utf-8")
            )

        # 5. POST Auth handler
        if method == "POST":
            err_html = "<html><body style='background:#0f172a;color:#ef4444;font-family:sans-serif;text-align:center;padding:50px;'><h3>Access Denied: Invalid Multifactor Token</h3><p><a href='/' style='color:#38bdf8;'>Back to Login</a></p></body></html>"
            return (
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Server: CorpVault-Gateway/3.1\r\n"
                b"Connection: close\r\n\r\n" + err_html.encode("utf-8")
            )

        # Default: Serve Fake Portal Login
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Server: CorpVault-Gateway/3.1\r\n"
            b"Connection: close\r\n\r\n" + FAKE_LOGIN_HTML.encode("utf-8")
        )

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

