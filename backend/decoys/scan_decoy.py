import asyncio
from typing import Callable, List, Optional
from backend.config import HOST

SERVICE_BANNERS = {
    2121: (b"220 (vsFTPd 3.0.3)\r\n", "ftp"),
    3306: (b"J\x00\x00\x00\n5.7.33-0ubuntu0.18.04.1\x00\r\x00\x00\x00\x1a?c(g=zG\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00m,iP\"d4sF;G\x00mysql_native_password\x00", "mysql"),
    3389: (b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x00\x00\x00\x00", "ms-wbt-server (rdp)"),
    5900: (b"RFB 003.008\n", "vnc"),
    6379: (b"-NOAUTH Authentication required.\r\n", "redis")
}

class PortScanDecoy:
    def __init__(self, ports: List[int], host: str = HOST, on_event: Optional[Callable] = None):
        self.ports = ports
        self.host = host
        self.on_event = on_event or (lambda e: None)
        self.servers = []

    async def start(self):
        """Start listening on designated trap ports."""
        for port in self.ports:
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port: self._handle_scan(r, w, p),
                    self.host,
                    port
                )
                self.servers.append(server)
            except Exception as e:
                print(f"[!] PortScanDecoy: Could not bind port {port}: {e}")

    async def _handle_scan(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
        client_addr = writer.get_extra_info("peername")
        client_ip = client_addr[0] if client_addr else "0.0.0.0"
        client_port = client_addr[1] if client_addr else 0
        banner_info = SERVICE_BANNERS.get(port, (b"", f"port-{port}"))
        service_name = banner_info[1]

        try:
            # Send fake service banner if configured
            if banner_info[0]:
                writer.write(banner_info[0])
                await writer.drain()

            # Attempt to read incoming probe payload
            probe_payload = ""
            try:
                raw_data = await asyncio.wait_for(reader.read(512), timeout=3.0)
                if raw_data:
                    probe_payload = raw_data.decode("latin-1", errors="replace")[:100]
            except asyncio.TimeoutError:
                pass

            # Dispatch reconnaissance event
            self.on_event({
                "source_ip": client_ip,
                "source_port": client_port,
                "target_port": port,
                "protocol": "TCP",
                "service": service_name,
                "payload": f"Probe / Banner Grab: {repr(probe_payload)}" if probe_payload else "TCP Connect Sweep"
            })
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self):
        for s in self.servers:
            s.close()
            await s.wait_closed()
