import asyncio
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import BASE_DIR, HONEYPOT_NODE, WEB_PORT, SSH_PORT, HTTP_PORT, TELNET_PORT, SCAN_PORTS
from backend.engine.database import db
from backend.engine.geo_enricher import geo_enricher
from backend.engine.classifier import classifier
from backend.engine.session_recorder import session_recorder

app = FastAPI(title="SpectrePot Threat Operations")

# CORS — restrict to same origin in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000"],  # Update to your public domain/IP when deployed
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

FRONTEND_DIR = BASE_DIR / "frontend"

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        dead_connections = set()
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead_connections.add(conn)
        for dead in dead_connections:
            self.active_connections.discard(dead)

ws_manager = ConnectionManager()
event_loop: asyncio.AbstractEventLoop = None
START_TIME = time.time()

def process_raw_event(raw_event: Dict[str, Any]):
    """Sync wrapper to schedule attack event processing in the running async loop."""
    global event_loop
    if event_loop and event_loop.is_running():
        asyncio.run_coroutine_threadsafe(handle_incoming_attack(raw_event), event_loop)

async def handle_incoming_attack(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich, classify, persist, and broadcast an attack event."""
    ip = raw_event.get("source_ip", "127.0.0.1")
    geo = geo_enricher.enrich_ip(ip)

    # Classify MITRE ATT&CK & severity
    classification = classifier.classify(
        protocol=raw_event.get("protocol", "TCP"),
        service=raw_event.get("service", "unknown"),
        payload=raw_event.get("payload", ""),
        username=raw_event.get("username", ""),
        password=raw_event.get("password", ""),
        target_port=raw_event.get("target_port", 0)
    )

    enriched_event = {
        "timestamp": time.time(),
        "session_id": raw_event.get("session_id"),
        "source_ip": geo.get("display_ip", ip),
        "source_port": raw_event.get("source_port", 0),
        "target_port": raw_event.get("target_port", 0),
        "protocol": raw_event.get("protocol", "TCP"),
        "service": raw_event.get("service", "unknown"),
        "attack_type": classification["attack_type"],
        "mitre_id": classification["mitre_id"],
        "mitre_tactic": classification["mitre_tactic"],
        "severity": classification["severity"],
        "description": classification["description"],
        "payload": raw_event.get("payload", ""),
        "username": raw_event.get("username", ""),
        "password": raw_event.get("password", ""),
        "geo_country": geo.get("country", "Unknown"),
        "geo_country_code": geo.get("country_code", "XX"),
        "geo_city": geo.get("city", "Unknown"),
        "geo_lat": geo.get("lat", 0.0),
        "geo_lon": geo.get("lon", 0.0),
        "geo_asn": geo.get("asn", "Unknown"),
        # Destination Honeypot Node coordinates for 3D Globe arc rendering
        "dest_lat": HONEYPOT_NODE["lat"],
        "dest_lon": HONEYPOT_NODE["lon"],
        "dest_node": HONEYPOT_NODE["name"]
    }

    # Store in database
    event_id = await db.record_attack(enriched_event)
    enriched_event["id"] = event_id

    # Broadcast to all connected dashboard WebSockets
    await ws_manager.broadcast({
        "type": "NEW_ATTACK",
        "data": enriched_event
    })

    return enriched_event


# API Endpoints
@app.get("/api/status")
async def get_system_status():
    uptime = round(time.time() - START_TIME, 1)
    return {
        "status": "ONLINE",
        "uptime_seconds": uptime,
        "honeypot_node": HONEYPOT_NODE,
        "services": {
            "web_dashboard": {"port": WEB_PORT, "status": "ONLINE"},
            "ssh_decoy": {"port": SSH_PORT, "status": "ONLINE"},
            "http_decoy": {"port": HTTP_PORT, "status": "ONLINE"},
            "telnet_decoy": {"port": TELNET_PORT, "status": "ONLINE"},
            "scan_decoys": {"ports": SCAN_PORTS, "status": "ONLINE"}
        }
    }

@app.get("/api/stats")
async def get_telemetry_stats():
    return await db.get_statistics()

@app.get("/api/attacks")
async def get_attacks(limit: int = Query(50, ge=1, le=500)):
    return await db.get_recent_attacks(limit=limit)

@app.get("/api/sessions")
async def get_sessions(limit: int = Query(15, ge=1, le=100)):
    return await db.get_recent_sessions(limit=limit)

@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str):
    session = await db.get_session(session_id)
    if not session:
        return JSONResponse(status_code=404, content={"error": "Session not found"})
    return session

@app.post("/api/clear")
async def clear_data():
    await db.clear_all()
    await ws_manager.broadcast({"type": "DATA_CLEARED"})
    return {"status": "CLEARED"}

# WebSocket for live dashboard streaming
@app.websocket("/ws/threats")
async def websocket_threat_feed(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial connection handshake with honeypot node position
        await websocket.send_json({
            "type": "INIT_NODE",
            "node": HONEYPOT_NODE
        })
        while True:
            # Keep connection alive and accept client commands if any
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Mount Frontend static files
if FRONTEND_DIR.exists():
    app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
    app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")

    @app.get("/")
    async def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

