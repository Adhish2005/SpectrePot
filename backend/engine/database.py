import json
import time
import aiosqlite
from typing import Dict, Any, List, Optional
from backend.config import DB_PATH

class Database:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)

    async def init_db(self):
        """Initialize database tables and indexes."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    session_id TEXT,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER,
                    target_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    mitre_id TEXT,
                    mitre_tactic TEXT,
                    severity TEXT NOT NULL,
                    payload TEXT,
                    username TEXT,
                    password TEXT,
                    geo_country TEXT,
                    geo_country_code TEXT,
                    geo_city TEXT,
                    geo_lat REAL,
                    geo_lon REAL,
                    geo_asn TEXT
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    protocol TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    start_time REAL NOT NULL,
                    end_time REAL,
                    command_count INTEGER DEFAULT 0,
                    username TEXT,
                    password TEXT,
                    recording_json TEXT
                )
            """)

            # Create performance indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(source_ip)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_attacks_protocol ON attacks(protocol)")
            await db.commit()

    async def record_attack(self, event: Dict[str, Any]) -> int:
        """Insert a newly detected attack event."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO attacks (
                    timestamp, session_id, source_ip, source_port, target_port,
                    protocol, service, attack_type, mitre_id, mitre_tactic,
                    severity, payload, username, password,
                    geo_country, geo_country_code, geo_city, geo_lat, geo_lon, geo_asn
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("timestamp", time.time()),
                event.get("session_id"),
                event.get("source_ip", "0.0.0.0"),
                event.get("source_port", 0),
                event.get("target_port", 0),
                event.get("protocol", "TCP"),
                event.get("service", "unknown"),
                event.get("attack_type", "recon"),
                event.get("mitre_id", "T1046"),
                event.get("mitre_tactic", "Discovery"),
                event.get("severity", "LOW"),
                event.get("payload", ""),
                event.get("username", ""),
                event.get("password", ""),
                event.get("geo_country", "Unknown"),
                event.get("geo_country_code", "XX"),
                event.get("geo_city", "Unknown"),
                event.get("geo_lat", 0.0),
                event.get("geo_lon", 0.0),
                event.get("geo_asn", "Unknown")
            ))
            await db.commit()
            return cursor.lastrowid

    async def save_session(self, session_data: Dict[str, Any]):
        """Create or update a recorded interactive attacker session."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO sessions (
                    session_id, protocol, source_ip, start_time, end_time,
                    command_count, username, password, recording_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    end_time=excluded.end_time,
                    command_count=excluded.command_count,
                    recording_json=excluded.recording_json
            """, (
                session_data["session_id"],
                session_data.get("protocol", "SSH"),
                session_data.get("source_ip", ""),
                session_data.get("start_time", time.time()),
                session_data.get("end_time", time.time()),
                session_data.get("command_count", 0),
                session_data.get("username", ""),
                session_data.get("password", ""),
                json.dumps(session_data.get("events", []))
            ))
            await db.commit()

    async def get_recent_attacks(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch the most recent attack events."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Fetch details and recorded frames for an attacker session."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                data = dict(row)
                if data.get("recording_json"):
                    data["events"] = json.loads(data["recording_json"])
                return data

    async def get_recent_sessions(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetch a list of interactive attacker sessions."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT session_id, protocol, source_ip, start_time, end_time, command_count, username FROM sessions ORDER BY start_time DESC LIMIT ?",
                (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_statistics(self) -> Dict[str, Any]:
        """Aggregate telemetry metrics for dashboard charts."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # Total attacks count
            async with db.execute("SELECT COUNT(*) as total FROM attacks") as cursor:
                total_attacks = (await cursor.fetchone())["total"]

            # Severity distribution
            async with db.execute(
                "SELECT severity, COUNT(*) as count FROM attacks GROUP BY severity"
            ) as cursor:
                severity_counts = {row["severity"]: row["count"] for row in await cursor.fetchall()}

            # Protocol distribution
            async with db.execute(
                "SELECT protocol, COUNT(*) as count FROM attacks GROUP BY protocol"
            ) as cursor:
                protocol_counts = {row["protocol"]: row["count"] for row in await cursor.fetchall()}

            # Top 10 Attacking Countries
            async with db.execute("""
                SELECT geo_country, geo_country_code, COUNT(*) as count 
                FROM attacks 
                WHERE geo_country != 'Unknown' 
                GROUP BY geo_country 
                ORDER BY count DESC LIMIT 8
            """) as cursor:
                top_countries = [dict(row) for row in await cursor.fetchall()]

            # Top 10 Target Ports
            async with db.execute("""
                SELECT target_port, service, COUNT(*) as count 
                FROM attacks 
                GROUP BY target_port 
                ORDER BY count DESC LIMIT 8
            """) as cursor:
                top_ports = [dict(row) for row in await cursor.fetchall()]

            # Top Attempted Credentials (usernames / passwords)
            async with db.execute("""
                SELECT username, password, COUNT(*) as count 
                FROM attacks 
                WHERE username != '' 
                GROUP BY username, password 
                ORDER BY count DESC LIMIT 10
            """) as cursor:
                top_credentials = [dict(row) for row in await cursor.fetchall()]

            # Unique Attacking IPs
            async with db.execute("SELECT COUNT(DISTINCT source_ip) as unique_ips FROM attacks") as cursor:
                unique_ips = (await cursor.fetchone())["unique_ips"]

            return {
                "total_attacks": total_attacks,
                "unique_ips": unique_ips,
                "severity_counts": severity_counts,
                "protocol_counts": protocol_counts,
                "top_countries": top_countries,
                "top_ports": top_ports,
                "top_credentials": top_credentials
            }

    async def clear_all(self):
        """Clear all stored attacks and sessions."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM attacks")
            await db.execute("DELETE FROM sessions")
            await db.commit()

db = Database()

