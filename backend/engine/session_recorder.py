import time
from typing import Dict, Any, List, Optional
from backend.engine.database import db

class SessionRecorder:
    def __init__(self):
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

    def start_session(self, session_id: str, protocol: str, source_ip: str, username: str = "", password: str = "") -> Dict[str, Any]:
        """Begin recording an attacker session."""
        session = {
            "session_id": session_id,
            "protocol": protocol,
            "source_ip": source_ip,
            "start_time": time.time(),
            "end_time": None,
            "command_count": 0,
            "username": username,
            "password": password,
            "events": []
        }
        self.active_sessions[session_id] = session
        return session

    def record_event(self, session_id: str, event_type: str, data: str):
        """Append a keystroke or output event to the session stream."""
        if session_id not in self.active_sessions:
            return
        
        session = self.active_sessions[session_id]
        relative_offset = round(time.time() - session["start_time"], 3)
        
        session["events"].append({
            "t": relative_offset,
            "type": event_type,  # 'in' (attacker typed), 'out' (terminal response)
            "data": data
        })

        if event_type == "in" and data.strip():
            session["command_count"] += 1

    async def end_session(self, session_id: str):
        """Finalize session and persist to database."""
        if session_id not in self.active_sessions:
            return
        
        session = self.active_sessions.pop(session_id)
        session["end_time"] = time.time()
        await db.save_session(session)

session_recorder = SessionRecorder()

