import re
from typing import Dict, Any

class ThreatClassifier:
    def classify(self, protocol: str, service: str, payload: str = "", username: str = "", password: str = "", target_port: int = 0) -> Dict[str, Any]:
        """Classify incoming attack event into MITRE ATT&CK techniques and severity levels."""
        p_lower = (payload or "").lower()
        
        # 1. Log4Shell / JNDI Injection
        if "${jndi:" in p_lower:
            return {
                "attack_type": "Log4Shell JNDI Exploit",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "severity": "CRITICAL",
                "description": "Log4j JNDI remote code execution exploit attempt detected."
            }

        # 2. Remote Command Injection (RCE)
        rce_patterns = [
            r";\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|rm)",
            r"\|\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl)",
            r"`.*`",
            r"\$\(.*\)",
            r"bash\s+-i\s+>&",
            r"nc(\.traditional)?\s+-e",
            r"/bin/sh",
            r"/bin/bash"
        ]
        for pat in rce_patterns:
            if re.search(pat, payload or "", re.IGNORECASE):
                return {
                    "attack_type": "Command Injection (RCE)",
                    "mitre_id": "T1059.004",
                    "mitre_tactic": "Execution",
                    "severity": "CRITICAL",
                    "description": "Attempted arbitrary system command injection."
                }

        # 3. Directory Traversal / Local File Inclusion (LFI)
        if any(token in p_lower for token in ["../", "..\\", "/etc/passwd", "/etc/shadow", "windows/win.ini", "boot.ini"]):
            return {
                "attack_type": "Directory Traversal / LFI",
                "mitre_id": "T1005",
                "mitre_tactic": "Collection",
                "severity": "HIGH",
                "description": "Path traversal attempt to extract system files."
            }

        # 4. Sensitive Environment & Credential Leak Probing
        if any(token in p_lower for token in [".env", ".git", "wp-config", "id_rsa", "credentials", "database.yml"]):
            return {
                "attack_type": "Credential & Config Harvest",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "severity": "HIGH",
                "description": "Probing for exposed environment files or secret keys."
            }

        # 5. SQL Injection
        sqli_patterns = [
            r"union\s+select",
            r"'\s+or\s+'1'='1",
            r"'\s+or\s+1=1",
            r"--\s*$",
            r"waitfor\s+delay",
            r"sleep\(\d+\)"
        ]
        for pat in sqli_patterns:
            if re.search(pat, p_lower):
                return {
                    "attack_type": "SQL Injection (SQLi)",
                    "mitre_id": "T1190",
                    "mitre_tactic": "Initial Access",
                    "severity": "HIGH",
                    "description": "SQL injection payload attempting database manipulation."
                }

        # 6. Web Exploitation / Vulnerability Probing (phpMyAdmin, WordPress, Actuator)
        if any(token in p_lower for token in ["phpmyadmin", "wp-login", "wp-admin", "actuator/heapdump", "swagger-ui", "solr", "telescope"]):
            return {
                "attack_type": "Web Application Exploitation",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "severity": "MEDIUM",
                "description": "Probing for known vulnerable CMS / Admin endpoints."
            }

        # 7. SSH / Telnet / Service Credential Brute-Force
        if username or password:
            return {
                "attack_type": "Credential Brute-Force",
                "mitre_id": "T1110.001",
                "mitre_tactic": "Credential Access",
                "severity": "HIGH" if (username in ["root", "admin", "ubuntu"]) else "MEDIUM",
                "description": f"Authentication attempt with credential pair '{username}:{password}'."
            }

        # 8. Interactive Shell Commands (Post-exploitation)
        if protocol.upper() in ["SSH", "TELNET"] and payload:
            return {
                "attack_type": "Interactive Shell Execution",
                "mitre_id": "T1059",
                "mitre_tactic": "Execution",
                "severity": "HIGH",
                "description": f"Attacker executed shell command: {payload}"
            }

        # 9. Port Scan / Reconnaissance
        return {
            "attack_type": "Network Service Reconnaissance",
            "mitre_id": "T1046",
            "mitre_tactic": "Discovery",
            "severity": "LOW",
            "description": f"TCP SYN/Connect reconnaissance sweep on port {target_port} ({service})."
        }

classifier = ThreatClassifier()

