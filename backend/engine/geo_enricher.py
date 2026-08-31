import ipaddress
import time
import requests
from typing import Dict, Any


class GeoEnricher:
    """
    Real-IP GeoIP enrichment engine for production honeypot deployment.
    Uses ip-api.com (free, no API key required, 45 req/min rate limit).
    Results are cached in-memory to avoid duplicate lookups for the same source IP.
    Private/loopback IPs are rejected and returned as UNKNOWN — they should never
    appear in production since all traffic originates from the public internet.
    """

    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        # Simple rate-limit guard: track last request timestamp
        self._last_request_time = 0.0
        self._min_interval = 1.5  # seconds between requests (stays under 45/min)

    def is_private_or_local(self, ip_str: str) -> bool:
        """Return True if the IP is RFC1918 private, loopback, link-local, or reserved."""
        if ip_str in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "test", ""):
            return True
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            return True

    def _unknown_geo(self, ip_str: str) -> Dict[str, Any]:
        """Return a neutral UNKNOWN geo record for unresolvable IPs."""
        return {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "asn": "Unknown",
            "display_ip": ip_str,
            "simulated": False
        }

    def enrich_ip(self, ip_str: str) -> Dict[str, Any]:
        """
        Enrich a real public IP with geographic and ASN metadata.
        Returns cached result if already seen. Returns UNKNOWN for private IPs.
        """
        if not ip_str:
            return self._unknown_geo("0.0.0.0")

        # Return from cache immediately (thread-safe reads are fine for CPython dict)
        if ip_str in self.cache:
            return self.cache[ip_str]

        # Private/local IPs should not appear in production traffic — log as UNKNOWN
        if self.is_private_or_local(ip_str):
            geo = self._unknown_geo(ip_str)
            self.cache[ip_str] = geo
            return geo

        # Rate-limit guard: sleep if needed to stay under ip-api.com 45 req/min
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

        try:
            self._last_request_time = time.time()
            resp = requests.get(
                f"http://ip-api.com/json/{ip_str}"
                f"?fields=status,country,countryCode,city,lat,lon,as,query",
                timeout=4.0
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    geo = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "city": data.get("city", "Unknown"),
                        "lat": float(data.get("lat", 0.0)),
                        "lon": float(data.get("lon", 0.0)),
                        "asn": data.get("as", "Unknown"),
                        "display_ip": ip_str,
                        "simulated": False
                    }
                    self.cache[ip_str] = geo
                    return geo
        except Exception:
            pass

        # Fallback: API unavailable or returned non-success — store as UNKNOWN
        geo = self._unknown_geo(ip_str)
        self.cache[ip_str] = geo
        return geo


geo_enricher = GeoEnricher()
