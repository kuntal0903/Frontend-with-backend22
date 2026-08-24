"""
Port Scanner & Service Banner Collector

WHY THIS FILE EXISTS:
    Discovers open TCP ports on a target and grabs service banners
    for identification.  Uses async socket connections with a
    concurrency semaphore to avoid overwhelming the target.

WHAT IT ACCEPTS:
    A domain/IP string and optional kwargs:
        - ports: List[int] — override default port list
        - ips: List[str] — additional IPs to scan

WHAT IT RETURNS:
    CollectorResult with open ports, services, and banner data.

DESIGN:
    Uses ``asyncio.open_connection`` — no raw sockets, no SYN scanning.
    This is a standard TCP connect scan, equivalent to what any web
    browser does when establishing a connection.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from config import settings
from modules.domain.collectors.base import BaseCollector

# Well-known port → service mapping
_PORT_SERVICE_MAP: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2083: "cpanel-ssl", 2087: "whm-ssl", 2096: "webmail-ssl",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9090: "web-console",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    27017: "mongodb",
}


class PortCollector(BaseCollector):
    """Async TCP connect scan with service banner grabbing."""

    collector_name = "ports"
    source_name = "tcp_connect"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        ports: List[int] = kwargs.get("ports", settings.DEFAULT_PORTS)
        semaphore = asyncio.Semaphore(settings.PORT_SCAN_CONCURRENCY)

        # Scan all ports concurrently (bounded by semaphore)
        tasks = [
            self._check_port(target, port, semaphore)
            for port in ports
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Separate open from closed
        open_ports: List[Dict[str, Any]] = []
        closed_ports: List[int] = []
        for port, result in zip(ports, results):
            if isinstance(result, Exception):
                closed_ports.append(port)
            elif result is not None:
                open_ports.append(result)
            else:
                closed_ports.append(port)

        # Sort by port number
        open_ports.sort(key=lambda p: p["port"])

        return {
            "raw_data": {
                "target": target,
                "ports_scanned": len(ports),
                "open_ports": open_ports,
            },
            "processed_data": {
                "target": target,
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "total_scanned": len(ports),
                "open_port_numbers": [p["port"] for p in open_ports],
                "services_found": [
                    p["service"] for p in open_ports if p.get("service")
                ],
            },
        }

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        # TCP connect is definitive for open ports
        return 1.0

    async def _check_port(
        self,
        host: str,
        port: int,
        semaphore: asyncio.Semaphore,
    ) -> Optional[Dict[str, Any]]:
        """
        Try to connect to *host*:*port*.
        Returns a dict for open ports, None for closed.
        """
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=settings.PORT_CONNECT_TIMEOUT,
                )

                # Port is open — try to grab banner
                banner = await self._grab_banner(reader)
                service = self._identify_service(port, banner)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                result: Dict[str, Any] = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "protocol": "tcp",
                }
                if banner:
                    result["banner"] = banner

                return result

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

    async def _grab_banner(self, reader: asyncio.StreamReader) -> str:
        """Read up to 1024 bytes from the connection (best-effort)."""
        try:
            data = await asyncio.wait_for(
                reader.read(1024),
                timeout=settings.BANNER_READ_TIMEOUT,
            )
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    @staticmethod
    def _identify_service(port: int, banner: str) -> str:
        """Identify service from port number and/or banner content."""
        # Try banner-based identification first
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "ssh"
        if "ftp" in banner_lower:
            return "ftp"
        if "smtp" in banner_lower:
            return "smtp"
        if "http" in banner_lower:
            return "http"
        if "mysql" in banner_lower:
            return "mysql"
        if "postgresql" in banner_lower or "postgres" in banner_lower:
            return "postgresql"
        if "redis" in banner_lower:
            return "redis"
        if "mongo" in banner_lower:
            return "mongodb"
        if "elastic" in banner_lower:
            return "elasticsearch"

        # Fall back to port-based mapping
        return _PORT_SERVICE_MAP.get(port, "unknown")
