"""
SSL/TLS Certificate Collector

WHY THIS FILE EXISTS:
    Collects certificate data from two independent sources:
    1. Direct TLS handshake to the target on port 443.
    2. Certificate Transparency logs via crt.sh public API.

WHAT IT ACCEPTS:
    A domain string (e.g. "example.com").

WHAT IT RETURNS:
    CollectorResult with parsed certificate fields (issuer, subject,
    SAN list, validity dates, serial, signature algorithm) and CT log
    history for additional subdomain discovery.

DATA SOURCES:
    - Python ssl + asyncio for direct TLS connection
    - crt.sh JSON API (free, no API key)
"""
from __future__ import annotations

import asyncio
import hashlib
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional

from modules.domain.collectors.base import BaseCollector


class CertificateCollector(BaseCollector):
    """Collects TLS certificate data and CT log entries."""

    collector_name = "certificate"
    source_name = "ssl+crt.sh"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        live_cert = await self._get_live_certificate(target)
        ct_entries = await self._get_ct_entries(target)

        # Extract unique SAN domains from both sources
        san_domains: List[str] = []
        if live_cert and live_cert.get("san"):
            san_domains.extend(live_cert["san"])
        for entry in ct_entries:
            name = entry.get("common_name", "")
            if name and name not in san_domains:
                san_domains.append(name)
            for extra in entry.get("name_value", "").split("\n"):
                extra = extra.strip()
                if extra and extra not in san_domains:
                    san_domains.append(extra)

        return {
            "raw_data": {
                "domain": target,
                "live_certificate": live_cert,
                "ct_entries": ct_entries,
            },
            "processed_data": {
                "domain": target,
                "has_certificate": live_cert is not None,
                "certificate": live_cert,
                "ct_log_entries": len(ct_entries),
                "san_domains": san_domains,
                "total_san_domains": len(san_domains),
            },
        }

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        has_live = raw.get("processed_data", {}).get("has_certificate", False)
        ct_count = raw.get("processed_data", {}).get("ct_log_entries", 0)
        if has_live and ct_count > 0:
            return 1.0
        if has_live or ct_count > 0:
            return 0.7
        return 0.3

    # ── Live Certificate via TLS Handshake ───────────────────────────

    async def _get_live_certificate(
        self, domain: str, port: int = 443
    ) -> Optional[Dict[str, Any]]:
        """Connect to *domain*:*port* and extract the server certificate."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # We want the cert even if invalid

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port, ssl=ctx),
                timeout=self._timeout,
            )
            ssl_obj = writer.transport.get_extra_info("ssl_object")
            if ssl_obj is None:
                writer.close()
                return None

            der_cert = ssl_obj.getpeercert(binary_form=True)
            peer_cert = ssl_obj.getpeercert()
            writer.close()
            await writer.wait_closed()

            if not peer_cert:
                return None

            return self._parse_peer_cert(peer_cert, der_cert)

        except Exception as exc:
            self.logger.debug(
                "Live cert fetch failed",
                extra={"domain": domain, "error": str(exc)},
            )
            return None

    @staticmethod
    def _parse_peer_cert(
        peer: Dict[str, Any],
        der_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Parse the dict returned by ``ssl.SSLSocket.getpeercert()``."""

        def _extract_field(field_tuples: tuple) -> str:
            parts = []
            for entry in field_tuples:
                for key, value in entry:
                    parts.append(f"{key}={value}")
            return ", ".join(parts)

        san_list: List[str] = []
        for san_type, san_value in peer.get("subjectAltName", ()):
            if san_type == "DNS":
                san_list.append(san_value)

        result: Dict[str, Any] = {
            "subject": _extract_field(peer.get("subject", ())),
            "issuer": _extract_field(peer.get("issuer", ())),
            "san": san_list,
            "serial_number": peer.get("serialNumber", ""),
            "version": peer.get("version"),
            "not_before": peer.get("notBefore"),
            "not_after": peer.get("notAfter"),
            "signature_algorithm": peer.get("signatureAlgorithm", "unknown"),
        }

        if der_bytes:
            result["sha256_fingerprint"] = hashlib.sha256(der_bytes).hexdigest()

        # Check if cert is currently valid
        try:
            not_after = datetime.strptime(
                result["not_after"], "%b %d %H:%M:%S %Y %Z"
            )
            result["is_expired"] = not_after < datetime.utcnow()
            result["days_until_expiry"] = (not_after - datetime.utcnow()).days
        except Exception:
            result["is_expired"] = None
            result["days_until_expiry"] = None

        return result

    # ── Certificate Transparency via crt.sh ──────────────────────────

    async def _get_ct_entries(self, domain: str) -> List[Dict[str, Any]]:
        """Query crt.sh for CT log entries."""
        try:
            session = await self._get_session()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url, timeout=self._timeout) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
                if not isinstance(data, list):
                    return []

                # Deduplicate and limit results
                seen: set = set()
                unique: List[Dict[str, Any]] = []
                for entry in data:
                    name = entry.get("common_name", "")
                    if name not in seen:
                        seen.add(name)
                        unique.append({
                            "id": entry.get("id"),
                            "common_name": name,
                            "name_value": entry.get("name_value", ""),
                            "issuer_name": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                            "serial_number": entry.get("serial_number"),
                        })
                    if len(unique) >= 500:
                        break
                return unique

        except Exception as exc:
            self.logger.debug(
                "crt.sh query failed",
                extra={"domain": domain, "error": str(exc)},
            )
            return []
