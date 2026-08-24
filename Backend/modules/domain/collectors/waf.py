"""
WAF (Web Application Firewall) Detection Collector

WHY THIS FILE EXISTS:
    Identifies the presence of a WAF through strictly passive
    fingerprinting — response headers, cookie names, error page
    signatures, and server header patterns.

WHAT IT ACCEPTS:
    A domain string and optional kwargs:
        - headers: dict — HTTP headers (reused from header collector)

WHAT IT RETURNS:
    CollectorResult with detected WAF vendor(s) and evidence.

DESIGN:
    Strictly passive — no crafted attack payloads, no injection
    attempts.  We only analyse normal HTTP responses.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from modules.domain.collectors.base import BaseCollector

# ── WAF Signatures ───────────────────────────────────────────────────

_WAF_HEADER_SIGS: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "headers": {"cf-ray": None, "cf-cache-status": None},
        "server_pattern": r"cloudflare",
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "name": "Cloudflare",
    },
    "akamai": {
        "headers": {"x-akamai-transformed": None, "akamai-origin-hop": None},
        "server_pattern": r"akamaighost|akamainetworking",
        "cookies": ["akamai_"],
        "name": "Akamai",
    },
    "aws_waf": {
        "headers": {"x-amzn-waf-action": None, "x-amzn-requestid": None},
        "server_pattern": None,
        "cookies": ["awsalb", "awsalbcors"],
        "name": "AWS WAF / ALB",
    },
    "azure_front_door": {
        "headers": {"x-azure-ref": None, "x-fd-healthprobe": None},
        "server_pattern": None,
        "cookies": [],
        "name": "Azure Front Door",
    },
    "sucuri": {
        "headers": {"x-sucuri-id": None, "x-sucuri-cache": None},
        "server_pattern": r"sucuri",
        "cookies": ["sucuri_"],
        "name": "Sucuri",
    },
    "imperva": {
        "headers": {"x-cdn": "imperva", "x-iinfo": None},
        "server_pattern": None,
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
        "name": "Imperva / Incapsula",
    },
    "f5_bigip": {
        "headers": {},
        "server_pattern": r"bigip|big-ip|f5",
        "cookies": ["bigipserver", "f5_cspm", "ts_"],
        "name": "F5 BIG-IP",
    },
    "barracuda": {
        "headers": {"barra_counter_session": None},
        "server_pattern": r"barracuda",
        "cookies": ["barra_counter_session"],
        "name": "Barracuda",
    },
    "fortinet": {
        "headers": {},
        "server_pattern": r"fortiweb",
        "cookies": ["fortiwafsid", "cookiesession1"],
        "name": "Fortinet FortiWeb",
    },
    "modsecurity": {
        "headers": {},
        "server_pattern": r"mod_security|modsecurity",
        "cookies": [],
        "name": "ModSecurity",
    },
    "wordfence": {
        "headers": {},
        "server_pattern": None,
        "cookies": ["wfwaf-authcookie"],
        "name": "Wordfence (WordPress)",
    },
    "stackpath": {
        "headers": {"x-sp-url": None, "x-sp-waf-action": None},
        "server_pattern": r"stackpath",
        "cookies": [],
        "name": "StackPath",
    },
}


class WAFCollector(BaseCollector):
    """Detects WAF presence through passive HTTP fingerprinting."""

    collector_name = "waf"
    source_name = "http_fingerprint"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        # Try to reuse headers from kwargs, or fetch fresh
        headers: Dict[str, str] = kwargs.get("headers", {})
        cookies_raw: str = ""
        server_header: str = ""
        body: str = ""

        if not headers:
            page_data = await self._fetch_page(target)
            if page_data:
                headers = page_data.get("headers", {})
                cookies_raw = page_data.get("cookies_raw", "")
                server_header = headers.get("server", "")
                body = page_data.get("body", "")
            else:
                return {
                    "raw_data": {"domain": target, "error": "Could not fetch page"},
                    "processed_data": {
                        "domain": target,
                        "waf_detected": False,
                        "waf_providers": [],
                        "evidence": [],
                    },
                }
        else:
            cookies_raw = headers.get("set-cookie", "")
            server_header = headers.get("server", "")

        detected: Set[str] = set()
        evidence: List[Dict[str, str]] = []

        for waf_id, sig in _WAF_HEADER_SIGS.items():
            found = False

            # Check specific headers
            for h_key, h_expected in sig.get("headers", {}).items():
                if h_key in headers:
                    if h_expected is None or h_expected in headers[h_key].lower():
                        found = True
                        evidence.append({
                            "waf": sig["name"],
                            "method": "header",
                            "detail": f"{h_key}: {headers[h_key][:80]}",
                        })

            # Check server header pattern
            pattern = sig.get("server_pattern")
            if pattern and server_header:
                if re.search(pattern, server_header, re.IGNORECASE):
                    found = True
                    evidence.append({
                        "waf": sig["name"],
                        "method": "server_header",
                        "detail": f"Server: {server_header}",
                    })

            # Check cookies
            for cookie_sig in sig.get("cookies", []):
                if cookie_sig.lower() in cookies_raw.lower():
                    found = True
                    evidence.append({
                        "waf": sig["name"],
                        "method": "cookie",
                        "detail": f"Cookie pattern: {cookie_sig}",
                    })

            if found:
                detected.add(sig["name"])

        return {
            "raw_data": {
                "domain": target,
                "headers_checked": list(headers.keys()),
                "evidence": evidence,
            },
            "processed_data": {
                "domain": target,
                "waf_detected": len(detected) > 0,
                "waf_providers": sorted(detected),
                "total_detected": len(detected),
                "evidence": evidence,
            },
        }

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        pd = raw.get("processed_data", {})
        evidence_count = len(pd.get("evidence", []))
        if evidence_count >= 3:
            return 1.0
        if evidence_count >= 1:
            return 0.8
        return 0.5  # No WAF detected is still a valid result

    # ── Page Fetch ───────────────────────────────────────────────────

    async def _fetch_page(
        self, domain: str
    ) -> Optional[Dict[str, Any]]:
        try:
            session = await self._get_session()
            async with session.get(
                f"https://{domain}",
                allow_redirects=True,
                ssl=False,
            ) as resp:
                body = await resp.text(encoding="utf-8", errors="ignore")
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies_raw = headers.get("set-cookie", "")
                return {
                    "headers": headers,
                    "cookies_raw": cookies_raw,
                    "server": headers.get("server", ""),
                    "body": body[:50000],
                }
        except Exception:
            return None
