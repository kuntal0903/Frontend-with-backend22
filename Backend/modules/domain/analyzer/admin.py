"""
Administrative Portal Analyzer

WHY THIS FILE EXISTS:
    Scans discovered subdomains and performs path-based probing on the
    root domain to identify exposed admin/management interfaces.

WHAT IT ACCEPTS:
    A domain string, list of discovered subdomains, and an optional
    aiohttp session.

WHAT IT RETURNS:
    A list of discovered admin portals with URL, status code, and
    evidence of why it was flagged.

DESIGN:
    Two-pass detection:
    1. Subdomain pattern matching (admin.*, cpanel.*, etc.)
    2. URL path probing on the root domain (/admin, /wp-admin, etc.)
    Only checks HTTP response codes — no authentication bypass.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

import aiohttp

from common.logger import get_logger
from config import settings

logger = get_logger("domain", "admin_analyzer")

# Subdomain patterns that indicate admin interfaces
_ADMIN_SUBDOMAIN_PATTERNS = [
    "admin", "administrator", "cpanel", "whm", "webmail",
    "dashboard", "manage", "management", "panel", "portal",
    "console", "control", "backend", "cms", "sysadmin",
    "root", "superadmin", "staff", "internal", "ops",
]

# URL paths to check on root domain and subdomains
_ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/cpanel", "/whm", "/webmail",
    "/manager", "/manage", "/dashboard",
    "/admin/login", "/panel", "/control",
    "/phpmyadmin", "/pma", "/adminer",
    "/_admin", "/site-admin",
]


class AdminAnalyzer:
    """Discovers exposed administrative interfaces."""

    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self._session = session

    async def analyze(
        self,
        domain: str,
        subdomains: List[str],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        logger.info("Admin portal analysis started", extra={"domain": domain})

        found_portals: List[Dict[str, Any]] = []
        errors: List[str] = []

        # Pass 1: Check subdomains matching admin patterns
        admin_subs = self._match_admin_subdomains(subdomains)
        for sub in admin_subs:
            result = await self._check_url(f"https://{sub}")
            if result:
                found_portals.append({
                    "url": result["url"],
                    "type": "subdomain",
                    "status_code": result["status_code"],
                    "confidence": result["confidence"],
                    "evidence": f"Subdomain matches admin pattern ({result['confidence']}): {sub}",
                    "subdomain": sub,
                })

        # Pass 2: Check admin paths on root domain
        path_tasks = [
            self._check_url(f"https://{domain}{path}")
            for path in _ADMIN_PATHS
        ]
        path_results = await asyncio.gather(*path_tasks, return_exceptions=True)
        for path, result in zip(_ADMIN_PATHS, path_results):
            if isinstance(result, Exception):
                continue
            if result:
                found_portals.append({
                    "url": result["url"],
                    "type": "path",
                    "status_code": result["status_code"],
                    "confidence": result["confidence"],
                    "evidence": f"Admin path responds ({result['confidence']}): {path}",
                    "path": path,
                })

        logger.info(
            "Admin portal analysis finished",
            extra={"domain": domain, "found": len(found_portals)},
        )

        return {
            "domain": domain,
            "admin_portals": found_portals,
            "total_found": len(found_portals),
            "admin_subdomains_checked": len(admin_subs),
            "admin_paths_checked": len(_ADMIN_PATHS),
            "errors": errors,
        }

    @staticmethod
    def _match_admin_subdomains(subdomains: List[str]) -> List[str]:
        matched: List[str] = []
        for sub in subdomains:
            prefix = sub.split(".")[0].lower()
            if prefix in _ADMIN_SUBDOMAIN_PATTERNS:
                matched.append(sub)
        return matched

    async def _check_url(
        self, url: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch a URL and assess whether it is a genuine admin interface.

        Returns a dict with a ``confidence`` field:
            ``confirmed``  — has an actual admin form / auth form
            ``likely``     — admin keywords present in body/title
            ``possible``   — 200 OK with no body evidence (lowest bar)

        Returns None for:
            - Non-2xx responses (4xx/5xx)
            - Redirects to a completely different host (external redirect)
            - Network / timeout errors
        """
        # Admin form / auth indicators to search in the response body
        _ADMIN_BODY_PATTERNS = [
            (r'<form[^>]+(?:action|id|class)[^>]*(?:login|admin|auth)', "confirmed"),
            (r'<input[^>]+type=["\']password["\']',                      "confirmed"),
            (r'<title>[^<]*(?:admin|administrator|dashboard|panel|control)[^<]*</title>',
             "likely"),
            (r'(?:admin|administration|control panel|dashboard|back.?office)',
             "likely"),
        ]

        try:
            session = self._session
            if session is None or session.closed:
                timeout = aiohttp.ClientTimeout(total=settings.HTTP_REQUEST_TIMEOUT)
                session = aiohttp.ClientSession(
                    timeout=timeout,
                    headers={"User-Agent": settings.USER_AGENT},
                )
                self._session = session

            async with session.get(
                url,
                allow_redirects=True,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                # 4xx/5xx — not accessible, skip
                if resp.status >= 400:
                    return None

                # If we were redirected to a different host, that is not
                # evidence of an admin portal ON the target — skip it.
                from urllib.parse import urlparse as _up
                final_host = _up(str(resp.url)).netloc.lower()
                original_host = _up(url).netloc.lower()
                if final_host != original_host:
                    # Redirected off-domain — not a portal on this target
                    return None

                # Read body and look for admin indicators
                confidence = "possible"
                try:
                    body = await resp.text(encoding="utf-8", errors="ignore")
                    body = body[:51200]  # 50 KB cap
                    for pattern, tier in _ADMIN_BODY_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            confidence = tier
                            break  # highest tier wins first
                except Exception:
                    pass

                # Only report if we have actual content evidence (confirmed or likely).
                # 'possible' (bare 200 with no body evidence) is suppressed to
                # prevent reporting every admin path that simply returns 200 from a CDN.
                if confidence in ("confirmed", "likely"):
                    return {
                        "url": str(resp.url),
                        "status_code": resp.status,
                        "confidence": confidence,
                    }
                return None

        except Exception:
            return None
