"""
Login Portal Discovery Analyzer

WHY THIS FILE EXISTS:
    Identifies login/authentication pages across discovered assets.
    Login pages are high-value targets for attackers and are a critical
    component of the attack surface inventory.

WHAT IT ACCEPTS:
    A domain string, list of discovered subdomains, and optional session.

WHAT IT RETURNS:
    A list of detected login portals with URL, type, and evidence.

DESIGN:
    1. Subdomain pattern matching (sso.*, auth.*, login.*, etc.)
    2. Path probing on root domain (/login, /signin, etc.)
    3. HTML content analysis for password fields and login forms
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse as _urlparse

import aiohttp

from common.logger import get_logger
from config import settings

logger = get_logger("domain", "login_analyzer")

_LOGIN_SUBDOMAIN_PATTERNS = [
    "login", "signin", "sso", "auth", "authenticate",
    "oauth", "id", "identity", "accounts", "account",
    "cas", "adfs", "saml", "oidc", "keycloak",
]

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/sso", "/oauth", "/oauth2", "/saml",
    "/accounts/login", "/user/login", "/users/sign_in",
    "/wp-login.php", "/admin/login",
    "/auth/login", "/auth/signin",
    "/login.html", "/login.php", "/login.asp",
]

_LOGIN_FORM_PATTERNS = [
    # Strong: actual password input field — the definitive indicator of a login form.
    r'<input[^>]+type=["\']password["\']',
    # Strong: form element whose action, id, class, or name references auth concepts.
    r'<form[^>]+(?:action|id|class|name)[^>]*(?:login|signin|sign-in|auth|authenticate|credential)',
    # Strong: input field explicitly named as a credential field.
    r'<input[^>]+name=["\'](?:username|email|password|passwd|user|credential)["\']',
    # Medium: autocomplete=username or autocomplete=current-password on an input
    # (standard HTML5 login form attribute — not present on normal pages).
    r'<input[^>]+autocomplete=["\'](?:username|current-password|new-password)["\']',
]
# NOTE: Intentionally removed the broad text pattern r'(?:sign\s*in|log\s*in|authenticate)'
# because it matches ANY page that mentions "Sign In" in body text (e.g. Google's homepage,
# every blog with a header nav link). Structural HTML evidence only.


class LoginPortalAnalyzer:
    """Discovers login and authentication endpoints."""

    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self._session = session

    async def analyze(
        self,
        domain: str,
        subdomains: List[str],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        logger.info("Login portal analysis started", extra={"domain": domain})

        found_portals: List[Dict[str, Any]] = []

        # Pass 1: Check subdomains matching login patterns
        login_subs = self._match_login_subdomains(subdomains)
        sub_tasks = [self._check_login_page(f"https://{sub}") for sub in login_subs]
        sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)

        for sub, result in zip(login_subs, sub_results):
            if isinstance(result, Exception):
                continue
            if result:
                found_portals.append({
                    "url": result["url"],
                    "type": "subdomain",
                    "subdomain": sub,
                    "status_code": result["status_code"],
                    "has_login_form": result.get("has_login_form", False),
                    "auth_type": self._detect_auth_type(sub, result),
                    "evidence": result.get("evidence", []),
                })

        # Pass 2: Check login paths on root domain
        path_tasks = [
            self._check_login_page(f"https://{domain}{path}", strict_host=domain)
            for path in _LOGIN_PATHS
        ]
        path_results = await asyncio.gather(*path_tasks, return_exceptions=True)

        for path, result in zip(_LOGIN_PATHS, path_results):
            if isinstance(result, Exception):
                continue
            if result:
                found_portals.append({
                    "url": result["url"],
                    "type": "path",
                    "path": path,
                    "status_code": result["status_code"],
                    "has_login_form": result.get("has_login_form", False),
                    "auth_type": "form",
                    "evidence": result.get("evidence", []),
                })

        logger.info(
            "Login portal analysis finished",
            extra={"domain": domain, "found": len(found_portals)},
        )

        return {
            "domain": domain,
            "login_portals": found_portals,
            "total_found": len(found_portals),
            "subdomains_checked": len(login_subs),
            "paths_checked": len(_LOGIN_PATHS),
        }

    @staticmethod
    def _match_login_subdomains(subdomains: List[str]) -> List[str]:
        matched: List[str] = []
        for sub in subdomains:
            prefix = sub.split(".")[0].lower()
            if prefix in _LOGIN_SUBDOMAIN_PATTERNS:
                matched.append(sub)
        return matched

    async def _check_login_page(
        self, url: str, strict_host: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch *url* and return info if it contains an actual login form.

        Parameters
        ----------
        strict_host
            When set, the final (post-redirect) hostname must match this
            value.  Use this for path-based probes so that cross-domain
            redirects (e.g. google.com/wp-login.php -> accounts.google.com)
            are NOT falsely reported as login portals on the original host.
            Leave as None for subdomain-based probes, where the subdomain
            itself is the target and redirects within it are acceptable.
        """
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
                if resp.status >= 500:
                    return None

                # Off-domain redirect guard for path-based probes.
                # If we probed google.com/wp-login.php and ended up at
                # accounts.google.com, that is a redirect to a different host —
                # not evidence of a login portal at the original URL.
                if strict_host is not None:
                    final_host = _urlparse(str(resp.url)).hostname or ""
                    if final_host != strict_host:
                        return None

                body = ""
                evidence: List[str] = []
                has_login_form = False

                try:
                    body = await resp.text(encoding="utf-8", errors="ignore")
                    body = body[:51200]  # 50KB cap

                    for pattern in _LOGIN_FORM_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            has_login_form = True
                            evidence.append(f"Matched: {pattern}")
                except Exception:
                    pass

                # Only report if there is an actual login form in the response.
                # A bare 2xx/3xx with no form is NOT evidence of a login portal —
                # it is just a URL that resolves, which is not a finding.
                if has_login_form:
                    return {
                        "url": str(resp.url),
                        "status_code": resp.status,
                        "has_login_form": has_login_form,
                        "evidence": evidence,
                    }
                return None

        except Exception:
            return None

    @staticmethod
    def _detect_auth_type(subdomain: str, result: Dict) -> str:
        prefix = subdomain.split(".")[0].lower()
        if prefix in ("sso", "cas", "adfs", "saml", "oidc"):
            return "sso"
        if prefix in ("oauth", "oauth2"):
            return "oauth"
        if prefix in ("keycloak",):
            return "keycloak"
        if result.get("has_login_form"):
            return "form"
        return "unknown"
