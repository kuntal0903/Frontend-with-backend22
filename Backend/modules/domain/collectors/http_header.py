"""
HTTP Header Collector

WHY THIS FILE EXISTS:
    Dedicated collector for HTTP response headers.
    Captures full header set, evaluates security headers, follows
    redirect chains, and checks cookie security flags.

    Separate from technology.py because:
    - Technology detection *interprets* headers for stack identification.
    - This collector captures and evaluates headers as security assets
      in their own right (HSTS, CSP, X-Frame-Options, etc.).

WHAT IT ACCEPTS:
    A domain string.  Requests both HTTP and HTTPS.

WHAT IT RETURNS:
    CollectorResult with full headers, security header analysis,
    redirect chain, and cookie analysis.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from modules.domain.collectors.base import BaseCollector

# Security headers to check and their descriptions
_SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "high",
        "description": "Enforces HTTPS connections",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "high",
        "description": "Prevents XSS and injection attacks",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME sniffing",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls referrer information",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Controls browser features access",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "Legacy XSS filter (deprecated but informative)",
    },
}


class HTTPHeaderCollector(BaseCollector):
    """Captures HTTP headers and evaluates security posture."""

    collector_name = "http_header"
    source_name = "aiohttp"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        https_result = await self._fetch_headers(f"https://{target}")
        http_result = await self._fetch_headers(f"http://{target}")

        # Prefer HTTPS result for analysis
        primary = https_result or http_result

        # Security analysis
        security_analysis: Dict[str, Any] = {}
        if primary:
            security_analysis = self._analyse_security_headers(
                primary.get("headers", {})
            )

        # Cookie analysis
        cookies: List[Dict[str, Any]] = []
        if primary:
            cookies = self._analyse_cookies(primary.get("cookies", []))

        return {
            "raw_data": {
                "domain": target,
                "https": https_result,
                "http": http_result,
            },
            "processed_data": {
                "domain": target,
                "has_https": https_result is not None,
                "has_http": http_result is not None,
                "headers": primary.get("headers", {}) if primary else {},
                "security_headers": security_analysis,
                "cookies": cookies,
                "redirect_chain": primary.get("redirect_chain", []) if primary else [],
                "final_url": primary.get("final_url", "") if primary else "",
                "status_code": primary.get("status_code", 0) if primary else 0,
            },
        }

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        pd = raw.get("processed_data", {})
        if pd.get("has_https"):
            return 1.0
        if pd.get("has_http"):
            return 0.8
        return 0.2

    # ── Fetch Headers ────────────────────────────────────────────────

    async def _fetch_headers(
        self, url: str
    ) -> Optional[Dict[str, Any]]:
        try:
            session = await self._get_session()
            redirect_chain: List[str] = []
            async with session.get(
                url,
                allow_redirects=True,
                max_redirects=10,
                ssl=False,
            ) as resp:
                # Capture redirect history
                for hist in resp.history:
                    redirect_chain.append(str(hist.url))

                headers = {k.lower(): v for k, v in resp.headers.items()}

                # Capture cookies
                raw_cookies: List[Dict[str, Any]] = []
                for cookie in resp.cookies.values():
                    raw_cookies.append({
                        "name": cookie.key,
                        "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                        "domain": cookie.get("domain", ""),
                        "path": cookie.get("path", "/"),
                        "secure": "secure" in cookie.get("secure", ""),
                        "httponly": "httponly" in cookie.get("httponly", ""),
                        "samesite": cookie.get("samesite", ""),
                    })

                return {
                    "url": url,
                    "final_url": str(resp.url),
                    "status_code": resp.status,
                    "headers": headers,
                    "cookies": raw_cookies,
                    "redirect_chain": redirect_chain,
                }

        except Exception as exc:
            self.logger.debug(
                "Header fetch failed",
                extra={"url": url, "error": str(exc)},
            )
            return None

    # ── Security Header Analysis ─────────────────────────────────────

    @staticmethod
    def _analyse_security_headers(
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        present: List[Dict[str, Any]] = []
        missing: List[Dict[str, Any]] = []

        for header_key, meta in _SECURITY_HEADERS.items():
            if header_key in headers:
                present.append({
                    **meta,
                    "header": header_key,
                    "value": headers[header_key],
                })
            else:
                missing.append({
                    **meta,
                    "header": header_key,
                })

        score = round(len(present) / max(len(_SECURITY_HEADERS), 1) * 100)
        return {
            "present": present,
            "missing": missing,
            "total_present": len(present),
            "total_missing": len(missing),
            "score": score,
            "rating": (
                "strong" if score >= 80 else
                "moderate" if score >= 50 else
                "weak"
            ),
        }

    # ── Cookie Analysis ──────────────────────────────────────────────

    @staticmethod
    def _analyse_cookies(
        cookies: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        analysed: List[Dict[str, Any]] = []
        for cookie in cookies:
            issues: List[str] = []
            if not cookie.get("secure"):
                issues.append("Missing Secure flag")
            if not cookie.get("httponly"):
                issues.append("Missing HttpOnly flag")
            if not cookie.get("samesite"):
                issues.append("Missing SameSite attribute")
            analysed.append({**cookie, "security_issues": issues})
        return analysed
