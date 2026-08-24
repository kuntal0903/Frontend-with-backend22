"""
Staging & Development Environment Analyzer

WHY THIS FILE EXISTS:
    Detects exposed staging, development, test, UAT, and preview
    environments which are frequently misconfigured and exposed
    to the internet without proper access controls.

WHAT IT ACCEPTS:
    A domain string, list of discovered subdomains, and optional session.

WHAT IT RETURNS:
    A list of detected staging/dev environments with evidence.

DESIGN:
    Matches subdomains against known dev/staging patterns, then
    validates with HTTP requests to confirm the host is live.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import aiohttp

from common.logger import get_logger
from config import settings

logger = get_logger("domain", "staging_analyzer")

_STAGING_PATTERNS = [
    "dev", "dev1", "dev2", "develop", "development",
    "staging", "stage", "stg",
    "test", "testing", "tst",
    "uat", "qa", "quality",
    "sandbox", "sbx",
    "beta", "alpha",
    "demo", "preview", "canary",
    "preprod", "pre-prod", "preproduction",
    "internal", "intranet",
    "lab", "playground", "experiment",
    "debug", "local",
    "v2", "next", "new", "old",
]


class StagingAnalyzer:
    """Detects exposed staging and development environments."""

    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self._session = session

    async def analyze(
        self,
        domain: str,
        subdomains: List[str],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        logger.info("Staging analysis started", extra={"domain": domain})

        found_envs: List[Dict[str, Any]] = []

        # Match subdomains against staging patterns
        staging_subs = self._match_staging_subdomains(subdomains)

        # Validate each match with HTTP request
        tasks = [self._validate_host(sub) for sub in staging_subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for sub, result in zip(staging_subs, results):
            if isinstance(result, Exception):
                continue
            if result:
                prefix = sub.split(".")[0]
                found_envs.append({
                    "subdomain": sub,
                    "url": result["url"],
                    "status_code": result["status_code"],
                    "type": self._classify_env(prefix),
                    "evidence": f"Subdomain '{prefix}' matches staging/dev pattern",
                    "debug_indicators": result.get("debug_indicators", []),
                })

        logger.info(
            "Staging analysis finished",
            extra={"domain": domain, "found": len(found_envs)},
        )

        return {
            "domain": domain,
            "staging_environments": found_envs,
            "total_found": len(found_envs),
            "patterns_checked": len(_STAGING_PATTERNS),
            "subdomains_matched": len(staging_subs),
        }

    @staticmethod
    def _match_staging_subdomains(subdomains: List[str]) -> List[str]:
        matched: List[str] = []
        for sub in subdomains:
            prefix = sub.split(".")[0].lower()
            if prefix in _STAGING_PATTERNS:
                matched.append(sub)
        return matched

    @staticmethod
    def _classify_env(prefix: str) -> str:
        dev_prefixes = {"dev", "dev1", "dev2", "develop", "development", "debug", "local"}
        staging_prefixes = {"staging", "stage", "stg", "preprod", "pre-prod", "preproduction"}
        test_prefixes = {"test", "testing", "tst", "uat", "qa", "quality"}
        preview_prefixes = {"beta", "alpha", "demo", "preview", "canary", "sandbox", "sbx"}

        if prefix in dev_prefixes:
            return "development"
        if prefix in staging_prefixes:
            return "staging"
        if prefix in test_prefixes:
            return "testing"
        if prefix in preview_prefixes:
            return "preview"
        return "other"

    async def _validate_host(
        self, subdomain: str
    ) -> Optional[Dict[str, Any]]:
        """Check if the subdomain is live and look for debug indicators."""
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
                f"https://{subdomain}",
                allow_redirects=True,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status >= 500:
                    return None

                # Check for debug indicators in headers
                debug_indicators: List[str] = []
                headers = {k.lower(): v for k, v in resp.headers.items()}

                if "x-debug" in headers or "x-debug-token" in headers:
                    debug_indicators.append("Debug headers present")
                if headers.get("x-powered-by", "").lower().count("debug"):
                    debug_indicators.append("Debug mode in X-Powered-By")
                if "server-timing" in headers:
                    debug_indicators.append("Server-Timing header exposed")

                # Check response body for debug markers (first 10KB)
                try:
                    body = await resp.text(encoding="utf-8", errors="ignore")
                    body = body[:10240]
                    debug_strings = [
                        "stack trace", "traceback", "debug mode",
                        "laravel", "symfony profiler", "django debug",
                        "xdebug", "error_reporting",
                    ]
                    for ds in debug_strings:
                        if ds.lower() in body.lower():
                            debug_indicators.append(
                                f"Debug marker in response body: '{ds}'"
                            )
                except Exception:
                    pass

                return {
                    "url": str(resp.url),
                    "status_code": resp.status,
                    "debug_indicators": debug_indicators,
                }

        except Exception:
            return None
