"""
API Endpoint Discovery Analyzer

WHY THIS FILE EXISTS:
    Discovers publicly accessible API endpoints across discovered
    assets — REST, GraphQL, Swagger/OpenAPI, gRPC web endpoints.

WHAT IT ACCEPTS:
    A domain string, list of discovered subdomains, and optional session.

WHAT IT RETURNS:
    A list of detected API endpoints with type and evidence.

DESIGN:
    1. Subdomain pattern matching (api.*, rest.*, graphql.*, etc.)
    2. Path probing for known API documentation and endpoint paths
    3. Content-type analysis (JSON/XML response detection)
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import aiohttp

from common.logger import get_logger
from config import settings

logger = get_logger("domain", "api_analyzer")

_API_SUBDOMAIN_PATTERNS = [
    "api", "rest", "graphql", "gateway", "api-gateway",
    "api2", "api-v2", "apiv2", "ws", "websocket",
    "rpc", "grpc", "service", "services", "microservice",
    "backend", "data", "feed", "stream",
]

_API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/openapi",
    "/docs", "/redoc", "/api-docs",
    "/api/health", "/api/status", "/health", "/healthz",
    "/.well-known/openapi",
    "/rest", "/restapi",
]

_API_CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "application/graphql",
    "application/hal+json",
    "application/vnd.api+json",
    "text/xml",
]


class APIDiscoveryAnalyzer:
    """Discovers publicly accessible API endpoints."""

    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self._session = session

    async def analyze(
        self,
        domain: str,
        subdomains: List[str],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        logger.info("API discovery started", extra={"domain": domain})

        found_apis: List[Dict[str, Any]] = []

        # Pass 1: Check subdomains matching API patterns
        api_subs = self._match_api_subdomains(subdomains)
        sub_tasks = [self._check_api_endpoint(f"https://{sub}") for sub in api_subs]
        sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)

        for sub, result in zip(api_subs, sub_results):
            if isinstance(result, Exception):
                continue
            if result:
                found_apis.append({
                    "url": result["url"],
                    "type": "subdomain",
                    "subdomain": sub,
                    "status_code": result["status_code"],
                    "content_type": result.get("content_type", ""),
                    "is_json": result.get("is_json", False),
                    "api_type": self._classify_api(sub, result),
                    "evidence": result.get("evidence", []),
                })

        # Pass 2: Check API paths on root domain
        path_tasks = [
            self._check_api_endpoint(f"https://{domain}{path}")
            for path in _API_PATHS
        ]
        path_results = await asyncio.gather(*path_tasks, return_exceptions=True)

        for path, result in zip(_API_PATHS, path_results):
            if isinstance(result, Exception):
                continue
            if result:
                api_type = "openapi"
                if "swagger" in path:
                    api_type = "swagger"
                elif "graphql" in path:
                    api_type = "graphql"
                elif "health" in path:
                    api_type = "health_check"
                else:
                    api_type = "rest"

                found_apis.append({
                    "url": result["url"],
                    "type": "path",
                    "path": path,
                    "status_code": result["status_code"],
                    "content_type": result.get("content_type", ""),
                    "is_json": result.get("is_json", False),
                    "api_type": api_type,
                    "evidence": result.get("evidence", []),
                })

        logger.info(
            "API discovery finished",
            extra={"domain": domain, "found": len(found_apis)},
        )

        return {
            "domain": domain,
            "api_endpoints": found_apis,
            "total_found": len(found_apis),
            "subdomains_checked": len(api_subs),
            "paths_checked": len(_API_PATHS),
        }

    @staticmethod
    def _match_api_subdomains(subdomains: List[str]) -> List[str]:
        matched: List[str] = []
        for sub in subdomains:
            prefix = sub.split(".")[0].lower()
            if prefix in _API_SUBDOMAIN_PATTERNS:
                matched.append(sub)
        return matched

    async def _check_api_endpoint(
        self, url: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch a URL and determine whether it is a genuine API endpoint.

        Requires actual API evidence before reporting:
            - An API-compatible Content-Type (JSON, XML, GraphQL, HAL, etc.)
            - API-specific response headers (x-ratelimit-limit, x-api-version, etc.)
            - A response body that is a JSON object or array

        Returns None for:
            - 4xx/5xx responses
            - Off-domain redirects
            - URLs with no API evidence at all (bare 200 with HTML body)
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
                if resp.status >= 400:
                    return None

                # If we were redirected to a completely different host,
                # that is not evidence of an API endpoint on the target.
                from urllib.parse import urlparse as _up
                final_host = _up(str(resp.url)).netloc.lower()
                original_host = _up(url).netloc.lower()
                if final_host != original_host:
                    return None

                content_type = resp.headers.get("content-type", "").lower()
                evidence: List[str] = []
                is_json = False

                # 1. Check Content-Type for API-compatible types
                for api_ct in _API_CONTENT_TYPES:
                    if api_ct in content_type:
                        is_json = "json" in api_ct
                        evidence.append(f"Content-Type: {content_type}")
                        break

                # 2. Check for API-specific response headers
                api_headers = [
                    "x-ratelimit-limit", "x-ratelimit-remaining",
                    "x-api-version", "x-request-id",
                    "x-correlation-id", "x-response-time",
                ]
                lower_headers = {k.lower() for k in resp.headers}
                for h in api_headers:
                    if h in lower_headers:
                        evidence.append(f"API header present: {h}")

                # 3. If Content-Type is not API but body looks like JSON, flag it
                if not evidence and "json" not in content_type:
                    try:
                        body = await resp.text(encoding="utf-8", errors="ignore")
                        stripped = body.strip()
                        if stripped and stripped[0] in ("{", "["):
                            # Looks like a JSON object or array — likely an API
                            is_json = True
                            evidence.append("Response body appears to be JSON")
                    except Exception:
                        pass

                # Only report if we have actual API evidence.
                # A bare HTTP 200 with an HTML body is NOT an API endpoint.
                if evidence:
                    return {
                        "url": str(resp.url),
                        "status_code": resp.status,
                        "content_type": content_type,
                        "is_json": is_json,
                        "evidence": evidence,
                    }
                return None

        except Exception:
            return None


    @staticmethod
    def _classify_api(subdomain: str, result: Dict) -> str:
        prefix = subdomain.split(".")[0].lower()
        if prefix in ("graphql",):
            return "graphql"
        if prefix in ("ws", "websocket"):
            return "websocket"
        if prefix in ("grpc", "rpc"):
            return "grpc"
        if prefix in ("gateway", "api-gateway"):
            return "api_gateway"
        return "rest"
