"""
Technology Fingerprinting Collector

WHY THIS FILE EXISTS:
    Identifies the web technology stack by analysing HTTP responses:
    server headers, meta tags, cookies, URL patterns, and JavaScript
    library paths.

WHAT IT ACCEPTS:
    A domain string.

WHAT IT RETURNS:
    CollectorResult with classified technologies:
    Web Server, Framework, CMS, Language, JavaScript Library, CDN hints.

DESIGN:
    Pattern-matching against known signatures.  No active exploitation.
    Analyses HTML body (first 100KB), response headers, and cookies.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from modules.domain.collectors.base import BaseCollector

# ── Signature Database ───────────────────────────────────────────────

_SERVER_SIGNATURES: Dict[str, str] = {
    "nginx": "Nginx",
    "apache": "Apache",
    "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "caddy": "Caddy",
    "openresty": "OpenResty",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "tomcat": "Apache Tomcat",
    "jetty": "Jetty",
    "cowboy": "Cowboy (Erlang)",
    "envoy": "Envoy",
}

_POWERED_BY_SIGNATURES: Dict[str, str] = {
    "php": "PHP",
    "asp.net": "ASP.NET",
    "express": "Express.js",
    "next.js": "Next.js",
    "nuxt": "Nuxt.js",
    "flask": "Flask",
    "django": "Django",
    "rails": "Ruby on Rails",
    "laravel": "Laravel",
    "spring": "Spring",
}

_COOKIE_SIGNATURES: Dict[str, str] = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "_rails": "Ruby on Rails",
    "connect.sid": "Express.js",
    "ci_session": "CodeIgniter",
    "cakephp": "CakePHP",
}

_META_GENERATOR_PATTERNS: Dict[str, str] = {
    r"wordpress": "WordPress",
    r"joomla": "Joomla",
    r"drupal": "Drupal",
    r"shopify": "Shopify",
    r"wix\.com": "Wix",
    r"squarespace": "Squarespace",
    r"ghost": "Ghost",
    r"hugo": "Hugo",
    r"jekyll": "Jekyll",
    r"typo3": "TYPO3",
    r"magento": "Magento",
    r"prestashop": "PrestaShop",
    r"contentful": "Contentful",
}

_URL_PATTERNS: Dict[str, str] = {
    r"/wp-content/": "WordPress",
    r"/wp-includes/": "WordPress",
    r"/wp-admin/": "WordPress",
    r"/sites/default/files": "Drupal",
    r"/administrator/": "Joomla",
    r"/media/jui/": "Joomla",
    r"/skin/frontend/": "Magento",
}

_JS_PATTERNS: Dict[str, str] = {
    r"jquery[.-](\d+\.\d+)": "jQuery",
    r"react[.-]": "React",
    r"angular[.-]": "Angular",
    r"vue[.-]": "Vue.js",
    r"bootstrap[.-]": "Bootstrap",
    r"lodash": "Lodash",
    r"moment[.-]": "Moment.js",
    r"axios": "Axios",
}


class TechnologyCollector(BaseCollector):
    """HTTP fingerprinting to detect web technology stack."""

    collector_name = "technology"
    source_name = "http_fingerprint"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        page_data = await self._fetch_page(f"https://{target}")
        if not page_data:
            page_data = await self._fetch_page(f"http://{target}")

        if not page_data:
            return {
                "raw_data": {"domain": target, "error": "Could not fetch page"},
                "processed_data": {
                    "domain": target,
                    "technologies": [],
                    "categories": {},
                },
            }

        detected: List[Dict[str, str]] = []
        categories: Dict[str, Set[str]] = {
            "web_server": set(),
            "framework": set(),
            "cms": set(),
            "language": set(),
            "javascript": set(),
            "other": set(),
        }

        # Analyse server header
        self._check_server_header(page_data, detected, categories)
        # Analyse X-Powered-By
        self._check_powered_by(page_data, detected, categories)
        # Analyse cookies
        self._check_cookies(page_data, detected, categories)
        # Analyse HTML meta generator
        self._check_meta_generator(page_data, detected, categories)
        # Analyse URL patterns in HTML
        self._check_url_patterns(page_data, detected, categories)
        # Analyse JS libraries
        self._check_js_patterns(page_data, detected, categories)
        # Analyse additional headers
        self._check_extra_headers(page_data, detected, categories)

        # Deduplicate
        seen: set = set()
        unique_detected: List[Dict[str, str]] = []
        for tech in detected:
            key = (tech["name"], tech.get("category", ""))
            if key not in seen:
                seen.add(key)
                unique_detected.append(tech)

        return {
            "raw_data": {
                "domain": target,
                "headers": page_data.get("headers", {}),
                "status_code": page_data.get("status_code"),
            },
            "processed_data": {
                "domain": target,
                "technologies": unique_detected,
                "categories": {k: sorted(v) for k, v in categories.items() if v},
                "total_technologies": len(unique_detected),
            },
        }

    # ── Page Fetch ───────────────────────────────────────────────────

    async def _fetch_page(
        self, url: str
    ) -> Optional[Dict[str, Any]]:
        try:
            session = await self._get_session()
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                body = await resp.text(encoding="utf-8", errors="ignore")
                body = body[:102400]  # cap at 100KB

                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = {c.key.lower(): c.value for c in resp.cookies.values()}

                return {
                    "url": url,
                    "status_code": resp.status,
                    "headers": headers,
                    "cookies": cookies,
                    "body": body,
                }
        except Exception:
            return None

    # ── Detection Methods ────────────────────────────────────────────

    @staticmethod
    def _check_server_header(
        data: Dict, detected: List, categories: Dict
    ) -> None:
        server = data.get("headers", {}).get("server", "").lower()
        for sig, name in _SERVER_SIGNATURES.items():
            if sig in server:
                detected.append({
                    "name": name,
                    "category": "web_server",
                    "evidence": f"Server: {data['headers'].get('server', '')}",
                })
                categories["web_server"].add(name)

    @staticmethod
    def _check_powered_by(
        data: Dict, detected: List, categories: Dict
    ) -> None:
        powered = data.get("headers", {}).get("x-powered-by", "").lower()
        if not powered:
            return
        for sig, name in _POWERED_BY_SIGNATURES.items():
            if sig in powered:
                cat = "language" if name in ("PHP", "ASP.NET") else "framework"
                detected.append({
                    "name": name,
                    "category": cat,
                    "evidence": f"X-Powered-By: {data['headers']['x-powered-by']}",
                })
                categories[cat].add(name)

    @staticmethod
    def _check_cookies(
        data: Dict, detected: List, categories: Dict
    ) -> None:
        cookies = data.get("cookies", {})
        for sig, name in _COOKIE_SIGNATURES.items():
            if sig in cookies:
                cat = "language" if name in ("PHP", "Java", "ASP.NET") else "framework"
                detected.append({
                    "name": name,
                    "category": cat,
                    "evidence": f"Cookie: {sig}",
                })
                categories[cat].add(name)

    @staticmethod
    def _check_meta_generator(
        data: Dict, detected: List, categories: Dict
    ) -> None:
        body = data.get("body", "")
        gen_match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE,
        )
        if not gen_match:
            return
        gen_value = gen_match.group(1).lower()
        for pattern, name in _META_GENERATOR_PATTERNS.items():
            if re.search(pattern, gen_value, re.IGNORECASE):
                detected.append({
                    "name": name,
                    "category": "cms",
                    "evidence": f"meta generator: {gen_match.group(1)}",
                })
                categories["cms"].add(name)

    @staticmethod
    def _check_url_patterns(
        data: Dict, detected: List, categories: Dict
    ) -> None:
        body = data.get("body", "")
        for pattern, name in _URL_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                detected.append({
                    "name": name,
                    "category": "cms",
                    "evidence": f"URL pattern: {pattern}",
                })
                categories["cms"].add(name)

    @staticmethod
    def _check_js_patterns(
        data: Dict, detected: List, categories: Dict
    ) -> None:
        body = data.get("body", "")
        for pattern, name in _JS_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                detected.append({
                    "name": name,
                    "category": "javascript",
                    "evidence": f"JS pattern: {pattern}",
                })
                categories["javascript"].add(name)

    @staticmethod
    def _check_extra_headers(
        data: Dict, detected: List, categories: Dict
    ) -> None:
        headers = data.get("headers", {})

        # Django
        if "csrftoken" in str(headers.get("set-cookie", "")).lower():
            detected.append({
                "name": "Django",
                "category": "framework",
                "evidence": "CSRF cookie pattern",
            })
            categories["framework"].add("Django")

        # ASP.NET version
        asp_ver = headers.get("x-aspnet-version")
        if asp_ver:
            detected.append({
                "name": f"ASP.NET {asp_ver}",
                "category": "framework",
                "evidence": f"X-AspNet-Version: {asp_ver}",
            })
            categories["framework"].add(f"ASP.NET {asp_ver}")

        # PHP via X-Powered-By version
        if "php/" in headers.get("x-powered-by", "").lower():
            version = headers["x-powered-by"]
            detected.append({
                "name": f"PHP ({version})",
                "category": "language",
                "evidence": f"X-Powered-By: {version}",
            })
            categories["language"].add(f"PHP ({version})")
