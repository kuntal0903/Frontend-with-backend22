"""
Cloud & CDN Provider Detection Collector

WHY THIS FILE EXISTS:
    Identifies cloud hosting and CDN providers through three
    independent techniques:
    1. CNAME record patterns (*.amazonaws.com, *.azurewebsites.net, etc.)
    2. HTTP response header signatures (x-amz-*, cf-ray, x-goog-*, etc.)
    3. IP range matching against published cloud provider ranges

WHAT IT ACCEPTS:
    A domain string and optional kwargs:
        - dns_records: dict — DNS data from the DNS collector
        - headers: dict — HTTP headers from the header collector

WHAT IT RETURNS:
    CollectorResult with cloud_provider, cdn_provider, and hosting
    details with evidence attribution.

DESIGN:
    IP range matching uses hardcoded known CIDR blocks for the top
    providers. For production scale, download and cache the published
    JSON files (AWS ip-ranges.json, etc.) on a schedule.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Set

import dns.asyncresolver
import dns.exception

from modules.domain.collectors.base import BaseCollector

# ── CNAME Patterns ───────────────────────────────────────────────────

_CNAME_CLOUD: Dict[str, str] = {
    ".amazonaws.com": "AWS",
    ".cloudfront.net": "AWS CloudFront",
    ".elasticbeanstalk.com": "AWS Elastic Beanstalk",
    ".elb.amazonaws.com": "AWS ELB",
    ".s3.amazonaws.com": "AWS S3",
    ".azurewebsites.net": "Azure App Service",
    ".azure-api.net": "Azure API Management",
    ".cloudapp.azure.com": "Azure Cloud",
    ".blob.core.windows.net": "Azure Blob Storage",
    ".trafficmanager.net": "Azure Traffic Manager",
    ".googleapis.com": "Google Cloud",
    ".appspot.com": "Google App Engine",
    ".run.app": "Google Cloud Run",
    ".firebaseapp.com": "Firebase",
    ".web.app": "Firebase",
    ".netlify.app": "Netlify",
    ".vercel.app": "Vercel",
    ".herokuapp.com": "Heroku",
    ".render.com": "Render",
    ".fly.dev": "Fly.io",
    ".pages.dev": "Cloudflare Pages",
    ".workers.dev": "Cloudflare Workers",
    ".digitaloceanspaces.com": "DigitalOcean",
    ".ondigitalocean.app": "DigitalOcean App Platform",
    ".github.io": "GitHub Pages",
    ".gitlab.io": "GitLab Pages",
    ".pantheonsite.io": "Pantheon",
    ".wpengine.com": "WP Engine",
    ".kinsta.cloud": "Kinsta",
}

# ── CDN Header Signatures ───────────────────────────────────────────

_CDN_HEADERS: Dict[str, Dict[str, str]] = {
    "cf-ray": {"provider": "Cloudflare", "header": "cf-ray"},
    "cf-cache-status": {"provider": "Cloudflare", "header": "cf-cache-status"},
    "x-amz-cf-id": {"provider": "AWS CloudFront", "header": "x-amz-cf-id"},
    "x-amz-cf-pop": {"provider": "AWS CloudFront", "header": "x-amz-cf-pop"},
    "x-cdn": {"provider": "CDN (generic)", "header": "x-cdn"},
    "x-fastly-request-id": {"provider": "Fastly", "header": "x-fastly-request-id"},
    "x-served-by": {"provider": "Fastly", "header": "x-served-by"},
    "x-cache": {"provider": "CDN (generic)", "header": "x-cache"},
    "x-akamai-transformed": {"provider": "Akamai", "header": "x-akamai-transformed"},
    "x-vercel-id": {"provider": "Vercel", "header": "x-vercel-id"},
    "x-netlify-request-id": {"provider": "Netlify", "header": "x-netlify-request-id"},
    "fly-request-id": {"provider": "Fly.io", "header": "fly-request-id"},
}

_CLOUD_HEADERS: Dict[str, str] = {
    "x-amz-request-id": "AWS",
    "x-amz-id-2": "AWS",
    "x-ms-request-id": "Azure",
    "x-azure-ref": "Azure",
    "x-goog-generation": "Google Cloud",
    "x-goog-stored-content-length": "Google Cloud",
    "x-guploader-uploadid": "Google Cloud",
}

# ── Known IP ranges (top CIDR blocks only — production should use full files) ──

_CLOUD_CIDRS: Dict[str, List[str]] = {
    "AWS": [
        "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8",
        "18.0.0.0/8", "34.0.0.0/8", "35.0.0.0/8",
        "52.0.0.0/8", "54.0.0.0/8",
    ],
    "Azure": [
        "13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10",
        "52.96.0.0/12", "104.40.0.0/13",
    ],
    "Google Cloud": [
        "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/12",
        "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13",
    ],
    "Cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14",
        "108.162.192.0/18", "131.0.72.0/22",
        "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20",
        "188.114.96.0/20", "190.93.240.0/20",
        "197.234.240.0/22", "198.41.128.0/17",
    ],
    "DigitalOcean": [
        "134.209.0.0/16", "137.184.0.0/16", "138.68.0.0/16",
        "139.59.0.0/16", "142.93.0.0/16", "143.110.0.0/16",
        "143.198.0.0/16", "144.126.0.0/16",
        "157.230.0.0/16", "159.65.0.0/16", "159.89.0.0/16",
        "161.35.0.0/16", "164.90.0.0/16", "164.92.0.0/16",
        "165.22.0.0/16", "165.227.0.0/16",
        "167.71.0.0/16", "167.99.0.0/16", "167.172.0.0/16",
        "174.138.0.0/16", "178.62.0.0/16", "178.128.0.0/16",
    ],
}


class CloudCollector(BaseCollector):
    """Detects cloud hosting and CDN providers."""

    collector_name = "cloud"
    source_name = "dns+headers+ip"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        cloud_providers: Set[str] = set()
        cdn_providers: Set[str] = set()
        evidence: List[Dict[str, str]] = []
        errors: List[str] = []

        # ── 1. CNAME analysis ────────────────────────────────────────
        cname_results = await self._check_cname(target)
        for provider, cname in cname_results:
            cloud_providers.add(provider)
            evidence.append({
                "method": "cname",
                "provider": provider,
                "detail": cname,
            })

        # ── 2. Header analysis (from kwargs or fresh fetch) ──────────
        headers: Dict[str, str] = kwargs.get("headers", {})
        if not headers:
            headers = await self._fetch_headers(target)

        for header_key, meta in _CDN_HEADERS.items():
            if header_key in headers:
                cdn_providers.add(meta["provider"])
                evidence.append({
                    "method": "header",
                    "provider": meta["provider"],
                    "detail": f"{header_key}: {headers[header_key][:80]}",
                })

        for header_key, provider in _CLOUD_HEADERS.items():
            if header_key in headers:
                cloud_providers.add(provider)
                evidence.append({
                    "method": "header",
                    "provider": provider,
                    "detail": f"{header_key}: {headers[header_key][:80]}",
                })

        # Server header hints
        server = headers.get("server", "").lower()
        if "cloudflare" in server:
            cdn_providers.add("Cloudflare")
            evidence.append({
                "method": "server_header",
                "provider": "Cloudflare",
                "detail": f"Server: {headers.get('server', '')}",
            })
        if "amazons3" in server or "amazons3" in server.replace(" ", ""):
            cloud_providers.add("AWS S3")

        # ── 3. IP range matching ─────────────────────────────────────
        ip_results = await self._check_ip_ranges(target)
        for provider, ip in ip_results:
            cloud_providers.add(provider)
            evidence.append({
                "method": "ip_range",
                "provider": provider,
                "detail": f"IP {ip} in known range",
            })

        return {
            "raw_data": {
                "domain": target,
                "evidence": evidence,
                "errors": errors,
            },
            "processed_data": {
                "domain": target,
                "cloud_providers": sorted(cloud_providers),
                "cdn_providers": sorted(cdn_providers),
                "total_providers": len(cloud_providers) + len(cdn_providers),
                "evidence": evidence,
                "is_cloud_hosted": len(cloud_providers) > 0,
                "has_cdn": len(cdn_providers) > 0,
            },
        }

    # ── CNAME Check ──────────────────────────────────────────────────

    async def _check_cname(
        self, domain: str
    ) -> List[tuple]:
        results: List[tuple] = []
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        try:
            answer = await resolver.resolve(domain, "CNAME")
            for rr in answer:
                cname = str(rr.target).rstrip(".").lower()
                for pattern, provider in _CNAME_CLOUD.items():
                    if cname.endswith(pattern):
                        results.append((provider, cname))
        except Exception:
            pass
        return results

    # ── Header Fetch ─────────────────────────────────────────────────

    async def _fetch_headers(self, domain: str) -> Dict[str, str]:
        try:
            session = await self._get_session()
            async with session.get(
                f"https://{domain}",
                allow_redirects=True,
                ssl=False,
            ) as resp:
                return {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return {}

    # ── IP Range Matching ────────────────────────────────────────────

    async def _check_ip_ranges(
        self, domain: str
    ) -> List[tuple]:
        results: List[tuple] = []
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        try:
            answer = await resolver.resolve(domain, "A")
            for rr in answer:
                ip_str = rr.to_text()
                try:
                    ip = ipaddress.ip_address(ip_str)
                    for provider, cidrs in _CLOUD_CIDRS.items():
                        for cidr in cidrs:
                            if ip in ipaddress.ip_network(cidr):
                                results.append((provider, ip_str))
                                break
                except ValueError:
                    pass
        except Exception:
            pass
        return results
