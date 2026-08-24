"""
Subdomain Discovery Collector

WHY THIS FILE EXISTS:
    Multi-source subdomain enumeration — the single most important
    discovery task in attack surface mapping.

DATA SOURCES (independent, results merged):
    1. crt.sh Certificate Transparency logs
    2. DNS brute-force using a configurable wordlist

WHAT IT ACCEPTS:
    A root domain string and optional kwargs:
        - ct_domains: List[str] — SAN domains from the certificate
          collector (injected during enrichment phase)

WHAT IT RETURNS:
    CollectorResult with deduplicated, validated subdomain list
    and per-source attribution.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

import dns.asyncresolver
import dns.exception
import dns.resolver

from common.utils import is_valid_domain, normalize_domain
from config import settings
from modules.domain.collectors.base import BaseCollector
from modules.domain.collectors.wildcard_detector import WildcardDetector

# ── Wordlists ────────────────────────────────────────────────────────

_WORDLIST_SMALL: List[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "portal", "vpn", "remote", "ns1", "ns2",
    "api", "dev", "staging", "test", "qa", "uat", "beta",
    "demo", "sandbox", "preprod", "prod", "app", "web",
    "cdn", "static", "assets", "media", "img", "images",
    "docs", "wiki", "support", "help", "status", "monitor",
    "grafana", "kibana", "jenkins", "gitlab", "git", "ci",
    "auth", "sso", "login", "id", "oauth", "accounts",
    "dashboard", "panel", "cpanel", "whm", "manage",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "elastic", "search", "log", "logs", "syslog",
    "mx", "relay", "gateway", "proxy", "lb", "load",
    "backup", "bak", "old", "new", "v2", "internal",
    "intranet", "extranet", "partner", "client", "customer",
    "shop", "store", "pay", "payment", "billing", "invoice",
    "m", "mobile", "blog", "news", "forum", "community",
]

_WORDLIST_MEDIUM: List[str] = _WORDLIST_SMALL + [
    "www2", "www3", "mail2", "smtp2", "ns3", "ns4",
    "api2", "api-v2", "rest", "graphql", "ws", "websocket",
    "dev1", "dev2", "stage", "stg", "tst", "testing",
    "alpha", "preview", "canary", "edge", "next",
    "assets2", "cdn2", "upload", "files", "share",
    "crm", "erp", "hr", "it", "ops", "devops",
    "jira", "confluence", "slack", "teams", "zoom",
    "prometheus", "nagios", "zabbix", "splunk", "datadog",
    "vault", "secrets", "key", "cert", "pki",
    "s3", "storage", "archive", "cache", "memcached",
    "mq", "queue", "rabbit", "kafka",
    "k8s", "kube", "docker", "registry", "container",
    "ci-cd", "build", "deploy", "release", "artifact",
    "sentry", "error", "debug", "trace",
    "staging-api", "dev-api", "test-api",
]


class SubdomainCollector(BaseCollector):
    """Multi-source subdomain discovery with deduplication."""

    collector_name = "subdomain"
    source_name = "crt.sh+dns_bruteforce"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        found: Dict[str, Set[str]] = {
            "crt.sh": set(),
            "dns_bruteforce": set(),
            "certificate_san": set(),
        }
        errors: List[str] = []

        # Source 1: crt.sh CT log
        try:
            ct_subs = await self._crtsh_enum(target)
            found["crt.sh"] = ct_subs
        except Exception as exc:
            errors.append(f"crt.sh failed: {exc}")

        # Source 2: DNS brute-force
        if settings.SUBDOMAIN_BRUTEFORCE_ENABLED:
            try:
                brute_subs = await self._dns_bruteforce(target)
                found["dns_bruteforce"] = brute_subs
            except Exception as exc:
                errors.append(f"DNS bruteforce failed: {exc}")

        # Source 3: Certificate SAN (injected by orchestrator)
        ct_domains: List[str] = kwargs.get("ct_domains", [])
        for d in ct_domains:
            normalised = normalize_domain(d)
            if normalised and normalised.endswith(f".{target}"):
                found["certificate_san"].add(normalised)

        # Merge & deduplicate
        all_subdomains: Set[str] = set()
        for source_subs in found.values():
            all_subdomains.update(source_subs)

        # Build per-subdomain attribution
        subdomain_details: List[Dict[str, Any]] = []
        for sub in sorted(all_subdomains):
            sources = [
                src for src, subs in found.items() if sub in subs
            ]
            subdomain_details.append({
                "subdomain": sub,
                "sources": sources,
                "source_count": len(sources),
            })

        return {
            "raw_data": {
                "domain": target,
                "by_source": {k: sorted(v) for k, v in found.items()},
                "errors": errors,
            },
            "processed_data": {
                "domain": target,
                "subdomains": sorted(all_subdomains),
                "subdomain_details": subdomain_details,
                "total_unique": len(all_subdomains),
                "by_source_count": {
                    k: len(v) for k, v in found.items()
                },
                "wildcard_detected": getattr(self, "_last_wildcard_detected", False),
                "wildcard_ips": sorted(getattr(self, "_last_wildcard_ips", set())),
            },
        }

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        pd = raw.get("processed_data", {})
        sources_with_data = sum(
            1 for v in pd.get("by_source_count", {}).values() if v > 0
        )
        if sources_with_data >= 2:
            return 1.0
        if sources_with_data == 1:
            return 0.7
        return 0.3

    # ── crt.sh ───────────────────────────────────────────────────────

    async def _crtsh_enum(self, domain: str) -> Set[str]:
        session = await self._get_session()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with session.get(url) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json(content_type=None)
            if not isinstance(data, list):
                return set()

        results: Set[str] = set()
        for entry in data:
            for field in ("common_name", "name_value"):
                raw_value = entry.get(field, "")
                for name in raw_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if (
                        is_valid_domain(name)
                        and name.endswith(f".{domain}")
                        and name != domain
                    ):
                        results.add(name)
        return results

    # ── DNS Brute-force ──────────────────────────────────────────────

    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """
        Brute-force DNS subdomain enumeration with wildcard DNS detection.

        Before probing the wordlist, runs WildcardDetector to identify
        whether the domain uses wildcard DNS.  Any brute-force hit that
        resolves exclusively to the wildcard IP set is discarded as a
        false positive.
        """
        wordlist = self._get_wordlist()
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0

        # Step 1: Wildcard detection — must happen before any wordlist probing.
        detector = WildcardDetector()
        wildcard = await detector.detect(domain)

        # Store for inclusion in processed_data
        self._last_wildcard_detected = wildcard.is_wildcard
        self._last_wildcard_ips = wildcard.wildcard_ips

        if wildcard.is_wildcard:
            self.logger.warning(
                "Wildcard DNS detected — brute-force results will be filtered",
                extra={
                    "domain": domain,
                    "wildcard_ips": sorted(wildcard.wildcard_ips),
                },
            )

        found: Set[str] = set()
        discarded: int = 0

        for prefix in wordlist:
            fqdn = f"{prefix}.{domain}"
            try:
                answer = await resolver.resolve(fqdn, "A")
                resolved_ips: Set[str] = {rr.to_text() for rr in answer}

                # Wildcard filter: if ALL resolved IPs are in the wildcard
                # IP set, this is a wildcard catch-all, not a real host.
                if wildcard.should_exclude(resolved_ips):
                    discarded += 1
                    continue

                found.add(fqdn)

            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                pass
            except Exception:
                pass

        if wildcard.is_wildcard and discarded > 0:
            self.logger.info(
                "Wildcard filter discarded brute-force false positives",
                extra={"domain": domain, "discarded": discarded, "kept": len(found)},
            )

        return found

    @staticmethod
    def _get_wordlist() -> List[str]:
        size = settings.SUBDOMAIN_WORDLIST_SIZE
        if size == "medium":
            return _WORDLIST_MEDIUM
        # Default to small
        return _WORDLIST_SMALL
