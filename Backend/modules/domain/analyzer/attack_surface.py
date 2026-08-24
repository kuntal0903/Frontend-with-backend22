"""
Attack Surface Analyzer

WHY THIS FILE EXISTS:
    Aggregates all collector results into a single attack surface
    score (0–100) with a categorised risk breakdown.

WHAT IT ACCEPTS:
    A dict of CollectorResult objects keyed by collector name.

WHAT IT RETURNS:
    A dict with overall risk score, severity rating, and per-category
    breakdown (exposed services, missing security headers, mail
    security, certificate health, cloud/CDN exposure, etc.).

DESIGN:
    Pure analysis — no I/O, no network calls.  Operates entirely on
    the structured output of upstream collectors.
"""
from __future__ import annotations

from typing import Any, Dict, List

from modules.domain.schemas import CollectorResult


class AttackSurfaceAnalyzer:
    """Computes attack surface score from aggregated collector data."""

    async def analyze(
        self, domain: str, collector_results: Dict[str, CollectorResult]
    ) -> Dict[str, Any]:
        categories: Dict[str, Dict[str, Any]] = {}

        # ── Subdomains ───────────────────────────────────────────────
        sub_data = self._pd(collector_results, "subdomain")
        total_subs = sub_data.get("total_unique", 0)
        categories["subdomains"] = {
            "total": total_subs,
            "risk": self._range_risk(total_subs, low=5, med=20),
            "detail": f"{total_subs} unique subdomains discovered",
        }

        # ── Open Ports ───────────────────────────────────────────────
        port_data = self._pd(collector_results, "ports")
        total_open = port_data.get("total_open", 0)
        high_risk_ports = [
            p for p in port_data.get("open_ports", [])
            if p.get("port") in (21, 22, 23, 3306, 5432, 6379, 27017, 3389, 5900)
        ]
        categories["open_ports"] = {
            "total_open": total_open,
            "high_risk_ports": [p.get("port") for p in high_risk_ports],
            "risk": (
                "critical" if high_risk_ports else
                self._range_risk(total_open, low=3, med=10)
            ),
            "detail": (
                f"{total_open} open ports, "
                f"{len(high_risk_ports)} high-risk (DB/admin/remote access)"
            ),
        }

        # ── Security Headers ─────────────────────────────────────────
        header_data = self._pd(collector_results, "http_header")
        sec_headers = header_data.get("security_headers", {})
        header_score = sec_headers.get("score", 0)
        categories["security_headers"] = {
            "score": header_score,
            "missing": sec_headers.get("total_missing", 0),
            "risk": (
                "low" if header_score >= 80 else
                "medium" if header_score >= 50 else
                "high"
            ),
            "detail": (
                f"Security header score: {header_score}/100, "
                f"{sec_headers.get('total_missing', 0)} headers missing"
            ),
        }

        # ── Certificate Health ───────────────────────────────────────
        cert_data = self._pd(collector_results, "certificate")
        cert = cert_data.get("certificate") or {}
        cert_risk = "low"
        cert_issues: List[str] = []
        if not cert_data.get("has_certificate"):
            cert_risk = "critical"
            cert_issues.append("No TLS certificate found")
        else:
            if cert.get("is_expired"):
                cert_risk = "critical"
                cert_issues.append("Certificate is expired")
            elif cert.get("days_until_expiry") is not None:
                days = cert["days_until_expiry"]
                if days < 30:
                    cert_risk = "high"
                    cert_issues.append(f"Certificate expires in {days} days")
                elif days < 90:
                    cert_risk = "medium"
                    cert_issues.append(f"Certificate expires in {days} days")

        categories["certificate"] = {
            "risk": cert_risk,
            "issues": cert_issues,
            "detail": "; ".join(cert_issues) if cert_issues else "Certificate healthy",
        }

        # ── Mail Security ────────────────────────────────────────────
        mail_data = self._pd(collector_results, "mail")
        mail_posture = mail_data.get("mail_security_posture", {})
        mail_score = mail_posture.get("score", 0)
        categories["mail_security"] = {
            "score": mail_score,
            "rating": mail_posture.get("rating", "unknown"),
            "has_spf": mail_data.get("has_spf", False),
            "has_dmarc": mail_data.get("has_dmarc", False),
            "has_dkim": mail_data.get("has_dkim", False),
            "risk": (
                "low" if mail_score >= 80 else
                "medium" if mail_score >= 50 else
                "high"
            ),
            "detail": (
                f"Mail security score: {mail_score}/100 "
                f"({mail_posture.get('rating', 'unknown')})"
            ),
        }

        # ── WAF ──────────────────────────────────────────────────────
        waf_data = self._pd(collector_results, "waf")
        has_waf = waf_data.get("waf_detected", False)
        categories["waf"] = {
            "detected": has_waf,
            "providers": waf_data.get("waf_providers", []),
            "risk": "low" if has_waf else "medium",
            "detail": (
                f"WAF detected: {', '.join(waf_data.get('waf_providers', []))}"
                if has_waf else "No WAF detected"
            ),
        }

        # ── Cloud / CDN ──────────────────────────────────────────────
        cloud_data = self._pd(collector_results, "cloud")
        categories["cloud_cdn"] = {
            "cloud_providers": cloud_data.get("cloud_providers", []),
            "cdn_providers": cloud_data.get("cdn_providers", []),
            "is_cloud_hosted": cloud_data.get("is_cloud_hosted", False),
            "has_cdn": cloud_data.get("has_cdn", False),
            "risk": "info",
            "detail": (
                f"Cloud: {', '.join(cloud_data.get('cloud_providers', ['none']))}, "
                f"CDN: {', '.join(cloud_data.get('cdn_providers', ['none']))}"
            ),
        }

        # ── Nameserver ───────────────────────────────────────────────
        ns_data = self._pd(collector_results, "nameserver")
        zone_vuln = ns_data.get("zone_transfer_vulnerable", False)
        categories["nameservers"] = {
            "total": ns_data.get("total_nameservers", 0),
            "zone_transfer_vulnerable": zone_vuln,
            "risk": "critical" if zone_vuln else "low",
            "detail": (
                "ZONE TRANSFER ALLOWED — critical misconfiguration!"
                if zone_vuln else
                f"{ns_data.get('total_nameservers', 0)} nameservers, zone transfer denied"
            ),
        }

        # ── Technologies ─────────────────────────────────────────────
        tech_data = self._pd(collector_results, "technology")
        categories["technologies"] = {
            "total": tech_data.get("total_technologies", 0),
            "categories": tech_data.get("categories", {}),
            "risk": "info",
            "detail": f"{tech_data.get('total_technologies', 0)} technologies detected",
        }

        # ── Overall Score ────────────────────────────────────────────
        risk_score = self._calculate_overall_score(categories)
        severity = (
            "critical" if risk_score >= 80 else
            "high" if risk_score >= 60 else
            "medium" if risk_score >= 40 else
            "low"
        )

        # Key findings
        key_findings = self._extract_key_findings(categories)

        return {
            "domain": domain,
            "risk_score": risk_score,
            "severity": severity,
            "categories": categories,
            "key_findings": key_findings,
            "total_categories_assessed": len(categories),
        }

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _pd(results: Dict[str, CollectorResult], name: str) -> Dict[str, Any]:
        """Get processed_data from a collector result by name."""
        r = results.get(name)
        if r is None:
            return {}
        return r.processed_data

    @staticmethod
    def _range_risk(value: int, low: int, med: int) -> str:
        if value >= med:
            return "high"
        if value >= low:
            return "medium"
        return "low"

    @staticmethod
    def _calculate_overall_score(categories: Dict[str, Any]) -> int:
        """Map risk labels to numeric values and average."""
        risk_values = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 0}
        scored = [
            risk_values.get(cat.get("risk", "info"), 0)
            for cat in categories.values()
            if cat.get("risk") != "info"
        ]
        if not scored:
            return 0
        return round(sum(scored) / len(scored))

    @staticmethod
    def _extract_key_findings(categories: Dict[str, Any]) -> List[str]:
        """Pull out the most actionable findings."""
        findings: List[str] = []
        for name, cat in categories.items():
            risk = cat.get("risk", "info")
            if risk in ("critical", "high"):
                findings.append(f"[{risk.upper()}] {cat.get('detail', name)}")
        return findings
