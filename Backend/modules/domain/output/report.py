"""
Report Generator

WHY THIS FILE EXISTS:
    Produces the final machine-readable JSON report from scan data.
    The report is the primary deliverable of a domain scan.

WHAT IT ACCEPTS:
    A DomainReportSchema dict (from the pipeline's Step 9).

WHAT IT RETURNS:
    The same dict, optionally enriched with executive summary,
    recommendations, and formatting for export.

DESIGN:
    Currently a pass-through with summary enrichment.
    Future: PDF generation, CSV export, STIX/TAXII output.
"""
from __future__ import annotations

from typing import Any, Dict, List


class ReportGenerator:
    """Enriches the raw scan report with executive summary and recommendations."""

    def generate(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Take the pipeline output and add:
        - Executive summary
        - Recommendations based on findings
        """
        report_data["executive_summary"] = self._build_summary(report_data)
        report_data["recommendations"] = self._build_recommendations(report_data)
        return report_data

    @staticmethod
    def _build_summary(data: Dict[str, Any]) -> Dict[str, Any]:
        """Build a human-friendly executive summary."""
        attack_surface = data.get("attack_surface", {})
        risk_score = attack_surface.get("risk_score", 0)
        severity = attack_surface.get("severity", "unknown")

        # Count assets by type
        assets = data.get("assets", {})
        type_counts: Dict[str, int] = {
            atype: len(items) for atype, items in assets.items()
        }

        return {
            "target": data.get("target_domain", ""),
            "scan_id": data.get("scan_id", ""),
            "duration_seconds": data.get("duration_seconds"),
            "total_assets": data.get("total_assets_found", 0),
            "risk_score": risk_score,
            "severity": severity,
            "asset_breakdown": type_counts,
            "key_findings": attack_surface.get("key_findings", []),
        }

    @staticmethod
    def _build_recommendations(data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate actionable recommendations based on findings."""
        recommendations: List[Dict[str, str]] = []
        attack_surface = data.get("attack_surface", {})
        categories = attack_surface.get("categories", {})

        # Certificate issues
        cert = categories.get("certificate", {})
        if cert.get("risk") in ("critical", "high"):
            recommendations.append({
                "priority": "critical" if cert["risk"] == "critical" else "high",
                "category": "certificate",
                "recommendation": (
                    "Resolve certificate issues immediately: "
                    + "; ".join(cert.get("issues", []))
                ),
            })

        # Security headers
        headers = categories.get("security_headers", {})
        if headers.get("risk") in ("high", "medium"):
            recommendations.append({
                "priority": "high",
                "category": "security_headers",
                "recommendation": (
                    f"Implement missing security headers. "
                    f"Current score: {headers.get('score', 0)}/100. "
                    f"Add HSTS, CSP, and X-Frame-Options at minimum."
                ),
            })

        # Open ports
        ports = categories.get("open_ports", {})
        if ports.get("high_risk_ports"):
            recommendations.append({
                "priority": "critical",
                "category": "open_ports",
                "recommendation": (
                    f"High-risk ports exposed: "
                    f"{ports['high_risk_ports']}. "
                    f"Close or restrict access to database and "
                    f"remote-access ports."
                ),
            })

        # Mail security
        mail = categories.get("mail_security", {})
        if mail.get("risk") in ("high",):
            recommendations.append({
                "priority": "high",
                "category": "mail_security",
                "recommendation": (
                    "Implement email security records: "
                    + ("SPF " if not mail.get("has_spf") else "")
                    + ("DMARC " if not mail.get("has_dmarc") else "")
                    + ("DKIM " if not mail.get("has_dkim") else "")
                    + "to prevent email spoofing."
                ),
            })

        # Zone transfer
        ns = categories.get("nameservers", {})
        if ns.get("zone_transfer_vulnerable"):
            recommendations.append({
                "priority": "critical",
                "category": "nameservers",
                "recommendation": (
                    "DNS zone transfer is allowed! This exposes your "
                    "entire DNS zone to anyone. Restrict AXFR to "
                    "authorized secondary nameservers only."
                ),
            })

        # WAF
        waf = categories.get("waf", {})
        if not waf.get("detected"):
            recommendations.append({
                "priority": "medium",
                "category": "waf",
                "recommendation": (
                    "No WAF detected. Consider deploying a web "
                    "application firewall to protect against common "
                    "web attacks."
                ),
            })

        # Staging environments (from analyzers)
        analyzers = attack_surface.get("analyzers", {})
        staging = analyzers.get("staging_environments", {})
        if staging.get("total_found", 0) > 0:
            recommendations.append({
                "priority": "high",
                "category": "staging",
                "recommendation": (
                    f"{staging['total_found']} staging/dev environments "
                    f"are publicly accessible. Restrict access via "
                    f"VPN, IP allowlisting, or authentication."
                ),
            })

        # Admin portals
        admin = analyzers.get("admin_portals", {})
        if admin.get("total_found", 0) > 0:
            recommendations.append({
                "priority": "high",
                "category": "admin_portals",
                "recommendation": (
                    f"{admin['total_found']} admin portals are publicly "
                    f"accessible. Restrict to internal networks or add "
                    f"multi-factor authentication."
                ),
            })

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(
            key=lambda r: priority_order.get(r["priority"], 99)
        )

        return recommendations
