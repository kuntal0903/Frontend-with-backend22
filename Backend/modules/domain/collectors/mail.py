"""
Mail Server & Security Collector

WHY THIS FILE EXISTS:
    Collects mail infrastructure details: MX records with priorities,
    SPF record (parsed from TXT), DMARC policy (_dmarc.{domain}),
    and common DKIM selectors.

WHAT IT ACCEPTS:
    A domain string.

WHAT IT RETURNS:
    CollectorResult with MX hosts, SPF/DMARC/DKIM records, and a
    mail-security posture assessment.

DESIGN:
    Each lookup (MX, SPF, DMARC, DKIM) is independent — one failure
    does not block the others.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

from modules.domain.collectors.base import BaseCollector

# Common DKIM selectors to check
_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "mail", "dkim", "s1", "s2",
]


class MailCollector(BaseCollector):
    """Collects MX, SPF, DMARC, and common DKIM records."""

    collector_name = "mail"
    source_name = "dnspython"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self._timeout

        mx_records = await self._get_mx(resolver, target)
        spf_record = await self._get_spf(resolver, target)
        dmarc_record = await self._get_dmarc(resolver, target)
        dkim_records = await self._get_dkim(resolver, target)

        # Assess mail security posture
        posture = self._assess_posture(mx_records, spf_record, dmarc_record, dkim_records)

        return {
            "raw_data": {
                "domain": target,
                "mx": mx_records,
                "spf": spf_record,
                "dmarc": dmarc_record,
                "dkim": dkim_records,
            },
            "processed_data": {
                "domain": target,
                "mx_records": mx_records,
                "spf_record": spf_record,
                "dmarc_record": dmarc_record,
                "dkim_records": dkim_records,
                "mail_security_posture": posture,
                "has_mx": len(mx_records) > 0,
                "has_spf": spf_record is not None,
                "has_dmarc": dmarc_record is not None,
                "has_dkim": len(dkim_records) > 0,
            },
        }

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        pd = raw.get("processed_data", {})
        checks = [pd.get("has_mx"), pd.get("has_spf"), pd.get("has_dmarc")]
        passed = sum(1 for c in checks if c)
        return round(passed / len(checks), 2)

    # ── MX ───────────────────────────────────────────────────────────

    async def _get_mx(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> List[Dict[str, Any]]:
        try:
            answer = await resolver.resolve(domain, "MX")
            records = []
            for rr in answer:
                records.append({
                    "priority": rr.preference,
                    "exchange": str(rr.exchange).rstrip("."),
                    "ttl": answer.rrset.ttl,
                })
            return sorted(records, key=lambda r: r["priority"])
        except Exception:
            return []

    # ── SPF ──────────────────────────────────────────────────────────

    async def _get_spf(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> Optional[str]:
        try:
            answer = await resolver.resolve(domain, "TXT")
            for rr in answer:
                text = rr.to_text().strip('"')
                if text.startswith("v=spf1"):
                    return text
        except Exception:
            pass
        return None

    # ── DMARC ────────────────────────────────────────────────────────

    async def _get_dmarc(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> Optional[str]:
        try:
            answer = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rr in answer:
                text = rr.to_text().strip('"')
                if text.startswith("v=DMARC1"):
                    return text
        except Exception:
            pass
        return None

    # ── DKIM ─────────────────────────────────────────────────────────

    async def _get_dkim(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> List[Dict[str, str]]:
        records: List[Dict[str, str]] = []
        for selector in _DKIM_SELECTORS:
            try:
                answer = await resolver.resolve(
                    f"{selector}._domainkey.{domain}", "TXT"
                )
                for rr in answer:
                    text = rr.to_text().strip('"')
                    if "v=DKIM1" in text or "k=" in text:
                        records.append({"selector": selector, "record": text})
            except Exception:
                pass
        return records

    # ── Security Posture ─────────────────────────────────────────────

    @staticmethod
    def _assess_posture(
        mx: List, spf: Optional[str], dmarc: Optional[str], dkim: List
    ) -> Dict[str, Any]:
        score = 0
        findings: List[str] = []

        if mx:
            score += 20
        else:
            findings.append("No MX records found")

        if spf:
            score += 25
            if "-all" in spf:
                score += 5
                findings.append("SPF configured with hard fail (-all)")
            elif "~all" in spf:
                findings.append("SPF configured with soft fail (~all)")
            else:
                findings.append("SPF present but enforcement is weak")
        else:
            findings.append("No SPF record found — spoofing risk")

        if dmarc:
            score += 25
            if "p=reject" in dmarc:
                score += 10
                findings.append("DMARC policy set to reject")
            elif "p=quarantine" in dmarc:
                score += 5
                findings.append("DMARC policy set to quarantine")
            else:
                findings.append("DMARC present but policy is none/monitoring")
        else:
            findings.append("No DMARC record found — spoofing risk")

        if dkim:
            score += 15
            findings.append(f"DKIM found for {len(dkim)} selector(s)")
        else:
            findings.append("No DKIM selectors found")

        return {
            "score": min(score, 100),
            "rating": (
                "strong" if score >= 80 else
                "moderate" if score >= 50 else
                "weak"
            ),
            "findings": findings,
        }
