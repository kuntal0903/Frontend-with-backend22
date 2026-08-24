"""
DNS Collector

WHY THIS FILE EXISTS:
    Single-responsibility collector for DNS record enumeration.
    Queries all standard record types (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR)
    using dnspython's async resolver.

WHAT IT ACCEPTS:
    A domain string (e.g. "example.com").

WHAT IT RETURNS:
    CollectorResult with raw_data (resolver responses) and processed_data
    (structured dict of records keyed by type).

DATA SOURCES:
    dnspython async resolver against system-configured nameservers.

ERROR HANDLING:
    NXDOMAIN → empty result (domain doesn't exist)
    NoAnswer → skip that record type
    Timeout  → CollectorTimeoutError
    Other    → logged and returned in errors list
"""
from __future__ import annotations

from typing import Any, Dict, List

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from modules.domain.collectors.base import BaseCollector

# Record types to query — ordered by most-informative first.
_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]


class DNSCollector(BaseCollector):
    """
    Collects DNS records for all standard types.

    Processes each record type independently so a failure in one
    does not prevent the others from returning data.
    """

    collector_name = "dns"
    source_name = "dnspython"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self._timeout

        raw_records: Dict[str, List[Dict[str, Any]]] = {}
        processed_records: Dict[str, List[Dict[str, Any]]] = {}
        errors: List[str] = []

        for rtype in _RECORD_TYPES:
            try:
                answer = await resolver.resolve(target, rtype)
                raw_entries: List[Dict[str, Any]] = []
                processed_entries: List[Dict[str, Any]] = []

                for rr in answer:
                    raw_entry = {"value": rr.to_text(), "ttl": answer.rrset.ttl}
                    raw_entries.append(raw_entry)

                    processed_entry = self._process_record(rtype, rr, answer.rrset.ttl)
                    processed_entries.append(processed_entry)

                raw_records[rtype] = raw_entries
                processed_records[rtype] = processed_entries

            except dns.resolver.NXDOMAIN:
                errors.append(f"NXDOMAIN for {target} ({rtype})")
                break  # domain doesn't exist — no point querying further

            except dns.resolver.NoAnswer:
                # No records of this type — perfectly normal
                raw_records[rtype] = []
                processed_records[rtype] = []

            except dns.resolver.NoNameservers:
                errors.append(f"No nameservers available for {rtype}")

            except dns.exception.Timeout:
                errors.append(f"Timeout querying {rtype}")

            except Exception as exc:
                errors.append(f"{rtype} query failed: {exc}")

        # Attempt PTR lookups for discovered A records
        ptr_records = await self._collect_ptr(
            resolver,
            [r["value"] for r in processed_records.get("A", [])],
        )
        if ptr_records:
            raw_records["PTR"] = ptr_records
            processed_records["PTR"] = ptr_records

        return {
            "raw_data": {
                "domain": target,
                "records": raw_records,
                "errors": errors,
            },
            "processed_data": {
                "domain": target,
                "records": processed_records,
                "record_counts": {
                    rtype: len(recs) for rtype, recs in processed_records.items()
                },
                "total_records": sum(
                    len(recs) for recs in processed_records.values()
                ),
            },
        }

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        """Higher confidence when more record types return data."""
        records = raw.get("processed_data", {}).get("records", {})
        non_empty = sum(1 for v in records.values() if v)
        return min(1.0, non_empty / max(len(_RECORD_TYPES), 1))

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _process_record(
        rtype: str, rr: Any, ttl: int
    ) -> Dict[str, Any]:
        """Normalise a single DNS record into a uniform dict."""
        base = {"type": rtype, "ttl": ttl, "value": rr.to_text()}

        if rtype == "MX":
            base["priority"] = rr.preference
            base["exchange"] = str(rr.exchange).rstrip(".")
        elif rtype == "SOA":
            base["mname"] = str(rr.mname).rstrip(".")
            base["rname"] = str(rr.rname).rstrip(".")
            base["serial"] = rr.serial
            base["refresh"] = rr.refresh
            base["retry"] = rr.retry
            base["expire"] = rr.expire
            base["minimum"] = rr.minimum
        elif rtype == "CNAME":
            base["value"] = str(rr.target).rstrip(".")

        return base

    async def _collect_ptr(
        self,
        resolver: dns.asyncresolver.Resolver,
        ips: List[str],
    ) -> List[Dict[str, Any]]:
        """Best-effort reverse DNS for discovered IPs."""
        results: List[Dict[str, Any]] = []
        for ip in ips:
            try:
                rev_name = dns.reversename.from_address(ip)
                answer = await resolver.resolve(rev_name, "PTR")
                for rr in answer:
                    results.append({
                        "type": "PTR",
                        "ip": ip,
                        "value": str(rr.target).rstrip("."),
                        "ttl": answer.rrset.ttl,
                    })
            except Exception:
                pass  # PTR is best-effort; failures are expected
        return results
