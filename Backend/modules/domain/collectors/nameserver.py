"""
Nameserver Collector

WHY THIS FILE EXISTS:
    Dedicated collector for authoritative nameserver enumeration.
    Resolves NS records, maps each to its IP, and performs a passive
    zone-transfer (AXFR) check.

WHAT IT ACCEPTS:
    A domain string (e.g. "example.com").

WHAT IT RETURNS:
    CollectorResult with nameserver FQDNs, their IPs, and AXFR status.

NOTE ON AXFR:
    We *attempt* an AXFR query — this is a standard DNS request, not an
    exploit.  Most servers refuse it; that refusal is the expected outcome.
    A successful transfer indicates a misconfiguration worth flagging.
"""
from __future__ import annotations

from typing import Any, Dict, List

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone

from modules.domain.collectors.base import BaseCollector


class NameserverCollector(BaseCollector):
    """Enumerates authoritative nameservers and checks zone transfer."""

    collector_name = "nameserver"
    source_name = "dnspython"

    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self._timeout

        nameservers: List[Dict[str, Any]] = []
        errors: List[str] = []

        # 1. Resolve NS records
        try:
            ns_answer = await resolver.resolve(target, "NS")
        except dns.resolver.NXDOMAIN:
            errors.append(f"NXDOMAIN: {target} does not exist")
            return self._empty_result(target, errors)
        except dns.resolver.NoAnswer:
            errors.append("No NS records returned")
            return self._empty_result(target, errors)
        except dns.exception.Timeout:
            errors.append("Timeout querying NS records")
            return self._empty_result(target, errors)
        except Exception as exc:
            errors.append(f"NS query error: {exc}")
            return self._empty_result(target, errors)

        # 2. For each NS, resolve its IP(s) and check AXFR
        for rr in ns_answer:
            ns_fqdn = str(rr.target).rstrip(".")
            ns_entry: Dict[str, Any] = {
                "nameserver": ns_fqdn,
                "ips": [],
                "zone_transfer": False,
            }

            # Resolve NS → IP
            try:
                a_answer = await resolver.resolve(ns_fqdn, "A")
                ns_entry["ips"] = [r.to_text() for r in a_answer]
            except Exception:
                pass

            # Passive AXFR check
            for ip in ns_entry["ips"]:
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ip, target, timeout=5.0, lifetime=5.0)
                    )
                    if zone:
                        ns_entry["zone_transfer"] = True
                        ns_entry["zone_transfer_ip"] = ip
                        break
                except Exception:
                    pass  # Expected — most servers refuse AXFR

            nameservers.append(ns_entry)

        return {
            "raw_data": {
                "domain": target,
                "nameservers": nameservers,
                "errors": errors,
            },
            "processed_data": {
                "domain": target,
                "nameservers": nameservers,
                "total_nameservers": len(nameservers),
                "zone_transfer_vulnerable": any(
                    ns.get("zone_transfer") for ns in nameservers
                ),
            },
        }

    @staticmethod
    def _empty_result(target: str, errors: List[str]) -> Dict[str, Any]:
        return {
            "raw_data": {"domain": target, "nameservers": [], "errors": errors},
            "processed_data": {
                "domain": target,
                "nameservers": [],
                "total_nameservers": 0,
                "zone_transfer_vulnerable": False,
            },
        }
