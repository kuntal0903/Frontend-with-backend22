"""
Wildcard DNS Detector

WHY THIS FILE EXISTS:
    Some domains configure wildcard DNS records (e.g. *.tesla.com -> IP)
    so that every subdomain resolves — including completely made-up ones.

    If we run a DNS brute-force against such a domain WITHOUT first
    detecting this, every word in the wordlist will "resolve" and be
    reported as a discovered subdomain.  For a 100-word wordlist that is
    100 false positives.  For a domain with many subdomains and a large
    wordlist it can be thousands.

HOW IT WORKS:
    1. Generate N random hostnames that almost certainly do not exist
       (e.g. ``xj7q2k9m.example.com``).
    2. Resolve each one via DNS.
    3. If WILDCARD_THRESHOLD or more of them resolve successfully to the
       same IP set, wildcard DNS is active on that domain.
    4. Record the "wildcard IPs" — the IP addresses that the wildcard
       record resolves to.
    5. The brute-force caller filters out any result that resolves
       exclusively to one of these wildcard IPs.

WHAT IT RETURNS:
    WildcardResult dataclass with:
        is_wildcard: bool
        wildcard_ips: Set[str]   — IPs to exclude from brute-force results
        probe_results: dict      — per-probe detail for debugging

DESIGN:
    Pure async DNS — no HTTP, no external services.
    Deterministic: same random seed produces reproducible probe names.
    Intentionally conservative: only flags wildcard if THRESHOLD probes agree.
"""
from __future__ import annotations

import hashlib
import random
import string
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

import dns.asyncresolver
import dns.exception
import dns.resolver

from common.logger import get_logger

logger = get_logger("domain", "wildcard_detector")

# ── Configuration ─────────────────────────────────────────────────────

# Number of random hostnames to probe
PROBE_COUNT = 5

# How many probes must resolve to the same IP set to confirm wildcard.
# 3/5 means we tolerate transient failures but still detect wildcards reliably.
WILDCARD_THRESHOLD = 3

# Length of each random hostname label (e.g. "xk9q2j7m")
PROBE_LABEL_LENGTH = 12

# DNS resolver lifetime per probe (seconds)
PROBE_TIMEOUT = 4.0


# ── Result Type ───────────────────────────────────────────────────────

@dataclass
class WildcardResult:
    """Result of a wildcard DNS probe run against a domain."""
    domain: str
    is_wildcard: bool
    wildcard_ips: Set[str] = field(default_factory=set)
    probe_count: int = 0
    probes_resolved: int = 0
    probe_results: Dict[str, Optional[Set[str]]] = field(default_factory=dict)

    def should_exclude(self, resolved_ips: Set[str]) -> bool:
        """
        Return True if *resolved_ips* overlaps with the wildcard IP set.

        A brute-force hit that resolves to ONLY wildcard IPs should be
        excluded.  If it resolves to at least one non-wildcard IP it may
        be a real host behind a shared IP with the wildcard record.
        """
        if not self.is_wildcard or not self.wildcard_ips:
            return False
        # Exclude only if ALL resolved IPs are in the wildcard set.
        # A host that also has unique IPs is likely real.
        return resolved_ips.issubset(self.wildcard_ips)


# ── Detector ──────────────────────────────────────────────────────────

class WildcardDetector:
    """
    Probes a domain for wildcard DNS before running brute-force enumeration.

    Usage
    -----
    detector = WildcardDetector()
    result = await detector.detect("tesla.com")
    if result.is_wildcard:
        # filter brute-force hits using result.should_exclude(ips)
    """

    async def detect(
        self,
        domain: str,
        seed: Optional[int] = None,
    ) -> WildcardResult:
        """
        Probe *domain* for wildcard DNS.

        Parameters
        ----------
        domain
            The root domain to probe (e.g. ``"tesla.com"``).
        seed
            Optional random seed for reproducible probe names.
            Defaults to a hash of the domain for consistent probes.
        """
        if seed is None:
            seed = int(hashlib.md5(domain.encode()).hexdigest(), 16) % (2**31)

        rng = random.Random(seed)
        probes = [
            self._random_label(rng) + "." + domain
            for _ in range(PROBE_COUNT)
        ]

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = PROBE_TIMEOUT

        result = WildcardResult(
            domain=domain,
            is_wildcard=False,
            probe_count=PROBE_COUNT,
        )
        ip_sets: list = []

        for probe in probes:
            ips = await self._resolve_a(resolver, probe)
            result.probe_results[probe] = ips
            if ips:
                result.probes_resolved += 1
                ip_sets.append(frozenset(ips))

        # Check if enough probes resolved to the same IP set
        if result.probes_resolved >= WILDCARD_THRESHOLD:
            counts = Counter(ip_sets)
            most_common_set, count = counts.most_common(1)[0]
            if count >= WILDCARD_THRESHOLD:
                result.is_wildcard = True
                result.wildcard_ips = set(most_common_set)

        logger.info(
            "Wildcard detection complete",
            extra={
                "domain": domain,
                "is_wildcard": result.is_wildcard,
                "probes_resolved": result.probes_resolved,
                "wildcard_ips": sorted(result.wildcard_ips),
            },
        )
        return result

    @staticmethod
    def _random_label(rng: random.Random) -> str:
        """
        Generate a random hostname label that almost certainly does not exist.

        Uses only lowercase letters and digits — valid DNS label characters.
        The length (12 chars) makes accidental collision astronomically unlikely.
        """
        chars = string.ascii_lowercase + string.digits
        # Start with a letter (DNS labels must not start with a digit)
        return rng.choice(string.ascii_lowercase) + "".join(
            rng.choices(chars, k=PROBE_LABEL_LENGTH - 1)
        )

    @staticmethod
    async def _resolve_a(
        resolver: dns.asyncresolver.Resolver,
        hostname: str,
    ) -> Optional[Set[str]]:
        """
        Resolve *hostname* to A records.  Returns None if NXDOMAIN or timeout.
        Returns a set of IP strings if the hostname resolves.
        """
        try:
            answer = await resolver.resolve(hostname, "A")
            return {rr.to_text() for rr in answer}
        except dns.resolver.NXDOMAIN:
            return None  # Expected for non-wildcard domains
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NoNameservers:
            return None
        except dns.exception.Timeout:
            return None
        except Exception:
            return None
