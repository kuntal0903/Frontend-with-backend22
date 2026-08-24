"""
Shared Helper Utilities

WHY THIS FILE EXISTS:
    Pure functions used by multiple collectors and the pipeline.
    Domain validation, IP classification, deduplication, UUID generation.
    No side effects — every function is deterministic and testable.

WHAT IT ACCEPTS / RETURNS:
    Each function documents its inputs and outputs via type hints.
    All functions operate on primitive types (str, list, bool).

DESIGN:
    Pure utility module.  No classes, no state, no I/O.
    If a utility needs I/O (network, disk), it belongs in a collector.
"""
import hashlib
import ipaddress
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import tldextract


# ── Domain Validation ────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_valid_domain(domain: str) -> bool:
    """Return True if *domain* matches a syntactically valid domain name."""
    return bool(_DOMAIN_RE.match(domain))


def clean_domain(domain: str) -> str:
    """Strip protocol, path, port, and whitespace; lowercase the result."""
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.rstrip(".")
    return domain


def normalize_domain(raw: str) -> Optional[str]:
    """Clean *raw* and return it only if it is a valid domain, else ``None``."""
    cleaned = clean_domain(raw)
    return cleaned if is_valid_domain(cleaned) else None


def extract_root_domain(domain: str) -> str:
    """
    Extract the registrable (root) domain from a FQDN.

    Uses ``tldextract`` for correct public-suffix list handling.
    Examples:
        api.example.com      -> example.com
        api.example.co.uk    -> example.co.uk   (not co.uk)
        sub.api.example.com  -> example.com

    Falls back to naive last-two-parts split only if tldextract returns
    an empty suffix (e.g. for bare IP addresses or localhost).
    """
    cleaned = clean_domain(domain)
    extracted = tldextract.extract(cleaned)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    # Fallback for IPs, localhost, or single-label names
    parts = cleaned.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return cleaned


# ── IP Utilities ─────────────────────────────────────────────────────


def is_valid_ip(address: str) -> bool:
    """Return True if *address* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_private_ip(address: str) -> bool:
    """Return True if *address* is in a private / reserved range."""
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


# ── Deduplication ────────────────────────────────────────────────────


def deduplicate_list(items: List[Any], key: Optional[str] = None) -> List[Any]:
    """
    Remove duplicates while preserving insertion order.

    Parameters
    ----------
    items : list
        Input list (of primitives or dicts).
    key : str, optional
        If items are dicts, deduplicate by this dict key.
    """
    seen: set = set()
    result: List[Any] = []
    for item in items:
        identifier = item.get(key) if key and isinstance(item, dict) else item
        hashable = _make_hashable(identifier)
        if hashable not in seen:
            seen.add(hashable)
            result.append(item)
    return result


def _make_hashable(obj: Any) -> Any:
    """Convert *obj* to a hashable representation for set membership."""
    if isinstance(obj, dict):
        return tuple(sorted(obj.items()))
    if isinstance(obj, (list, tuple)):
        return tuple(obj)
    return obj


# ── UUID Generation ──────────────────────────────────────────────────


def generate_asset_id() -> str:
    """Generate a UUID4 string for asset identification."""
    return str(uuid.uuid4())


def generate_deterministic_id(*parts: str) -> str:
    """
    Generate a deterministic UUID5-style ID from input parts.

    Useful for deduplication: the same asset discovered twice
    produces the same ID.
    """
    raw = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return str(uuid.UUID(digest[:32]))


# ── Miscellaneous ────────────────────────────────────────────────────


def safe_get(data: Dict, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts without raising KeyError."""
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current
