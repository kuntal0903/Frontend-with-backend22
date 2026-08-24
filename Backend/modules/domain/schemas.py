"""
Domain Pydantic Schemas (Request / Response / Internal)

WHY THIS FILE EXISTS:
    Strict boundary between external API payloads and internal data.
    Every piece of data entering or leaving the domain module is
    validated through one of these schemas.

WHAT IT PROVIDES:
    Request  — DomainScanRequest
    Response — DomainScanResponse, DomainScanStatusResponse
    Internal — CollectorResult, DiscoveredAssetSchema, DomainReportSchema

DESIGN:
    Pydantic v2 models with Field validators for input cleaning.
    CollectorResult is the universal output contract that every
    collector must produce.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from common.utils import clean_domain, is_valid_domain


# ── Enums ────────────────────────────────────────────────────────────


class AssetType(str, enum.Enum):
    """All possible asset types that can be discovered."""
    ROOT_DOMAIN = "root_domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    DNS_RECORD = "dns_record"
    NAMESERVER = "nameserver"
    MAIL_SERVER = "mail_server"
    CERTIFICATE = "certificate"
    OPEN_PORT = "open_port"
    SERVICE = "service"
    HTTP_HEADER = "http_header"
    TECHNOLOGY = "technology"
    CLOUD_PROVIDER = "cloud_provider"
    CDN_PROVIDER = "cdn_provider"
    WAF = "waf"
    ADMIN_PORTAL = "admin_portal"
    LOGIN_PORTAL = "login_portal"
    STAGING_ENV = "staging_env"
    API_ENDPOINT = "api_endpoint"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class CollectorStatus(str, enum.Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class ValidationStatus(str, enum.Enum):
    VALIDATED = "validated"
    UNVALIDATED = "unvalidated"
    INVALID = "invalid"


class LifecycleStatus(str, enum.Enum):
    """
    Lifecycle state of a discovered asset.

    Progression:
        DISCOVERED  — found by a passive source, not yet DNS-validated
        VERIFIED    — passed DNS resolution check
        ACTIVE      — DNS resolves AND HTTP responds
        INACTIVE    — was active, but DNS or HTTP no longer responds
        HISTORICAL  — found in CT logs / archives but NXDOMAIN today
    """
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    ACTIVE = "active"
    INACTIVE = "inactive"
    HISTORICAL = "historical"


# ── Request ──────────────────────────────────────────────────────────


class DomainScanRequest(BaseModel):
    """Input payload to start a domain scan."""
    domain: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description="Target domain to scan (e.g. example.com)",
        json_schema_extra={"examples": ["example.com"]},
    )

    @field_validator("domain", mode="before")
    @classmethod
    def _clean_and_validate(cls, v: str) -> str:
        cleaned = clean_domain(v)
        if not is_valid_domain(cleaned):
            raise ValueError(
                f"'{v}' is not a valid domain name after normalisation."
            )
        return cleaned


# ── Collector Result ─────────────────────────────────────────────────


class CollectorResult(BaseModel):
    """
    Universal output contract for every collector.

    Every collector — regardless of what it discovers — returns this
    exact shape.  The orchestrator can treat all results uniformly.
    """
    status: CollectorStatus = CollectorStatus.SUCCESS
    collector_name: str
    execution_time: float = Field(
        default=0.0, description="Seconds the collector took"
    )
    source: str = Field(
        default="", description="Data source identifier (e.g. 'dnspython', 'crt.sh')"
    )
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    processed_data: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Confidence score 0.0–1.0",
    )


# ── Discovered Asset ─────────────────────────────────────────────────


class DiscoveredAssetSchema(BaseModel):
    """
    Schema for a single discovered asset (used in reports and API).

    Fields
    ------
    sources
        All data sources that found this asset (e.g. ``["crt.sh", "dns_bruteforce"]``).
        Multiple independent sources increase confidence.
    evidence
        Structured observations that justify this asset's existence.
        Each entry is a free-form dict with at minimum ``source`` and ``detail``.
    last_verified
        UTC timestamp of the most recent successful DNS or HTTP verification.
        None if never verified beyond passive discovery.
    lifecycle_status
        Current known state of this asset.  Starts as DISCOVERED.
        Advances to ACTIVE once DNS and HTTP are confirmed.
    methods
        Discovery methods used, e.g. ``["passive_crtsh", "dns_bruteforce"]``.
    """
    id: str
    asset_type: AssetType
    asset_value: str
    discovery_source: str                    # primary source (kept for backward compat)
    sources: List[str] = Field(
        default_factory=list,
        description="All sources that found this asset",
    )
    methods: List[str] = Field(
        default_factory=list,
        description="Discovery methods used (passive_crtsh, dns_bruteforce, etc.)",
    )
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Structured evidence observations for this asset",
    )
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    confidence_score: float = 1.0
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED
    lifecycle_status: LifecycleStatus = LifecycleStatus.DISCOVERED
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified: Optional[datetime] = Field(
        default=None,
        description="Last time DNS/HTTP confirmed this asset was active",
    )


# ── Responses ────────────────────────────────────────────────────────


class DomainScanResponse(BaseModel):
    """Returned immediately when a scan is initiated."""
    success: bool = True
    message: str = "Scan initiated"
    scan_id: str
    target_domain: str
    status: ScanStatus = ScanStatus.PENDING


class DomainScanStatusResponse(BaseModel):
    """Returned when polling scan status."""
    scan_id: str
    target_domain: str
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_assets_found: int = 0
    collector_results: Dict[str, CollectorResult] = Field(default_factory=dict)


# ── Report ───────────────────────────────────────────────────────────


class DomainReportSchema(BaseModel):
    """Full machine-readable scan report."""
    scan_id: str
    target_domain: str
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    total_assets_found: int = 0

    # Per-collector summaries
    collector_results: Dict[str, CollectorResult] = Field(default_factory=dict)

    # Asset inventory grouped by type
    assets: Dict[str, List[DiscoveredAssetSchema]] = Field(default_factory=dict)

    # Attack surface summary
    attack_surface: Dict[str, Any] = Field(default_factory=dict)

    # Metadata
    scan_config: Dict[str, Any] = Field(default_factory=dict)
