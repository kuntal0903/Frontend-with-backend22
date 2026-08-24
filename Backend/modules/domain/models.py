"""
Domain ORM Models

WHY THIS FILE EXISTS:
    Persistent storage for scan runs and every discovered asset.
    The database is the single source of truth for historical data,
    continuous monitoring, and cross-module correlation.

MODELS:
    DomainScan        — One row per scan invocation.
    DiscoveredAsset   — One row per discovered asset (FK → DomainScan).
    CollectorRun      — One row per collector execution (FK → DomainScan).
    DnsRelationship   — Edge in the DNS relationship graph (FK → DiscoveredAsset).

DESIGN DECISIONS:
    • UUID primary keys — enables cross-module referencing and API
      exposure without leaking sequential IDs.
    • ``first_seen`` / ``last_seen`` / ``last_verified`` — supports
      continuous monitoring; re-scans update timestamps without duplicates.
    • ``lifecycle_status`` — DISCOVERED → VERIFIED → ACTIVE | INACTIVE | HISTORICAL.
    • ``sources`` / ``evidence`` / ``methods`` — JSON columns for multi-source
      attribution and structured evidence that can be queried by the API.
    • ``confidence_score`` — float 0.0–1.0 so consumers can filter noise.
    • ``raw_data`` — preserves original collector output for forensic purposes.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.sqlite import JSON  # portable across sqlite / pg
from sqlalchemy.orm import relationship

from common.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class DomainScan(Base):
    """
    Represents a single scan invocation against a target domain.

    Lifecycle: pending → running → completed | failed | partial
    """
    __tablename__ = "domain_scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    target_domain = Column(String(253), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="pending")
    started_at = Column(DateTime(timezone=True), default=_utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    total_assets_found = Column(Integer, default=0)
    scan_config = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    assets = relationship(
        "DiscoveredAsset", back_populates="scan", cascade="all, delete-orphan"
    )
    collector_runs = relationship(
        "CollectorRun", back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<DomainScan id={self.id} domain={self.target_domain} status={self.status}>"


class DiscoveredAsset(Base):
    """
    A single asset discovered during a scan.

    Examples: a subdomain, an IP address, a certificate, an open port.
    Keyed by (scan_id, asset_type, asset_value) to prevent duplicates
    within the same scan.

    New fields (v2.0):
        sources         — all data sources that found this asset
        evidence        — structured observations (JSON list)
        methods         — discovery methods used (JSON list)
        lifecycle_status— DISCOVERED / VERIFIED / ACTIVE / INACTIVE / HISTORICAL
        last_verified   — last time DNS/HTTP confirmed this asset active
    """
    __tablename__ = "discovered_assets"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(
        String(36), ForeignKey("domain_scans.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    asset_type = Column(String(50), nullable=False, index=True)
    asset_value = Column(String(1024), nullable=False)
    discovery_source = Column(String(100), nullable=False)   # primary source
    sources = Column(JSON, nullable=True)                    # List[str] all sources
    evidence = Column(JSON, nullable=True)                   # List[dict] observations
    methods = Column(JSON, nullable=True)                    # List[str] methods
    raw_data = Column(JSON, nullable=True)
    confidence_score = Column(Float, default=1.0)
    validation_status = Column(String(20), default="unvalidated")
    lifecycle_status = Column(String(20), default="discovered", index=True)
    first_seen = Column(DateTime(timezone=True), default=_utcnow)
    last_seen = Column(DateTime(timezone=True), default=_utcnow)
    last_verified = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    scan = relationship("DomainScan", back_populates="assets")
    relationships_as_source = relationship(
        "DnsRelationship",
        foreign_keys="DnsRelationship.source_asset_id",
        back_populates="source_asset",
        cascade="all, delete-orphan",
    )
    relationships_as_target = relationship(
        "DnsRelationship",
        foreign_keys="DnsRelationship.target_asset_id",
        back_populates="target_asset",
    )

    def __repr__(self) -> str:
        return (
            f"<DiscoveredAsset type={self.asset_type} "
            f"value={self.asset_value[:40]}>"
        )


class DnsRelationship(Base):
    """
    An edge in the DNS relationship graph between two discovered assets.

    Examples:
        accounts.google.com  SUBDOMAIN_OF  google.com
        www.example.com      CNAME_TO      lb-1234.example.net
        api.example.com      RESOLVES_TO   1.2.3.4

    WHY THIS EXISTS:
        The old data model stored only a flat list of assets.  CNAME
        relationships detected in cloud.py were never persisted.  This
        model enables graph queries: "what resolves to this IP?",
        "what CNAMEs point at this CDN endpoint?", etc.
    """
    __tablename__ = "dns_relationships"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(
        String(36), ForeignKey("domain_scans.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    source_asset_id = Column(
        String(36), ForeignKey("discovered_assets.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    target_asset_id = Column(
        String(36), ForeignKey("discovered_assets.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    relationship_type = Column(
        String(30), nullable=False, index=True,
        # Allowed values: SUBDOMAIN_OF | CNAME_TO | RESOLVES_TO | MX_FOR | NS_FOR
    )
    ttl = Column(Integer, nullable=True)      # DNS TTL at time of discovery
    discovered_at = Column(DateTime(timezone=True), default=_utcnow)
    metadata_ = Column("metadata", JSON, nullable=True)  # extra context

    # Relationships
    source_asset = relationship(
        "DiscoveredAsset",
        foreign_keys=[source_asset_id],
        back_populates="relationships_as_source",
    )
    target_asset = relationship(
        "DiscoveredAsset",
        foreign_keys=[target_asset_id],
        back_populates="relationships_as_target",
    )

    def __repr__(self) -> str:
        return (
            f"<DnsRelationship {self.source_asset_id[:8]} "
            f"-[{self.relationship_type}]-> {self.target_asset_id[:8]}>"
        )


class CollectorRun(Base):
    """
    Tracks execution metadata for each collector within a scan.
    Used for observability, debugging, and performance analysis.
    """
    __tablename__ = "collector_runs"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(
        String(36), ForeignKey("domain_scans.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    collector_name = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    execution_time = Column(Float, nullable=True)
    records_found = Column(Integer, default=0)
    errors = Column(JSON, nullable=True)

    # Relationship
    scan = relationship("DomainScan", back_populates="collector_runs")

    def __repr__(self) -> str:
        return (
            f"<CollectorRun collector={self.collector_name} "
            f"status={self.status}>"
        )
