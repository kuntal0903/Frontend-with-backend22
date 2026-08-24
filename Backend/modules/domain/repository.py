"""
Domain Repository — Data Access Layer

WHY THIS FILE EXISTS:
    Isolates all database operations from business logic.
    The service / pipeline never touch SQLAlchemy directly.
    If we migrate from SQL to MongoDB later, only this file changes.

WHAT IT ACCEPTS:
    An ``AsyncSession`` (injected by the caller or FastAPI dependency).

WHAT IT RETURNS:
    ORM model instances or plain dicts — never raw SQL rows.

DESIGN:
    Repository Pattern.  One method per logical operation.
    No business logic — only CRUD + queries.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from modules.domain.models import CollectorRun, DiscoveredAsset, DomainScan


class DomainRepository:
    """Data-access layer for domain scan persistence."""

    def __init__(self, session: AsyncSession):
        self._session = session

    # ── Scan CRUD ────────────────────────────────────────────────────

    async def create_scan(
        self,
        scan_id: str,
        target_domain: str,
        scan_config: Optional[Dict[str, Any]] = None,
    ) -> DomainScan:
        scan = DomainScan(
            id=scan_id,
            target_domain=target_domain,
            status="running",
            scan_config=scan_config or {},
        )
        self._session.add(scan)
        await self._session.flush()
        return scan

    async def get_scan(self, scan_id: str) -> Optional[DomainScan]:
        result = await self._session.execute(
            select(DomainScan).where(DomainScan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        total_assets: int = 0,
        error_message: Optional[str] = None,
    ) -> None:
        values: Dict[str, Any] = {
            "status": status,
            "total_assets_found": total_assets,
        }
        if status in ("completed", "failed", "partial"):
            values["completed_at"] = datetime.now(timezone.utc)
        if error_message:
            values["error_message"] = error_message
        await self._session.execute(
            update(DomainScan).where(DomainScan.id == scan_id).values(**values)
        )
        await self._session.flush()

    # ── Asset CRUD ───────────────────────────────────────────────────

    async def store_assets(
        self, scan_id: str, assets: List[Dict[str, Any]]
    ) -> int:
        """
        Bulk-insert discovered assets. Returns the count stored.

        Each dict in *assets* must contain at minimum:
        id, asset_type, asset_value, discovery_source.
        """
        if not assets:
            return 0
        records = [
            DiscoveredAsset(
                id=a["id"],
                scan_id=scan_id,
                asset_type=a["asset_type"],
                asset_value=a["asset_value"],
                discovery_source=a["discovery_source"],
                sources=a.get("sources", [a["discovery_source"]]),
                evidence=a.get("evidence", []),
                methods=a.get("methods", [a["discovery_source"]]),
                raw_data=a.get("raw_data"),
                confidence_score=a.get("confidence_score", 1.0),
                validation_status=a.get("validation_status", "unvalidated"),
                lifecycle_status=a.get("lifecycle_status", "discovered"),
                first_seen=a.get("first_seen", datetime.now(timezone.utc)),
                last_seen=a.get("last_seen", datetime.now(timezone.utc)),
                last_verified=a.get("last_verified"),
            )
            for a in assets
        ]
        self._session.add_all(records)
        await self._session.flush()
        return len(records)

    async def store_dns_relationships(
        self, scan_id: str, relationships: List[Dict[str, Any]]
    ) -> int:
        """
        Bulk-insert DNS graph relationship edges.
        Each dict in *relationships* must contain:
        source_asset_id, target_asset_id, relationship_type.
        """
        if not relationships:
            return 0
        from modules.domain.models import DnsRelationship
        records = [
            DnsRelationship(
                scan_id=scan_id,
                source_asset_id=r["source_asset_id"],
                target_asset_id=r["target_asset_id"],
                relationship_type=r["relationship_type"],
                ttl=r.get("ttl"),
                metadata_=r.get("metadata"),
            )
            for r in relationships
        ]
        self._session.add_all(records)
        await self._session.flush()
        return len(records)

    async def get_assets_by_scan(
        self,
        scan_id: str,
        asset_type: Optional[str] = None,
    ) -> List[DiscoveredAsset]:
        stmt = select(DiscoveredAsset).where(DiscoveredAsset.scan_id == scan_id)
        if asset_type:
            stmt = stmt.where(DiscoveredAsset.asset_type == asset_type)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    # ── Collector Runs ───────────────────────────────────────────────

    async def store_collector_run(
        self,
        scan_id: str,
        collector_name: str,
        status: str,
        execution_time: float,
        records_found: int,
        errors: Optional[List[str]] = None,
    ) -> CollectorRun:
        run = CollectorRun(
            scan_id=scan_id,
            collector_name=collector_name,
            status=status,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            execution_time=execution_time,
            records_found=records_found,
            errors=errors or [],
        )
        self._session.add(run)
        await self._session.flush()
        return run

    async def get_collector_runs(self, scan_id: str) -> List[CollectorRun]:
        result = await self._session.execute(
            select(CollectorRun).where(CollectorRun.scan_id == scan_id)
        )
        return list(result.scalars().all())

    # ── Commit / Rollback ────────────────────────────────────────────

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()
