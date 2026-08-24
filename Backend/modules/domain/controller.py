"""
Domain Controller — Thin Delegation Layer

WHY THIS FILE EXISTS:
    Maps incoming validated requests to service calls and translates
    service results / exceptions into API-friendly responses.
    Contains zero business logic.

WHAT IT ACCEPTS:
    Validated Pydantic request objects and a database session.

WHAT IT RETURNS:
    APIResponse or raises HTTP-friendly exceptions.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from common.exceptions import ResourceNotFoundException, ValidationException
from common.response import error_response, success_response
from modules.domain.service import DomainService


class DomainController:
    """Thin controller — all work delegated to DomainService."""

    def __init__(self):
        self.service = DomainService()

    async def initiate_scan(
        self, domain: str, db: AsyncSession
    ) -> Dict[str, Any]:
        """Start a new domain scan and return the full report."""
        report = await self.service.run_scan(domain, db)
        return success_response(
            data=report,
            message="Domain scan completed successfully",
            scan_id=report.get("scan_id"),
            execution_time=report.get("duration_seconds"),
        ).model_dump()

    async def get_scan_status(
        self, scan_id: str, db: AsyncSession
    ) -> Dict[str, Any]:
        """Retrieve the current status of a scan."""
        result = await self.service.get_scan_status(scan_id, db)
        if result is None:
            raise ResourceNotFoundException(f"Scan '{scan_id}' not found")
        return success_response(data=result).model_dump()

    async def get_scan_assets(
        self,
        scan_id: str,
        db: AsyncSession,
        asset_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve discovered assets for a scan."""
        # Verify scan exists
        scan = await self.service.get_scan_status(scan_id, db)
        if scan is None:
            raise ResourceNotFoundException(f"Scan '{scan_id}' not found")

        assets = await self.service.get_scan_assets(
            scan_id, db, asset_type=asset_type
        )
        return success_response(
            data={"scan_id": scan_id, "assets": assets, "total": len(assets)},
        ).model_dump()
