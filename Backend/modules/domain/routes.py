"""
Domain API Routes

WHY THIS FILE EXISTS:
    Thin HTTP layer — defines endpoint paths, HTTP methods, and
    request/response types.  All logic delegated to the controller.
    No business logic lives here.

ENDPOINTS:
    POST /api/v1/domain/scan          — Start a scan
    GET  /api/v1/domain/scan/{id}     — Get scan status
    GET  /api/v1/domain/scan/{id}/assets — List discovered assets
    GET  /api/v1/domain/scan/{id}/report — Full JSON report (same as POST response)
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from common.database import get_db
from common.exceptions import BaseAppException
from modules.domain.controller import DomainController
from modules.domain.schemas import DomainScanRequest

router = APIRouter(prefix="/domain", tags=["Domain"])
controller = DomainController()


@router.post("/scan")
async def initiate_scan(
    payload: DomainScanRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Start a full domain scan.

    The scan runs synchronously and returns the complete report.
    For very large targets, consider wrapping this in a background task.
    """
    try:
        return await controller.initiate_scan(payload.domain, db)
    except BaseAppException as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/scan/{scan_id}")
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the current status and summary of a scan."""
    try:
        return await controller.get_scan_status(scan_id, db)
    except BaseAppException as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.get("/scan/{scan_id}/assets")
async def get_scan_assets(
    scan_id: str,
    asset_type: Optional[str] = Query(
        default=None,
        description="Filter by asset type (e.g. subdomain, ip_address, open_port)",
    ),
    db: AsyncSession = Depends(get_db),
):
    """List all discovered assets for a scan, optionally filtered by type."""
    try:
        return await controller.get_scan_assets(scan_id, db, asset_type=asset_type)
    except BaseAppException as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.get("/scan/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve the full JSON report for a completed scan.

    Currently returns the same data as the scan status endpoint.
    A dedicated report retrieval from stored data can be added later.
    """
    try:
        return await controller.get_scan_status(scan_id, db)
    except BaseAppException as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
