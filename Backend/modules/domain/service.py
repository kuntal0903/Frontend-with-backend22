"""
Domain Service — Orchestrator

WHY THIS FILE EXISTS:
    Single entry point for domain scan operations.  Coordinates the
    pipeline, database, HTTP sessions, and analyzers.

WHAT IT DOES:
    1. Creates a scan record in the database.
    2. Opens a shared aiohttp session for all collectors.
    3. Runs the 9-step pipeline.
    4. Runs analyzers on the collected data.
    5. Updates the scan record with final status.
    6. Returns the structured report.

DESIGN:
    The service owns the lifecycle of HTTP sessions and database
    transactions.  Collectors and the pipeline receive these as
    injected dependencies — they never create their own.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from common.logger import get_logger
from common.utils import generate_asset_id
from config import settings
from modules.domain.analyzer.admin import AdminAnalyzer
from modules.domain.analyzer.api_discovery import APIDiscoveryAnalyzer
from modules.domain.analyzer.attack_surface import AttackSurfaceAnalyzer
from modules.domain.analyzer.login_portal import LoginPortalAnalyzer
from modules.domain.analyzer.staging import StagingAnalyzer
from modules.domain.pipeline import DomainPipeline
from modules.domain.repository import DomainRepository
from modules.domain.schemas import AssetType, CollectorStatus, ScanStatus

logger = get_logger("domain", "service")


class DomainService:
    """Top-level orchestrator for domain scan operations."""

    def __init__(self):
        self.pipeline = DomainPipeline()

    async def run_scan(
        self,
        domain: str,
        db: AsyncSession,
    ) -> Dict[str, Any]:
        """
        Execute a full domain scan end-to-end.

        Parameters
        ----------
        domain : str
            Target domain (already validated by the schema layer).
        db : AsyncSession
            Database session for persistence.

        Returns
        -------
        dict
            Full structured report (DomainReportSchema).
        """
        scan_id = generate_asset_id()
        started_at = datetime.now(timezone.utc)
        repo = DomainRepository(db)

        logger.info(
            "Scan initiated",
            extra={"scan_id": scan_id, "domain": domain},
        )

        # Create DB record
        await repo.create_scan(
            scan_id=scan_id,
            target_domain=domain,
            scan_config={
                "timeout": settings.SCAN_TIMEOUT_SECONDS,
                "max_collectors": settings.MAX_CONCURRENT_COLLECTORS,
            },
        )

        try:
            # Step 1: Validate
            validated_domain = self.pipeline.validate_target(domain)

            # Steps 2–9 inside shared HTTP session
            timeout = aiohttp.ClientTimeout(total=settings.SCAN_TIMEOUT_SECONDS)
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": settings.USER_AGENT},
            ) as session:

                # Step 2: Collect
                collector_results = await self.pipeline.collect_data(
                    validated_domain, session
                )

                # Step 3: Normalize
                assets = self.pipeline.normalize_data(
                    validated_domain, collector_results
                )

                # Step 4: Deduplicate
                assets = self.pipeline.deduplicate(assets)

                # Step 5: Validate results
                assets = self.pipeline.validate_results(assets)

                # Step 6: Enrich
                assets = self.pipeline.enrich_results(
                    validated_domain, assets, collector_results
                )

                # Step 7: Classify
                assets = self.pipeline.classify_results(assets)

                # ── Run Analyzers ────────────────────────────────────
                # Extract subdomains for analyzer use
                subdomains = [
                    a["asset_value"] for a in assets
                    if a["asset_type"] == AssetType.SUBDOMAIN.value
                ]

                # Attack surface
                attack_surface_analyzer = AttackSurfaceAnalyzer()
                attack_surface = await attack_surface_analyzer.analyze(
                    validated_domain, collector_results
                )

                # Secondary analyzers (run in parallel)
                admin_analyzer = AdminAnalyzer(session=session)
                staging_analyzer = StagingAnalyzer(session=session)
                login_analyzer = LoginPortalAnalyzer(session=session)
                api_analyzer = APIDiscoveryAnalyzer(session=session)

                admin_res, staging_res, login_res, api_res = await self._run_analyzers(
                    validated_domain,
                    subdomains,
                    admin_analyzer,
                    staging_analyzer,
                    login_analyzer,
                    api_analyzer,
                )

                analyzer_results = {
                    "admin_portals": admin_res,
                    "staging_environments": staging_res,
                    "login_portals": login_res,
                    "api_endpoints": api_res,
                }

                # Add analyzer-discovered assets to the asset list
                assets.extend(
                    self._analyzer_assets_to_list(analyzer_results)
                )
                assets = self.pipeline.deduplicate(assets)

                # Step 8: Store
                stored_count = await self.pipeline.store_results(
                    scan_id, assets, collector_results, repo
                )

                # Step 9: Generate report
                report = await self.pipeline.generate_report(
                    scan_id=scan_id,
                    domain=validated_domain,
                    started_at=started_at,
                    assets=assets,
                    collector_results=collector_results,
                    attack_surface=attack_surface,
                    analyzer_results=analyzer_results,
                )

            # Update scan status
            await repo.update_scan_status(
                scan_id,
                status=ScanStatus.COMPLETED.value,
                total_assets=len(assets),
            )
            await repo.commit()

            logger.info(
                "Scan completed",
                extra={
                    "scan_id": scan_id,
                    "domain": domain,
                    "total_assets": len(assets),
                },
            )
            return report

        except Exception as exc:
            logger.error(
                "Scan failed",
                extra={"scan_id": scan_id, "domain": domain, "error": str(exc)},
            )
            await repo.update_scan_status(
                scan_id,
                status=ScanStatus.FAILED.value,
                error_message=str(exc),
            )
            await repo.commit()
            raise

    async def get_scan_status(
        self, scan_id: str, db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """Retrieve scan status and summary."""
        repo = DomainRepository(db)
        scan = await repo.get_scan(scan_id)
        if not scan:
            return None
        return {
            "scan_id": scan.id,
            "target_domain": scan.target_domain,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "total_assets_found": scan.total_assets_found,
            "error_message": scan.error_message,
        }

    async def get_scan_assets(
        self,
        scan_id: str,
        db: AsyncSession,
        asset_type: Optional[str] = None,
    ) -> list:
        """Retrieve discovered assets for a scan."""
        repo = DomainRepository(db)
        assets = await repo.get_assets_by_scan(scan_id, asset_type=asset_type)
        return [
            {
                "id": a.id,
                "asset_type": a.asset_type,
                "asset_value": a.asset_value,
                "discovery_source": a.discovery_source,
                "confidence_score": a.confidence_score,
                "validation_status": a.validation_status,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
            for a in assets
        ]

    # ── Private Helpers ──────────────────────────────────────────────

    @staticmethod
    async def _run_analyzers(
        domain: str,
        subdomains: list,
        admin: AdminAnalyzer,
        staging: StagingAnalyzer,
        login: LoginPortalAnalyzer,
        api: APIDiscoveryAnalyzer,
    ) -> tuple:
        """Run all secondary analyzers concurrently."""
        results = await asyncio.gather(
            admin.analyze(domain, subdomains),
            staging.analyze(domain, subdomains),
            login.analyze(domain, subdomains),
            api.analyze(domain, subdomains),
            return_exceptions=True,
        )
        return tuple(
            r if not isinstance(r, Exception) else {"error": str(r)}
            for r in results
        )

    @staticmethod
    def _analyzer_assets_to_list(
        analyzer_results: Dict[str, Any]
    ) -> list:
        """Convert analyzer findings into asset dicts."""
        from common.utils import generate_asset_id

        assets = []
        now = datetime.now(timezone.utc)

        # Admin portals
        for portal in analyzer_results.get("admin_portals", {}).get("admin_portals", []):
            assets.append({
                "id": generate_asset_id(),
                "asset_type": AssetType.ADMIN_PORTAL.value,
                "asset_value": portal.get("url", ""),
                "discovery_source": "admin_analyzer",
                "sources": ["admin_analyzer"],
                "methods": ["http_probe"],
                "evidence": [{"source": "admin_analyzer", "detail": portal.get("evidence", "")}],
                "raw_data": portal,
                "confidence_score": 0.8,
                "validation_status": "validated",
                "lifecycle_status": "active",
                "first_seen": now,
                "last_seen": now,
                "last_verified": now,
            })

        # Staging environments
        for env in analyzer_results.get("staging_environments", {}).get("staging_environments", []):
            assets.append({
                "id": generate_asset_id(),
                "asset_type": AssetType.STAGING_ENV.value,
                "asset_value": env.get("subdomain", ""),
                "discovery_source": "staging_analyzer",
                "sources": ["staging_analyzer"],
                "methods": ["pattern_match"],
                "evidence": [{"source": "staging_analyzer", "detail": f"Pattern match: {env.get('subdomain', '')}"}],
                "raw_data": env,
                "confidence_score": 0.8,
                "validation_status": "validated",
                "lifecycle_status": "verified",
                "first_seen": now,
                "last_seen": now,
                "last_verified": now,
            })

        # Login portals
        for portal in analyzer_results.get("login_portals", {}).get("login_portals", []):
            ev_list = portal.get("evidence", [])
            assets.append({
                "id": generate_asset_id(),
                "asset_type": AssetType.LOGIN_PORTAL.value,
                "asset_value": portal.get("url", ""),
                "discovery_source": "login_analyzer",
                "sources": ["login_analyzer"],
                "methods": ["html_structure_probe"],
                "evidence": [{"source": "login_analyzer", "detail": str(ev)} for ev in ev_list] if ev_list else [{"source": "login_analyzer", "detail": "Login form detected"}],
                "raw_data": portal,
                "confidence_score": 0.9,
                "validation_status": "validated",
                "lifecycle_status": "active",
                "first_seen": now,
                "last_seen": now,
                "last_verified": now,
            })

        # API endpoints
        for ep in analyzer_results.get("api_endpoints", {}).get("api_endpoints", []):
            ev_list = ep.get("evidence", [])
            assets.append({
                "id": generate_asset_id(),
                "asset_type": AssetType.API_ENDPOINT.value,
                "asset_value": ep.get("url", ""),
                "discovery_source": "api_analyzer",
                "sources": ["api_analyzer"],
                "methods": ["api_header_probe"],
                "evidence": [{"source": "api_analyzer", "detail": str(ev)} for ev in ev_list] if ev_list else [{"source": "api_analyzer", "detail": "API endpoint detected"}],
                "raw_data": ep,
                "confidence_score": 0.8,
                "validation_status": "validated",
                "lifecycle_status": "active",
                "first_seen": now,
                "last_seen": now,
                "last_verified": now,
            })

        return assets

