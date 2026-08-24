"""
Abstract Base Collector

WHY THIS FILE EXISTS:
    Every collector in the domain module must produce identical output
    (``CollectorResult``) and handle errors identically.  Without a
    shared contract, collectors drift — each returning different shapes,
    handling errors differently, and logging inconsistently.

    This abstract base class enforces:
        1. A uniform ``execute()`` lifecycle (timing, logging, error catch).
        2. A single ``collect()`` method that subclasses implement.
        3. Automatic wrapping of raw output into ``CollectorResult``.

WHAT SUBCLASSES DO:
    Override ``collector_name``, ``source_name``, and ``collect(target)``.
    Everything else (timing, error handling, logging) is inherited.

HOW THE ORCHESTRATOR USES IT:
    result: CollectorResult = await some_collector.execute("example.com")
"""
from __future__ import annotations

import asyncio
import time
import traceback
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import aiohttp

from common.exceptions import (
    CollectorConnectionError,
    CollectorDNSError,
    CollectorHTTPError,
    CollectorRateLimitError,
    CollectorSSLError,
    CollectorTimeoutError,
)
from common.logger import get_logger
from config import settings
from modules.domain.schemas import CollectorResult, CollectorStatus


class BaseCollector(ABC):
    """
    Abstract base class for all domain collectors.

    Subclass contract
    -----------------
    1. Set ``collector_name`` (e.g. ``"dns"``) and ``source_name``
       (e.g. ``"dnspython"``).
    2. Implement ``async collect(target, **kwargs) -> dict`` with the
       actual collection logic.  Return a dict with ``raw_data`` and
       ``processed_data`` keys.
    3. (Optional) Override ``get_confidence()`` to customise the
       confidence score calculation.
    """

    collector_name: str = "base"
    source_name: str = "unknown"

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        timeout: Optional[int] = None,
    ):
        self._session = session
        self._timeout = timeout or settings.COLLECTOR_TIMEOUT_SECONDS
        self.logger = get_logger("domain", self.collector_name)

    # ── Public Entry Point ───────────────────────────────────────────

    async def execute(self, target: str, **kwargs: Any) -> CollectorResult:
        """
        Run the collector with full lifecycle management.

        1. Log start
        2. Start timer
        3. Call ``collect()`` inside a timeout guard
        4. Wrap result into ``CollectorResult``
        5. Catch and classify any exception
        6. Log finish
        """
        self.logger.info(
            "Collector started",
            extra={"target": target},
        )
        start = time.perf_counter()
        try:
            raw = await asyncio.wait_for(
                self.collect(target, **kwargs),
                timeout=self._timeout,
            )
            elapsed = time.perf_counter() - start
            result = CollectorResult(
                status=CollectorStatus.SUCCESS,
                collector_name=self.collector_name,
                execution_time=round(elapsed, 3),
                source=self.source_name,
                raw_data=raw.get("raw_data", {}),
                processed_data=raw.get("processed_data", {}),
                errors=[],
                confidence=self.get_confidence(raw),
            )
            self.logger.info(
                "Collector finished",
                extra={
                    "target": target,
                    "elapsed": result.execution_time,
                    # Prefer an explicit total field; fall back to summing all
                    # list values in processed_data. len(processed_data) would
                    # only count top-level keys (3-4), not actual records.
                    "records": (
                        result.processed_data.get("total_records")
                        or result.processed_data.get("total_unique")
                        or result.processed_data.get("total_open")
                        or sum(
                            len(v) for v in result.processed_data.values()
                            if isinstance(v, list)
                        )
                    ),
                },
            )
            return result

        except asyncio.TimeoutError:
            return self._fail(target, start, "Timed out", CollectorStatus.TIMEOUT)

        except CollectorTimeoutError:
            return self._fail(target, start, "Timed out", CollectorStatus.TIMEOUT)

        except CollectorDNSError as exc:
            return self._fail(target, start, str(exc))

        except CollectorSSLError as exc:
            return self._fail(target, start, str(exc))

        except CollectorConnectionError as exc:
            return self._fail(target, start, str(exc))

        except CollectorHTTPError as exc:
            return self._fail(target, start, str(exc))

        except CollectorRateLimitError as exc:
            return self._fail(target, start, str(exc))

        except aiohttp.ClientError as exc:
            return self._fail(target, start, f"HTTP client error: {exc}")

        except OSError as exc:
            return self._fail(target, start, f"OS/network error: {exc}")

        except Exception as exc:  # noqa: BLE001 — catch-all safety net
            tb = traceback.format_exc()
            self.logger.error(
                "Collector unexpected error",
                extra={"target": target, "traceback": tb},
            )
            return self._fail(target, start, f"Unexpected: {exc}")

    # ── Subclass Contract ────────────────────────────────────────────

    @abstractmethod
    async def collect(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Perform the actual data collection.

        Must return a dict with keys:
            ``raw_data``       — the unprocessed upstream response
            ``processed_data`` — cleaned / structured data
        """
        ...

    def get_confidence(self, raw: Dict[str, Any]) -> float:
        """
        Calculate a confidence score for the collected data.

        Override in subclasses for domain-specific heuristics.
        Default is 1.0 (fully confident).
        """
        return 1.0

    # ── HTTP Session Helper ──────────────────────────────────────────

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return the shared session or create one."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": settings.USER_AGENT},
            )
        return self._session

    # ── Internal Helpers ─────────────────────────────────────────────

    def _fail(
        self,
        target: str,
        start: float,
        error_msg: str,
        status: CollectorStatus = CollectorStatus.FAILED,
    ) -> CollectorResult:
        elapsed = round(time.perf_counter() - start, 3)
        self.logger.warning(
            "Collector failed",
            extra={"target": target, "error": error_msg, "elapsed": elapsed},
        )
        return CollectorResult(
            status=status,
            collector_name=self.collector_name,
            execution_time=elapsed,
            source=self.source_name,
            raw_data={},
            processed_data={},
            errors=[error_msg],
            confidence=0.0,
        )
