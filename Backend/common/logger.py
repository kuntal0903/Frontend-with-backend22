"""
Structured JSON Logging

WHY THIS FILE EXISTS:
    Enterprise systems feed logs into ELK / Splunk / Datadog.
    Unstructured text is unsearchable at scale.
    Every log line must be machine-parseable JSON with contextual fields.

WHAT IT DOES:
    - Provides a ``get_logger(module, collector)`` factory
    - Injects module / collector / timestamp into every record
    - Outputs JSON to stdout (container-friendly)

HOW OTHER FILES USE IT:
    from common.logger import get_logger
    logger = get_logger("domain", "dns")
    logger.info("Query started", extra={"target": "example.com"})
"""
import logging
import sys
from typing import Optional

from pythonjsonlogger import json as json_log


class _ContextFilter(logging.Filter):
    """Injects ``module_name`` and ``collector_name`` into every record."""

    def __init__(self, module_name: str, collector_name: Optional[str] = None):
        super().__init__()
        self.module_name = module_name
        self.collector_name = collector_name or ""

    def filter(self, record: logging.LogRecord) -> bool:
        record.module_name = self.module_name  # type: ignore[attr-defined]
        record.collector_name = self.collector_name  # type: ignore[attr-defined]
        return True


def get_logger(
    module: str,
    collector: Optional[str] = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """
    Create a structured JSON logger scoped to a module and optional collector.

    Parameters
    ----------
    module : str
        Logical module name (e.g. ``"domain"``, ``"cloud"``).
    collector : str, optional
        Collector name within the module (e.g. ``"dns"``, ``"certificate"``).
    level : int
        Logging level (default ``INFO``).

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """
    name = f"asm.{module}.{collector}" if collector else f"asm.{module}"
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = json_log.JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(module_name)s "
                "%(collector_name)s %(message)s",
            rename_fields={
                "asctime": "timestamp",
                "levelname": "level",
            },
        )
        handler.setFormatter(formatter)
        logger.addFilter(_ContextFilter(module, collector))
        logger.addHandler(handler)
        logger.propagate = False

    return logger
