"""
Custom Exception Hierarchy

WHY THIS FILE EXISTS:
    Every collector can fail in distinct, predictable ways.
    Typed exceptions let the orchestrator decide how to react
    (retry? skip? abort?) without string-matching error messages.

HIERARCHY:
    BaseAppException
    ├── ResourceNotFoundException
    ├── ValidationException
    └── CollectorException
        ├── CollectorTimeoutError
        ├── CollectorConnectionError
        ├── CollectorDNSError
        ├── CollectorSSLError
        ├── CollectorHTTPError
        ├── CollectorRateLimitError
        └── CollectorValidationError

DESIGN:
    Every exception carries structured context (collector, target,
    timestamp) so error logs are always actionable.
"""
from datetime import datetime, timezone
from typing import Optional


class BaseAppException(Exception):
    """Root exception for all application errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        *,
        details: Optional[dict] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()
        super().__init__(self.message)

    def to_dict(self) -> dict:
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class ResourceNotFoundException(BaseAppException):
    def __init__(self, message: str = "Resource not found", **kwargs):
        super().__init__(message=message, status_code=404, **kwargs)


class ValidationException(BaseAppException):
    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(message=message, status_code=422, **kwargs)


# ── Collector-specific exceptions ────────────────────────────────────


class CollectorException(BaseAppException):
    """Base for all collector failures."""

    def __init__(
        self,
        message: str = "Collector operation failed",
        *,
        collector: str = "unknown",
        target: str = "unknown",
        **kwargs,
    ):
        super().__init__(
            message=message,
            status_code=500,
            details={"collector": collector, "target": target},
            **kwargs,
        )
        self.collector = collector
        self.target = target


class CollectorTimeoutError(CollectorException):
    """Raised when a collector exceeds its time budget."""

    def __init__(self, **kwargs):
        super().__init__(message="Collector timed out", **kwargs)


class CollectorConnectionError(CollectorException):
    """Raised when a TCP / HTTP connection cannot be established."""

    def __init__(self, **kwargs):
        super().__init__(message="Connection failed", **kwargs)


class CollectorDNSError(CollectorException):
    """Raised when DNS resolution fails."""

    def __init__(self, **kwargs):
        super().__init__(message="DNS resolution failed", **kwargs)


class CollectorSSLError(CollectorException):
    """Raised when TLS handshake or certificate retrieval fails."""

    def __init__(self, **kwargs):
        super().__init__(message="SSL/TLS error", **kwargs)


class CollectorHTTPError(CollectorException):
    """Raised on unexpected HTTP status codes."""

    def __init__(self, status: int = 0, **kwargs):
        super().__init__(message=f"HTTP error (status={status})", **kwargs)
        self.http_status = status


class CollectorRateLimitError(CollectorException):
    """Raised when an upstream API returns 429 / rate-limit response."""

    def __init__(self, retry_after: Optional[int] = None, **kwargs):
        super().__init__(message="Rate limited by upstream", **kwargs)
        self.retry_after = retry_after


class CollectorValidationError(CollectorException):
    """Raised when collector output fails schema validation."""

    def __init__(self, **kwargs):
        super().__init__(message="Collector output validation failed", **kwargs)
