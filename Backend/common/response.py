"""
Standardised API Response Wrappers

WHY THIS FILE EXISTS:
    Every API endpoint must return a uniform envelope so consumers
    never need to guess the shape of success / error payloads.

WHAT IT PROVIDES:
    - ``APIResponse`` — Pydantic model with success, message, data,
      scan_id, and execution_time fields.
    - ``success_response`` / ``error_response`` — convenience builders.

HOW ROUTES USE IT:
    return success_response(data=report, scan_id=scan.id, execution_time=4.3)
"""
from typing import Any, Optional

from pydantic import BaseModel, Field


class APIResponse(BaseModel):
    """Envelope for every JSON response returned by the API."""

    success: bool = True
    message: str = "Operation completed successfully"
    data: Optional[Any] = None
    scan_id: Optional[str] = Field(
        default=None, description="UUID of the related scan, if applicable"
    )
    execution_time: Optional[float] = Field(
        default=None, description="Wall-clock seconds the operation took"
    )


def success_response(
    data: Any = None,
    message: str = "Success",
    scan_id: Optional[str] = None,
    execution_time: Optional[float] = None,
) -> APIResponse:
    return APIResponse(
        success=True,
        message=message,
        data=data,
        scan_id=scan_id,
        execution_time=execution_time,
    )


def error_response(
    message: str = "An error occurred",
    data: Any = None,
    scan_id: Optional[str] = None,
) -> APIResponse:
    return APIResponse(
        success=False,
        message=message,
        data=data,
        scan_id=scan_id,
    )
