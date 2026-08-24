"""
Verification module — validates assets discovered by the Discovery Module.

Components:
    routes      — FastAPI router (POST /verify, etc.)
    controller  — thin delegation layer
    service     — orchestrator (owns sessions, coordinates pipeline)
    pipeline    — orchestrates the verification steps sequentially
    repository  — data access layer
    schemas     — Pydantic request/response/internal models
    models      — SQLAlchemy ORM models for verification results
    verifiers/  — independent validation checks
"""
