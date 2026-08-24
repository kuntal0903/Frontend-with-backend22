"""
Domain module — attack surface discovery for target domains.

Components:
    routes      — FastAPI router (POST /scan, GET /scan/{id}, etc.)
    controller  — thin delegation layer
    service     — orchestrator (owns sessions, coordinates pipeline)
    pipeline    — 9-step processing workflow
    repository  — data access layer (Repository pattern)
    schemas     — Pydantic request/response/internal models
    models      — SQLAlchemy ORM models
    collectors/ — independent data collection modules
    analyzer/   — higher-level analysis modules
    output/     — report generation
"""
