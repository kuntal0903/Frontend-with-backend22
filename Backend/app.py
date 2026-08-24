"""
Application Entry Point

WHY THIS FILE EXISTS:
    Creates the FastAPI application, registers routers, configures
    middleware, and manages startup/shutdown lifecycle events.

LIFECYCLE:
    Startup  → init database, create tables
    Shutdown → dispose database connections

MIDDLEWARE:
    - CORS (configurable origins)
    - Global exception handler for BaseAppException
    - Request ID injection (optional future)
"""
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from common.database import close_db, init_db
from common.exceptions import BaseAppException
from common.logger import get_logger
from config import settings

logger = get_logger("app")


# ── Lifecycle ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Async context manager for startup/shutdown hooks."""
    logger.info("Starting application", extra={"version": settings.VERSION})
    await init_db()
    logger.info("Database initialised")
    yield
    logger.info("Shutting down application")
    await close_db()
    logger.info("Database connections closed")


# ── App Factory ──────────────────────────────────────────────────────

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Attack Surface Management Platform — Domain Module",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    lifespan=lifespan,
)


# ── CORS ─────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global Exception Handler ────────────────────────────────────────

@app.exception_handler(BaseAppException)
async def app_exception_handler(request: Request, exc: BaseAppException):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )


# ── Routes ───────────────────────────────────────────────────────────

from modules.domain.routes import router as domain_router  # noqa: E402

app.include_router(domain_router, prefix=settings.API_V1_PREFIX)
app.include_router(domain_router, prefix="/v1")
app.include_router(domain_router, prefix="")


# ── Health Check ─────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "version": settings.VERSION,
        "module": "domain",
    }


# ── Entry Point ──────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
