import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import delete, text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import models
from app.api import auth, scans, training
from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.middleware import RequestGuard

logger = logging.getLogger("kavach")


@asynccontextmanager
async def lifespan(application: FastAPI):
    settings = get_settings()
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        now = datetime.now(UTC)
        db.execute(
            delete(models.Scan).where(
                models.Scan.created_at < now - timedelta(days=settings.history_retention_days)
            )
        )
        db.execute(delete(models.AuthSession).where(models.AuthSession.expires_at < now))
        db.commit()
    application.state.scan_slots = asyncio.Semaphore(settings.max_concurrent_scans)
    yield
    engine.dispose()


app = FastAPI(
    title="Kavach API",
    version="1.0.0",
    description="Transparent website risk checks, scam message analysis, and interactive security training.",
    lifespan=lifespan,
)
settings = get_settings()
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(RequestGuard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Request-ID", "Retry-After"],
)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(training.router, prefix="/api/v1")


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        {
            "error": {
                "code": f"http_{exc.status_code}",
                "message": exc.detail,
                "request_id": getattr(request.state, "request_id", None),
            }
        },
        status_code=exc.status_code,
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    details = [
        {
            "field": ".".join(str(part) for part in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        {
            "error": {
                "code": "validation_error",
                "message": "Check the submitted fields",
                "details": details,
                "request_id": getattr(request.state, "request_id", None),
            }
        },
        status_code=422,
    )


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)
    logger.error("Unhandled %s, request_id=%s", type(exc).__name__, request_id)
    return JSONResponse(
        {
            "error": {
                "code": "internal_error",
                "message": "The request could not be completed",
                "request_id": request_id,
            }
        },
        status_code=500,
    )


@app.get("/", include_in_schema=False)
def index():
    return {"name": "Kavach", "version": "1.0.0", "docs": "/docs", "health": "/health"}


@app.get("/health", tags=["Operations"])
def health():
    return {"status": "ok", "service": "kavach", "version": "1.0.0"}


@app.get("/health/ready", tags=["Operations"])
def readiness():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(503, "Database unavailable") from None
    return {"status": "ready", "database": "connected"}
