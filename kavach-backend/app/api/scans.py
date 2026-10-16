import asyncio
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user, optional_user
from app.config import get_settings
from app.database import get_db
from app.models import Scan, User
from app.schemas import HistoryResponse, MessageRequest, ScanResponse, URLAuditRequest
from app.services import message_analysis, url_audit
from app.services.network import UnsafeTarget, normalize_url

router = APIRouter(tags=["Threat analysis"])
DB = Annotated[Session, Depends(get_db)]
OptionalUser = Annotated[User | None, Depends(optional_user)]
CurrentUser = Annotated[User, Depends(get_current_user)]


def prune_history(db: Session, user_id: str):
    cutoff = datetime.now(UTC) - timedelta(days=get_settings().history_retention_days)
    db.execute(delete(Scan).where(Scan.user_id == user_id, Scan.created_at < cutoff))
    db.commit()


async def run_scan(request: Request, operation):
    semaphore = request.app.state.scan_slots
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=0.1)
    except TimeoutError:
        raise HTTPException(
            503, "All analysis slots are busy; retry shortly", headers={"Retry-After": "5"}
        ) from None
    try:
        async with asyncio.timeout(25):
            return await operation()
    except UnsafeTarget as exc:
        raise HTTPException(422, str(exc)) from None
    except TimeoutError:
        raise HTTPException(504, "Analysis timed out; retry shortly") from None
    finally:
        semaphore.release()


def scan_response(db: Session, user: User | None, save: bool, kind: str, label: str, result: dict):
    created = datetime.now(UTC)
    record = None
    if save and user:
        prune_history(db, user.id)
        record = Scan(user_id=user.id, kind=kind, label=label[:255], result=result, created_at=created)
        db.add(record)
        db.commit()
    return ScanResponse(id=record.id if record else None, kind=kind, created_at=created, result=result)


@router.post("/audits/url", response_model=ScanResponse)
async def audit_link(payload: URLAuditRequest, request: Request, db: DB, user: OptionalUser):
    if payload.save_history and not user:
        raise HTTPException(401, "Sign in to save analysis history", headers={"WWW-Authenticate": "Bearer"})
    try:
        normalized = normalize_url(payload.url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    result = await run_scan(request, lambda: url_audit.audit_url(normalized))
    return scan_response(
        db, user, payload.save_history, "url", urlsplit(normalized).hostname or "URL", result
    )


@router.post("/audits/message", response_model=ScanResponse)
async def dissect_message(payload: MessageRequest, request: Request, db: DB, user: OptionalUser):
    if payload.save_history and not user:
        raise HTTPException(401, "Sign in to save analysis history", headers={"WWW-Authenticate": "Bearer"})
    result = await run_scan(
        request,
        lambda: message_analysis.analyze_message(
            payload.text, payload.channel, payload.raw_headers, payload.inspect_links
        ),
    )
    # History labels contain no message text or sender address.
    return scan_response(
        db, user, payload.save_history, "message", f"{payload.channel.title()} analysis", result
    )


@router.get("/history", response_model=HistoryResponse, tags=["History"])
def history(
    db: DB,
    user: CurrentUser,
    kind: Literal["url", "message"] | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
):
    prune_history(db, user.id)
    conditions = [Scan.user_id == user.id]
    if kind:
        conditions.append(Scan.kind == kind)
    total = db.scalar(select(func.count()).select_from(Scan).where(*conditions))
    records = db.scalars(
        select(Scan).where(*conditions).order_by(Scan.created_at.desc(), Scan.id).offset(offset).limit(limit)
    ).all()
    return {"items": records, "total": total, "limit": limit, "offset": offset}


@router.get("/history/{scan_id}", response_model=ScanResponse, tags=["History"])
def history_item(scan_id: str, db: DB, user: CurrentUser):
    prune_history(db, user.id)
    record = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not record:
        raise HTTPException(404, "Analysis not found")
    return ScanResponse(id=record.id, kind=record.kind, created_at=record.created_at, result=record.result)


@router.delete("/history/{scan_id}", status_code=204, tags=["History"])
def delete_history_item(scan_id: str, db: DB, user: CurrentUser):
    result = db.execute(delete(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(404, "Analysis not found")
    db.commit()
    return Response(status_code=204)


@router.delete("/history", status_code=204, tags=["History"])
def clear_history(db: DB, user: CurrentUser):
    db.execute(delete(Scan).where(Scan.user_id == user.id))
    db.commit()
    return Response(status_code=204)


@router.get("/dashboard", tags=["History"])
def dashboard(db: DB, user: CurrentUser):
    prune_history(db, user.id)
    counts = dict(
        db.execute(select(Scan.kind, func.count()).where(Scan.user_id == user.id).group_by(Scan.kind)).all()
    )
    return {
        "saved_analyses": sum(counts.values()),
        "url_analyses": counts.get("url", 0),
        "message_analyses": counts.get("message", 0),
        "history_retention_days": get_settings().history_retention_days,
    }
