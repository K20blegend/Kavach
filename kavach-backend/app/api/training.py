from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import User
from app.services.training import (
    SCENARIOS,
    TrainingAttempt,
    get_or_create_attempt,
    grade,
    public_scenario,
    scenario_metadata,
    serialize_attempt,
    submit_attempt,
    user_progress,
)

router = APIRouter(prefix="/training", tags=["Training"])


class AttemptCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str = Field(min_length=1, max_length=64)


class AttemptSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selected_indicator_ids: list[str] = Field(max_length=50)


def _find_scenario(scenario_id: str) -> dict:
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Training scenario not found")
    return scenario


def _owned_attempt(db: Session, attempt_id: str, user: User) -> TrainingAttempt:
    attempt = db.scalar(
        select(TrainingAttempt).where(TrainingAttempt.id == attempt_id, TrainingAttempt.user_id == user.id)
    )
    if attempt is None:
        raise HTTPException(status_code=404, detail="Training attempt not found")
    return attempt


@router.get("/scenarios")
def list_scenarios(
    difficulty: Literal["easy", "medium", "hard"] | None = None,
    channel: Literal["browser", "email", "sms", "chat"] | None = None,
):
    scenarios = [
        scenario_metadata(scenario)
        for scenario in SCENARIOS.values()
        if (difficulty is None or scenario["difficulty"] == difficulty)
        and (channel is None or scenario["channel"] == channel)
    ]
    return {"items": scenarios, "total": len(scenarios)}


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    return public_scenario(_find_scenario(scenario_id))


@router.post("/scenarios/{scenario_id}/evaluate")
def evaluate_scenario(scenario_id: str, payload: AttemptSubmission):
    # grade simulator choices directly
    scenario = _find_scenario(scenario_id)
    valid_ids = {element["id"] for element in scenario["elements"]}
    if len(payload.selected_indicator_ids) != len(set(payload.selected_indicator_ids)):
        raise HTTPException(status_code=422, detail="Each indicator may be selected only once")
    if not set(payload.selected_indicator_ids).issubset(valid_ids):
        raise HTTPException(status_code=422, detail="Selection contains an unknown element ID")
    return grade(scenario, payload.selected_indicator_ids)


@router.post("/attempts", status_code=status.HTTP_201_CREATED)
def create_attempt(
    payload: AttemptCreate,
    response: Response,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    attempt, created = get_or_create_attempt(db, user.id, _find_scenario(payload.scenario_id))
    if not created:
        response.status_code = status.HTTP_200_OK
    return serialize_attempt(attempt)


@router.get("/attempts/{attempt_id}")
def get_attempt(attempt_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return serialize_attempt(_owned_attempt(db, attempt_id, user))


@router.post("/attempts/{attempt_id}/submit")
def submit(
    attempt_id: str,
    payload: AttemptSubmission,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    attempt = _owned_attempt(db, attempt_id, user)
    scenario = _find_scenario(attempt.scenario_id)
    valid_ids = {element["id"] for element in scenario["elements"]}
    if len(payload.selected_indicator_ids) != len(set(payload.selected_indicator_ids)):
        raise HTTPException(status_code=422, detail="Each indicator may be selected only once")
    if not set(payload.selected_indicator_ids).issubset(valid_ids):
        raise HTTPException(status_code=422, detail="Selection contains an unknown element ID")
    attempt, accepted = submit_attempt(db, attempt, payload.selected_indicator_ids)
    if not accepted:
        raise HTTPException(
            status_code=409, detail="This attempt has already been submitted and cannot be changed"
        )
    return serialize_attempt(attempt)


@router.get("/progress")
def progress(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return user_progress(db, user.id)
