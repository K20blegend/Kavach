import secrets
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import (
    DUMMY_HASH,
    access_token,
    get_auth_session,
    get_current_user,
    hash_refresh,
    make_session,
    password_hasher,
    unauthorized,
)
from app.config import get_settings
from app.database import get_db
from app.models import AuthSession, User
from app.schemas import (
    LoginRequest,
    PasswordRequest,
    ProfileRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["Accounts"])
DB = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]


def token_response(user, session, refresh):
    return TokenResponse(
        access_token=access_token(session),
        refresh_token=refresh,
        expires_in=get_settings().access_token_minutes * 60,
        user=UserResponse.model_validate(user),
    )


@router.post("/register", response_model=TokenResponse, status_code=201)
def register(payload: RegisterRequest, db: DB):
    user = User(
        email=str(payload.email).lower(),
        display_name=payload.display_name.strip(),
        password_hash=password_hasher.hash(payload.password.get_secret_value()),
    )
    db.add(user)
    try:
        db.flush()
        session, refresh = make_session(db, user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An account with this email already exists") from None
    return token_response(user, session, refresh)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: DB):
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    valid = password_hasher.verify(
        payload.password.get_secret_value(), user.password_hash if user else DUMMY_HASH
    )
    if not user or not valid:
        raise unauthorized()
    session, refresh = make_session(db, user)
    db.commit()
    return token_response(user, session, refresh)


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: DB):
    old_hash = hash_refresh(payload.refresh_token.get_secret_value())
    replacement = secrets.token_urlsafe(48)
    now = datetime.now(UTC)
    # A conditional update makes a refresh token single-use even with concurrent requests.
    result = db.execute(
        update(AuthSession)
        .where(
            AuthSession.refresh_hash == old_hash,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        .values(refresh_hash=hash_refresh(replacement))
    )
    if result.rowcount != 1:
        db.rollback()
        raise unauthorized()
    session = db.scalar(select(AuthSession).where(AuthSession.refresh_hash == hash_refresh(replacement)))
    user = db.get(User, session.user_id)
    if not user or user.auth_version != session.auth_version:
        db.rollback()
        raise unauthorized()
    db.commit()
    return token_response(user, session, replacement)


@router.post("/logout", status_code=204)
def logout(auth: Annotated[tuple[User, AuthSession], Depends(get_auth_session)], db: DB):
    auth[1].revoked_at = datetime.now(UTC)
    db.commit()
    return Response(status_code=204)


@router.get("/me", response_model=UserResponse)
def me(user: CurrentUser):
    return user


@router.patch("/me", response_model=UserResponse)
def profile(payload: ProfileRequest, user: CurrentUser, db: DB):
    user.display_name = payload.display_name.strip()
    db.commit()
    return user


@router.post("/password", status_code=204)
def change_password(payload: PasswordRequest, user: CurrentUser, db: DB):
    if not password_hasher.verify(payload.current_password.get_secret_value(), user.password_hash):
        raise unauthorized()
    db.execute(
        update(User)
        .where(User.id == user.id)
        .values(
            password_hash=password_hasher.hash(payload.new_password.get_secret_value()),
            auth_version=User.auth_version + 1,
        )
    )
    db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    db.commit()
    return Response(status_code=204)
