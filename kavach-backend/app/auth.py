import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import AuthSession, User

password_hasher = PasswordHash.recommended()
DUMMY_HASH = password_hasher.hash("timing-equalization-placeholder")
bearer = HTTPBearer(auto_error=False)


@lru_cache
def signing_key() -> str:
    settings = get_settings()
    if settings.jwt_secret:
        return settings.jwt_secret
    key_path = Path(".data/jwt.key")
    key_path.parent.mkdir(exist_ok=True)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return key_path.read_text(encoding="utf-8").strip()
    with os.fdopen(fd, "w", encoding="utf-8") as key_file:
        key_file.write(secrets.token_urlsafe(48))
    return key_path.read_text(encoding="utf-8").strip()


def hash_refresh(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def unauthorized() -> HTTPException:
    return HTTPException(401, "Invalid or expired credentials", headers={"WWW-Authenticate": "Bearer"})


def access_token(session: AuthSession) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": session.user_id,
            "sid": session.id,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=get_settings().access_token_minutes),
            "iss": "kavach",
            "aud": "kavach-api",
            "type": "access",
        },
        signing_key(),
        algorithm="HS256",
    )


def make_session(db: Session, user: User) -> tuple[AuthSession, str]:
    token = secrets.token_urlsafe(48)
    session = AuthSession(
        user_id=user.id,
        refresh_hash=hash_refresh(token),
        auth_version=user.auth_version,
        expires_at=datetime.now(UTC) + timedelta(days=get_settings().refresh_token_days),
    )
    db.add(session)
    db.flush()
    return session, token


def authenticate(credentials: HTTPAuthorizationCredentials, db: Session) -> tuple[User, AuthSession]:
    try:
        claims = jwt.decode(
            credentials.credentials,
            signing_key(),
            algorithms=["HS256"],
            audience="kavach-api",
            issuer="kavach",
            options={"require": ["exp", "iat", "nbf", "sub", "sid", "type"]},
        )
        if claims["type"] != "access":
            raise unauthorized()
        session = db.get(AuthSession, claims["sid"])
        if (
            not session
            or session.user_id != claims["sub"]
            or session.revoked_at
            or aware(session.expires_at) <= datetime.now(UTC)
        ):
            raise unauthorized()
        user = db.get(User, session.user_id)
        if not user or session.auth_version != user.auth_version:
            raise unauthorized()
        return user, session
    except jwt.InvalidTokenError:
        raise unauthorized() from None


def get_auth_session(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> tuple[User, AuthSession]:
    if credentials is None:
        raise unauthorized()
    return authenticate(credentials, db)


def get_current_user(auth: Annotated[tuple[User, AuthSession], Depends(get_auth_session)]) -> User:
    return auth[0]


def optional_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User | None:
    return authenticate(credentials, db)[0] if credentials else None
