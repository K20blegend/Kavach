from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr


class RegisterRequest(BaseModel):
    email: EmailStr = Field(max_length=254)
    display_name: str = Field(min_length=1, max_length=80, pattern=r"\S")
    password: SecretStr = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr = Field(max_length=254)
    password: SecretStr = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: SecretStr = Field(min_length=32, max_length=256)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    display_name: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class ProfileRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=80, pattern=r"\S")


class PasswordRequest(BaseModel):
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=10, max_length=128)


class URLAuditRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    save_history: bool = False


class MessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=50000, pattern=r"\S")
    channel: Literal["email", "sms", "social"] = "email"
    raw_headers: str | None = Field(default=None, max_length=30000)
    inspect_links: bool = False
    save_history: bool = False


class ScanResponse(BaseModel):
    id: str | None
    kind: str
    created_at: datetime
    result: dict


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    kind: str
    label: str
    created_at: datetime


class HistoryResponse(BaseModel):
    items: list[ScanSummary]
    total: int
    limit: int
    offset: int
