from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KAVACH_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///.data/kavach.db"
    jwt_secret: str | None = None
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "testserver"]
    access_token_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_days: int = Field(default=7, ge=1, le=30)
    history_retention_days: int = Field(default=30, ge=1, le=365)
    rate_limit_per_minute: int = Field(default=90, ge=1, le=10000)
    scan_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    max_concurrent_scans: int = Field(default=8, ge=1, le=100)
    max_request_bytes: int = Field(default=131072, ge=4096, le=1048576)
    dnsbl_zones: list[str] = ["zen.spamhaus.org", "bl.spamcop.net"]

    @model_validator(mode="after")
    def validate_production(self):
        if self.jwt_secret is not None and len(self.jwt_secret) < 32:
            raise ValueError("JWT secret must contain at least 32 characters")
        if self.environment == "production":
            if not self.jwt_secret:
                raise ValueError("KAVACH_JWT_SECRET is required in production")
            if "*" in self.cors_origins or "*" in self.allowed_hosts:
                raise ValueError("Production origins and hosts must be explicit")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
