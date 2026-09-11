from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_API_", env_file=".env", extra="ignore")

    environment: str = "dev"
    issuer_url: str = "https://auth-dev.clusterkeep.dev.net"
    database_url: str = "postgresql+asyncpg://auth_api:auth_api@postgres:5432/auth_api"
    redis_url: str = "redis://redis:6379/0"
    redis_namespace: str = "authapi"

    cookie_name: str = "ck_sso"
    cookie_domain: str = ".clusterkeep.dev.net"
    cookie_secure: bool = True

    session_idle_seconds: int = 60 * 60 * 8
    session_absolute_seconds: int = 60 * 60 * 24 * 7

    authorization_code_seconds: int = 60
    access_token_seconds: int = 60 * 60
    id_token_seconds: int = 60 * 60
    refresh_token_seconds: int = 60 * 60 * 24 * 30
    service_token_seconds: int = 60 * 60 * 12

    argon2_time_cost: int = 3
    argon2_memory_cost: int = 64 * 1024
    argon2_parallelism: int = 4
    argon2_hash_length: int = 32
    argon2_salt_length: int = 32

    password_pepper: str = ""

    signing_key_secret_name: str = "auth-api-signing-keys"

    max_failed_logins: int = 10
    lockout_seconds: int = 15 * 60

    allowed_redirect_hosts: list[str] = Field(default_factory=list)

    @field_validator("issuer_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("allowed_redirect_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, v: object) -> object:
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
