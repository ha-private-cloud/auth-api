from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import RedisStore, SsoSession
from app.config import Settings, get_settings
from app.security.passwords import PasswordService
from app.security.pqsign import InvalidServiceToken
from app.security.tokens import TokenService


async def get_db(request: Request) -> AsyncSession:
    async with request.app.state.sessionmaker() as session:
        yield session


def get_redis(request: Request) -> RedisStore:
    return request.app.state.redis


def get_tokens(request: Request) -> TokenService:
    return request.app.state.tokens


def get_passwords(request: Request) -> PasswordService:
    return request.app.state.passwords


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[AsyncSession, Depends(get_db)]
RedisDep = Annotated[RedisStore, Depends(get_redis)]
TokensDep = Annotated[TokenService, Depends(get_tokens)]
PasswordsDep = Annotated[PasswordService, Depends(get_passwords)]


async def get_current_session(request: Request, settings: SettingsDep, redis: RedisDep) -> SsoSession | None:
    return await redis.get_session(request.cookies.get(settings.cookie_name, ""))


async def require_session(session: Annotated[SsoSession | None, Depends(get_current_session)]) -> SsoSession:
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no active session")
    return session


OptionalSessionDep = Annotated[SsoSession | None, Depends(get_current_session)]
SessionDep = Annotated[SsoSession, Depends(require_session)]


async def require_service_token(
    tokens: TokensDep,
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return tokens.verify_service_token(authorization.split(" ", 1)[1].strip())
    except InvalidServiceToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid service token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def require_admin(claims: Annotated[dict, Depends(require_service_token)]) -> dict:
    if "cluster-admins" not in claims.get("groups", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="requires cluster-admins")
    return claims
