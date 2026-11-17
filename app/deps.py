import secrets
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app import repository
from app.cache import RedisStore, SsoSession, digest
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
    db: DbDep,
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    def refuse(detail: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"}
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise refuse("missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = tokens.verify_service_token(token)
    except InvalidServiceToken as exc:
        raise refuse("invalid service token") from exc
    credential = await repository.get_service_credential(db, digest(token))
    if credential is not None and credential.revoked_at is not None:
        raise refuse("service token revoked")
    user = await repository.get_user_by_id(db, str(claims.get("sub", "")))
    if user is None or not user.is_active:
        raise refuse("service token user is not active")
    return claims


ADMIN_GROUPS = ("cluster-admins", "admin")
CLUSTER_ADMIN_GROUP = "cluster-admins"
CLUSTER_GROUP_PREFIX = "cluster-"


async def require_admin(claims: Annotated[dict, Depends(require_service_token)]) -> dict:
    if not any(g in claims.get("groups", []) for g in ADMIN_GROUPS):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="requires an admin group")
    return claims


async def require_registration_token(
    settings: SettingsDep,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Gates self-registration to services holding this shared secret (e.g. clusterkeep-ui's invite-code page), not end users directly."""
    presented = (authorization or "").removeprefix("Bearer ").strip()
    if not settings.registration_token or not secrets.compare_digest(presented, settings.registration_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid registration token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_cluster_group_rights(claims: dict, before: list[str], after: list[str]) -> None:
    """cluster-* groups map to Kubernetes ClusterRoles, so only cluster admins may change them."""
    changed = {g for g in set(before) ^ set(after) if g.startswith(CLUSTER_GROUP_PREFIX)}
    if changed and CLUSTER_ADMIN_GROUP not in claims.get("groups", []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only cluster-admins may change cluster-* groups")
