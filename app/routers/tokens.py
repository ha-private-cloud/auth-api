from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app import repository
from app.cache import digest
from app.models import ServiceCredential
from app.deps import DbDep, SessionDep, SettingsDep, TokensDep, require_service_token

router = APIRouter(prefix="/api/v1", tags=["service-tokens"])


class ServiceTokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    audience: str = Field(min_length=1, max_length=128)
    scopes: list[str] = Field(default_factory=list)


class ServiceTokenResponse(BaseModel):
    token: str
    name: str
    audience: str
    scopes: list[str]
    algorithm: str
    expires_in: int


@router.post("/service-tokens", response_model=ServiceTokenResponse, status_code=status.HTTP_201_CREATED)
async def issue_service_token(
    settings: SettingsDep,
    db: DbDep,
    tokens: TokensDep,
    session: SessionDep,
    body: ServiceTokenRequest,
) -> ServiceTokenResponse:
    """Authenticated via the SSO cookie, not a bearer token, so a leaked service token can't mint further ones."""
    user = await repository.get_user_by_id(db, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user no longer active")

    token = tokens.service_token(
        subject=user.id,
        username=user.username,
        audience=body.audience,
        scopes=body.scopes,
        groups=user.groups,
        session_id=session.session_id,
    )
    await repository.record_service_credential(
        db,
        user=user,
        name=body.name,
        audience=body.audience,
        scopes=body.scopes,
        token_digest=digest(token),
        lifetime_seconds=settings.service_token_seconds,
    )

    return ServiceTokenResponse(
        token=token,
        name=body.name,
        audience=body.audience,
        scopes=body.scopes,
        algorithm="ML-DSA-65",
        expires_in=settings.service_token_seconds,
    )


@router.get("/service-tokens/verify")
async def verify(claims: Annotated[dict, Depends(require_service_token)]) -> dict:
    return {"active": True, "claims": claims}


@router.delete("/service-tokens/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke(db: DbDep, session: SessionDep, credential_id: str) -> None:
    credential = await db.get(ServiceCredential, credential_id)
    if credential is None or credential.user_id != session.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such service token")

    await repository.revoke_service_credential(db, credential)
