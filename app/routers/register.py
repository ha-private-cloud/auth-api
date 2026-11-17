from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field

from app import repository
from app.deps import DbDep, PasswordsDep, RedisDep, SettingsDep, require_registration_token
from app.models import Invite

router = APIRouter(prefix="/api/v1", tags=["register"])


class SelfRegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    email: EmailStr
    invite: str = Field(min_length=1, max_length=128)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def self_register(
    db: DbDep,
    redis: RedisDep,
    passwords: PasswordsDep,
    settings: SettingsDep,
    body: SelfRegisterRequest,
    _: Annotated[None, Depends(require_registration_token)],
) -> Response:
    username = body.username.strip().lower()
    if await repository.get_user_by_username(db, username) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")

    invite_id = await repository.claim_invite(db, body.invite)
    if invite_id is None:
        await db.rollback()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid_invite")
    user = await repository.create_user(db, passwords, username=username, password=body.password, email=body.email)
    invite = await db.get(Invite, invite_id)
    invite.used_by = user.id
    await db.commit()

    token, _ = await redis.create_session(
        user_id=user.id, username=user.username, email=user.email, groups=user.groups
    )

    response = Response(status_code=status.HTTP_201_CREATED)
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=settings.session_absolute_seconds,
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response
