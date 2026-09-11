from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from app import repository
from app.deps import DbDep, PasswordsDep, RedisDep, SettingsDep, require_registration_token

router = APIRouter(prefix="/api/v1", tags=["register"])


class SelfRegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=12, max_length=1024)


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

    user = await repository.create_user(db, passwords, username=username, password=body.password)
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
