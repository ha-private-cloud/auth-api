from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app import repository
from app.deps import DbDep, PasswordsDep, RedisDep, SettingsDep, require_registration_token
from app.routers.login import safe_target

router = APIRouter(
    prefix="/api/v1/sessions",
    tags=["sessions"],
    dependencies=[Depends(require_registration_token)],
)

MIN_PASSWORD_LENGTH = 12


class SignInRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)
    next: str = Field(default="", max_length=4096)


class PasswordChangeRequest(BaseModel):
    change_token: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


class RevokeRequest(BaseModel):
    session_token: str = Field(min_length=1, max_length=256)


def _cookie(settings: SettingsDep) -> dict:
    return {
        "name": settings.cookie_name,
        "domain": settings.cookie_domain,
        "max_age": settings.session_absolute_seconds,
        "secure": settings.cookie_secure,
    }


async def _issue_session(redis: RedisDep, db: DbDep, user, target: str, settings: SettingsDep) -> JSONResponse:
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    token, _ = await redis.create_session(
        user_id=user.id, username=user.username, email=user.email, groups=user.groups
    )
    return JSONResponse(
        {"session_token": token, "redirect_to": target, "cookie": _cookie(settings)},
        status_code=status.HTTP_201_CREATED,
    )


def _error(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status_code)


@router.post("")
async def sign_in(
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
    passwords: PasswordsDep,
    body: SignInRequest,
) -> JSONResponse:
    target = safe_target(body.next, settings)
    identifier = body.username.strip().lower()
    user = await repository.get_user_for_sign_in(db, identifier)
    lockout_key = user.id if user is not None else identifier

    if await redis.failed_login_count(lockout_key) >= settings.max_failed_logins:
        return _error(status.HTTP_429_TOO_MANY_REQUESTS, "locked")

    # Verify against the dummy hash even when the user is missing, so an unknown username takes the same time.
    if user is None:
        await run_in_threadpool(passwords.verify, request.app.state.dummy_password_hash, body.password)
        await redis.register_failed_login(lockout_key)
        return _error(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

    if not await run_in_threadpool(passwords.verify, user.password_hash, body.password) or not user.is_active:
        await redis.register_failed_login(lockout_key)
        return _error(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

    if passwords.needs_rehash(user.password_hash):
        await repository.set_password(db, passwords, user, body.password)

    await redis.clear_failed_logins(lockout_key)

    if user.must_change_password:
        change_token = await redis.store_password_change(user_id=user.id, next_url=target)
        return JSONResponse(
            {"detail": "password_change_required", "change_token": change_token},
            status_code=status.HTTP_409_CONFLICT,
        )

    return await _issue_session(redis, db, user, target, settings)


@router.post("/password-change")
async def change_password(
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
    passwords: PasswordsDep,
    body: PasswordChangeRequest,
) -> JSONResponse:
    pending = await redis.get_password_change(body.change_token)
    user = None if pending is None else await repository.get_user_by_id(db, pending["user_id"])
    if user is None or not user.is_active:
        return _error(status.HTTP_410_GONE, "expired")

    if len(body.password) < MIN_PASSWORD_LENGTH:
        return _error(status.HTTP_400_BAD_REQUEST, "too_short")
    if await run_in_threadpool(passwords.verify, user.password_hash, body.password):
        return _error(status.HTTP_400_BAD_REQUEST, "unchanged")

    await repository.set_password(db, passwords, user, body.password)
    await redis.delete_password_change(body.change_token)
    await redis.delete_user_sessions(user.id)

    return await _issue_session(redis, db, user, safe_target(pending["next"], settings), settings)


@router.post("/revoke")
async def revoke(settings: SettingsDep, redis: RedisDep, body: RevokeRequest) -> dict:
    await redis.delete_session(body.session_token)
    return {"cookie": _cookie(settings)}
