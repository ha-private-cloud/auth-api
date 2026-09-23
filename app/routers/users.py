from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from app import repository
from app.deps import DbDep, PasswordsDep, RedisDep, require_admin, require_cluster_group_rights

router = APIRouter(prefix="/api/v1/users", tags=["users"])


class UserOut(BaseModel):
    id: str
    username: str
    email: str | None
    groups: list[str]
    is_active: bool
    must_change_password: bool


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    email: str | None = None
    groups: list[str] = Field(default_factory=list)
    must_change_password: bool = True


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=1024)


class GroupsUpdate(BaseModel):
    groups: list[str]


def _to_out(user) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        groups=user.groups,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
    )


@router.get("", response_model=list[UserOut])
async def list_all(db: DbDep, _: Annotated[dict, Depends(require_admin)]) -> list[UserOut]:
    return [_to_out(u) for u in await repository.list_users(db)]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create(
    db: DbDep,
    passwords: PasswordsDep,
    body: UserCreate,
    claims: Annotated[dict, Depends(require_admin)],
) -> UserOut:
    require_cluster_group_rights(claims, [], body.groups)
    if await repository.get_user_by_username(db, body.username) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    user = await repository.create_user(
        db,
        passwords,
        username=body.username,
        password=body.password,
        email=body.email,
        groups=body.groups,
        must_change_password=body.must_change_password,
    )
    return _to_out(user)


@router.patch("/{user_id}/groups", response_model=UserOut)
async def update_groups(
    db: DbDep,
    user_id: str,
    body: GroupsUpdate,
    claims: Annotated[dict, Depends(require_admin)],
) -> UserOut:
    user = await repository.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    require_cluster_group_rights(claims, user.groups, body.groups)
    await repository.set_groups(db, user, body.groups)
    return _to_out(user)


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    db: DbDep,
    passwords: PasswordsDep,
    redis: RedisDep,
    user_id: str,
    body: PasswordChange,
    _: Annotated[dict, Depends(require_admin)],
) -> None:
    user = await repository.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    if not await run_in_threadpool(passwords.verify, user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")

    await repository.set_password(db, passwords, user, body.new_password)
    # A password change must not leave older sessions alive.
    await redis.delete_user_sessions(user.id)


@router.delete("/{user_id}/sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_sessions(
    db: DbDep, redis: RedisDep, user_id: str, _: Annotated[dict, Depends(require_admin)]
) -> None:
    if await repository.get_user_by_id(db, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    await redis.delete_user_sessions(user_id)
