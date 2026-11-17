from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from app import repository
from app.deps import DbDep, SettingsDep, require_admin
from app.models import Invite

router = APIRouter(prefix="/api/v1/invites", tags=["invites"])


class InviteCreate(BaseModel):
    note: str | None = Field(default=None, max_length=255)
    days: int | None = Field(default=None, ge=1, le=30)


def _status(invite: Invite) -> str:
    if invite.used_at is not None:
        return "used"
    if invite.revoked_at is not None:
        return "revoked"
    expires = invite.expires_at if invite.expires_at.tzinfo else invite.expires_at.replace(tzinfo=timezone.utc)
    return "expired" if expires <= datetime.now(timezone.utc) else "open"


@router.post("", status_code=status.HTTP_201_CREATED)
async def create(
    db: DbDep, settings: SettingsDep, body: InviteCreate, claims: Annotated[dict, Depends(require_admin)]
) -> dict:
    note = (body.note or "").strip() or None
    invite, token = await repository.create_invite(
        db, created_by=claims.get("sub"), note=note, lifetime=timedelta(days=body.days or settings.invite_days)
    )
    return {"id": invite.id, "token": token, "note": invite.note, "expires_at": invite.expires_at.isoformat()}


@router.get("")
async def list_all(db: DbDep, _: Annotated[dict, Depends(require_admin)]) -> list[dict]:
    users = {u.id: u.username for u in await repository.list_users(db)}
    return [
        {
            "id": invite.id,
            "note": invite.note,
            "status": _status(invite),
            "created_by": users.get(invite.created_by),
            "used_by": users.get(invite.used_by),
            "created_at": invite.created_at.isoformat(),
            "expires_at": invite.expires_at.isoformat(),
        }
        for invite in await repository.list_invites(db)
    ]


@router.delete("/{invite_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke(db: DbDep, invite_id: str, _: Annotated[dict, Depends(require_admin)]) -> Response:
    invite = await db.get(Invite, invite_id)
    if invite is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such invite")
    if invite.used_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "invite already used")
    if invite.revoked_at is None:
        await repository.revoke_invite(db, invite)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
