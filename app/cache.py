import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any

import redis.asyncio as aioredis

from app.config import Settings

TOKEN_BYTES = 32


def new_opaque_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest(value: str) -> str:
    """Stored in place of the token itself, so Redis access cannot replay one."""
    return hashlib.sha3_512(value.encode("utf-8")).hexdigest()


@dataclass
class SsoSession:
    session_id: str
    user_id: str
    username: str
    email: str | None
    groups: list[str]
    auth_time: int
    absolute_expires_at: int


class RedisUnavailable(Exception):
    pass


class RedisStore:
    """Redis is authoritative here, not a cache - losing it logs everyone out but destroys no accounts."""

    def __init__(self, settings: Settings, client: aioredis.Redis) -> None:
        self._settings = settings
        self._client = client
        self._ns = settings.redis_namespace

    def _key(self, kind: str, token: str) -> str:
        return f"{self._ns}:{kind}:{digest(token)}"

    def _user_sessions_key(self, user_id: str) -> str:
        return f"{self._ns}:user-sessions:{user_id}"

    async def ping(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception as exc:
            raise RedisUnavailable(str(exc)) from exc

    async def create_session(
        self, *, user_id: str, username: str, email: str | None, groups: list[str]
    ) -> tuple[str, SsoSession]:
        now = int(time.time())
        token = new_opaque_token()
        session = SsoSession(
            session_id=secrets.token_hex(16),
            user_id=user_id,
            username=username,
            email=email,
            groups=groups,
            auth_time=now,
            absolute_expires_at=now + self._settings.session_absolute_seconds,
        )
        key = self._key("session", token)
        pipe = self._client.pipeline()
        pipe.set(key, json.dumps(asdict(session)), ex=self._settings.session_idle_seconds)
        pipe.sadd(self._user_sessions_key(user_id), key)
        pipe.expire(self._user_sessions_key(user_id), self._settings.session_absolute_seconds)
        await pipe.execute()
        return token, session

    async def get_session(self, token: str) -> SsoSession | None:
        if not token:
            return None
        key = self._key("session", token)
        raw = await self._client.get(key)
        if raw is None:
            return None
        session = SsoSession(**json.loads(raw))
        if session.absolute_expires_at <= int(time.time()):
            await self.delete_session(token)
            return None
        await self._client.expire(key, self._settings.session_idle_seconds)
        return session

    async def delete_session(self, token: str) -> None:
        key = self._key("session", token)
        raw = await self._client.get(key)
        pipe = self._client.pipeline()
        pipe.delete(key)
        if raw is not None:
            pipe.srem(self._user_sessions_key(json.loads(raw)["user_id"]), key)
        await pipe.execute()

    async def delete_user_sessions(self, user_id: str) -> int:
        index = self._user_sessions_key(user_id)
        keys = await self._client.smembers(index)
        if not keys:
            return 0
        pipe = self._client.pipeline()
        pipe.delete(*keys)
        pipe.delete(index)
        await pipe.execute()
        return len(keys)

    async def store_authorization_code(self, payload: dict[str, Any]) -> str:
        code = new_opaque_token()
        await self._client.set(
            self._key("code", code),
            json.dumps(payload),
            ex=self._settings.authorization_code_seconds,
        )
        return code

    async def consume_authorization_code(self, code: str) -> dict[str, Any] | None:
        """GETDEL, so a replayed code cannot be redeemed twice even under a race."""
        raw = await self._client.getdel(self._key("code", code))
        return None if raw is None else json.loads(raw)

    async def store_refresh_token(self, payload: dict[str, Any]) -> str:
        token = new_opaque_token()
        await self._client.set(
            self._key("refresh", token),
            json.dumps(payload),
            ex=self._settings.refresh_token_seconds,
        )
        return token

    async def rotate_refresh_token(self, token: str) -> dict[str, Any] | None:
        raw = await self._client.getdel(self._key("refresh", token))
        return None if raw is None else json.loads(raw)

    async def register_failed_login(self, username: str) -> int:
        key = f"{self._ns}:failed:{digest(username.lower())}"
        pipe = self._client.pipeline()
        pipe.incr(key)
        pipe.expire(key, self._settings.lockout_seconds)
        count, _ = await pipe.execute()
        return int(count)

    async def failed_login_count(self, username: str) -> int:
        raw = await self._client.get(f"{self._ns}:failed:{digest(username.lower())}")
        return int(raw) if raw else 0

    async def clear_failed_logins(self, username: str) -> None:
        await self._client.delete(f"{self._ns}:failed:{digest(username.lower())}")


def build_client(settings: Settings) -> aioredis.Redis:
    return aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        health_check_interval=30,
    )
