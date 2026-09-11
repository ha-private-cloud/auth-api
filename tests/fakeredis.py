import time


class FakeRedis:
    """Enough of redis.asyncio for the auth flows, including TTL and GETDEL."""

    def __init__(self) -> None:
        self._values: dict[str, tuple[str, float | None]] = {}
        self._sets: dict[str, set[str]] = {}

    def _expired(self, key: str) -> bool:
        entry = self._values.get(key)
        if entry is None:
            return True
        _, expires_at = entry
        if expires_at is not None and expires_at <= time.time():
            del self._values[key]
            return True
        return False

    async def ping(self) -> bool:
        return True

    async def set(self, key, value, ex=None):
        self._values[key] = (value, time.time() + ex if ex else None)
        return True

    async def get(self, key):
        return None if self._expired(key) else self._values[key][0]

    async def getdel(self, key):
        if self._expired(key):
            return None
        return self._values.pop(key)[0]

    async def delete(self, *keys):
        removed = 0
        for key in keys:
            removed += bool(self._values.pop(key, None)) or bool(self._sets.pop(key, None))
        return removed

    async def expire(self, key, seconds):
        if key in self._values:
            self._values[key] = (self._values[key][0], time.time() + seconds)
            return True
        return key in self._sets

    async def incr(self, key):
        current = int(await self.get(key) or 0) + 1
        expires_at = self._values.get(key, (None, None))[1]
        self._values[key] = (str(current), expires_at)
        return current

    async def sadd(self, key, *members):
        self._sets.setdefault(key, set()).update(members)
        return len(members)

    async def srem(self, key, *members):
        self._sets.get(key, set()).difference_update(members)
        return len(members)

    async def smembers(self, key):
        return set(self._sets.get(key, set()))

    async def aclose(self):
        return None

    def pipeline(self):
        return FakePipeline(self)


class FakePipeline:
    def __init__(self, client: FakeRedis) -> None:
        self._client = client
        self._queued: list[tuple[str, tuple, dict]] = []

    def __getattr__(self, name):
        def queue(*args, **kwargs):
            self._queued.append((name, args, kwargs))
            return self

        return queue

    async def execute(self):
        results = []
        for name, args, kwargs in self._queued:
            results.append(await getattr(self._client, name)(*args, **kwargs))
        self._queued.clear()
        return results
