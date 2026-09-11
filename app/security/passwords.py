import hashlib
import hmac

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import Settings


class PasswordHashingError(Exception):
    pass


class PasswordService:
    """256-bit digest/salt length is deliberate - keeps 128-bit margin against Grover's algorithm, don't shrink it."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pepper = settings.password_pepper.encode("utf-8")
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost,
            parallelism=settings.argon2_parallelism,
            hash_len=settings.argon2_hash_length,
            salt_len=settings.argon2_salt_length,
            type=Type.ID,
        )

    def _prehash(self, password: str) -> bytes:
        """HMAC-SHA-512 under the pepper, so a database-only leak of hashes isn't enough on its own."""
        if not self._pepper:
            return hashlib.sha512(password.encode("utf-8")).digest()
        return hmac.new(self._pepper, password.encode("utf-8"), hashlib.sha512).digest()

    def hash(self, password: str) -> str:
        if not password:
            raise PasswordHashingError("password must not be empty")
        return self._hasher.hash(self._prehash(password))

    def verify(self, stored_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(stored_hash, self._prehash(password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return True
