import base64
import json
from dataclasses import dataclass
from typing import Any

from pqcrypto.sign import ml_dsa_65

ALGORITHM = "ML-DSA-65"
PUBLIC_KEY_SIZE = ml_dsa_65.PUBLIC_KEY_SIZE
SECRET_KEY_SIZE = ml_dsa_65.SECRET_KEY_SIZE


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class InvalidServiceToken(Exception):
    pass


def generate_keypair() -> tuple[bytes, bytes]:
    public_key, secret_key = ml_dsa_65.keygen()
    return bytes(public_key), bytes(secret_key)


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass(frozen=True)
class ServiceTokenSigner:
    """Separate from the OIDC RS256 signer because the Kubernetes API server only verifies classical JOSE algorithms."""

    key_id: str
    public_key: bytes
    secret_key: bytes

    def sign(self, payload: dict[str, Any]) -> str:
        header = {"alg": ALGORITHM, "typ": "ck-service+pq", "kid": self.key_id}
        signing_input = f"{b64u_encode(_canonical(header))}.{b64u_encode(_canonical(payload))}"
        signature = ml_dsa_65.sign(self.secret_key, signing_input.encode("ascii"))
        return f"ck1.{signing_input}.{b64u_encode(bytes(signature))}"

    def detached_signature(self, payload: dict[str, Any]) -> str:
        return b64u_encode(bytes(ml_dsa_65.sign(self.secret_key, _canonical(payload))))


class ServiceTokenVerifier:
    def __init__(self, public_keys: dict[str, bytes]) -> None:
        self._public_keys = dict(public_keys)

    def verify(self, token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "ck1":
            raise InvalidServiceToken("malformed service token")

        _, header_b64, payload_b64, signature_b64 = parts
        try:
            header = json.loads(b64u_decode(header_b64))
            payload = json.loads(b64u_decode(payload_b64))
            signature = b64u_decode(signature_b64)
        except (ValueError, json.JSONDecodeError) as exc:
            raise InvalidServiceToken("undecodable service token") from exc

        if header.get("alg") != ALGORITHM:
            raise InvalidServiceToken(f"unexpected algorithm {header.get('alg')!r}")

        public_key = self._public_keys.get(header.get("kid", ""))
        if public_key is None:
            raise InvalidServiceToken("unknown key id")

        try:
            ml_dsa_65.verify(public_key, f"{header_b64}.{payload_b64}".encode("ascii"), signature)
        except Exception as exc:
            raise InvalidServiceToken("signature verification failed") from exc

        return payload

    def verify_detached(self, payload: dict[str, Any], signature_b64: str, key_id: str) -> bool:
        public_key = self._public_keys.get(key_id)
        if public_key is None:
            return False
        try:
            ml_dsa_65.verify(public_key, _canonical(payload), b64u_decode(signature_b64))
        except Exception:
            return False
        return True
