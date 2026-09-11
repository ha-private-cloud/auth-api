import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization

from app.config import Settings
from app.security.keys import KeyMaterial
from app.security.pqsign import InvalidServiceToken


class TokenService:
    def __init__(self, settings: Settings, keys: KeyMaterial) -> None:
        self._settings = settings
        self._keys = keys
        self._signer = keys.signer()
        self._verifier = keys.verifier()
        self._rsa_private_pem = keys.rsa_private_pem()
        self._rsa_public_pem = keys.rsa_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def issuer(self) -> str:
        return self._settings.issuer_url

    def _base_claims(self, subject: str, audience: str, lifetime: int) -> dict[str, Any]:
        now = int(time.time())
        return {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "jti": uuid.uuid4().hex,
        }

    def id_token(
        self,
        *,
        subject: str,
        username: str,
        client_id: str,
        nonce: str | None,
        auth_time: int,
        email: str | None,
        groups: list[str],
    ) -> str:
        """RS256 for the API server; `ck_pq` carries a detached ML-DSA-65 co-signature for ClusterKeep's own verifiers."""
        claims = self._base_claims(subject, client_id, self._settings.id_token_seconds)
        claims.update(
            {
                "preferred_username": username,
                "auth_time": auth_time,
                "groups": groups,
            }
        )
        if email:
            claims["email"] = email
            claims["email_verified"] = True
        if nonce:
            claims["nonce"] = nonce

        claims["ck_pq_kid"] = self._keys.pq_key_id
        claims["ck_pq"] = self._signer.detached_signature(claims)

        return jwt.encode(
            claims,
            self._rsa_private_pem,
            algorithm="RS256",
            headers={"kid": self._keys.rsa_key_id},
        )

    def verify_id_token(self, token: str, audience: str) -> dict[str, Any]:
        return jwt.decode(
            token, self._rsa_public_pem, algorithms=["RS256"], audience=audience, issuer=self.issuer
        )

    def id_token_pq_is_valid(self, claims: dict[str, Any]) -> bool:
        signature = claims.get("ck_pq")
        key_id = claims.get("ck_pq_kid")
        if not signature or not key_id:
            return False
        signed_claims = {k: v for k, v in claims.items() if k != "ck_pq"}
        return self._verifier.verify_detached(signed_claims, signature, key_id)

    def service_token(
        self,
        *,
        subject: str,
        username: str,
        audience: str,
        scopes: list[str],
        groups: list[str],
        session_id: str | None = None,
    ) -> str:
        """ML-DSA-65 throughout. Nothing outside ClusterKeep verifies these."""
        claims = self._base_claims(subject, audience, self._settings.service_token_seconds)
        claims.update(
            {
                "preferred_username": username,
                "scope": " ".join(scopes),
                "groups": groups,
                "token_use": "service",
            }
        )
        if session_id:
            claims["sid"] = session_id
        return self._signer.sign(claims)

    def verify_service_token(self, token: str, audience: str | None = None) -> dict[str, Any]:
        claims = self._verifier.verify(token)
        now = int(time.time())
        if claims.get("iss") != self.issuer:
            raise InvalidServiceToken("service token issued by a different issuer")
        if int(claims.get("exp", 0)) <= now:
            raise InvalidServiceToken("service token has expired")
        if int(claims.get("nbf", 0)) > now:
            raise InvalidServiceToken("service token is not yet valid")
        if audience is not None and claims.get("aud") != audience:
            raise InvalidServiceToken("service token audience mismatch")
        return claims
