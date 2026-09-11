import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security import pqsign

RSA_KEY_SIZE = 3072


def _rsa_key_id(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pqsign.b64u_encode(hashlib.sha256(der).digest()[:16])


def _pq_key_id(public_key: bytes) -> str:
    return pqsign.b64u_encode(hashlib.sha3_256(public_key).digest()[:16])


@dataclass
class KeyMaterial:
    """rsa_* signs OIDC id_tokens for the Kubernetes API server (RS256/ES256 only); pq_* signs everything ClusterKeep verifies itself."""

    rsa_private: rsa.RSAPrivateKey
    rsa_key_id: str
    pq_public: bytes
    pq_secret: bytes
    pq_key_id: str

    @classmethod
    def generate(cls) -> "KeyMaterial":
        rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        pq_public, pq_secret = pqsign.generate_keypair()
        return cls(
            rsa_private=rsa_private,
            rsa_key_id=_rsa_key_id(rsa_private.public_key()),
            pq_public=pq_public,
            pq_secret=pq_secret,
            pq_key_id=_pq_key_id(pq_public),
        )

    @classmethod
    def load(cls, rsa_private_pem: bytes, pq_public: bytes, pq_secret: bytes) -> "KeyMaterial":
        rsa_private = serialization.load_pem_private_key(rsa_private_pem, password=None)
        if not isinstance(rsa_private, rsa.RSAPrivateKey):
            raise ValueError("auth-api's OIDC signing key must be RSA")
        if len(pq_public) != pqsign.PUBLIC_KEY_SIZE or len(pq_secret) != pqsign.SECRET_KEY_SIZE:
            raise ValueError("ML-DSA-65 key material is the wrong size")
        return cls(
            rsa_private=rsa_private,
            rsa_key_id=_rsa_key_id(rsa_private.public_key()),
            pq_public=pq_public,
            pq_secret=pq_secret,
            pq_key_id=_pq_key_id(pq_public),
        )

    def rsa_private_pem(self) -> bytes:
        return self.rsa_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def signer(self) -> pqsign.ServiceTokenSigner:
        return pqsign.ServiceTokenSigner(self.pq_key_id, self.pq_public, self.pq_secret)

    def verifier(self) -> pqsign.ServiceTokenVerifier:
        return pqsign.ServiceTokenVerifier({self.pq_key_id: self.pq_public})

    def jwks(self) -> dict[str, Any]:
        numbers = self.rsa_private.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.rsa_key_id,
                    "n": pqsign.b64u_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                    "e": pqsign.b64u_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                }
            ]
        }

    def pq_jwks(self) -> dict[str, Any]:
        return {
            "keys": [
                {
                    "kty": "AKP",
                    "use": "sig",
                    "alg": pqsign.ALGORITHM,
                    "kid": self.pq_key_id,
                    "pub": base64.urlsafe_b64encode(self.pq_public).rstrip(b"=").decode("ascii"),
                }
            ]
        }
