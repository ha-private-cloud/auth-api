import pytest

from app.security import pqsign
from app.security.keys import KeyMaterial
from app.security.pqsign import InvalidServiceToken, ServiceTokenSigner, ServiceTokenVerifier


@pytest.fixture(scope="module")
def keypair():
    return pqsign.generate_keypair()


def test_ml_dsa_65_key_sizes_match_fips_204(keypair):
    public_key, secret_key = keypair
    assert len(public_key) == 1952
    assert len(secret_key) == 4032


def test_signed_token_round_trips(keypair):
    public_key, secret_key = keypair
    signer = ServiceTokenSigner("kid-1", public_key, secret_key)
    verifier = ServiceTokenVerifier({"kid-1": public_key})

    token = signer.sign({"sub": "alice", "aud": "storage-ui"})
    assert token.startswith("ck1.")
    assert verifier.verify(token) == {"sub": "alice", "aud": "storage-ui"}


def test_tampered_payload_is_rejected(keypair):
    public_key, secret_key = keypair
    signer = ServiceTokenSigner("kid-1", public_key, secret_key)
    verifier = ServiceTokenVerifier({"kid-1": public_key})

    prefix, header, _, signature = signer.sign({"sub": "alice"}).split(".")
    forged = pqsign.b64u_encode(b'{"sub":"mallory"}')
    with pytest.raises(InvalidServiceToken):
        verifier.verify(f"{prefix}.{header}.{forged}.{signature}")


def test_token_from_another_key_is_rejected(keypair):
    public_key, secret_key = keypair
    other_public, _ = pqsign.generate_keypair()
    token = ServiceTokenSigner("kid-1", public_key, secret_key).sign({"sub": "alice"})

    with pytest.raises(InvalidServiceToken):
        ServiceTokenVerifier({"kid-1": other_public}).verify(token)


def test_unknown_key_id_is_rejected(keypair):
    public_key, secret_key = keypair
    token = ServiceTokenSigner("kid-1", public_key, secret_key).sign({"sub": "alice"})

    with pytest.raises(InvalidServiceToken, match="unknown key id"):
        ServiceTokenVerifier({"kid-2": public_key}).verify(token)


def test_algorithm_confusion_is_rejected(keypair):
    """A header claiming a weaker algorithm must not bypass ML-DSA verification."""
    public_key, secret_key = keypair
    signer = ServiceTokenSigner("kid-1", public_key, secret_key)
    _, _, payload, signature = signer.sign({"sub": "alice"}).split(".")

    forged_header = pqsign.b64u_encode(b'{"alg":"none","typ":"ck-service+pq","kid":"kid-1"}')
    with pytest.raises(InvalidServiceToken, match="unexpected algorithm"):
        ServiceTokenVerifier({"kid-1": public_key}).verify(f"ck1.{forged_header}.{payload}.{signature}")


def test_key_material_survives_a_reload():
    """Restarts and extra replicas must keep the same key ids."""
    keys = KeyMaterial.generate()
    reloaded = KeyMaterial.load(keys.rsa_private_pem(), keys.pq_public, keys.pq_secret)
    assert (reloaded.rsa_key_id, reloaded.pq_key_id) == (keys.rsa_key_id, keys.pq_key_id)


def test_pq_jwks_advertises_ml_dsa_65():
    assert KeyMaterial.generate().pq_jwks()["keys"][0]["alg"] == "ML-DSA-65"
