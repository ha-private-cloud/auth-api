from app.security.passwords import PasswordService


def test_hash_is_argon2id_with_configured_parameters(settings):
    """The stored digest is Argon2id, never the password."""
    digest = PasswordService(settings).hash("a-long-enough-password")
    assert digest.startswith("$argon2id$")
    assert "a-long-enough-password" not in digest


def test_same_password_hashes_differently_each_time(settings):
    """A fresh random salt per hash, so identical passwords do not collide."""
    service = PasswordService(settings)
    assert service.hash("repeated-password") != service.hash("repeated-password")


def test_verify_accepts_correct_and_rejects_wrong(settings):
    service = PasswordService(settings)
    digest = service.hash("the-right-password")
    assert service.verify(digest, "the-right-password")
    assert not service.verify(digest, "the-wrong-password")


def test_verify_returns_false_on_a_corrupt_hash(settings):
    """A mangled column must fail closed rather than raise."""
    assert not PasswordService(settings).verify("not-a-hash", "anything")


def test_pepper_changes_the_digest(settings):
    """A database-only leak is not enough to mount an offline attack."""
    peppered = PasswordService(settings.model_copy(update={"password_pepper": "pepper-one"}))
    other = PasswordService(settings.model_copy(update={"password_pepper": "pepper-two"}))
    assert not other.verify(peppered.hash("shared-password"), "shared-password")


def test_production_defaults_use_a_256_bit_digest_and_salt():
    """256-bit output keeps 128 bits of margin against Grover."""
    from app.config import Settings

    defaults = Settings()
    assert defaults.argon2_hash_length == 32
    assert defaults.argon2_salt_length == 32
    assert defaults.argon2_memory_cost >= 64 * 1024
