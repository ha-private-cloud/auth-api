import base64
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import OidcClient, ServiceCredential, SigningKey, User
from app.security.keys import KeyMaterial
from app.security.passwords import PasswordService


async def get_user_by_username(session: AsyncSession, username: str) -> User | None:
    result = await session.execute(select(User).where(User.username == username.lower()))
    return result.scalar_one_or_none()


async def get_user_by_id(session: AsyncSession, user_id: str) -> User | None:
    return await session.get(User, user_id)


async def list_users(session: AsyncSession) -> list[User]:
    result = await session.execute(select(User).order_by(User.username))
    return list(result.scalars())


async def create_user(
    session: AsyncSession,
    passwords: PasswordService,
    *,
    username: str,
    password: str,
    email: str | None = None,
    groups: list[str] | None = None,
    must_change_password: bool = False,
) -> User:
    user = User(
        username=username.lower(),
        email=email,
        password_hash=passwords.hash(password),
        groups=groups or [],
        must_change_password=must_change_password,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def set_groups(session: AsyncSession, user: User, groups: list[str]) -> None:
    user.groups = groups
    await session.commit()


async def set_password(
    session: AsyncSession, passwords: PasswordService, user: User, password: str
) -> None:
    user.password_hash = passwords.hash(password)
    user.must_change_password = False
    await session.commit()


async def require_password_change(session: AsyncSession, user: User) -> None:
    user.must_change_password = True
    await session.commit()


async def get_client(session: AsyncSession, client_id: str) -> OidcClient | None:
    result = await session.execute(select(OidcClient).where(OidcClient.client_id == client_id))
    return result.scalar_one_or_none()


async def upsert_client(
    session: AsyncSession,
    passwords: PasswordService,
    *,
    client_id: str,
    name: str,
    redirect_uris: list[str],
    post_logout_redirect_uris: list[str] | None = None,
    scopes: list[str] | None = None,
    client_secret: str | None = None,
    require_pkce: bool = True,
    is_public: bool = False,
) -> OidcClient:
    client = await get_client(session, client_id)
    if client is None:
        client = OidcClient(client_id=client_id, name=name)
        session.add(client)

    client.name = name
    client.redirect_uris = redirect_uris
    client.post_logout_redirect_uris = post_logout_redirect_uris or []
    client.scopes = scopes or ["openid", "profile", "email", "groups"]
    client.require_pkce = require_pkce
    client.is_public = is_public
    if client_secret is not None:
        client.client_secret_hash = passwords.hash(client_secret)

    await session.commit()
    await session.refresh(client)
    return client


async def load_or_create_keys(session: AsyncSession) -> KeyMaterial:
    """First replica to start wins; the rest read the row it committed."""
    result = await session.execute(select(SigningKey).where(SigningKey.is_active.is_(True)))
    row = result.scalars().first()
    if row is not None:
        return KeyMaterial.load(
            row.rsa_private_pem.encode("utf-8"),
            base64.b64decode(row.pq_public_b64),
            base64.b64decode(row.pq_secret_b64),
        )

    keys = KeyMaterial.generate()
    session.add(
        SigningKey(
            rsa_private_pem=keys.rsa_private_pem().decode("utf-8"),
            pq_public_b64=base64.b64encode(keys.pq_public).decode("ascii"),
            pq_secret_b64=base64.b64encode(keys.pq_secret).decode("ascii"),
        )
    )
    await session.commit()
    return keys


async def record_service_credential(
    session: AsyncSession,
    *,
    user: User,
    name: str,
    audience: str,
    scopes: list[str],
    token_digest: str,
    lifetime_seconds: int,
) -> ServiceCredential:
    credential = ServiceCredential(
        user_id=user.id,
        name=name,
        audience=audience,
        scopes=scopes,
        token_digest=token_digest,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds),
    )
    session.add(credential)
    await session.commit()
    await session.refresh(credential)
    return credential


async def get_service_credential(session: AsyncSession, token_digest: str) -> ServiceCredential | None:
    result = await session.execute(
        select(ServiceCredential).where(ServiceCredential.token_digest == token_digest)
    )
    return result.scalar_one_or_none()


async def revoke_service_credential(session: AsyncSession, credential: ServiceCredential) -> None:
    credential.revoked_at = datetime.now(timezone.utc)
    await session.commit()
