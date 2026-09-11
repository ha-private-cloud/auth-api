import pytest
from httpx import ASGITransport, AsyncClient

from app import repository
from app.cache import RedisStore
from app.config import Settings, get_settings
from app.db import build_engine, build_sessionmaker, create_schema
from app.main import create_app
from app.security.passwords import PasswordService
from app.security.tokens import TokenService
from tests.fakeredis import FakeRedis

ADMIN_PASSWORD = "correct-horse-battery-staple"


async def login(client):
    await client.post("/login", data={"username": "alice", "password": ADMIN_PASSWORD})


@pytest.fixture
def settings() -> Settings:
    return Settings(
        environment="test",
        issuer_url="https://auth-test.clusterkeep.dev.net",
        database_url="sqlite+aiosqlite:///:memory:",
        cookie_domain=".clusterkeep.dev.net",
        cookie_secure=False,
        password_pepper="test-pepper-value-not-a-real-secret",
        registration_token="test-registration-token",
        # Argon2 at production cost would dominate the suite's runtime.
        argon2_time_cost=1,
        argon2_memory_cost=8,
        argon2_parallelism=1,
    )


@pytest.fixture
async def app(settings, monkeypatch):
    monkeypatch.setattr("app.main.get_settings", lambda: settings)
    monkeypatch.setattr("app.deps.get_settings", lambda: settings)

    application = create_app()
    application.dependency_overrides[get_settings] = lambda: settings

    engine = build_engine(settings)
    application.state.settings = settings
    application.state.passwords = PasswordService(settings)
    application.state.dummy_password_hash = application.state.passwords.hash("nobody")
    application.state.engine = engine
    application.state.sessionmaker = build_sessionmaker(engine)
    application.state.redis_client = FakeRedis()
    application.state.redis = RedisStore(settings, application.state.redis_client)

    await create_schema(engine)
    async with application.state.sessionmaker() as session:
        keys = await repository.load_or_create_keys(session)
        application.state.keys = keys
        application.state.tokens = TokenService(settings, keys)

    yield application

    await engine.dispose()
    get_settings.cache_clear()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="https://auth-test.clusterkeep.dev.net"
    ) as http_client:
        yield http_client


@pytest.fixture
async def admin_user(app):
    async with app.state.sessionmaker() as session:
        return await repository.create_user(
            session,
            app.state.passwords,
            username="alice",
            password=ADMIN_PASSWORD,
            email="alice@clusterkeep.dev.net",
            groups=["cluster-admins"],
        )


@pytest.fixture
async def headlamp_client(app):
    async with app.state.sessionmaker() as session:
        return await repository.upsert_client(
            session,
            app.state.passwords,
            client_id="headlamp",
            name="Headlamp",
            redirect_uris=["https://headlamp.clusterkeep.dev.net/oidc-callback"],
            post_logout_redirect_uris=["https://headlamp.clusterkeep.dev.net"],
            scopes=["openid", "profile", "email", "groups", "offline_access"],
            client_secret="headlamp-test-secret",
            require_pkce=False,
        )
