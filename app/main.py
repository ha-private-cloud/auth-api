import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import repository
from app.cache import RedisStore, build_client
from app.config import Settings, get_settings
from app.db import build_engine, build_sessionmaker, create_schema
from app.routers import health, login, oidc, register, tokens, users
from app.security.passwords import PasswordService
from app.security.tokens import TokenService

logger = logging.getLogger("auth-api")


async def bootstrap(app: FastAPI, settings: Settings) -> None:
    async with app.state.sessionmaker() as session:
        keys = await repository.load_or_create_keys(session)
        app.state.keys = keys
        app.state.tokens = TokenService(settings, keys)

        headlamp_url = os.environ.get("AUTH_API_HEADLAMP_URL", "")
        headlamp_secret = os.environ.get("AUTH_API_HEADLAMP_CLIENT_SECRET", "")
        if headlamp_url and headlamp_secret:
            await repository.upsert_client(
                session,
                app.state.passwords,
                client_id="headlamp",
                name="Headlamp",
                redirect_uris=[f"{headlamp_url.rstrip('/')}/oidc-callback"],
                post_logout_redirect_uris=[headlamp_url.rstrip("/")],
                scopes=["openid", "profile", "email", "groups", "offline_access"],
                client_secret=headlamp_secret,
                require_pkce=False,
            )

        admin_user = os.environ.get("AUTH_API_BOOTSTRAP_USERNAME", "")
        admin_password = os.environ.get("AUTH_API_BOOTSTRAP_PASSWORD", "")
        if admin_user and admin_password:
            if await repository.get_user_by_username(session, admin_user) is None:
                await repository.create_user(
                    session,
                    app.state.passwords,
                    username=admin_user,
                    password=admin_password,
                    email=os.environ.get("AUTH_API_BOOTSTRAP_EMAIL") or None,
                    groups=["cluster-admins", "admin"],
                    must_change_password=True,
                )
                logger.info("bootstrapped admin user %s", admin_user)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.settings = settings
    app.state.passwords = PasswordService(settings)
    # Used for unknown usernames so login timing doesn't reveal whether the account exists.
    app.state.dummy_password_hash = app.state.passwords.hash("auth-api-nonexistent-user")

    app.state.engine = build_engine(settings)
    app.state.sessionmaker = build_sessionmaker(app.state.engine)
    app.state.redis_client = build_client(settings)
    app.state.redis = RedisStore(settings, app.state.redis_client)

    await create_schema(app.state.engine)
    await bootstrap(app, settings)

    yield

    await app.state.redis_client.aclose()
    await app.state.engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="ClusterKeep auth-api",
        version="0.1.0",
        description=(
            "Identity provider for ClusterKeep. Argon2id credentials in Postgres, "
            "ML-DSA-65 (FIPS 204) service tokens, RS256 OIDC for Headlamp and the "
            "Kubernetes API server."
        ),
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "prd" else None,
        redoc_url=None,
    )

    application.include_router(health.router)
    application.include_router(login.router)
    application.include_router(oidc.router)
    application.include_router(tokens.router)
    application.include_router(users.router)
    application.include_router(register.router)
    return application


app = create_app()
