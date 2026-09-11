from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Form, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import repository
from app.deps import DbDep, OptionalSessionDep, PasswordsDep, RedisDep, SessionDep, SettingsDep

router = APIRouter(tags=["login"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _is_safe_redirect(target: str, settings: SettingsDep) -> bool:
    """Open-redirect guard - an unchecked `next` could hand an attacker a freshly authenticated session."""
    if not target:
        return False
    parsed = urlparse(target)
    if not parsed.scheme and not parsed.netloc:
        return target.startswith("/")
    if parsed.scheme not in ("https", "http"):
        return False

    host = parsed.hostname or ""
    if host in settings.allowed_redirect_hosts_list:
        return True
    cookie_domain = settings.cookie_domain.lstrip(".")
    return host == cookie_domain or host.endswith(f".{cookie_domain}")


def _default_redirect(settings: SettingsDep) -> str:
    return f"{settings.issuer_url}/account"


def _set_session_response(target: str, settings: SettingsDep, token: str) -> Response:
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=settings.session_absolute_seconds,
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_form(
    request: Request, settings: SettingsDep, session: OptionalSessionDep, next: str = ""
) -> Response:
    target = next if _is_safe_redirect(next, settings) else _default_redirect(settings)

    if session is not None:
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request,
        "login.html",
        {"next": target, "environment": settings.environment, "error": None},
    )


@router.post("/login")
async def login_submit(
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
    passwords: PasswordsDep,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "",
) -> Response:
    target = next if _is_safe_redirect(next, settings) else _default_redirect(settings)

    def rejected() -> Response:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"next": target, "environment": settings.environment, "error": "Incorrect username or password."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if await redis.failed_login_count(username) >= settings.max_failed_logins:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next": target,
                "environment": settings.environment,
                "error": "Too many failed attempts. Try again later.",
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    user = await repository.get_user_by_username(db, username)

    # Verify against the dummy hash even when the user is missing, so an unknown username takes the same time.
    if user is None:
        await run_in_threadpool(passwords.verify, request.app.state.dummy_password_hash, password)
        await redis.register_failed_login(username)
        return rejected()

    if not await run_in_threadpool(passwords.verify, user.password_hash, password) or not user.is_active:
        await redis.register_failed_login(username)
        return rejected()

    if passwords.needs_rehash(user.password_hash):
        await repository.set_password(db, passwords, user, password)

    await redis.clear_failed_logins(username)
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    token, _ = await redis.create_session(
        user_id=user.id, username=user.username, email=user.email, groups=user.groups
    )
    return _set_session_response(target, settings, token)


@router.get("/logout")
@router.post("/logout")
async def logout(
    request: Request,
    settings: SettingsDep,
    redis: RedisDep,
    post_logout_redirect_uri: str = "",
) -> Response:
    await redis.delete_session(request.cookies.get(settings.cookie_name, ""))

    target = (
        post_logout_redirect_uri
        if _is_safe_redirect(post_logout_redirect_uri, settings)
        else f"{settings.issuer_url}/login"
    )
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(settings.cookie_name, domain=settings.cookie_domain, path="/")
    return response


@router.get("/session")
async def current_session(session: SessionDep) -> dict:
    return {
        "sub": session.user_id,
        "preferred_username": session.username,
        "email": session.email,
        "groups": session.groups,
        "auth_time": session.auth_time,
    }
