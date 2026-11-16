from pathlib import Path
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.deps import OptionalSessionDep, RedisDep, SessionDep, SettingsDep

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
    if settings.default_redirect_url:
        return settings.default_redirect_url
    page = urlparse(settings.login_page_url)
    return f"{page.scheme}://{page.netloc}/"


def safe_target(next_url: str, settings: SettingsDep) -> str:
    return next_url if _is_safe_redirect(next_url, settings) else _default_redirect(settings)


def login_page_redirect(settings: SettingsDep, next_url: str) -> RedirectResponse:
    return RedirectResponse(
        f"{settings.login_page_url}?{urlencode({'next': next_url})}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/login")
async def login_form(settings: SettingsDep, session: OptionalSessionDep, next: str = "") -> Response:
    target = safe_target(next, settings)
    if session is not None:
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    return login_page_redirect(settings, target)


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
        else settings.login_page_url
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
