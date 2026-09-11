import asyncio
import base64
import hashlib
import secrets
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse

from app import repository
from app.cache import digest
from app.deps import DbDep, OptionalSessionDep, PasswordsDep, RedisDep, SettingsDep, TokensDep, require_service_token

router = APIRouter(tags=["oidc"])

SUPPORTED_SCOPES = ["openid", "profile", "email", "groups", "offline_access"]


def _pkce_matches(verifier: str, challenge: str, method: str) -> bool:
    if method == "S256":
        computed = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        return secrets.compare_digest(computed, challenge)
    if method == "plain":
        return secrets.compare_digest(verifier, challenge)
    return False


@router.get("/.well-known/openid-configuration")
async def discovery(settings: SettingsDep) -> JSONResponse:
    issuer = settings.issuer_url
    return JSONResponse(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "jwks_uri": f"{issuer}/jwks.json",
            "end_session_endpoint": f"{issuer}/logout",
            "scopes_supported": SUPPORTED_SCOPES,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "claims_supported": [
                "iss", "sub", "aud", "exp", "iat", "nonce", "auth_time",
                "preferred_username", "email", "email_verified", "groups",
                "ck_pq", "ck_pq_kid",
            ],
        }
    )


@router.get("/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    return JSONResponse(request.app.state.keys.jwks())


@router.get("/pq/jwks.json")
async def pq_jwks(request: Request) -> JSONResponse:
    return JSONResponse(request.app.state.keys.pq_jwks())


@router.get("/authorize")
async def authorize(
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
    session: OptionalSessionDep,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "openid",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str = "S256",
    prompt: str | None = None,
) -> Response:
    if response_type != "code":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "only response_type=code is supported")

    client = await repository.get_client(db, client_id)
    if client is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown client_id")
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "redirect_uri is not registered for this client")
    if client.require_pkce and not code_challenge:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "code_challenge is required for this client")

    if session is None or prompt == "login":
        login_url = f"{settings.issuer_url}/login?" + urlencode(
            {"next": str(request.url)}
        )
        return RedirectResponse(login_url, status_code=status.HTTP_303_SEE_OTHER)

    code = await redis.store_authorization_code(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "user_id": session.user_id,
            "username": session.username,
            "email": session.email,
            "groups": session.groups,
            "auth_time": session.auth_time,
            "sid": session.session_id,
        }
    )

    params = {"code": code}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(params)}", status_code=status.HTTP_303_SEE_OTHER)


def _client_credentials(
    request: Request, client_id: str | None, client_secret: str | None
) -> tuple[str | None, str | None]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
            basic_id, _, basic_secret = decoded.partition(":")
            return basic_id, basic_secret
        except Exception:
            return client_id, client_secret
    return client_id, client_secret


@router.post("/token")
async def token(
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
    tokens: TokensDep,
    passwords: PasswordsDep,
    grant_type: Annotated[str, Form()],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
) -> JSONResponse:
    client_id, client_secret = _client_credentials(request, client_id, client_secret)
    if not client_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "client_id is required")

    client = await repository.get_client(db, client_id)
    if client is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown client")
    if client.client_secret_hash and not await run_in_threadpool(
        passwords.verify, client.client_secret_hash, client_secret or ""
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid client credentials")

    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "code is required")
        grant = await redis.consume_authorization_code(code)
        if grant is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "authorization code is invalid or already used")
        if grant["client_id"] != client_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "authorization code was issued to another client")
        if redirect_uri and grant["redirect_uri"] != redirect_uri:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "redirect_uri mismatch")
        if grant.get("code_challenge"):
            if not code_verifier or not _pkce_matches(
                code_verifier, grant["code_challenge"], grant.get("code_challenge_method", "S256")
            ):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "PKCE verification failed")
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "refresh_token is required")
        grant = await redis.rotate_refresh_token(refresh_token)
        if grant is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "refresh token is invalid or already used")
        if grant["client_id"] != client_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "refresh token was issued to another client")
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unsupported grant_type {grant_type!r}")

    id_token, access_token = await asyncio.gather(
        run_in_threadpool(
            tokens.id_token,
            subject=grant["user_id"],
            username=grant["username"],
            client_id=client_id,
            nonce=grant.get("nonce"),
            auth_time=grant["auth_time"],
            email=grant.get("email"),
            groups=grant.get("groups", []),
        ),
        run_in_threadpool(
            tokens.service_token,
            subject=grant["user_id"],
            username=grant["username"],
            audience=client_id,
            scopes=grant.get("scope", "openid").split(),
            groups=grant.get("groups", []),
            session_id=grant.get("sid"),
        ),
    )

    body = {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": settings.access_token_seconds,
        "scope": grant.get("scope", "openid"),
    }

    if "offline_access" in grant.get("scope", "").split() or grant_type == "refresh_token":
        body["refresh_token"] = await redis.store_refresh_token(grant)

    return JSONResponse(body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.get("/userinfo")
async def userinfo(db: DbDep, claims: Annotated[dict, Depends(require_service_token)]) -> JSONResponse:
    user = await repository.get_user_by_id(db, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user no longer active")

    body = {"sub": user.id, "preferred_username": user.username, "groups": user.groups}
    if user.email:
        body |= {"email": user.email, "email_verified": True}
    return JSONResponse(body)


@router.post("/introspect")
async def introspect(
    db: DbDep, tokens: TokensDep, token: Annotated[str, Form()]
) -> JSONResponse:
    try:
        claims = tokens.verify_service_token(token)
    except Exception:
        return JSONResponse({"active": False})

    credential = await repository.get_service_credential(db, digest(token))
    if credential is not None and credential.revoked_at is not None:
        return JSONResponse({"active": False})

    return JSONResponse(
        {
            "active": True,
            "sub": claims["sub"],
            "username": claims.get("preferred_username"),
            "aud": claims.get("aud"),
            "scope": claims.get("scope", ""),
            "groups": claims.get("groups", []),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "iss": claims.get("iss"),
            "alg": "ML-DSA-65",
        }
    )
