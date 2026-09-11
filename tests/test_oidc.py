import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import jwt

from tests.conftest import login


async def _authorize(client, **overrides):
    params = {
        "client_id": "headlamp",
        "redirect_uri": "https://headlamp.clusterkeep.dev.net/oidc-callback",
        "response_type": "code",
        "scope": "openid profile email groups",
        "state": "state-123",
        "nonce": "nonce-456",
    }
    params.update(overrides)
    return await client.get("/authorize", params=params, follow_redirects=False)


async def test_discovery_matches_the_issuer(client, settings):
    body = (await client.get("/.well-known/openid-configuration")).json()
    assert body["issuer"] == settings.issuer_url
    assert body["authorization_endpoint"] == f"{settings.issuer_url}/authorize"
    assert body["id_token_signing_alg_values_supported"] == ["RS256"]


async def test_jwks_publishes_an_rsa_signing_key(client):
    key = (await client.get("/jwks.json")).json()["keys"][0]
    assert (key["kty"], key["alg"], key["use"]) == ("RSA", "RS256", "sig")
    assert key["kid"]


async def test_pq_jwks_publishes_the_ml_dsa_key(client):
    key = (await client.get("/pq/jwks.json")).json()["keys"][0]
    assert key["alg"] == "ML-DSA-65"
    assert len(base64.urlsafe_b64decode(key["pub"] + "==")) == 1952


async def test_authorize_without_a_session_redirects_to_login(client, headlamp_client):
    response = await _authorize(client)
    assert response.status_code == 303
    assert "/login?next=" in response.headers["location"]


async def test_authorize_with_a_live_session_issues_a_code_without_reprompting(
    client, admin_user, headlamp_client
):
    """This is what makes the clusterkeep-ui button land in Headlamp logged in."""
    await login(client)
    response = await _authorize(client)

    assert response.status_code == 303
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["state"] == ["state-123"]
    assert query["code"]


async def test_authorize_rejects_an_unregistered_redirect_uri(client, admin_user, headlamp_client):
    await login(client)
    response = await _authorize(client, redirect_uri="https://evil.example.com/callback")
    assert response.status_code == 400


async def test_authorize_rejects_an_unknown_client(client, admin_user, headlamp_client):
    await login(client)
    response = await _authorize(client, client_id="not-a-client")
    assert response.status_code == 400


async def test_full_authorization_code_flow_yields_a_verifiable_id_token(
    client, admin_user, headlamp_client, app, settings
):
    await login(client)
    code = parse_qs(urlparse((await _authorize(client)).headers["location"]).query)["code"][0]

    response = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://headlamp.clusterkeep.dev.net/oidc-callback",
            "client_id": "headlamp",
            "client_secret": "headlamp-test-secret",
        },
    )
    assert response.status_code == 200
    body = response.json()

    # RS256, because the Kubernetes API server verifies this token itself.
    assert jwt.get_unverified_header(body["id_token"])["alg"] == "RS256"

    claims = app.state.tokens.verify_id_token(body["id_token"], "headlamp")
    assert claims["preferred_username"] == "alice"
    assert claims["nonce"] == "nonce-456"
    assert claims["groups"] == ["cluster-admins"]
    assert claims["iss"] == settings.issuer_url


async def test_id_token_carries_a_valid_ml_dsa_co_signature(client, admin_user, headlamp_client, app):
    """The hybrid claim: classical for the apiserver, ML-DSA for ClusterKeep."""
    await login(client)
    code = parse_qs(urlparse((await _authorize(client)).headers["location"]).query)["code"][0]
    body = (
        await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://headlamp.clusterkeep.dev.net/oidc-callback",
                "client_id": "headlamp",
                "client_secret": "headlamp-test-secret",
            },
        )
    ).json()

    claims = app.state.tokens.verify_id_token(body["id_token"], "headlamp")
    assert claims["ck_pq_kid"] == app.state.keys.pq_key_id
    assert app.state.tokens.id_token_pq_is_valid(claims)

    forged = dict(claims, groups=["cluster-admins", "smuggled"])
    assert not app.state.tokens.id_token_pq_is_valid(forged)


async def test_an_authorization_code_cannot_be_redeemed_twice(client, admin_user, headlamp_client):
    await login(client)
    code = parse_qs(urlparse((await _authorize(client)).headers["location"]).query)["code"][0]
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://headlamp.clusterkeep.dev.net/oidc-callback",
        "client_id": "headlamp",
        "client_secret": "headlamp-test-secret",
    }
    assert (await client.post("/token", data=form)).status_code == 200
    assert (await client.post("/token", data=form)).status_code == 400


async def test_token_endpoint_rejects_a_wrong_client_secret(client, admin_user, headlamp_client):
    await login(client)
    code = parse_qs(urlparse((await _authorize(client)).headers["location"]).query)["code"][0]

    response = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://headlamp.clusterkeep.dev.net/oidc-callback",
            "client_id": "headlamp",
            "client_secret": "wrong-secret",
        },
    )
    assert response.status_code == 401


async def test_pkce_is_enforced_when_the_code_was_bound_to_a_challenge(
    client, admin_user, headlamp_client
):
    await login(client)
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    location = (
        await _authorize(client, code_challenge=challenge, code_challenge_method="S256")
    ).headers["location"]
    code = parse_qs(urlparse(location).query)["code"][0]

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://headlamp.clusterkeep.dev.net/oidc-callback",
        "client_id": "headlamp",
        "client_secret": "headlamp-test-secret",
    }
    assert (await client.post("/token", data=dict(form, code_verifier="b" * 64))).status_code == 400


async def test_userinfo_requires_a_valid_service_token(client, admin_user, headlamp_client, app):
    await login(client)
    code = parse_qs(urlparse((await _authorize(client)).headers["location"]).query)["code"][0]
    body = (
        await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://headlamp.clusterkeep.dev.net/oidc-callback",
                "client_id": "headlamp",
                "client_secret": "headlamp-test-secret",
            },
        )
    ).json()

    assert (await client.get("/userinfo")).status_code == 401
    ok = await client.get("/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert ok.status_code == 200
    assert ok.json()["preferred_username"] == "alice"
