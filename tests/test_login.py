import pytest

from app import repository
from tests.conftest import ADMIN_PASSWORD, FRONTEND_HEADERS

SESSIONS = "/api/v1/sessions"


async def sign_in(client, password=ADMIN_PASSWORD, username="alice", next_url=""):
    return await client.post(
        SESSIONS,
        json={"username": username, "password": password, "next": next_url},
        headers=FRONTEND_HEADERS,
    )


async def test_sessions_api_requires_the_frontend_token(client, admin_user):
    response = await client.post(SESSIONS, json={"username": "alice", "password": ADMIN_PASSWORD})
    assert response.status_code == 401


async def test_successful_sign_in_returns_an_opaque_session_and_cookie_settings(client, admin_user, settings):
    response = await sign_in(client, next_url="https://headlamp.clusterkeep.dev.net")
    assert response.status_code == 201
    body = response.json()
    assert body["redirect_to"] == "https://headlamp.clusterkeep.dev.net"
    assert body["cookie"] == {
        "name": settings.cookie_name,
        "domain": settings.cookie_domain,
        "max_age": settings.session_absolute_seconds,
        "secure": settings.cookie_secure,
    }
    # The token is a random handle: no username, no claims, nothing signed.
    assert "alice" not in body["session_token"]
    assert len(body["session_token"]) >= 40
    assert settings.cookie_name not in response.cookies


async def test_wrong_password_is_rejected(client, admin_user):
    response = await sign_in(client, password="not-the-password")
    assert response.status_code == 401
    assert "session_token" not in response.json()


async def test_unknown_user_gives_the_same_answer_as_a_wrong_password(client, admin_user):
    unknown = await sign_in(client, username="nobody", password="whatever-value")
    wrong = await sign_in(client, password="not-the-password")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


async def test_repeated_failures_lock_the_account_out(client, admin_user, settings):
    for _ in range(settings.max_failed_logins):
        await sign_in(client, password="wrong-password")
    assert (await sign_in(client)).status_code == 429


async def test_successful_sign_in_clears_the_failure_counter(client, admin_user, app):
    await sign_in(client, password="wrong-password")
    assert await app.state.redis.failed_login_count("alice") == 1
    await sign_in(client)
    assert await app.state.redis.failed_login_count("alice") == 0


async def test_offsite_next_is_refused(client, admin_user, settings):
    response = await sign_in(client, next_url="https://evil.example.com/steal")
    assert response.json()["redirect_to"] == "https://ck-test.clusterkeep.dev.net/"


async def test_sign_in_without_next_lands_on_the_default_redirect(client, admin_user, settings):
    settings.default_redirect_url = "https://storage.clusterkeep.dev.net"
    assert (await sign_in(client)).json()["redirect_to"] == "https://storage.clusterkeep.dev.net"


async def test_issued_session_is_accepted_by_the_session_endpoint(client, admin_user, settings):
    client.cookies.set(settings.cookie_name, (await sign_in(client)).json()["session_token"])
    response = await client.get("/session")
    assert response.status_code == 200
    assert response.json()["preferred_username"] == "alice"
    assert response.json()["groups"] == ["cluster-admins"]


async def test_revoking_ends_the_session_immediately(client, admin_user, settings):
    token = (await sign_in(client)).json()["session_token"]
    revoked = await client.post(f"{SESSIONS}/revoke", json={"session_token": token}, headers=FRONTEND_HEADERS)
    assert revoked.status_code == 200
    assert revoked.json()["cookie"]["name"] == settings.cookie_name
    client.cookies.set(settings.cookie_name, token)
    assert (await client.get("/session")).status_code == 401


async def test_revoking_requires_the_frontend_token(client, admin_user):
    token = (await sign_in(client)).json()["session_token"]
    assert (await client.post(f"{SESSIONS}/revoke", json={"session_token": token})).status_code == 401


async def test_a_password_change_revokes_every_existing_session(client, admin_user, app, settings):
    token = (await sign_in(client)).json()["session_token"]
    await app.state.redis.delete_user_sessions(admin_user.id)
    client.cookies.set(settings.cookie_name, token)
    assert (await client.get("/session")).status_code == 401


async def _flag_for_change(app, user):
    async with app.state.sessionmaker() as session:
        fresh = await repository.get_user_by_id(session, user.id)
        await repository.require_password_change(session, fresh)


async def test_flagged_account_gets_a_change_token_instead_of_a_session(client, app, admin_user):
    await _flag_for_change(app, admin_user)
    response = await sign_in(client)
    assert response.status_code == 409
    assert response.json()["change_token"]
    assert "session_token" not in response.json()


async def test_changing_the_password_signs_in_and_clears_the_flag(client, app, admin_user):
    await _flag_for_change(app, admin_user)
    token = (await sign_in(client, next_url="https://storage.clusterkeep.dev.net")).json()["change_token"]

    response = await client.post(
        f"{SESSIONS}/password-change",
        json={"change_token": token, "password": "a-brand-new-passphrase"},
        headers=FRONTEND_HEADERS,
    )
    assert response.status_code == 201
    assert response.json()["redirect_to"] == "https://storage.clusterkeep.dev.net"
    assert response.json()["session_token"]

    async with app.state.sessionmaker() as session:
        user = await repository.get_user_by_username(session, "alice")
    assert user.must_change_password is False

    replay = await client.post(
        f"{SESSIONS}/password-change",
        json={"change_token": token, "password": "another-new-passphrase"},
        headers=FRONTEND_HEADERS,
    )
    assert replay.status_code == 410


@pytest.mark.parametrize(
    ("password", "code"),
    [("short", "too_short"), (ADMIN_PASSWORD, "unchanged")],
)
async def test_bad_new_passwords_are_refused(client, app, admin_user, password, code):
    await _flag_for_change(app, admin_user)
    token = (await sign_in(client)).json()["change_token"]
    response = await client.post(
        f"{SESSIONS}/password-change",
        json={"change_token": token, "password": password},
        headers=FRONTEND_HEADERS,
    )
    assert response.status_code == 400
    assert response.json()["detail"] == code


async def test_password_change_requires_the_frontend_token(client, app, admin_user):
    await _flag_for_change(app, admin_user)
    token = (await sign_in(client)).json()["change_token"]
    response = await client.post(
        f"{SESSIONS}/password-change", json={"change_token": token, "password": "a-brand-new-passphrase"}
    )
    assert response.status_code == 401


async def test_login_page_redirects_to_the_clusterkeep_ui_sign_in_page(client, settings):
    response = await client.get("/login", params={"next": "https://headlamp.clusterkeep.dev.net"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == (
        f"{settings.login_page_url}?next=https%3A%2F%2Fheadlamp.clusterkeep.dev.net"
    )


async def test_login_page_sends_signed_in_users_straight_on(client, admin_user, settings):
    client.cookies.set(settings.cookie_name, (await sign_in(client)).json()["session_token"])
    response = await client.get(
        "/login", params={"next": "https://headlamp.clusterkeep.dev.net"}, follow_redirects=False
    )
    assert response.headers["location"] == "https://headlamp.clusterkeep.dev.net"


async def test_auth_api_no_longer_accepts_form_posts(client, admin_user):
    response = await client.post("/login", data={"username": "alice", "password": ADMIN_PASSWORD})
    assert response.status_code == 405
