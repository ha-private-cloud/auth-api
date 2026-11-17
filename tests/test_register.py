from datetime import timedelta

REGISTRATION_HEADERS = {"Authorization": "Bearer test-registration-token"}
VALID_BODY = {"username": "newuser", "password": "a-long-enough-password", "email": "newuser@example.com"}


async def test_registration_requires_the_shared_bearer_token(client):
    response = await client.post("/api/v1/register", json=VALID_BODY)
    assert response.status_code == 401


async def test_wrong_bearer_token_is_rejected(client):
    response = await client.post(
        "/api/v1/register", json=VALID_BODY, headers={"Authorization": "Bearer not-the-token"}
    )
    assert response.status_code == 401


async def _invite(app):
    from app import repository

    async with app.state.sessionmaker() as session:
        _, token = await repository.create_invite(session, created_by=None, note=None, lifetime=timedelta(days=1))
    return token


async def test_successful_registration_creates_an_active_unprivileged_user_and_sets_a_session(client, settings, app):
    response = await client.post(
        "/api/v1/register", json={**VALID_BODY, "invite": await _invite(app)}, headers=REGISTRATION_HEADERS
    )
    assert response.status_code == 201
    assert settings.cookie_name in response.cookies

    session = await client.get("/session")
    assert session.status_code == 200
    assert session.json()["preferred_username"] == "newuser"
    assert session.json()["groups"] == []


async def test_registration_rejects_a_short_password(client):
    response = await client.post(
        "/api/v1/register",
        json={**VALID_BODY, "password": "tooshort"},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 422


async def test_registration_requires_an_email(client):
    body = {k: v for k, v in VALID_BODY.items() if k != "email"}
    response = await client.post("/api/v1/register", json=body, headers=REGISTRATION_HEADERS)
    assert response.status_code == 422


async def test_registration_rejects_a_malformed_email(client):
    response = await client.post(
        "/api/v1/register",
        json={**VALID_BODY, "email": "not-an-email"},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 422


async def _invite_status(app, invite):
    from app import repository
    from app.cache import digest
    from app.models import Invite
    from sqlalchemy import select

    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(Invite).where(Invite.token_digest == digest(invite)))).scalar_one()
    return row.used_at


async def test_registration_rejects_a_taken_username_and_keeps_the_invite(client, admin_user, app):
    invite = await _invite(app)
    response = await client.post(
        "/api/v1/register",
        json={**VALID_BODY, "username": "alice", "invite": invite},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "username already exists"
    assert await _invite_status(app, invite) is None


async def test_registration_rejects_an_email_already_in_use_and_keeps_the_invite(client, admin_user, app):
    invite = await _invite(app)
    response = await client.post(
        "/api/v1/register",
        json={**VALID_BODY, "email": "Alice@ClusterKeep.dev.net", "invite": invite},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "email already exists"
    assert await _invite_status(app, invite) is None


async def test_taken_usernames_and_emails_are_not_revealed_without_a_valid_invite(client, admin_user):
    for body in ({"username": "alice"}, {"email": "alice@clusterkeep.dev.net"}):
        response = await client.post(
            "/api/v1/register", json={**VALID_BODY, **body, "invite": "made-up"}, headers=REGISTRATION_HEADERS
        )
        assert response.status_code == 403


async def test_usernames_cannot_contain_an_at_sign(client, app):
    response = await client.post(
        "/api/v1/register",
        json={**VALID_BODY, "username": "new@user", "invite": await _invite(app)},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["msg"] == "Usernames can't contain @."
