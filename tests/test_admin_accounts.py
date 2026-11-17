from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from app import repository
from app.models import Invite
from tests.conftest import ADMIN_PASSWORD, FRONTEND_HEADERS, login

REGISTRATION_HEADERS = {"Authorization": "Bearer test-registration-token"}


def admin_token(app, user, groups=("admin",)):
    return app.state.tokens.service_token(
        subject=user.id, username=user.username, audience="auth-api", scopes=[], groups=list(groups)
    )


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def make_user(app, username, groups=()):
    async with app.state.sessionmaker() as session:
        return await repository.create_user(
            session, app.state.passwords, username=username, password=f"{username}-long-password",
            email=f"{username}@example.com", groups=list(groups),
        )


async def test_disabling_a_user_ends_their_sessions_and_blocks_sign_in(client, admin_user, app):
    bob = await make_user(app, "bob")
    signed_in = await client.post(
        "/api/v1/sessions", json={"username": "bob", "password": "bob-long-password"}, headers=FRONTEND_HEADERS
    )
    bob_session = signed_in.json()["session_token"]

    response = await client.patch(
        f"/api/v1/users/{bob.id}/active", json={"is_active": False}, headers=bearer(admin_token(app, admin_user))
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is False

    client.cookies.set("ck_sso", bob_session)
    assert (await client.get("/session")).status_code == 401
    again = await client.post(
        "/api/v1/sessions", json={"username": "bob", "password": "bob-long-password"}, headers=FRONTEND_HEADERS
    )
    assert again.status_code == 401


async def test_re_enabling_lets_them_sign_in_again(client, admin_user, app):
    bob = await make_user(app, "bob")
    headers = bearer(admin_token(app, admin_user))
    await client.patch(f"/api/v1/users/{bob.id}/active", json={"is_active": False}, headers=headers)
    await client.patch(f"/api/v1/users/{bob.id}/active", json={"is_active": True}, headers=headers)
    response = await client.post(
        "/api/v1/sessions", json={"username": "bob", "password": "bob-long-password"}, headers=FRONTEND_HEADERS
    )
    assert response.status_code == 201


async def test_a_disabled_users_service_tokens_stop_working_straight_away(client, admin_user, app):
    carol = await make_user(app, "carol", groups=["admin"])
    carol_token = admin_token(app, carol)
    assert (await client.get("/api/v1/users", headers=bearer(carol_token))).status_code == 200

    await client.patch(
        f"/api/v1/users/{carol.id}/active", json={"is_active": False}, headers=bearer(admin_token(app, admin_user))
    )
    assert (await client.get("/api/v1/users", headers=bearer(carol_token))).status_code == 401


async def test_a_revoked_service_token_is_refused(client, admin_user, app):
    await login(client)
    minted = await client.post(
        "/api/v1/service-tokens", json={"name": "to-revoke", "audience": "auth-api", "scopes": []}
    )
    token = minted.json()["token"]
    async with app.state.sessionmaker() as session:
        from app.cache import digest

        credential = await repository.get_service_credential(session, digest(token))
        await repository.revoke_service_credential(session, credential)
    assert (await client.get("/api/v1/users", headers=bearer(token))).status_code == 401


async def test_admins_cannot_disable_themselves(client, admin_user, app):
    response = await client.patch(
        f"/api/v1/users/{admin_user.id}/active", json={"is_active": False},
        headers=bearer(admin_token(app, admin_user, groups=("cluster-admins",))),
    )
    assert response.status_code == 400


async def test_only_cluster_admins_can_disable_a_cluster_admin(client, admin_user, app):
    plain_admin = await make_user(app, "dave", groups=["admin"])
    response = await client.patch(
        f"/api/v1/users/{admin_user.id}/active", json={"is_active": False}, headers=bearer(admin_token(app, plain_admin))
    )
    assert response.status_code == 403


async def test_invites_are_created_listed_without_their_token_and_revoked(client, admin_user, app):
    headers = bearer(admin_token(app, admin_user))
    created = await client.post("/api/v1/invites", json={"note": "Sam"}, headers=headers)
    assert created.status_code == 201
    body = created.json()
    assert len(body["token"]) >= 32
    assert body["note"] == "Sam"

    listed = (await client.get("/api/v1/invites", headers=headers)).json()
    assert [i["status"] for i in listed] == ["open"]
    assert body["token"] not in str(listed)

    assert (await client.delete(f"/api/v1/invites/{body['id']}", headers=headers)).status_code == 204
    assert (await client.get("/api/v1/invites", headers=headers)).json()[0]["status"] == "revoked"


async def test_invites_need_an_admin(client, admin_user, app):
    bob = await make_user(app, "bob")
    assert (await client.post("/api/v1/invites", json={}, headers=bearer(admin_token(app, bob, groups=())))).status_code == 403


async def test_registration_needs_a_valid_invite_and_uses_it_up(client, admin_user, app):
    invite = (await client.post("/api/v1/invites", json={}, headers=bearer(admin_token(app, admin_user)))).json()
    body = {"username": "newuser", "password": "a-long-enough-password", "email": "newuser@example.com"}

    assert (await client.post("/api/v1/register", json=body, headers=REGISTRATION_HEADERS)).status_code == 422
    wrong = await client.post("/api/v1/register", json={**body, "invite": "nope"}, headers=REGISTRATION_HEADERS)
    assert wrong.status_code == 403

    ok = await client.post("/api/v1/register", json={**body, "invite": invite["token"]}, headers=REGISTRATION_HEADERS)
    assert ok.status_code == 201
    reused = await client.post(
        "/api/v1/register", json={**body, "username": "another", "invite": invite["token"]}, headers=REGISTRATION_HEADERS
    )
    assert reused.status_code == 403

    listed = (await client.get("/api/v1/invites", headers=bearer(admin_token(app, admin_user)))).json()
    assert listed[0]["status"] == "used"
    assert listed[0]["used_by"] == "newuser"


async def test_expired_and_revoked_invites_are_refused(client, admin_user, app):
    headers = bearer(admin_token(app, admin_user))
    expired = (await client.post("/api/v1/invites", json={}, headers=headers)).json()
    revoked = (await client.post("/api/v1/invites", json={}, headers=headers)).json()
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(Invite).where(Invite.id == expired["id"]).values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
        )
        await session.commit()
    await client.delete(f"/api/v1/invites/{revoked['id']}", headers=headers)

    body = {"username": "late", "password": "a-long-enough-password", "email": "late@example.com"}
    for invite in (expired, revoked):
        response = await client.post("/api/v1/register", json={**body, "invite": invite["token"]}, headers=REGISTRATION_HEADERS)
        assert response.status_code == 403
    statuses = sorted(i["status"] for i in (await client.get("/api/v1/invites", headers=headers)).json())
    assert statuses == ["expired", "revoked"]


async def test_a_taken_username_does_not_use_up_the_invite(client, admin_user, app):
    invite = (await client.post("/api/v1/invites", json={}, headers=bearer(admin_token(app, admin_user)))).json()
    body = {"username": "alice", "password": ADMIN_PASSWORD, "email": "x@example.com", "invite": invite["token"]}
    assert (await client.post("/api/v1/register", json=body, headers=REGISTRATION_HEADERS)).status_code == 409
    listed = (await client.get("/api/v1/invites", headers=bearer(admin_token(app, admin_user)))).json()
    assert listed[0]["status"] == "open"


async def test_admins_cannot_create_a_user_with_an_email_in_use(client, admin_user, app):
    response = await client.post(
        "/api/v1/users",
        json={"username": "bob", "password": "bob-long-password", "email": "ALICE@clusterkeep.dev.net"},
        headers=bearer(admin_token(app, admin_user)),
    )
    assert response.status_code == 409


async def test_admins_cannot_create_a_username_with_an_at_sign(client, admin_user, app):
    response = await client.post(
        "/api/v1/users",
        json={"username": "bob@example.com", "password": "bob-long-password"},
        headers=bearer(admin_token(app, admin_user)),
    )
    assert response.status_code == 422
