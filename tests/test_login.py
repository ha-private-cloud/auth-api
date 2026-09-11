from tests.conftest import ADMIN_PASSWORD


async def test_login_page_renders(client):
    response = await client.get("/login")
    assert response.status_code == 200
    assert 'name="password"' in response.text


async def test_successful_login_sets_an_opaque_session_cookie(client, admin_user, settings):
    response = await client.post(
        "/login",
        data={"username": "alice", "password": ADMIN_PASSWORD, "next": "https://headlamp.clusterkeep.dev.net"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "https://headlamp.clusterkeep.dev.net"

    cookie = response.cookies[settings.cookie_name]
    # The cookie is a random handle: no username, no claims, nothing signed.
    assert "alice" not in cookie
    assert len(cookie) >= 40


async def test_wrong_password_is_rejected(client, admin_user):
    response = await client.post(
        "/login", data={"username": "alice", "password": "not-the-password"}, follow_redirects=False
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.text


async def test_unknown_user_gives_the_same_message_as_a_wrong_password(client, admin_user):
    """No username enumeration through the login form."""
    unknown = await client.post(
        "/login", data={"username": "nobody", "password": "whatever-value"}, follow_redirects=False
    )
    wrong = await client.post(
        "/login", data={"username": "alice", "password": "not-the-password"}, follow_redirects=False
    )
    assert unknown.status_code == wrong.status_code == 401
    assert "Incorrect username or password" in unknown.text


async def test_repeated_failures_lock_the_account_out(client, admin_user, settings):
    for _ in range(settings.max_failed_logins):
        await client.post("/login", data={"username": "alice", "password": "wrong-password"})

    response = await client.post(
        "/login", data={"username": "alice", "password": ADMIN_PASSWORD}, follow_redirects=False
    )
    assert response.status_code == 429


async def test_successful_login_clears_the_failure_counter(client, admin_user, app):
    await client.post("/login", data={"username": "alice", "password": "wrong-password"})
    assert await app.state.redis.failed_login_count("alice") == 1

    await client.post("/login", data={"username": "alice", "password": ADMIN_PASSWORD})
    assert await app.state.redis.failed_login_count("alice") == 0


async def test_offsite_next_is_refused(client, admin_user, settings):
    """Open-redirect guard: a fresh session must not be steered off-domain."""
    response = await client.post(
        "/login",
        data={"username": "alice", "password": ADMIN_PASSWORD, "next": "https://evil.example.com/steal"},
        follow_redirects=False,
    )
    assert response.headers["location"] == f"{settings.issuer_url}/account"


async def test_session_endpoint_reflects_the_logged_in_user(client, admin_user):
    await client.post("/login", data={"username": "alice", "password": ADMIN_PASSWORD})
    response = await client.get("/session")
    assert response.status_code == 200
    assert response.json()["preferred_username"] == "alice"
    assert response.json()["groups"] == ["cluster-admins"]


async def test_logout_revokes_the_session_immediately(client, admin_user):
    await client.post("/login", data={"username": "alice", "password": ADMIN_PASSWORD})
    assert (await client.get("/session")).status_code == 200

    await client.get("/logout", follow_redirects=False)
    assert (await client.get("/session")).status_code == 401


async def test_a_password_change_revokes_every_existing_session(client, admin_user, app):
    """Redis being shared is what makes this fleet-wide and instant."""
    await client.post("/login", data={"username": "alice", "password": ADMIN_PASSWORD})
    assert (await client.get("/session")).status_code == 200

    await app.state.redis.delete_user_sessions(admin_user.id)
    assert (await client.get("/session")).status_code == 401
