REGISTRATION_HEADERS = {"Authorization": "Bearer test-registration-token"}


async def test_registration_requires_the_shared_bearer_token(client):
    response = await client.post(
        "/api/v1/register", json={"username": "newuser", "password": "a-long-enough-password"}
    )
    assert response.status_code == 401


async def test_wrong_bearer_token_is_rejected(client):
    response = await client.post(
        "/api/v1/register",
        json={"username": "newuser", "password": "a-long-enough-password"},
        headers={"Authorization": "Bearer not-the-token"},
    )
    assert response.status_code == 401


async def test_successful_registration_creates_an_active_unprivileged_user_and_sets_a_session(client, settings):
    response = await client.post(
        "/api/v1/register",
        json={"username": "newuser", "password": "a-long-enough-password"},
        headers=REGISTRATION_HEADERS,
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
        json={"username": "shortpw", "password": "tooshort"},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 422


async def test_registration_rejects_a_taken_username(client, admin_user):
    response = await client.post(
        "/api/v1/register",
        json={"username": "alice", "password": "a-long-enough-password"},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 409
