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


async def test_successful_registration_creates_an_active_unprivileged_user_and_sets_a_session(client, settings):
    response = await client.post("/api/v1/register", json=VALID_BODY, headers=REGISTRATION_HEADERS)
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


async def test_registration_rejects_a_taken_username(client, admin_user):
    response = await client.post(
        "/api/v1/register",
        json={**VALID_BODY, "username": "alice"},
        headers=REGISTRATION_HEADERS,
    )
    assert response.status_code == 409
