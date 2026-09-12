from tests.conftest import login


async def _mint(client, audience="storage-ui", scopes=None):
    return await client.post(
        "/api/v1/service-tokens",
        json={"name": "test-token", "audience": audience, "scopes": scopes or ["storage:read"]},
    )


async def test_minting_requires_a_session(client, admin_user):
    """A leaked service token must not be able to mint further tokens."""
    assert (await _mint(client)).status_code == 401


async def test_minted_token_is_ml_dsa_65(client, admin_user):
    await login(client)
    body = (await _mint(client)).json()

    assert body["algorithm"] == "ML-DSA-65"
    assert body["token"].startswith("ck1.")


async def test_minted_token_verifies_and_carries_the_users_identity(client, admin_user, app):
    await login(client)
    token = (await _mint(client)).json()["token"]

    claims = app.state.tokens.verify_service_token(token, "storage-ui")
    assert claims["preferred_username"] == "alice"
    assert claims["scope"] == "storage:read"
    assert claims["groups"] == ["cluster-admins"]


async def test_verify_endpoint_accepts_the_token(client, admin_user):
    await login(client)
    token = (await _mint(client)).json()["token"]

    response = await client.get(
        "/api/v1/service-tokens/verify", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["claims"]["preferred_username"] == "alice"


async def test_verify_endpoint_rejects_a_tampered_token(client, admin_user):
    await login(client)
    token = (await _mint(client)).json()["token"]
    tampered = token[:-8] + "AAAAAAAA"

    response = await client.get(
        "/api/v1/service-tokens/verify", headers={"Authorization": f"Bearer {tampered}"}
    )
    assert response.status_code == 401


async def test_introspection_reports_an_active_token(client, admin_user):
    await login(client)
    token = (await _mint(client)).json()["token"]

    body = (await client.post("/introspect", data={"token": token})).json()
    assert body["active"] is True
    assert body["alg"] == "ML-DSA-65"
    assert body["username"] == "alice"


async def test_introspection_reports_a_garbage_token_as_inactive(client, admin_user):
    await login(client)
    assert (await client.post("/introspect", data={"token": "ck1.a.b.c"})).json() == {"active": False}


async def test_revoked_token_introspects_as_inactive(client, admin_user, app):
    """Signature stays valid forever, so revocation has to be a stored fact."""
    await login(client)
    token = (await _mint(client)).json()["token"]
    assert (await client.post("/introspect", data={"token": token})).json()["active"] is True

    from app import repository
    from app.cache import digest

    async with app.state.sessionmaker() as session:
        credential = await repository.get_service_credential(session, digest(token))
        await repository.revoke_service_credential(session, credential)

    assert (await client.post("/introspect", data={"token": token})).json()["active"] is False


async def test_admin_endpoints_reject_a_non_admin_token(client, admin_user, app):
    await login(client)
    async with app.state.sessionmaker() as session:
        from app import repository

        await repository.create_user(
            session, app.state.passwords, username="bob", password="bobs-long-password", groups=["viewers"]
        )

    token = app.state.tokens.service_token(
        subject="bob-id", username="bob", audience="auth-api", scopes=[], groups=["viewers"]
    )
    response = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


async def test_admin_can_list_users(client, admin_user, app):
    token = app.state.tokens.service_token(
        subject=admin_user.id,
        username="alice",
        audience="auth-api",
        scopes=[],
        groups=["cluster-admins"],
    )
    response = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert [u["username"] for u in response.json()] == ["alice"]


async def test_user_listing_never_exposes_password_hashes(client, admin_user, app):
    token = app.state.tokens.service_token(
        subject=admin_user.id,
        username="alice",
        audience="auth-api",
        scopes=[],
        groups=["cluster-admins"],
    )
    body = (await client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})).text
    assert "argon2" not in body
    assert "password_hash" not in body


async def test_admin_group_alone_also_grants_admin_access(client, admin_user, app):
    """admin-ui's own admins carry "admin", not "cluster-admins"."""
    token = app.state.tokens.service_token(
        subject=admin_user.id, username="alice", audience="auth-api", scopes=[], groups=["admin"]
    )
    response = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


async def test_admin_can_update_a_users_groups(client, admin_user, app):
    async with app.state.sessionmaker() as session:
        from app import repository

        bob = await repository.create_user(
            session, app.state.passwords, username="bob", password="bobs-long-password"
        )
        bob_id = bob.id

    token = app.state.tokens.service_token(
        subject=admin_user.id,
        username="alice",
        audience="auth-api",
        scopes=[],
        groups=["cluster-admins"],
    )
    response = await client.patch(
        f"/api/v1/users/{bob_id}/groups",
        json={"groups": ["admin"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["groups"] == ["admin"]


async def test_updating_groups_for_an_unknown_user_returns_404(client, admin_user, app):
    token = app.state.tokens.service_token(
        subject=admin_user.id,
        username="alice",
        audience="auth-api",
        scopes=[],
        groups=["cluster-admins"],
    )
    response = await client.patch(
        "/api/v1/users/does-not-exist/groups",
        json={"groups": ["admin"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


async def test_non_admin_cannot_update_groups(client, admin_user, app):
    token = app.state.tokens.service_token(
        subject="bob-id", username="bob", audience="auth-api", scopes=[], groups=["viewers"]
    )
    response = await client.patch(
        f"/api/v1/users/{admin_user.id}/groups",
        json={"groups": ["admin"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
