from app import repository
from app.main import bootstrap


async def test_cloudflare_access_client_seeded_from_env(app, settings, monkeypatch):
    monkeypatch.setenv("AUTH_API_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "team.cloudflareaccess.com")
    monkeypatch.setenv("AUTH_API_CLOUDFLARE_ACCESS_CLIENT_SECRET", "cf-test-secret")

    await bootstrap(app, settings)

    async with app.state.sessionmaker() as session:
        client = await repository.get_client(session, "cloudflare-access")
    assert client.redirect_uris == ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"]
    assert client.require_pkce is True
    assert "groups" in client.scopes
    assert app.state.passwords.verify(client.client_secret_hash, "cf-test-secret")


async def test_cloudflare_access_client_absent_without_secret(app, settings, monkeypatch):
    monkeypatch.setenv("AUTH_API_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "team.cloudflareaccess.com")
    monkeypatch.delenv("AUTH_API_CLOUDFLARE_ACCESS_CLIENT_SECRET", raising=False)

    await bootstrap(app, settings)

    async with app.state.sessionmaker() as session:
        assert await repository.get_client(session, "cloudflare-access") is None
