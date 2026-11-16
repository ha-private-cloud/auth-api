async def test_browser_gets_the_not_found_page_for_an_unknown_path(client):
    response = await client.get("/does-not-exist", headers={"Accept": "text/html"})
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Page not found" in response.text
    assert "Back to ClusterKeep" in response.text


async def test_not_found_page_links_to_the_default_redirect(client, settings):
    response = await client.get("/does-not-exist", headers={"Accept": "text/html"})
    assert f'href="{settings.issuer_url}/account"' in response.text


async def test_api_clients_still_get_json_for_an_unknown_path(client):
    response = await client.get("/does-not-exist", headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


async def test_api_paths_keep_json_404s_for_browsers(client):
    response = await client.get("/api/v1/does-not-exist", headers={"Accept": "text/html"})
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
