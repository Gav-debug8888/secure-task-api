import pytest

from tests.conftest import login, register


def create(client, **overrides):
    payload = {"title": "Write threat model", "priority": "high", **overrides}
    return client.post("/api/tasks", json=payload)


def test_all_task_routes_require_auth(client):
    assert client.get("/api/tasks").status_code == 401
    assert client.post("/api/tasks", json={"title": "x"}).status_code == 401
    assert client.get("/api/tasks/1").status_code == 401
    assert client.patch("/api/tasks/1", json={"title": "x"}).status_code == 401
    assert client.delete("/api/tasks/1").status_code == 401


def test_crud_lifecycle(auth_client):
    r = create(auth_client)
    assert r.status_code == 201
    task = r.json()
    assert task["status"] == "todo"

    assert auth_client.get(f"/api/tasks/{task['id']}").json()["title"] == "Write threat model"

    r = auth_client.patch(f"/api/tasks/{task['id']}", json={"status": "done"})
    assert r.status_code == 200 and r.json()["status"] == "done"

    assert len(auth_client.get("/api/tasks").json()) == 1
    assert auth_client.get("/api/tasks", params={"status": "todo"}).json() == []

    assert auth_client.delete(f"/api/tasks/{task['id']}").status_code == 204
    assert auth_client.get(f"/api/tasks/{task['id']}").status_code == 404


def test_idor_other_users_tasks_are_invisible(client):
    register(client, "alice")
    login(client, "alice")
    alice_task = create(client).json()

    client.cookies.clear()
    register(client, "bob")
    login(client, "bob")

    assert client.get(f"/api/tasks/{alice_task['id']}").status_code == 404
    assert client.patch(f"/api/tasks/{alice_task['id']}", json={"title": "pwned"}).status_code == 404
    assert client.delete(f"/api/tasks/{alice_task['id']}").status_code == 404
    assert client.get("/api/tasks").json() == []


def test_cannot_mass_assign_owner(auth_client):
    assert create(auth_client, owner_id=999).status_code == 422


@pytest.mark.parametrize("payload", [
    {"title": ""},
    {"title": "x" * 201},
    {"title": "ok", "description": "d" * 2001},
    {"title": "ok", "status": "hacked"},
    {"title": "ok", "priority": "urgent!!"},
])
def test_task_input_validation(auth_client, payload):
    assert auth_client.post("/api/tasks", json=payload).status_code == 422


def test_sql_injection_payload_stored_as_plain_text(auth_client):
    payload = "'; DROP TABLE tasks; --"
    r = create(auth_client, title=payload)
    assert r.status_code == 201
    assert auth_client.get("/api/tasks").json()[0]["title"] == payload


def test_pagination_limits_enforced(auth_client):
    assert auth_client.get("/api/tasks", params={"limit": 1000}).status_code == 422
    assert auth_client.get("/api/tasks", params={"offset": -1}).status_code == 422


def test_cannot_null_required_field(auth_client):
    task = create(auth_client).json()
    assert auth_client.patch(f"/api/tasks/{task['id']}", json={"title": None}).status_code == 422


# ---------- Cross-cutting controls ----------
def test_security_headers(client):
    h = client.get("/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["x-xss-protection"] == "0"
    assert "max-age=" in h["strict-transport-security"]
    assert "default-src 'none'" in h["content-security-policy"]
    assert "server" not in h


def test_health_reveals_nothing_sensitive(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_cors_allows_only_configured_origin(client):
    ok = client.options("/api/tasks", headers={
        "Origin": "https://app.example.com", "Access-Control-Request-Method": "GET"})
    bad = client.options("/api/tasks", headers={
        "Origin": "https://evil.example.net", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://app.example.com"
    assert "access-control-allow-origin" not in bad.headers


def test_validation_errors_do_not_echo_input(auth_client):
    r = auth_client.post("/api/tasks", json={"title": "<script>alert(1)</script>", "status": "bad"})
    assert r.status_code == 422
    assert "<script>" not in r.text
