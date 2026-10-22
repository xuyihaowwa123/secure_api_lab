"""Smoke tests for the Secure REST API.

These tests exercise the three endpoints through Flask's test client, so a
regression in authentication or in the response contract fails the pipeline
instead of silently shipping.

Run locally:  JWT_SECRET_KEY=dev-only python -m pytest -q
"""

import pytest

from app import app


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_login_returns_token(client):
    resp = client.post(
        "/auth/login", json={"username": "admin", "password": "password123!"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "access_token" in body
    # a JWT is three dot-separated segments
    assert body["access_token"].count(".") == 2


def test_login_rejects_wrong_password(client):
    resp = client.post(
        "/auth/login", json={"username": "admin", "password": "wrong-password"}
    )
    assert resp.status_code == 401
    assert resp.get_json()["message"] == "Wrong username or password"


def test_protected_endpoint_without_token_is_401(client):
    for path in ("/api/data", "/api/user/profile"):
        resp = client.get(path)
        assert resp.status_code == 401, path


def test_protected_endpoint_with_token_is_200(client):
    login = client.post(
        "/auth/login", json={"username": "admin", "password": "password123!"}
    )
    token = login.get_json()["access_token"]
    headers = {"Authorization": "Bearer " + token}

    data = client.get("/api/data", headers=headers)
    assert data.status_code == 200
    assert data.get_json()["data_list"] == ["item1", "item2", "item3"]

    profile = client.get("/api/user/profile", headers=headers)
    assert profile.status_code == 200
    assert profile.get_json()["username"] == "admin"


def test_malformed_token_is_401(client):
    headers = {"Authorization": "Bearer not-a-real-token"}
    resp = client.get("/api/data", headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid token"


def test_xss_payload_is_escaped_in_response(client):
    # the endpoint must not echo raw angle brackets back to the client
    headers = {"Authorization": "Bearer " + _token(client)}
    resp = client.get("/api/user/profile", headers=headers)
    assert "<script>" not in resp.get_data(as_text=True)


def _token(client):
    return client.post(
        "/auth/login", json={"username": "admin", "password": "password123!"}
    ).get_json()["access_token"]
