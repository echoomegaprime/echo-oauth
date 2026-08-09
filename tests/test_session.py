from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from echo_oauth.runtime import OAuthStateStore, SessionStore, create_app


def _app(tmp_path: Path):
    return create_app(
        client_id="Ov23exampleclientid",
        redirect_uri="https://oauth.github.echo-op.com/oauth/callback",
        state_store=OAuthStateStore(tmp_path / "oauth.sqlite3", signing_key="s" * 64),
        session_store=SessionStore(tmp_path / "sessions.sqlite3", signing_key="k" * 64),
        exchange_code=lambda code: {"login": "echoomegaprime"},
    )


def test_callback_sets_secure_session_cookie_and_redirects_without_token(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with TestClient(app, base_url="https://oauth.github.echo-op.com") as client:
        start = client.get("/oauth/start", params={"return_to": "/command-center"}, follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        callback = client.get(
            "/oauth/callback",
            params={"code": "temporary-code", "state": state},
            follow_redirects=False,
        )
        session = client.get("/session")

    assert callback.status_code == 303
    assert callback.headers["location"] == "/command-center"
    cookie = callback.headers["set-cookie"]
    assert "echo_session=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    assert session.json() == {"authenticated": True, "provider": "github", "login": "echoomegaprime"}
    assert "access_token" not in callback.text


def test_logout_revokes_session_and_clears_cookie(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with TestClient(app, base_url="https://oauth.github.echo-op.com") as client:
        start = client.get("/oauth/start", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        client.get(
            "/oauth/callback",
            params={"code": "temporary-code", "state": state},
            follow_redirects=False,
        )
        before = client.get("/session")
        logout = client.post("/logout")
        after = client.get("/session")

    assert before.json()["authenticated"] is True
    assert logout.json() == {"ok": True}
    assert "Max-Age=0" in logout.headers["set-cookie"]
    assert after.json() == {"authenticated": False, "provider": "github"}


def test_session_cookie_tamper_fails_closed(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with TestClient(app, base_url="https://oauth.github.echo-op.com") as client:
        client.cookies.set("echo_session", "forged.value")
        response = client.get("/session")
    assert response.json() == {"authenticated": False, "provider": "github"}
