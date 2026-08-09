from __future__ import annotations

import time
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from echo_oauth.runtime import GitHubOAuthClient, OAuthStateStore, build_authorize_url, create_app


def test_state_is_single_use_and_preserves_bounded_return_path(tmp_path: Path) -> None:
    store = OAuthStateStore(tmp_path / "oauth.sqlite3", signing_key="s" * 64, ttl_seconds=600)
    state = store.issue("/command-center")
    assert store.consume(state) == "/command-center"
    with pytest.raises(ValueError, match="already used"):
        store.consume(state)


def test_tampered_or_expired_state_is_rejected(tmp_path: Path) -> None:
    store = OAuthStateStore(tmp_path / "oauth.sqlite3", signing_key="s" * 64, ttl_seconds=60)
    state = store.issue("/", now=1_800_000_000)
    with pytest.raises(ValueError, match="signature"):
        store.consume(state[:-1] + ("a" if state[-1] != "a" else "b"), now=1_800_000_001)
    with pytest.raises(ValueError, match="expired"):
        store.consume(state, now=1_800_000_061)


@pytest.mark.parametrize("return_to", ["https://evil.example/", "//evil.example", "javascript:alert(1)"])
def test_state_rejects_open_redirect_targets(tmp_path: Path, return_to: str) -> None:
    store = OAuthStateStore(tmp_path / "oauth.sqlite3", signing_key="s" * 64)
    with pytest.raises(ValueError, match="return path"):
        store.issue(return_to)


def test_authorization_url_contains_exact_registered_identity_and_state() -> None:
    url = build_authorize_url(
        client_id="Ov23exampleclientid",
        redirect_uri="https://echo-op.com/auth/github/callback",
        state="opaque-state",
        scopes=("read:user", "user:email"),
    )
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert (parsed.scheme, parsed.netloc, parsed.path) == ("https", "github.com", "/login/oauth/authorize")
    assert query == {
        "allow_signup": ["false"],
        "client_id": ["Ov23exampleclientid"],
        "redirect_uri": ["https://echo-op.com/auth/github/callback"],
        "scope": ["read:user user:email"],
        "state": ["opaque-state"],
    }


def test_http_callback_rejects_state_mismatch_before_token_exchange(tmp_path: Path) -> None:
    exchanged: list[str] = []

    def exchange(code: str) -> dict[str, str]:
        exchanged.append(code)
        return {"login": "echoomegaprime"}

    app = create_app(
        client_id="Ov23exampleclientid",
        redirect_uri="https://echo-op.com/auth/github/callback",
        state_store=OAuthStateStore(tmp_path / "oauth.sqlite3", signing_key="s" * 64),
        exchange_code=exchange,
    )
    with TestClient(app) as client:
        response = client.get("/oauth/callback", params={"code": "temporary-code", "state": "forged"})
    assert response.status_code == 400
    assert exchanged == []


def test_http_start_and_callback_complete_once_without_exposing_token(tmp_path: Path) -> None:
    store = OAuthStateStore(tmp_path / "oauth.sqlite3", signing_key="s" * 64)

    def exchange(code: str) -> dict[str, str]:
        assert code == "temporary-code"
        return {"login": "echoomegaprime", "access_token": "must-not-leak"}

    app = create_app(
        client_id="Ov23exampleclientid",
        redirect_uri="https://echo-op.com/auth/github/callback",
        state_store=store,
        exchange_code=exchange,
    )
    with TestClient(app) as client:
        start = client.get("/oauth/start", params={"return_to": "/command-center"}, follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        callback = client.get("/oauth/callback", params={"code": "temporary-code", "state": state})
        replay = client.get("/oauth/callback", params={"code": "temporary-code", "state": state})
        health = client.get("/health")
    assert start.status_code == 307
    assert callback.status_code == 200
    assert callback.json() == {"status": "authorized", "login": "echoomegaprime", "return_to": "/command-center"}
    assert "must-not-leak" not in callback.text
    assert replay.status_code == 400
    assert health.headers["x-content-type-options"] == "nosniff"


def test_github_exchange_uses_registered_callback_and_returns_only_identity() -> None:
    observed: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["content-length"])).decode()
            observed.append((self.path, body))
            payload = json.dumps({"access_token": "dummy-access-token", "token_type": "bearer"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            observed.append((self.path, self.headers.get("Authorization", "")))
            payload = json.dumps({"login": "echoomegaprime", "id": 123}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        client = GitHubOAuthClient(
            client_id="Ov23exampleclientid",
            client_secret="client-secret",
            redirect_uri="https://echo-op.com/auth/github/callback",
            web_base=base,
            api_base=base,
        )
        identity = client.exchange("temporary-code")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert identity == {"login": "echoomegaprime"}
    assert observed[0][0] == "/login/oauth/access_token"
    assert "redirect_uri=https%3A%2F%2Fecho-op.com%2Fauth%2Fgithub%2Fcallback" in observed[0][1]
    assert observed[1] == ("/user", "Bearer dummy-access-token")
