from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


class GitHubOAuthClient:
    """Exchange a short-lived code, validate the user, and discard the token."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        web_base: str = "https://github.com",
        api_base: str = "https://api.github.com",
        timeout_seconds: int = 15,
    ) -> None:
        if not client_id or not client_secret or not redirect_uri.startswith("https://"):
            raise ValueError("OAuth client identity and HTTPS redirect are required")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.web_base = web_base.rstrip("/")
        self.api_base = api_base.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def exchange(self, code: str) -> dict[str, str]:
        if not code or len(code) > 512:
            raise ValueError("invalid OAuth authorization code")
        form = urlencode(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri,
            }
        ).encode()
        token_request = urllib.request.Request(
            self.web_base + "/login/oauth/access_token",
            data=form,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "ECHO-OAuth/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(token_request, timeout=self.timeout_seconds) as response:
                token_body = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("GitHub token exchange failed") from exc
        access_token = token_body.get("access_token") if isinstance(token_body, dict) else None
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("GitHub token exchange did not return a token")
        identity_request = urllib.request.Request(
            self.api_base + "/user",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + access_token,
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "ECHO-OAuth/1.0",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(identity_request, timeout=self.timeout_seconds) as response:
                identity = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("GitHub identity validation failed") from exc
        login = identity.get("login") if isinstance(identity, dict) else None
        if not isinstance(login, str) or not login:
            raise RuntimeError("GitHub identity response was invalid")
        return {"login": login}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _validate_return_path(return_to: str) -> str:
    if (
        not isinstance(return_to, str)
        or not return_to.startswith("/")
        or return_to.startswith("//")
        or "\\" in return_to
        or len(return_to) > 512
    ):
        raise ValueError("invalid return path")
    return return_to


class OAuthStateStore:
    """HMAC-authenticated state tokens plus a durable one-time replay fence."""

    def __init__(self, path: str | Path, *, signing_key: str, ttl_seconds: int = 600) -> None:
        if len(signing_key.encode()) < 32:
            raise ValueError("state signing key must contain at least 32 bytes")
        if not 60 <= ttl_seconds <= 900:
            raise ValueError("state ttl must be between 60 and 900 seconds")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key = signing_key.encode()
        self.ttl_seconds = ttl_seconds
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_states (
                    nonce TEXT PRIMARY KEY,
                    issued_at INTEGER NOT NULL,
                    used_at INTEGER
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def issue(self, return_to: str = "/", *, now: int | None = None) -> str:
        return_path = _validate_return_path(return_to)
        issued = int(time.time() if now is None else now)
        nonce = secrets.token_urlsafe(24)
        payload = json.dumps(
            {"iat": issued, "nonce": nonce, "return_to": return_path},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        encoded = _b64url(payload)
        signature = _b64url(hmac.new(self.signing_key, encoded.encode(), hashlib.sha256).digest())
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO oauth_states(nonce,issued_at,used_at) VALUES(?,?,NULL)",
                (nonce, issued),
            )
        return encoded + "." + signature

    def consume(self, state: str, *, now: int | None = None) -> str:
        try:
            encoded, supplied = state.split(".", 1)
        except (AttributeError, ValueError) as exc:
            raise ValueError("invalid state signature") from exc
        expected = _b64url(hmac.new(self.signing_key, encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("invalid state signature")
        try:
            payload = json.loads(_b64url_decode(encoded))
            issued = int(payload["iat"])
            nonce = str(payload["nonce"])
            return_to = _validate_return_path(str(payload["return_to"]))
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid state payload") from exc
        current = int(time.time() if now is None else now)
        if issued > current + 30 or current - issued > self.ttl_seconds:
            raise ValueError("state expired")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE oauth_states SET used_at=? WHERE nonce=? AND used_at IS NULL",
                (current, nonce),
            )
        if cursor.rowcount != 1:
            raise ValueError("state already used or unknown")
        return return_to


def build_authorize_url(
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    scopes: tuple[str, ...] = ("read:user", "user:email"),
) -> str:
    if not client_id or not redirect_uri.startswith("https://") or not state:
        raise ValueError("client identity, HTTPS redirect, and state are required")
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "allow_signup": "false",
        }
    )
    return "https://github.com/login/oauth/authorize?" + query


def create_app(
    *,
    client_id: str,
    redirect_uri: str,
    state_store: OAuthStateStore,
    exchange_code: Callable[[str], Mapping[str, str]],
) -> FastAPI:
    """Build the public OAuth boundary with state validation before exchange."""

    app = FastAPI(title="ECHO OAuth", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.get("/health")
    async def health() -> dict[str, object]:
        return {"status": "ok", "oauth_provider": "github", "state_store": "sqlite"}

    @app.get("/oauth/start")
    async def oauth_start(return_to: str = "/") -> RedirectResponse:
        try:
            state = state_store.issue(return_to)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse(
            build_authorize_url(client_id=client_id, redirect_uri=redirect_uri, state=state)
        )

    @app.get("/oauth/callback")
    async def oauth_callback(code: str, state: str) -> dict[str, str]:
        try:
            return_to = state_store.consume(state)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            identity = exchange_code(code)
        except Exception as exc:
            raise HTTPException(status_code=502, detail="GitHub token exchange failed") from exc
        login = identity.get("login")
        if not isinstance(login, str) or not login:
            raise HTTPException(status_code=502, detail="GitHub identity response was invalid")
        return {"status": "authorized", "login": login, "return_to": return_to}

    return app
