from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from fastapi import FastAPI

from .runtime import GitHubOAuthClient, OAuthStateStore, SessionStore, create_app


_DIRECT_SECRETS = (
    "ECHO_GITHUB_OAUTH_CLIENT_SECRET",
    "ECHO_GITHUB_OAUTH_STATE_KEY",
    "ECHO_GITHUB_OAUTH_SESSION_KEY",
)


def _required(env: Mapping[str, str], name: str) -> str:
    value = str(env.get(name) or "").strip()
    if not value:
        raise ValueError(f"required environment setting is missing: {name}")
    return value


def _secret_file(env: Mapping[str, str], name: str) -> str:
    try:
        value = Path(_required(env, name)).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"required secret file is unreadable: {name}") from exc
    if not value:
        raise ValueError(f"required secret file is empty: {name}")
    return value


def create_runtime_from_environment(env: Mapping[str, str] | None = None) -> FastAPI:
    settings = dict(os.environ if env is None else env)
    if any(settings.get(name) for name in _DIRECT_SECRETS):
        raise ValueError("secret values must be supplied through files")
    client_id = _required(settings, "ECHO_GITHUB_OAUTH_CLIENT_ID")
    client_secret = _secret_file(settings, "ECHO_GITHUB_OAUTH_CLIENT_SECRET_FILE")
    callback = _required(settings, "ECHO_GITHUB_OAUTH_CALLBACK_URL")
    state_key = _secret_file(settings, "ECHO_GITHUB_OAUTH_STATE_KEY_FILE")
    session_key = _secret_file(settings, "ECHO_GITHUB_OAUTH_SESSION_KEY_FILE")
    state_db = Path(_required(settings, "ECHO_GITHUB_OAUTH_STATE_DB"))
    session_db = Path(_required(settings, "ECHO_GITHUB_OAUTH_SESSION_DB"))
    client = GitHubOAuthClient(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=callback,
    )
    return create_app(
        client_id=client_id,
        redirect_uri=callback,
        state_store=OAuthStateStore(state_db, signing_key=state_key, ttl_seconds=600),
        session_store=SessionStore(session_db, signing_key=session_key),
        exchange_code=client.exchange,
    )
