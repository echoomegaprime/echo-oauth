from __future__ import annotations

import os
from pathlib import Path

from echo_oauth import GitHubOAuthClient, OAuthStateStore, create_app


ROOT = Path(__file__).resolve().parent
CLIENT_ID = os.environ.get("ECHO_GITHUB_OAUTH_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("ECHO_GITHUB_OAUTH_CLIENT_SECRET", "")
CALLBACK_URL = os.environ.get("ECHO_GITHUB_OAUTH_CALLBACK_URL", "https://echo-op.com/auth/github/callback")
STATE_SIGNING_KEY = os.environ.get("ECHO_GITHUB_OAUTH_STATE_KEY", "")
STATE_DB = Path(os.environ.get("ECHO_GITHUB_OAUTH_STATE_DB", ROOT / "var" / "oauth-state.sqlite3"))

if not CLIENT_ID or not CLIENT_SECRET or len(STATE_SIGNING_KEY) < 32:
    raise RuntimeError("GitHub OAuth credentials and a 32-character state key are required")

oauth_client = GitHubOAuthClient(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri=CALLBACK_URL,
)
state_store = OAuthStateStore(STATE_DB, signing_key=STATE_SIGNING_KEY, ttl_seconds=600)
app = create_app(
    client_id=CLIENT_ID,
    redirect_uri=CALLBACK_URL,
    state_store=state_store,
    exchange_code=oauth_client.exchange,
)
