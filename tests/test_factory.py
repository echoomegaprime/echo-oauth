from __future__ import annotations

from pathlib import Path

import pytest

from echo_oauth.factory import create_runtime_from_environment


def _write(path: Path, value: str) -> str:
    path.write_text(value, encoding="utf-8")
    return str(path)


def test_oauth_factory_loads_secrets_from_files(tmp_path: Path) -> None:
    app = create_runtime_from_environment(
        {
            "ECHO_GITHUB_OAUTH_CLIENT_ID": "Ov23exampleclientid",
            "ECHO_GITHUB_OAUTH_CLIENT_SECRET_FILE": _write(tmp_path / "client", "client-secret"),
            "ECHO_GITHUB_OAUTH_CALLBACK_URL": "https://oauth.github.echo-op.com/oauth/callback",
            "ECHO_GITHUB_OAUTH_STATE_KEY_FILE": _write(tmp_path / "state", "s" * 64),
            "ECHO_GITHUB_OAUTH_SESSION_KEY_FILE": _write(tmp_path / "session", "k" * 64),
            "ECHO_GITHUB_OAUTH_STATE_DB": str(tmp_path / "state.sqlite3"),
            "ECHO_GITHUB_OAUTH_SESSION_DB": str(tmp_path / "session.sqlite3"),
        }
    )
    assert app.title == "ECHO OAuth"


def test_oauth_factory_rejects_direct_environment_secrets(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="secret values must be supplied through files"):
        create_runtime_from_environment(
            {
                "ECHO_GITHUB_OAUTH_CLIENT_SECRET": "direct-secret",
                "ECHO_GITHUB_OAUTH_STATE_DB": str(tmp_path / "state.sqlite3"),
            }
        )
