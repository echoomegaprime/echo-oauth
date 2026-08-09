# ECHO OAuth

[![CI](https://github.com/echoomegaprime/echo-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/echoomegaprime/echo-oauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-c9a227.svg)](LICENSE)

A narrow, production-oriented GitHub OAuth boundary for ECHO applications. It creates signed single-use state, rejects open redirects, exchanges authorization codes server-side, validates the GitHub identity, and discards access tokens before returning safe evidence.

## Security properties

- State is an HMAC-signed opaque value with a bounded lifetime and a persistent SQLite replay fence.
- Callback state is consumed before the authorization code is exchanged.
- Return paths are local absolute paths only; external and protocol-relative redirects are rejected.
- Client secrets and access tokens never appear in responses, persisted state, or committed files.
- Missing credentials fail startup closed.

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
export ECHO_GITHUB_OAUTH_CLIENT_ID="your-client-id"
export ECHO_GITHUB_OAUTH_CLIENT_SECRET="from-your-secret-manager"
export ECHO_GITHUB_OAUTH_STATE_KEY="a-random-key-of-at-least-32-characters"
uvicorn app:app --host 127.0.0.1 --port 8080
```

Windows PowerShell uses `.\.venv\Scripts\Activate.ps1` and `$env:NAME=...` assignments.

## Verify

```bash
python -m pytest -q
python -m compileall -q src app.py
```

See [Architecture](docs/ARCHITECTURE.md), [Operations](docs/OPERATIONS.md), and [Security Policy](SECURITY.md).
