# ECHO OAuth

[![CI](https://github.com/echoomegaprime/echo-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/echoomegaprime/echo-oauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-c9a227.svg)](LICENSE)

A narrow, production-oriented GitHub OAuth boundary for ECHO applications. It creates signed single-use state, rejects open redirects, exchanges authorization codes server-side, validates the GitHub identity, discards the provider token, and issues a revocable local session cookie.

## Security properties

- State is an HMAC-signed opaque value with a bounded lifetime and a persistent SQLite replay fence.
- Callback state is consumed before the authorization code is exchanged.
- Return paths are local absolute paths only; external and protocol-relative redirects are rejected.
- Provider access tokens never appear in responses or persisted state and are discarded after the identity lookup.
- Local sessions use a separate signing key, a durable nonce, bounded expiry, revocation, and a `Secure; HttpOnly; SameSite=lax` cookie.
- Client, state, and session secrets are loaded from protected files; direct secret environment variables fail startup.
- Missing credentials fail startup closed.

Production entrypoint: `https://github.echo-op.com/oauth/start`. The exact registered callback is `https://github.echo-op.com/oauth/callback`; same-origin session state is available at `GET /session`, and `POST /logout` revokes the durable session and clears the cookie.

## Verify locally

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
python -m pytest -q
python -m compileall -q src app.py
```

## Production configuration

Set the non-secret client ID, exact callback URL, and persistent state/session database paths. Supply the client secret, state-signing key, and session-signing key only through the `*_FILE` settings documented in [Operations](docs/OPERATIONS.md).

See [Architecture](docs/ARCHITECTURE.md), [Operations](docs/OPERATIONS.md), and [Security Policy](SECURITY.md).
