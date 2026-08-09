# Operations

## Configuration

Non-secret settings are `ECHO_GITHUB_OAUTH_CLIENT_ID`, `ECHO_GITHUB_OAUTH_CALLBACK_URL`, `ECHO_GITHUB_OAUTH_STATE_DB`, and `ECHO_GITHUB_OAUTH_SESSION_DB`. The databases must live on persistent storage so state replay fences, active sessions, and revocation survive restarts.

Secret settings are file paths: `ECHO_GITHUB_OAUTH_CLIENT_SECRET_FILE`, `ECHO_GITHUB_OAUTH_STATE_KEY_FILE`, and `ECHO_GITHUB_OAUTH_SESSION_KEY_FILE`. The process rejects the corresponding direct secret environment variables. Use independent random state and session keys and protect the files for the service identity only.

Register the exact public callback `https://github.echo-op.com/oauth/callback`; do not use wildcard callbacks. The managed tunnel exposes the OAuth runtime through the dedicated `github.echo-op.com` gateway hostname.

## Staging gate

Run the full test suite and compilation, boot the exact revision on a staging port with separate databases, and verify health, open-redirect rejection, expired/replayed state, secure cookie attributes, session validation, logout revocation, and absence of provider tokens from responses and both databases. Complete one real GitHub authorization-code exchange against the production callback before promotion without logging the code or token.

Rotate the client secret and signing keys in a controlled window. Rotating the state key invalidates outstanding authorizations; rotating the session key invalidates active cookies. Both fail closed and users can safely restart authorization.
