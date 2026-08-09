# Architecture

`GET /oauth/start` validates a local return path, stores a random nonce with an expiry, signs the state envelope, and redirects to GitHub with the exact registered callback and minimal scopes. `GET /oauth/callback` verifies the HMAC, rejects expired or replayed nonces, marks the nonce consumed atomically, and only then exchanges the short-lived code.

The GitHub client sends the client secret only to the configured token endpoint. It uses the returned token once to call `/user`, validates the expected identity shape, and returns only the login. The token is neither stored nor included in evidence.
