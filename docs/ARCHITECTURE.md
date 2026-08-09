# Architecture

`GET /oauth/start` validates a local return path, stores a random nonce with an expiry, signs the state envelope, and redirects to GitHub with the exact registered callback and minimal scopes. `GET /oauth/callback` verifies the HMAC, rejects expired or replayed nonces, atomically consumes the nonce, and only then exchanges the short-lived code.

The GitHub client sends the client secret only to the configured token endpoint. It uses the returned token once to call `/user`, validates the identity shape, then drops the token. The callback persists only a random local session nonce, login, issue/expiry timestamps, and revocation state. A separate HMAC key signs the opaque session cookie; neither key nor provider token is stored in the session database.

`GET /session` verifies the cookie signature, expiry, durable nonce, and revocation flag before returning the non-secret login. `POST /logout` revokes that nonce before deleting the cookie. Callback responses are `303` redirects to validated local paths, and the public gateway rejects external upstream `Location` values.
