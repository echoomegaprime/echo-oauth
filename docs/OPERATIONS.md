# Operations

Provide the client ID, client secret, and state-signing key through a secret manager. Keep the SQLite state database on persistent storage so replay detection survives ordinary restarts. Register the exact callback URL; do not use wildcard callbacks.

Before deployment, run tests and compilation, boot a staging container with non-production credentials, check `/health`, and exercise start plus callback failure paths. Production promotion requires an authorization-code exchange against GitHub and identity verification without logging the code or token.

Rotate the client secret and state key in a controlled window. Rotating the state key invalidates outstanding authorizations by design; users can safely restart the flow.
