# Verification matrix

| Boundary | Positive evidence | Negative evidence |
|---|---|---|
| State | Valid unexpired state returns its local path | Tamper, expiry, and replay fail |
| Redirect | Local absolute path is preserved | Absolute external and protocol-relative paths fail |
| Authorization URL | Client, callback, scopes, and state are exact | Missing or malformed configuration fails |
| Callback ordering | State is consumed before exchange | Invalid state never invokes exchange |
| Token exchange | GitHub user identity resolves | Token is absent from evidence and API errors fail closed |
| Local session | Callback creates a signed, expiring, durable session nonce | Tampered, expired, unknown, and revoked cookies fail |
| Logout | Session nonce is revoked before the cookie is deleted | Reusing the logged-out cookie is rejected |
| Secret boundary | File-mounted client/state/session keys initialize | Direct secret environment variables fail startup |
| HTTP | Callback uses a safe `303` plus `Secure; HttpOnly; SameSite=lax` | Security headers prevent framing and content sniffing |

Certification must bind this evidence, a real GitHub code exchange, and the deployed runtime to one immutable commit SHA.
