# Verification matrix

| Boundary | Positive evidence | Negative evidence |
|---|---|---|
| State | Valid unexpired state returns its local path | Tamper, expiry, and replay fail |
| Redirect | Local absolute path is preserved | Absolute external and protocol-relative paths fail |
| Authorization URL | Client, callback, scopes, and state are exact | Missing or malformed configuration fails |
| Callback ordering | State is consumed before exchange | Invalid state never invokes exchange |
| Token exchange | GitHub user identity resolves | Token is absent from evidence and API errors fail closed |
| HTTP | Health and callback behavior are deterministic | Security headers prevent framing and content sniffing |

Certification must bind this evidence to an immutable commit SHA.
