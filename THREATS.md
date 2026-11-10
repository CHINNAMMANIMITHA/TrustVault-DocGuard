# TrustVault threat model

## Scope and assets

Assets: document contents, account credentials, role assignments, per-document permissions, and audit records.

Trust boundaries: browser-to-Flask requests; authenticated user-to-document authorization; Flask-to-database; Flask-to-private upload storage; and deployment secrets/persistent volumes.

## Threats, controls and tests

| Threat | Control in this project | Test / verification approach |
|---|---|---|
| Unauthenticated document access | Login required on protected document routes | Request a document while logged out; expect login redirect |
| IDOR / guessing another document ID | Server checks owner, Admin role or explicit read permission for each download; edit routes require edit permission | Log in as unrelated user and request a known ID; expect 403 |
| Viewer changes document | Rename requires edit permission; Viewer has read-only permission | Viewer POSTs rename; expect 403 |
| Editor deletes or shares a document | Delete and share are restricted to Owner/Admin | Editor POSTs delete/share; expect 403 |
| User self-assigns Admin | Public registration always sets role to `owner`; Admin is created through CLI | Submit `role=admin` during registration; stored role remains `owner` |
| CSRF against state-changing routes | Flask-WTF CSRF protection | Send POST without a valid CSRF token in a CSRF-enabled test/deployment; expect rejection |
| Upload path traversal | `secure_filename` plus random server-generated storage name | Upload a filename containing traversal segments; confirm stored path remains in private upload directory |
| Disallowed or oversized upload | Extension allowlist and 10 MB limit | Upload a disallowed extension or oversized body; request is rejected |
| Revoked access remains usable | Permission is queried from the database for each protected request | Revoke permission, then request download; expect 403 |
| Ordinary user tampers with audit history | No user-facing audit mutation route; audit writes are performed by application code | Inspect routes and verify ordinary accounts cannot open `/admin/audit` |
| Password database disclosure | Werkzeug password hash functions; plaintext password is not stored | Inspect `password_hash` field and confirm it is a hash |

## Residual risks

The extension allowlist does not identify malware or validate file signatures. The audit table is not tamper-proof against a database administrator or compromised application process. The application also needs production rate limiting, stronger login abuse controls, MFA, verified-email password reset, append-only external audit storage, dependency scanning, backups and broader penetration testing. `X-Forwarded-For` must not be trusted unless a known reverse proxy strips and sets it correctly. Deploy with a strong secret, HTTPS, persistent database and private file storage.

## Security boundary

A user interface control is not authorization. Every sensitive route must independently check the current authenticated user's role and document permission before reading or changing document data.
