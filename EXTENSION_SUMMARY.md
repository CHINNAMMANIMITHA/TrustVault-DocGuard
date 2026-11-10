# Extension summary

This folder is an extension of the supplied TrustVault project, not a replacement or a new application.

Changes made in this extension package:

1. Expanded `tests/test_security.py` to cover Viewer read-only behavior, Editor rename boundaries, Owner/Admin access, denied sharing/deletion, public-registration role escalation, upload extension validation, audit events, and permission revocation.
2. Updated `README.md` with clearer Windows/macOS/Linux setup steps, permission definitions, testing instructions and production storage warnings.
3. Expanded `THREATS.md` with explicit threat/control/test mapping and residual risks.
4. Updated `app.py` so deployments can set `UPLOAD_FOLDER` for a persistent private volume, and legacy `postgres://` database URLs are normalized for SQLAlchemy.
5. Stopped trusting the raw client-supplied `X-Forwarded-For` header for audit IP addresses by default.

## Important verification note

The source was reviewed and the tests were expanded, but the test suite could not be executed in the packaging environment because the required Flask/Werkzeug dependencies were not installed and package downloads were unavailable. Run `pip install -r requirements.txt` followed by `pytest -q` on your computer, review any failures, and only then describe the tests as passing.

Do not copy invented dates, results or commit links into `PROMPTS.md`. Add your actual work-session details and Git commit URLs yourself as you make the extension commits.
