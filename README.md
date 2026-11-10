# TrustVault — Secure Document Sharing

TrustVault is a Flask application for uploading documents privately and sharing them with explicit Viewer or Editor permissions. Authorization is checked by the server on each protected document action; hiding a button in the browser is not treated as a security control.

## Implemented features

- User registration and login with Werkzeug password hashing.
- Public registration creates Owner accounts only; Admin accounts are provisioned through a Flask CLI command.
- Private file storage outside the public `static` directory, with random server-side storage names.
- Document upload, download, rename and deletion.
- Owner-controlled sharing and permission revocation.
- Viewer access: read/download only. Editor access: read/download and rename. Delete and permission management remain Owner/Admin operations.
- Admin access to documents and the audit page.
- Audit events for registration, login success/failure, logout, uploads, downloads, renames, deletes, permission changes and denied access.
- CSRF protection on state-changing forms, extension allowlisting and a 10 MB request/file limit.

## Run locally (Windows PowerShell)

```powershell
git clone https://github.com/CHINNAMMANIMITHA/TrustValue_project.git
cd TrustValue_project
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

For Windows Command Prompt, activate with `venv\\Scripts\\activate` instead. On macOS/Linux use `source venv/bin/activate`.

## Create an Admin account

Set these environment variables without committing their values:

- `ADMIN_USERNAME`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD` (at least 12 characters)

Then run:

```bash
flask --app app create-admin
```

There is intentionally no public Admin registration option.

## Run tests

```bash
pytest -q
```

The security tests cover Viewer/Editor boundaries, Owner/Admin access, unauthorized document access, attempted role escalation during registration, upload extension validation and audit events. Run them locally after making changes. A passing test suite is useful evidence, not proof that the application is vulnerability-free.

## Render / production configuration

Configure a strong random `SECRET_KEY`, `DATABASE_URL` (prefer managed PostgreSQL), `COOKIE_SECURE=true`, and `ADMIN_USERNAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` as appropriate. Use HTTPS. The database and private upload directory must be on persistent storage; free/ephemeral instances may lose local files or SQLite data when restarted or redeployed. Set `UPLOAD_FOLDER` to a persistent mounted path when your hosting plan supports one. Run with `gunicorn app:app`.

Do not use the development fallback secret in production. Do not commit credentials or uploaded documents. Back up the database and file volume.

## Known limitations / future work

- Extension allowlisting does not inspect file contents or detect malware. Add file signature validation and antivirus scanning before production use.
- Audit logs are stored in the application database. A privileged database operator could alter them; stronger deployments should export logs to append-only external storage.
- Add rate limiting, password reset with verified email, MFA, automated dependency scanning and broader security testing before production use.
- This project is an assessment prototype, not a certified secure document-management service.

## Repository documentation

See `THREATS.md` for the threat model and `PROMPTS.md` for the AI-use log. Complete the prompt log using your actual work dates, findings, corrections and real commit links; do not invent entries or commit links.
