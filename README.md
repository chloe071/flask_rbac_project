# Flask RBAC Cyber Simulation Suite

![tests](https://github.com/chloe071/flask_rbac_project/actions/workflows/tests.yml/badge.svg)

A role-based access control (RBAC) Flask web application that simulates cybersecurity incident-response exercises. Users take on roles (lead, analyst, observer) and work through scenarios with timed injects, action and forensic logs, chat, a threat feed, and PDF reports.

## Features

- Registration, login, and logout with hashed passwords (Flask-Bcrypt)
- Three roles with role-protected dashboards: **lead** (admin), **analyst**, **observer**
- Scenario management with timed injects, branching paths, and replay
- Action and forensic logging per scenario
- Real-time public chat and an encrypted lead-only secure channel (Flask-SocketIO + Fernet)
- Threat intelligence feed and achievement badges
- PDF report generation through a separate Node/Puppeteer service
- REST API secured with an API token
- Caching (Flask-Caching) and background jobs (Celery + Redis)

## Tech Stack

Flask, Flask-Login, Flask-Bcrypt, Flask-SQLAlchemy, Flask-Migrate, Flask-SocketIO, Flask-Caching, Celery, Redis, Bootstrap 5, Node.js (Express + Puppeteer), pytest, GitHub Actions.

## Setup

```bash
git clone https://github.com/chloe071/flask_rbac_project.git
cd flask_rbac_project/flask_rbac_project
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Set environment variables:

```bash
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"   # omit to disable the REST API
# Optional, for Celery/Redis:
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"
```

Create the database and run the app:

```bash
flask --app app.py db upgrade
python app.py
```

### Creating a lead (admin) account

Users can register as **analyst** or **observer** only. To make someone a lead, register them first, then run:

```bash
flask --app app.py make-lead <username>
```

### Optional services

```bash
redis-server                                          # background jobs
celery -A tasks.celery_app worker --loglevel=info     # async report tasks
cd pdf-service && npm install && node server.js       # PDF service on port 3000
```

## Running Tests

```bash
pip install pytest
pytest -q
```

Tests use a temporary database, so they never modify your local data. They run automatically on every push via GitHub Actions.

## Security Design

| Control | How it works |
|---|---|
| Authentication | Flask-Login sessions; bcrypt-hashed passwords; minimum 8-character passwords |
| Authorization | `roles_required` / `admin_required` decorators on dashboards, scenario management, and reports |
| No self-promotion to admin | Registration only accepts `analyst` or `observer`; `lead` is granted by an operator via CLI |
| Chat identity | Socket handlers use the server-side session to identify the sender, not client-supplied user IDs |
| Secure channel | `/secure` namespace connections are rejected unless the user is a lead |
| Message access | Users can only read messages addressed to a role they hold |
| API | Token compared in constant time (`hmac.compare_digest`); API disabled if no token is configured |
| Secrets | Secret key and API token come from environment variables; no insecure defaults |
| Cookies | `HttpOnly` and `SameSite=Lax` session cookies; debug mode off unless `FLASK_DEBUG=1` |
| PDF service | Node service binds to `127.0.0.1` only, so it can't be used from the network to render arbitrary pages |
| Dependencies | Dependabot checks Python and npm packages weekly; npm packages updated to patched versions (0 known vulnerabilities) |

### Security fix log

A review of the app found and fixed these issues, each with a regression test in `test_app.py`:

1. **Privilege escalation at registration** — anyone could choose the `lead` (admin) role when signing up. Registration now accepts only `analyst` or `observer`.
2. **Chat impersonation** — chat handlers trusted the `user` and `user_id` fields sent by the browser, so a user could post as someone else. They now use the logged-in session.
3. **Unrestricted secure channel** — any logged-in user could open the lead-only secure chat or read lead messages. Both are now restricted by role.
4. **Default credentials** — the app fell back to a hardcoded secret key and API token. Those defaults are gone.

## Known Issues & Future Improvements

- **CSRF protection** is not yet enabled on forms (planned: Flask-WTF).
- **Secure chat encryption key** is generated at startup, so encrypted messages can't be decrypted after a restart. Planned: load the key from an environment variable.
- **Celery PDF jobs** may need more work for reliable app-context handling.
- **Deployment**: not yet containerized (Docker).
- **UI**: planned improvements to scenario dashboards, alerts, and onboarding.

## Project Structure

```text
flask_rbac_project/
├── app.py               # Flask app, models, routes, socket handlers, CLI
├── tasks.py             # Celery tasks
├── celery_worker.py     # Celery worker entry point
├── test_app.py          # Route and security tests
├── migrations/          # Flask-Migrate (Alembic) migrations
├── pdf-service/         # Node/Puppeteer PDF generator
├── templates/           # Jinja2 templates
└── requirements.txt
```

## License

MIT — see [MIT License.md](flask_rbac_project/MIT%20License.md).

## Author

Chloe Cedano

### Notes for Recruiters

This project demonstrates full-stack development with a focus on access control, real-time features, and background processing. The security fix log above documents issues I found during review, how I fixed them, and the tests that verify each fix.
