# lthm-resume

Personal resume/portfolio site with a private stats dashboard and tools area.

## What is in this repo

- Public portfolio page at `/`
- Private stats dashboard at `/stats`
- Plaintext stats import page at `/stats/import`
- Raw drilldown endpoint for HTMX partial updates at `/stats/raw`

## Tech stack

- Python
- Flask
- pandas
- SQLite (in-memory data shaping for analytics)
- Plotly
- HTMX
- Jinja2 templates
- Waitress (serving)

## Project layout

- `app.py`: Flask app and routes
- `stats_service.py`: parsing, dedupe, analytics, chart generation, import logic
- `content.py`: public page content data
- `templates/`: Jinja templates
- `static/`: styles, JS, images
- `stats/`: source data files used by the private dashboard

## Requirements

- Python 3.10+ (3.11+ recommended)

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Environment variables

- `FLASK_SECRET_KEY` (required in production)
- `PASSKEY_SETUP_SECRET` (required until the first passkey is registered)
- `PASSKEY_RP_NAME` (optional, default `Louie Private Tools`)
- `PASSKEY_RP_ID` (optional locally, required explicitly in production)
- `PASSKEY_ALLOWED_ORIGINS` (optional locally, required explicitly in production)
- `PASSKEY_USER_NAME` (optional, default `louie`)
- `PASSKEY_USER_DISPLAY_NAME` (optional, default `Louie`)
- `PASSKEY_STORE_PATH` (optional override for the passkey JSON file)
- `PRIVATE_LOGIN_SECRET` (optional obscurity gate for `/login`; not primary auth)
- `PRIVATE_SESSION_LIFETIME_MINUTES` (optional, default `720`)
- `SESSION_COOKIE_SECURE` (set `true` on deployed hosts)
- `STATS_DIR` (optional override for stats file storage location)
- `PORT` (optional, default `8000`)
- `HOST` (optional, default `localhost`)
- `WAITRESS_THREADS` (optional, default `8`)

Example:

```bash
export FLASK_SECRET_KEY="replace-with-long-random-secret"
export PASSKEY_SETUP_SECRET="generate-a-random-bootstrap-secret"
export PASSKEY_RP_ID="localhost"
export PASSKEY_ALLOWED_ORIGINS="http://localhost:8000"
export PASSKEY_USER_NAME="louie"
export PASSKEY_USER_DISPLAY_NAME="Louie"
export PRIVATE_LOGIN_SECRET="a-long-random-login-url-secret"
export SESSION_COOKIE_SECURE="false"
export STATS_DIR="./stats"
```

## Run locally

Option 1 (same behavior as code entrypoint):

```bash
python3 app.py
```

Option 2 (same as `Procfile` style):

```bash
python3 -m waitress --listen=0.0.0.0:${PORT:-8000} app:app
```

Health endpoint:

- `GET /healthz` -> `{"status":"ok"}`

## Stats data format

Dashboard data is loaded from markdown/text files in `stats/`:

- `Home.md`
- `Home  Work.md`
- `Work Home.md`
- `Work.md`
- `Sleep.md`

Expected event line format:

```text
Event text at DD/MM/YYYY, HH.MM
```

Example:

```text
Left home at 05/03/2026, 08.14
```

Notes:

- Non-event lines are ignored.
- Events are deduplicated by `(source, event text, timestamp)`.
- Importing a full file repeatedly is supported.

## Private access flow

1. Open `/login`
   If `PRIVATE_LOGIN_SECRET` is set, use `/<your-secret>/login`
2. If no passkey exists yet, unlock setup with `PASSKEY_SETUP_SECRET`
3. Register the first passkey in the browser
4. Sign in with that passkey for `/nav`, `/stats`, `/split`, and `/passkeys`
5. Register a second passkey from `/passkeys` for recovery

## Deploying to Azure App Service

This repo includes:

- `Procfile`:
  - `web: sh -c 'python3 -m waitress --listen=0.0.0.0:${PORT:-8000} app:app'`

Recommended app settings in Azure:

- `FLASK_SECRET_KEY`
- `PASSKEY_SETUP_SECRET=...`
- `PASSKEY_RP_ID=your.custom.domain`
- `PASSKEY_ALLOWED_ORIGINS=https://your.custom.domain`
- `PASSKEY_RP_NAME=Louie Private Tools`
- `PASSKEY_STORE_PATH=/home/site/data/stats/.passkeys.json`
- `PRIVATE_LOGIN_SECRET=...` (optional)
- `STATS_DIR=/home/site/data/stats`
- `SESSION_COOKIE_SECURE=true`
- `SCM_DO_BUILD_DURING_DEPLOYMENT=true` (if using Oryx build)

Also ensure `requirements.txt` is present (it is) so dependencies install on deploy.

Behavior notes on Azure:

- If `STATS_DIR` is not set, the app auto-uses `/home/site/data/stats` when running on App Service.
- On first startup in Azure, it seeds that directory from the repo `stats/` files if it is empty.
- This avoids write failures when the deployed app package is mounted read-only.
- Keep the app single-instance if you use the file-backed passkey store on App Service.

### Deployment troubleshooting (`409 Conflict` from OneDeploy)

If GitHub Actions shows `Failed to deploy web package ... Conflict (CODE: 409)`:

1. Check that only one deployment source is active (GitHub Actions), not a second Deployment Center source.
2. Restart the App Service once, then rerun the workflow.
3. Ensure no concurrent workflow runs are active for the same branch.

This repo workflow includes concurrency protection and an automatic retry path with restart only when attempt 1 fails.
