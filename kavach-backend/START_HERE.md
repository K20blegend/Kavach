# Kavach backend handoff

Start with `README.md` for the API reference, scoring rules, privacy behavior, and deployment notes.

## Start locally

Install Python 3.12 or newer, extract the ZIP, and open a terminal inside the `kavach-backend` folder.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Open `http://127.0.0.1:8000/docs` to use the API console. Local startup creates a fresh SQLite database. There are no preconfigured user accounts; register through the API. The default configuration works locally without an `.env` file. To customize it, copy `.env.example` to `.env` and fill in your own settings.

## Folder map

```text
kavach-backend/
  START_HERE.md           Recipient quick start and folder map
  README.md               Full API, configuration, scoring, and privacy guide
  pyproject.toml          Package metadata and dependency declarations
  requirements.lock.txt   Exact versions used for local verification
  .env.example            Configuration placeholders
  app/
    main.py               Application, middleware setup, and health endpoints
    config.py             Validated environment configuration
    database.py           Database engine and session management
    models.py             Accounts, sessions, and scan-history tables
    schemas.py            Account and analysis request/response schemas
    auth.py               Password hashing and session validation
    middleware.py         Request size, rate limits, and security headers
    api/                  Account, analysis, history, and training routes
    services/             URL auditing, networking, message analysis, training
  tests/                  Automated tests with mocked external services
  scripts/
    start.ps1             Windows launcher
    smoke.py              Live API check; intentionally contacts example.com
    package.py            Rebuild this shareable ZIP
  .github/workflows/      Continuous-integration checks
  Dockerfile              Container build
  compose.yaml            API and PostgreSQL deployment
  FILE_MANIFEST.sha256    Checksums of the packaged project files
```

## Verify

After installing the development dependencies, run `python -m pytest -q` and `python -m ruff check app tests scripts` using the virtual environment's Python. The backend's local verification passed 76 tests and a live API smoke check. Docker configuration is included but was not executed locally.

DNS blocklists require a provider configuration. Unavailable checks remain explicitly unknown. Production requires a new signing secret, appropriate hosts/origins, HTTPS, and your own deployment configuration; see `README.md`.

This archive contains source, tests, and setup/deployment files. It excludes the original machine's databases, credentials, virtual environment, caches, and session notes. Example account values and test secrets are fictional.
