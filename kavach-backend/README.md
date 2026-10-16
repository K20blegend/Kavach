# Kavach backend

Kavach combines explainable website risk checks, scam message analysis, and practical security training. This repository is the complete backend API. A frontend can use the OpenAPI specification at `/openapi.json` or the interactive API console at `/docs`.

## Run on Windows

Python 3.12 or newer is required. From this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Or run `powershell -ExecutionPolicy Bypass -File scripts/start.ps1`. Open [the API console](http://127.0.0.1:8000/docs). Configuration is optional for local development; SQLite tables and a persistent development signing key are created automatically in `.data/`.

On Linux/macOS use `.venv/bin/python` in the equivalent commands. Copy `.env.example` to `.env` to change configuration. Environment variables take precedence over that file. `requirements.lock.txt` records the exact versions used for local verification; install it before `pip install -e . --no-deps` when reproducing that environment.

## Capabilities

- Website auditing: public DNS resolution, configurable IPv4 DNS blocklists, RDAP registration age, hostname-verified TLS inspection, Unicode homographs and brand edit distance, HTTP redirects and password-form observations.
- Message analysis: urgency, impersonation, financial lures, credential requests, reply-address mismatches, routing anomalies, SPF/DMARC policy discovery, and optional safe redirect inspection. Evidence includes offsets for highlighting the original message.
- Training: ten browser/email/SMS/chat scenarios, benign controls, difficulty filters, persistent attempts, false-positive penalties, feedback, XP, levels, and progress.
- Accounts: Argon2 password hashes, short-lived access JWTs, rotating opaque refresh tokens, immediate session logout, password changes and profile editing.
- History: explicit opt-in, user ownership, pagination, filtering, individual deletion, bulk deletion, and retention enforcement.
- Operations: health/readiness endpoints, structured errors, request IDs, body limits, rate limits, concurrent-scan limits, explicit CORS/host allowlists, and container packaging.

Analysis requires no paid API or language-model service. Third-party DNS, registry, and destination servers can be unavailable; the result reports those checks as `unknown`.

## API

The base path is `/api/v1`. JSON bodies use `Content-Type: application/json`. Authenticated requests use `Authorization: Bearer <access_token>`.

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/register` | Public | Register and open a session |
| POST | `/auth/login` | Public | Open a session |
| POST | `/auth/refresh` | Refresh token | Rotate the refresh token and issue access token |
| POST | `/auth/logout` | Signed in | Revoke the current session |
| GET / PATCH | `/auth/me` | Signed in | Read or update display name |
| POST | `/auth/password` | Signed in | Change password and invalidate every session |
| POST | `/audits/url` | Public | Audit a public HTTP(S) URL |
| POST | `/audits/message` | Public | Analyze email, SMS or social message |
| GET | `/history` | Signed in | List saved analyses; `kind`, `limit`, `offset` filters |
| GET / DELETE | `/history/{id}` | Owner | Read or remove an analysis |
| DELETE | `/history` | Signed in | Remove all saved analyses |
| GET | `/dashboard` | Signed in | Saved-analysis counts |
| GET | `/training/scenarios` | Public | Catalog; `difficulty` and `channel` filters |
| GET | `/training/scenarios/{id}` | Public | Simulated interface and selectable elements |
| POST | `/training/attempts` | Signed in | Begin a scenario |
| GET | `/training/attempts/{id}` | Owner | Read attempt state and completed feedback |
| POST | `/training/attempts/{id}/submit` | Owner | Grade selected element IDs |
| GET | `/training/progress` | Signed in | Accuracy, XP, levels, and completion |

`GET /health` reports liveness. `GET /health/ready` checks the database. `/docs`, `/redoc` and `/openapi.json` describe request schemas and account/history responses.

### Try an analysis

```powershell
$body = @{ url = 'https://example.com'; save_history = $false } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/v1/audits/url' -ContentType 'application/json' -Body $body
```

```json
POST /api/v1/audits/message
{
  "channel": "sms",
  "text": "Urgent: your bank account will be blocked. Send your OTP now to verify your account.",
  "inspect_links": false,
  "save_history": false
}
```

Both analysis endpoints return:

```json
{
  "id": null,
  "kind": "message",
  "created_at": "2026-10-16T10:00:00Z",
  "result": {
    "risk_score": 80,
    "verdict": "high_risk",
    "signals": [],
    "recommendations": [],
    "limitations": []
  }
}
```

This envelope illustrates the shape; scores and signal contents depend on the submitted evidence. Set `save_history: true` with an access token to receive a persistent analysis ID. URL results contain `trust_score`, `coverage`, and six `checks`; each check exposes its status, summary, evidence and score penalty. Message results contain `risk_score`, `signals`, `links`, `sender`, recommendations and limitations.

### Register and train

```json
POST /api/v1/auth/register
{
  "email": "you@example.com",
  "display_name": "Your name",
  "password": "choose-a-long-unique-password"
}
```

Save the returned `access_token` and `refresh_token`. Login accepts `email` and `password`; refresh accepts `refresh_token`. A refresh token is single-use: replace it with the new token after every successful refresh. Logout revokes the session, including previously issued access tokens. Password change accepts `current_password` and `new_password` and requires a fresh login afterward. Email addresses are account identifiers; this service does not send email or claim to verify email ownership.

Read a scenario, create an attempt with `{"scenario_id":"<id from catalog>"}`, then submit `{"selected_indicator_ids":["<element id>"]}` to its submit endpoint. A benign scenario may correctly require an empty list. Public scenario payloads contain no answer key. The first submission is final; identical retries return the existing result and changed retries return 409. Each scenario awards XP once per account. Render scenario text as text, and keep example links inert in the training UI.

## How scoring works

A website begins at 10 points; observed risk signals deduct points. Registration younger than 30 days deducts 2.5; 30–179 days deducts 1. HTTP deducts 2, failed certificate validation 3, and an observed DNS blocklist listing 4. Hostname lookalikes, downgrade redirects and unsafe password forms add their documented per-check penalties. Most unavailable checks deduct 0.5. An unconfigured DNSBL deducts nothing. The response exposes every penalty; the total is clamped to 0–10.

Scores below 5 are `high_risk`. Any failed check or score below 8 is `caution`. `low_risk` also requires completed DNS, TLS and HTTP checks and at least four completed checks; otherwise the verdict is `unknown`. Coverage is a count of completed checks, not a probability or a certification.

Message patterns carry fixed weights, with bonuses for combinations such as urgency plus a credential request. Scores are clamped to 0–100: below 25 is `low_risk`, 25–54 is `caution`, and 55 or higher is `high_risk`. A keyword on its own does not establish a scam. Rules and weights live in `app/services/message_analysis.py`; website weights live in `app/services/url_audit.py`.

TLS proves transport security for a hostname, not the operator's intentions. An old domain can be compromised. Brand matching uses a limited brand list and common confusables. HTTP analysis reads a bounded prefix, does not run JavaScript, and does not execute a malware sandbox.

## Sender authenticity and privacy

SPF/DMARC DNS records describe a domain's policy. Their presence does **not** establish that a pasted message passed authentication. Sender, Received, and Authentication-Results headers are user-supplied and remain unverified. The service does not verify DKIM signatures or perform full SPF evaluation against an authenticated SMTP envelope. It reports this directly in the response.

Raw message bodies and headers are not stored. With history enabled, matched evidence, extracted URLs and sender observations in the result are stored and can contain personal information. URL results can include query strings. History is off by default. Records older than the configured retention period are deleted at startup and during the owner's history/save/dashboard access. This does not erase database backups; manage those separately.

Message link expansion is off by default because visiting a URL can notify its owner or activate a tracking link. Opting in visits at most three links. Defanged links remain inert. URL auditing intentionally contacts the destination and registry/DNS services. Request bodies, passwords, and raw headers are not written to application logs. Avoid enabling request-body logging at a proxy.

## Network limits

Only public HTTP(S) addresses on ports 80/443 are allowed. Credentials in URLs, local/private/reserved addresses, unsupported schemes, IPv4-mapped IPv6 and transition address ranges are rejected. Every HTTP hop resolves and validates all returned addresses, then pins the connection to those addresses while keeping hostname/TLS validation. Redirects are revalidated. Environment proxies and cookies are disabled. Fetching is bounded by time, redirect count, compressed bytes and decompressed bytes. A submitted analysis has an overall 25-second deadline.

DNS blocklists are disabled by default. Configure `KAVACH_DNSBL_ZONES` with a JSON array of provider zones you are permitted to query. IPv4 listings and provider error responses are distinguished; unavailable or disabled checks stay unknown. No empty blacklist response is substituted for a real lookup.

## Configuration and deployment

See `.env.example` for supported variables. All use the `KAVACH_` prefix. List settings are JSON arrays. Production requires a signing secret of at least 32 characters and explicit origins/hosts.

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

For Docker Compose, put the generated value in `.env` as `KAVACH_JWT_SECRET` and set a URL-safe `POSTGRES_PASSWORD`, then run `docker compose up --build`. Compose starts a PostgreSQL-backed API at port 8000 with a persistent database volume. This container configuration has not been executed as part of the local Windows verification.

For a separate PostgreSQL installation, install `.[postgres]` and set `KAVACH_DATABASE_URL=postgresql+psycopg://user:password@host:5432/kavach`. The initial schema is created at startup. Changes to an existing schema require an explicit migration; `create_all` does not migrate columns. Start one API process for initial schema creation.

Put public deployments behind HTTPS. Set actual public hosts and frontend origins. The included rate limiter and scan semaphore are per process; use gateway/distributed limits when scaling. Uvicorn is launched with proxy headers disabled. If deploying behind a proxy, configure trusted forwarded-header sources explicitly before enabling them. The backend is an assessment tool, so apply operator-controlled outbound network restrictions as another layer of protection.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check app tests
```

The automated suite uses mocked external services and a fresh isolated database. It covers private-network blocking, redirect revalidation, TLS/RDAP/DNSBL outcomes, unknown checks, message evidence/scoring, account isolation, token rotation/revocation, retention, immutable training submissions, and API error handling. Live internet checks are separate from these deterministic tests.

With the server running, `python scripts/smoke.py` checks the live API and deliberately audits `https://example.com` over the internet. Network availability can change the observed check coverage.

Implementation references: [FastAPI security](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/), [aiohttp connection and resolver configuration](https://docs.aiohttp.org/en/stable/client_advanced.html), and [IANA's RDAP bootstrap directory](https://data.iana.org/rdap/dns.json).
