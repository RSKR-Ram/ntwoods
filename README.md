# HRMS Backend (Flask + Supabase Postgres)

Flask backend for the HRMS React frontend (`HRMS-NTWOODS`) using Supabase Postgres (via SQLAlchemy).

## Quickstart (local)

```bash
cd backend-flask
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env
python legacy_app.py
```

Backend runs on `http://127.0.0.1:5002` (see `PORT`).

## API

- `GET /health`
- `POST /api` (single action router; matches the frontend client)
  - Body: `{ "action": "ACTION_NAME", "token": "<sessionToken|null>", "data": { ... } }`
- `GET /files/<fileId>?token=<sessionToken>`
- REST endpoints (preferred for new modules)
  - Auth: `Authorization: Bearer <sessionToken>` (or `X-Session-Token`)
  - Employee profile (enterprise): `GET /api/employees/<employeeId>/profile`
  - Employee docs: `GET /api/employees/<employeeId>/docs`, `POST /api/docs/upload`, `GET /api/docs/download/<docId>`
  - Role history: `POST /api/employees/<employeeId>/role-change`
  - Aadhaar+DOB duplicate check: `POST /api/employees/check-duplicate`
  - Exit workflows: `POST /api/exit/*` (see below)
  - Training tests: `GET /api/training/modules`, `POST /api/training/*`, `GET /api/training/video/stream/<moduleId>`

Note: many legacy endpoints return HTTP 200 even on errors; always check `{ ok: true|false }` in the JSON.

## Schema migrations

This codebase does not use Alembic yet.

- Tables are created via `Base.metadata.create_all()` at startup.
- Incremental (idempotent) schema evolution + backfills are handled in `schema.ensure_schema()` (called at startup).

Production recommendation: deploy backend first, let it apply schema changes, then deploy frontend.

## Employee documents (enterprise)

- Upload: `POST /api/docs/upload` (multipart: `employeeId`, `docType`, `visibility`, `file`)
- Secure download: `GET /api/docs/download/<docId>` (permission check, then stream/redirect)
- Storage modes:
  - `FILE_STORAGE_MODE=local` (dev): bytes stored in `UPLOAD_DIR`
  - `FILE_STORAGE_MODE=gas` (prod option): uploads forwarded to Google Apps Script (Drive); download endpoint enforces auth then redirects

## Exit workflows (strict server-side rules)

Endpoints:
- `POST /api/exit/start-notice` `{ employeeId, noticeDays }` → SELF exit case
- `POST /api/exit/mark-absconded` `{ employeeId, absentSince, remark }` → ABSCONDED exit case
- `POST /api/exit/terminate-init` `{ employeeId, lastWorkingDay, remark }` → TERMINATED exit case
- `POST /api/exit/settlement-clear` `{ exitId, settlementDocId }`
- `POST /api/exit/attach-termination-letter` `{ exitId, terminationLetterDocId }`
- `POST /api/exit/complete` `{ exitId }`

Config (settings table keys):
- `EXIT_NOTICE_DAYS_DEFAULT` (default `30`)
- `EXIT_ABSCONDED_REQUIRE_SETTLEMENT` (default `false`)

## Training tests + video streaming

- Admin config: `GET /api/training/admin/questions/<moduleId>`, `POST /api/training/admin/save-questions`
- Attempts: `POST /api/training/start-test`, `POST /api/training/submit-test`
- Video: `GET /api/training/video/stream/<moduleId>?index=0` (proxy/stream; best-effort URL hiding)

## Audit logs + correlation IDs

- Every request gets an `X-Request-ID` response header.
- Critical actions append to `audit_log` with `correlation_id` to trace end-to-end activity.

## Supabase setup

1) Create a Supabase project.
2) Copy the Postgres connection string (prefer the “Connection pooling” URL when available).
3) Set `DATABASE_URL` in `.env` (include `?sslmode=require`).

Important: tune `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, and Gunicorn `WEB_CONCURRENCY` to stay within Supabase connection limits.

## Production env (minimum)

- `APP_ENV=production`
- `DATABASE_URL=...`
- `PEPPER=...` (long random string)
- `SERVER_SALT=...` (optional; defaults to `PEPPER`)
- `GOOGLE_CLIENT_ID=...`
- `ALLOWED_ORIGINS=https://your-frontend-domain` (comma-separated; include GitHub Pages origin if used)
- `MAX_EMPLOYEE_DOC_UPLOAD_MB=20` (optional)

## Deploy (Gunicorn)

This repo includes:
- `Procfile` (process entry)
- `gunicorn.conf.py` (workers/threads via env vars)
- `wsgi.py` (Gunicorn import target)

Start command:

```bash
gunicorn wsgi:app -c gunicorn.conf.py
```
