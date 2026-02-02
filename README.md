# HRMS Backend (Flask + Supabase/Postgres)

Production-ready Flask API with background task processing, caching, and comprehensive deployment options.

## Quick Start (Local Development)

```bash
cd ntwoods
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

pip install -r requirements.txt
copy .env.example .env  # Edit with your values

# Run Flask dev server
python legacy_app.py

# Or with Gunicorn
gunicorn wsgi:app -c gunicorn.conf.py
```

Backend runs on `http://127.0.0.1:5002`

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_ENV` | No | `development` | `development`, `production`, `testing` |
| `DATABASE_URL` | Yes | `sqlite:///./hrms.db` | Postgres URL for production |
| `REDIS_URL` | No | - | Redis URL for caching + Celery |
| `PEPPER` | Yes | - | Long random string for hashing |
| `JWT_SECRET` | Yes (prod) | `dev-secret` | JWT signing key |
| `GOOGLE_CLIENT_ID` | Yes (prod) | - | Google OAuth client ID |
| `CORS_ORIGINS` | No | `*` | Comma-separated allowed origins |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `RATE_LIMIT_DEFAULT` | No | `300 per minute` | Default rate limit |
| `SENTRY_DSN` | No | - | Sentry error tracking DSN |
| `WEB_CONCURRENCY` | No | `2` | Gunicorn workers |
| `CELERY_CONCURRENCY` | No | `4` | Celery worker concurrency |

---

## API Endpoints

### Health & Status
- `GET /health` - Lightweight health check (always 200 if process running)
- `GET /ready` - Readiness check (DB + Redis connectivity)
- `GET /version` - App version info

### Background Jobs
- `POST /api/v1/jobs/example` - Enqueue example task
- `POST /api/v1/jobs/notify` - Enqueue notification
- `GET /api/v1/jobs/<job_id>` - Get job status
- `DELETE /api/v1/jobs/<job_id>` - Cancel job

### Core API
- `POST /api` - Single action router (legacy)
- `GET /files/<fileId>?token=` - File download

See `openapi.yaml` for full API documentation.

---

## Running with Celery (Background Tasks)

```bash
# Terminal 1: Run Flask
gunicorn wsgi:app -c gunicorn.conf.py

# Terminal 2: Run Celery worker
celery -A app.tasks.celery_app worker --loglevel=INFO

# Test a job
curl -X POST http://localhost:5002/api/v1/jobs/example \
  -H "Content-Type: application/json" \
  -d '{"duration_seconds": 3}'
```

---

## Deploy to Render

### Option 1: Using render.yaml (Blueprint)

1. Push to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com)
3. Click **New → Blueprint**
4. Connect your repo (auto-detects `render.yaml`)
5. Set environment secrets in dashboard:
   - `PEPPER`
   - `JWT_SECRET`
   - `GOOGLE_CLIENT_ID`
   - `CORS_ORIGINS`

### Option 2: Manual Setup

**Web Service:**
- Build: `pip install -r requirements.txt`
- Start: `gunicorn wsgi:app -c gunicorn.conf.py`
- Health check: `/health`

**Background Worker:**
- Start: `celery -A app.tasks.celery_app worker --loglevel=INFO`

**Services needed:**
- Postgres database
- Redis (for Celery + caching)

---

## Deploy to VPS (Ubuntu)

### Option 1: Docker Compose (Recommended)

```bash
# Clone repo
git clone <repo-url> /var/www/hrms
cd /var/www/hrms

# Edit environment variables
cp ntwoods/.env.example ntwoods/.env
nano ntwoods/.env  # Set production values

# Build and run
docker compose up -d

# View logs
docker compose logs -f backend worker
```

### Option 2: Manual Setup

#### 1. Install dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.12 python3.12-venv nginx redis-server postgresql

# Setup app
cd /var/www/hrms-api
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Create .env
cp .env.example .env
nano .env
```

#### 2. Setup systemd services

```bash
# Copy service files
sudo cp systemd/gunicorn.service /etc/systemd/system/
sudo cp systemd/celery.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable gunicorn celery
sudo systemctl start gunicorn celery
```

#### 3. Configure Nginx

```bash
sudo cp nginx/app.conf /etc/nginx/sites-available/hrms-api
sudo ln -s /etc/nginx/sites-available/hrms-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### 4. SSL with Certbot

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.yourdomain.com
```

#### 5. Basic Hardening

```bash
# Firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

---

## Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_health.py -v

# With coverage
pytest tests/ --cov=. --cov-report=html
```

---

## Project Structure

```
ntwoods/
├── app/
│   ├── __init__.py          # App factory
│   ├── config.py             # Environment config
│   ├── db.py                 # MongoDB connection
│   ├── middlewares/          # Request middleware
│   │   ├── compression.py
│   │   ├── error_handler.py
│   │   ├── logging.py
│   │   ├── rate_limit.py
│   │   ├── request_id.py
│   │   └── security_headers.py
│   ├── routes/               # API blueprints
│   │   ├── auth.py
│   │   ├── core.py
│   │   ├── jobs.py
│   │   └── reports.py
│   ├── tasks/                # Celery tasks
│   │   ├── __init__.py
│   │   └── example_task.py
│   └── utils/
├── nginx/app.conf            # Nginx config
├── systemd/                  # systemd units
├── tests/                    # pytest tests
├── gunicorn.conf.py
├── render.yaml               # Render Blueprint
├── requirements.txt
└── wsgi.py
```

---

## Troubleshooting

**Connection timeout to database:**
- Check `DATABASE_URL` format
- Ensure DB allows connections from your IP
- For Supabase, use the pooler URL (port 6543)

**Celery not processing tasks:**
- Verify `REDIS_URL` is correct
- Check Redis is running: `redis-cli ping`
- View worker logs: `celery -A app.tasks.celery_app worker --loglevel=DEBUG`

**Rate limiting issues:**
- Adjust `RATE_LIMIT_DEFAULT` and `RATE_LIMIT_GLOBAL`
- Check `X-Forwarded-For` header is set by reverse proxy
