# SIEM Copilot — Threat Hunting & Incident Investigation

A production-quality **Cyber Security SIEM Copilot** for SOC analysts. Built with React + TypeScript (Tailwind CSS) frontend and a FastAPI + SQLAlchemy backend — 9 screens, working detection rules, correlation engine, threat-hunting parser, and an AI Copilot with evidence-grounded analysis.

---

## Quick Start (Local — no environment variables required)

The backend defaults to SQLite. No database configuration is needed to run locally.

### 1. Backend (FastAPI + SQLite)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# API available at: http://localhost:8000
# Interactive docs: http://localhost:8000/docs
```

### 2. Frontend (React + Vite)

```bash
# In the project root
npm install
npm run dev          # http://localhost:5173
npx tsc --noEmit     # type-check only
npm run build        # production bundle ? dist/
```

No `.env` file is required for local development. The frontend defaults to `http://localhost:8000` as the backend URL when `VITE_API_BASE_URL` is not set.

---

## Project Structure

```
S5_Mini/               ? repo root (also Vercel root directory)
+-- src/               ? React/TypeScript frontend
+-- backend/           ? FastAPI backend (Render root directory)
¦   +-- app/
¦   ¦   +-- main.py          ? startup: create tables, seed demo data
¦   ¦   +-- core/config.py   ? all settings via env vars
¦   ¦   +-- database/        ? SQLAlchemy engine + session
¦   ¦   +-- detection/       ? SOC detection rules (rule-001 ? rule-013)
¦   ¦   +-- correlation/     ? Correlation v3 engine
¦   ¦   +-- copilot/         ? AI Copilot (OpenAI + deterministic fallback)
¦   ¦   +-- api/             ? FastAPI routers
¦   +-- data/samples/        ? Small demo CSV for startup seeding
¦   +-- requirements.txt
¦   +-- tests/
+-- render.yaml              ? minimal Render config
+-- .gitignore
+-- README.md
```

---

## Production Architecture

```
User ? Vercel (React SPA)
         ? VITE_API_BASE_URL
       Render (FastAPI backend, backend/ root)
         ? DATABASE_URL
       Supabase (PostgreSQL)
```

- **Vercel**: Hosts the static React frontend. Root directory = repo root.
- **Render**: Hosts the FastAPI backend. Root directory = `backend/`. Port is set by Render automatically via `$PORT` — never hard-coded.
- **Supabase**: Provides a managed PostgreSQL database. Tables are created automatically on first startup via `Base.metadata.create_all` (idempotent, non-destructive).

---

## Environment Variables

### Backend (set in Render dashboard)

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | **Yes** | Supabase PostgreSQL URL, e.g. `postgresql://user:pass@host:5432/dbname` |
| `OPENAI_API_KEY` | No | If absent, the deterministic template Copilot is used automatically |
| `CORS_ORIGINS` | **Yes** | JSON list of allowed frontend origins, e.g. `["https://your-app.vercel.app"]` |

> **Security**: Set these directly in the Render dashboard ? Environment section. Never commit real values to the repo.

### Frontend (set in Vercel dashboard)

| Variable | Required | Description |
|---|---|---|
| `VITE_API_BASE_URL` | **Yes** | Full URL of your Render backend, e.g. `https://siem-copilot-backend.onrender.com` |

> **Security**: Set in Vercel dashboard ? Project ? Settings ? Environment Variables. Never commit to the repo.

---

## Database Initialization

On every startup, the backend runs `Base.metadata.create_all(bind=engine)` — this creates any missing tables and is safe to run against both a fresh Supabase database and an existing one (non-destructive, idempotent).

No migrations (Alembic) are required for a fresh deployment.

---

## Dataset Note

The large research dataset (`dataset/cybersecurity_threat_detection_logs.csv`, 874 MB) is **excluded from the repo** by `.gitignore` and is **never referenced by production startup code**. Startup only uses `backend/data/samples/demo_security_logs.csv` (6 KB) if the database is empty, and only if that file exists.

---

## Health Check

```
GET /health
? {"status": "healthy", "service": "Cyber Security SIEM Copilot", "api_docs": "/docs"}
```

No authentication required. Render uses this endpoint for its health check probe.

---

## Required Manual Steps (Render, Vercel, Supabase Dashboards)

> These steps cannot be automated from the repo. You must perform them in each dashboard.

### Supabase
1. Create a new Supabase project.
2. Note the **PostgreSQL connection string** (Settings ? Database ? Connection string ? URI).
3. No schema setup needed — FastAPI creates tables on first boot.

### Render
1. Create a new **Web Service** connected to this repository.
2. Set **Root Directory** to `backend`.
3. Set **Build Command**: `pip install -r requirements.txt`
4. Set **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Set **Health Check Path**: `/health`
6. Add environment variables in Render dashboard:
   - `DATABASE_URL` = your Supabase PostgreSQL URL
   - `OPENAI_API_KEY` = your OpenAI key (optional)
   - `CORS_ORIGINS` = `["https://your-app.vercel.app"]`
7. Deploy.

### Vercel
1. Import this repository into Vercel.
2. Set **Root Directory** to `.` (repo root — the default).
3. Framework preset: **Vite**.
4. Add environment variable:
   - `VITE_API_BASE_URL` = your Render backend URL (e.g. `https://siem-copilot-backend.onrender.com`)
5. Deploy.

---

## Technologies

| Concern | Technology |
|---|---|
| Frontend Framework | React 19 + TypeScript (strict) |
| Build Tool | Vite |
| Styling | Tailwind CSS v3 |
| Routing | React Router v7 |
| Charts | Recharts |
| Backend Framework | FastAPI |
| ORM | SQLAlchemy 2 |
| Database (local) | SQLite (zero-config) |
| Database (production) | PostgreSQL via Supabase |
| AI Copilot | OpenAI API + deterministic fallback |
| Deployment (frontend) | Vercel |
| Deployment (backend) | Render |
