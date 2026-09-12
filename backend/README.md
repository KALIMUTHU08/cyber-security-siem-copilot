# Cyber Security SIEM Copilot — Backend

Production-quality Python FastAPI backend for the **"Cyber Security SIEM Copilot for Threat Hunting and Incident Investigation"** project.

The backend powers an enterprise SOC interface by ingesting security logs, executing deterministic detection rules, computing additive risk scores, correlating related events into multi-stage incidents, providing controlled threat hunting, and delivering evidence-grounded AI Copilot analysis.

---

## 1. System Architecture

```
                       [ Security Logs (CSV / JSON / Stream) ]
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │ Log Ingestion Pipeline │  (Defensive Parser & Normalizer)
                            └───────────┬────────────┘
                                         │ Normalized Logs
                                         ▼
                            ┌────────────────────────┐
                            │ Detection Engine       │  (8 Deterministic Rules)
                            └───────────┬────────────┘
                                         │ Rule Matches
                                         ▼
                            ┌────────────────────────┐
                            │ Additive Risk Scoring  │  (0–100 Clamped Points + Factors)
                            └───────────┬────────────┘
                                         │ Security Alerts
                                         ▼
                            ┌────────────────────────┐
                            │ Event Correlation      │  (Cluster by Host/IP/User Window)
                            └───────────┬────────────┘
                                         │ Incidents + Timelines
                                         ▼
                     ┌───────────────────┴───────────────────┐
                     │                                       │
                     ▼                                       ▼
        ┌─────────────────────────┐             ┌─────────────────────────┐
        │ Controlled Threat Hunt  │             │ AI Copilot Engine       │
        │ (Safe Intent Parsing)   │             │ (Evidence Grounding &   │
        └─────────────────────────┘             │  Graceful Fallback)     │
                     │                                       │
                     └───────────────────┬───────────────────┘
                                         │
                                         ▼
                             [ REST API (FastAPI) ]
                                         │
                             [ SQLite / PostgreSQL ]
                                         │
                         [ React SOC Frontend (:5173) ]
```

---

## 2. Technology Stack

- **Framework**: FastAPI (Python 3.10+)
- **ORM & Database**: SQLAlchemy 2.0 with SQLite (zero-config, swappable for PostgreSQL)
- **Validation & Serialization**: Pydantic v2 with automatic camelCase aliasing
- **Server**: Uvicorn
- **Testing**: pytest (21 comprehensive unit & integration tests)

---

## 3. Directory Structure

```
backend/
├── app/
│   ├── main.py                  # FastAPI application entrypoint, CORS, lifespan seeding
│   ├── core/
│   │   └── config.py            # Pydantic Settings, thresholds, environment configuration
│   ├── database/
│   │   ├── base.py              # DeclarativeBase
│   │   └── session.py           # Engine & SessionLocal
│   ├── models/                  # SQLAlchemy ORM models
│   │   ├── log.py               # SecurityLogModel
│   │   ├── rule.py              # DetectionRuleModel
│   │   ├── alert.py             # AlertModel
│   │   ├── incident.py          # IncidentModel & IncidentTimelineEventModel
│   │   ├── copilot.py           # CopilotMessageModel
│   │   └── setting.py           # SystemSettingModel
│   ├── schemas/                 # Pydantic request/response schemas (camelCase)
│   │   ├── common.py            # CamelModel, RiskScore, PaginatedResult
│   │   ├── log.py               # SecurityLog, LogFilter, IngestStats
│   │   ├── alert.py             # SecurityAlert, AlertFilter
│   │   ├── incident.py          # Incident, TimelineEvent
│   │   ├── rule.py              # DetectionRule, RuleToggleRequest
│   │   ├── threat_hunting.py    # ThreatHuntQuery, ThreatHuntRequest
│   │   ├── copilot.py           # CopilotMessage, CopilotResponse
│   │   ├── dashboard.py         # DashboardStats, SystemHealth
│   │   └── analytics.py         # AnalyticsData, TimeSeriesPoint, Distributions
│   ├── ingestion/
│   │   ├── normalizer.py        # Log record normalization & IP/time sanitization
│   │   └── parser.py            # Defensive CSV & JSON parser
│   ├── detection/
│   │   ├── base.py              # BaseRule & RuleMatch
│   │   ├── registry.py          # RuleRegistry
│   │   └── rules.py             # 8 deterministic detection rules
│   ├── risk/
│   │   └── engine.py            # Additive risk calculation (0-100, factors, levels)
│   ├── correlation/
│   │   └── engine.py            # Incident clustering & 3-block assessment generator
│   ├── copilot/
│   │   ├── provider.py          # LLMProvider abstract base
│   │   ├── template_provider.py # Zero-cost deterministic fallback provider
│   │   ├── openai_provider.py   # OpenAI / OpenAI-compatible provider
│   │   └── service.py           # CopilotService with conversation persistence
│   ├── services/
│   │   ├── siem_pipeline.py     # End-to-end pipeline orchestrator
│   │   ├── analytics_service.py # SQL aggregations for dashboard & charts
│   │   └── threat_hunting.py    # Intent-based query execution
│   └── api/                     # REST API routers
│       ├── dashboard.py         # GET /api/dashboard
│       ├── logs.py              # GET/POST /api/logs, /api/logs/batch, /api/logs/upload
│       ├── alerts.py            # GET/PATCH /api/alerts, /api/alerts/batch
│       ├── incidents.py         # GET /api/incidents, /api/incidents/{id}
│       ├── threat_hunting.py    # POST /api/threat-hunting/query
│       ├── copilot.py           # POST /api/copilot/chat, GET /api/copilot/history
│       ├── analytics.py         # GET /api/analytics
│       └── settings.py          # GET/PATCH /api/settings/detection-rules
├── data/
│   └── samples/
│       └── demo_security_logs.csv # Complete multi-stage attack & background dataset
├── tests/                       # Automated pytest test suite
├── requirements.txt
├── .env.example
└── README.md
```

---

## 4. Detection Rules & Risk Scoring

### The 8 Deterministic Rules

| Rule ID | Rule Name | Threshold / Condition | Severity | Points |
|---|---|---|---|---|
| `rule-001` | **Brute Force Login** | `>10` failed logins from same IP in 60s | HIGH | 20 |
| `rule-002` | **Account Compromise** | Successful login following failed streak | CRITICAL | 25 |
| `rule-003` | **Privilege Escalation** | `PRIVILEGE_CHANGE` / sudo elevation | CRITICAL | 25 |
| `rule-004` | **Suspicious External Connection** | Egress connection to external non-whitelisted IP | HIGH | 20 |
| `rule-005` | **Port Scan Detected** | `>15` distinct destination ports probed in 30s | MEDIUM | 20 |
| `rule-006` | **Credential Spray** | Failed logins across `5+` usernames from same IP | HIGH | 20 |
| `rule-007` | **Distributed Brute Force** | Failed logins from `3+` distinct IPs against same user | MEDIUM | 20 |
| `rule-008` | **Off-Hours Login** | Successful login between 00:00 and 06:00 | LOW | 15 |

### Additive Risk Scoring
- Base rule score + bonus factors (privileged target: `+20`, external destination: `+20`, non-business hours: `+15`).
- Clamped strictly between **0 and 100**.
- Risk Level Bands:
  - `0–25`: **LOW**
  - `26–50`: **MEDIUM**
  - `51–75`: **HIGH**
  - `76–100`: **CRITICAL**

---

## 5. Event Correlation & Incident Engine

Alerts that share correlation keys (host, source IP, username) within a temporal window are automatically clustered into an **Incident** (e.g. `INC-10001`):
- Timeline events are ordered chronologically.
- Generates a **3-Block Assessment**:
  1. **Observed Evidence**: Verifiable facts with timestamps, IPs, and actions.
  2. **AI Assessment**: Hedged behavioral analysis explaining the attack progression.
  3. **Recommended Next Steps**: Prioritized containment and investigation actions.
- Avoids duplicate incident creation by merging subsequent alerts into active open incidents.

---

## 6. AI Copilot (with Graceful Deterministic Fallback)

- **Principle**: The AI never independently marks raw logs as malicious. It only reasons over structured telemetry and detection results already produced by the SIEM engine.
- **Zero-Cost Out of the Box**: Without an OpenAI API key configured, the Copilot seamlessly uses `DeterministicTemplateProvider`, grounding responses in the selected incident's concrete telemetry.
- **LLM Support**: Configure `OPENAI_API_KEY` in `.env` to enable LLM-generated analysis. The prompt treats logs as strictly untrusted data, neutralizing prompt injection attempts.

---

## 7. How to Run

### Step 1: Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Step 2: Start the Backend Server
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Docs: **http://localhost:8000/docs**
- Health Check: **http://localhost:8000/health**
- The server automatically creates the SQLite database and seeds the demo dataset on first launch.

### Step 3: Start the Frontend
In the project root directory:
```bash
npm run dev
```
Open **http://localhost:5173/** in your browser. All 9 screens are now backed by real data from the FastAPI server!

---

## 8. Running the Automated Tests

Run the complete test suite with verbose output:
```bash
cd backend
python -m pytest tests/ -v
```
All 21 tests cover:
- CSV/JSON parsing and error recovery
- 8 deterministic detection rules
- Additive risk scoring math
- Event correlation and incident deduplication
- All REST API endpoints

---

## 9. Swapping SQLite for PostgreSQL

To transition from SQLite to PostgreSQL:
1. Install psycopg2 / asyncpg:
   ```bash
   pip install psycopg2-binary
   ```
2. Set the `DATABASE_URL` in `backend/.env`:
   ```env
   DATABASE_URL="postgresql://user:password@localhost:5432/siem_copilot"
   ```
3. Restart the backend — SQLAlchemy models will automatically initialize tables in PostgreSQL with zero code changes.
