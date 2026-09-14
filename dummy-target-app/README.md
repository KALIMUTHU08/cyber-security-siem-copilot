# Controlled Demo Target Web Application

> **Local-Only Sandbox** for Demonstrating the **Cyber Security SIEM Copilot** Detection, Correlation, and Investigation Pipeline to Project Reviewers.

---

## 1. Ground Rules & Safety Boundaries

1. **Localhost Only:** Runs exclusively on `127.0.0.1:5000`. Never binds to `0.0.0.0`, never exposed to the public internet, and never deployed to Vercel/Render.
2. **Zero Real Exploitation:** The application contains **no real database** and **no real vulnerabilities**. All suspicious inputs (e.g. `' UNION SELECT`, `--`, `../`) are evaluated purely through safe in-memory string pattern matching and logged as structured security events.
3. **No SIEM Code Contamination:** Lives entirely in its own isolated directory (`dummy-target-app/`). It interacts with the SIEM solely by forwarding generated security logs to the SIEM's public ingestion endpoint.
4. **No Real Secrets:** All credentials shown (`demo_user` / `DemoPass123!`) are hardcoded synthetic demonstration placeholders.

---

## 2. Connection to the SIEM Backend

### Ingestion Endpoint
- **URL:** `http://127.0.0.1:8000/api/logs/upload`
- **HTTP Method:** `POST`
- **Format:** `multipart/form-data` with file `dummy_events.json` containing an array of JSON log records.
- **Authentication:** None required (public SOC ingestion pipeline). Optional `SIEM_API_TOKEN` supported via `.env`.

### Schema Mapping

| Dummy App Field | SIEM Expected Field | Type | Description / Example |
| :--- | :--- | :--- | :--- |
| `id` | `id` | `string` | Unique event ID (`target-a1b2c3d4`) |
| `timestamp` | `timestamp` | `string (ISO 8601)` | `2026-09-13T01:00:00Z` |
| `source_ip` | `source_ip` | `string` | Attacker or user IP (`198.51.100.90`) |
| `destination_ip` | `destination_ip` | `string` | Target server IP (`127.0.0.1`) |
| `username` | `username` | `string` | Account name (`admin`, `demo_user`) |
| `event_type` | `event_type` | `string` | `LOGIN`, `LOGIN_FAILED`, `FILE_ACCESS`, `NETWORK_CONNECTION` |
| `status` | `status` | `string` | `SUCCESS`, `FAILURE`, `BLOCKED` |
| `device` | `device` | `string` | Monitored host (`dummy-target-portal`) |
| `message` | `message` | `string` | Human-readable event description |
| `raw_log` | `raw_log` | `string` | Standardized syslog line |
| `parsed_fields` | `parsed_fields` | `dict` | `{"protocol": "HTTP", "request_path": "/...", "user_agent": "...", "action": "..."}` |

### CORS Note
Forwarding is performed **server-to-server** (from the Python dummy app backend directly to the SIEM FastAPI backend via `httpx`). Standard server-to-server HTTP calls do not enforce browser CORS restrictions. No change to the SIEM's `CORS_ORIGINS` is required for this demo.

---

## 3. SIEM Detection Rules & Thresholds

| Rule ID | Rule Name | Category | Exact SIEM Threshold |
| :--- | :--- | :--- | :--- |
| **Rule-001** | Brute Force Login | Authentication | **&ge; 10 failed login attempts** (`LOGIN_FAILED`) from the same source IP within **60 seconds**. |
| **Rule-010** | Sensitive Admin Path Access | Web Application | HTTP/HTTPS request containing exploit signatures: `union select`, `drop table`, `../`, `?admin`, etc. |
| **Rule-012** | Scanner User-Agent Detected | Reconnaissance | Request User-Agent matching `sqlmap`, `nikto`, `nmap`, etc., on a sensitive path or with action `blocked`. |

---

## 4. Setup & Running (Windows / PowerShell)

### Step 1: Start the SIEM Backend (Port 8000)
Open a PowerShell terminal in the SIEM root folder:
```powershell
# From the project root (S5_Mini)
cd backend
python -m uvicorn app.main:app --port 8000 --reload
```
*Verify: Open `http://127.0.0.1:8000/api/dashboard` in your browser to confirm the backend is healthy.*

### Step 2: Start the SIEM Frontend (Port 5173)
Open a second PowerShell terminal:
```powershell
# From the project root (S5_Mini)
npm run dev
```
*Verify: Open `http://localhost:5173` in your browser.*

### Step 3: Start the Controlled Dummy Target App (Port 5000)
Open a third PowerShell terminal:
```powershell
# From the project root (S5_Mini)
cd dummy-target-app
python main.py
```
*The dummy app will start on `http://127.0.0.1:5000`.*

---

## 5. Primary Reviewer Demonstration Script

**Narrative:** *"Attack activity happened on the dummy application &rarr; the SIEM collected the event &rarr; a detection rule identified it &rarr; an alert was generated &rarr; an incident was correlated &rarr; the Copilot explained the evidence."*

1. **Start the dummy web app:** Run `python main.py` in `dummy-target-app/`. Open `http://127.0.0.1:5000`.
2. **Open the Login page:** Navigate to `http://127.0.0.1:5000/login`.
3. **Trigger Brute Force sequence:**
   - Under **Reviewer Fast-Track**, click the red button: **"Run 11 Failed Logins from 198.51.100.90"** *(or manually type a wrong password 11 times in quick succession)*.
   - *Rationale:* The SIEM's `BruteForceRule` requires at least 10 failures within 60 seconds. 11 attempts guarantees immediate rule activation.
4. **Show generated security logs:**
   - You will automatically be taken to `http://127.0.0.1:5000/logs`.
   - Point out to the reviewer:
     - 11 structured records logged in real time.
     - Source IP: `198.51.100.90`
     - Event Type: `LOGIN_FAILED`
     - Status: `FAILURE`
     - Local file output: `dummy-target-app/logs/dummy_app_events.jsonl`.
5. **Send the logs to the SIEM:**
   - Click the bright cyan button: **"🚀 Send 11 Logs to SIEM Now"**.
   - Watch the banner confirm: `"Successfully forwarded 11 events to SIEM. Pipeline produced 1 alert(s) and 1 incident(s)."`
6. **Open the SIEM Alerts page:**
   - Navigate to the SIEM Frontend at `http://localhost:5173/alerts`.
7. **Show the detected brute-force alert:**
   - Reviewer will see: **"Brute Force Authentication Sequence — 198.51.100.90"** (Severity: HIGH, Rule: Brute Force Login).
   - Click into the alert to display the 11 correlated event evidence records.
8. **Open the correlated incident:**
   - Click on **Incidents** in the SIEM navigation (`http://localhost:5173/incidents`).
   - Show the newly clustered incident grouping alerts from IP `198.51.100.90`.
9. **Open SIEM Copilot:**
   - Navigate to **Copilot** (`http://localhost:5173/copilot`).
10. **Ask Copilot for an investigation:**
    - Type or select: *"Investigate the brute-force activity from 198.51.100.90 and recommend containment steps."*
    - Copilot will ground its analysis in the actual evidence logs (11 failed attempts), explain the attack timeline, and provide SOC containment recommendations (e.g. temporary IP block, account lock review).

---

## 6. Optional Secondary Demo Beats

### Beat A: SQL Injection / Suspicious Search Input
1. In the dummy app, navigate to `http://127.0.0.1:5000/search`.
2. Click the preset button: **`Exploit: '' UNION SELECT 1,2,3--'`** and click **Search Knowledge Base**.
3. Point out the security warning: *"Suspicious Input Pattern Detected & Logged."*
4. Go to `/logs` and click **"Send Logs to SIEM Now"**.
5. In the SIEM Alerts page, observe **Rule-010 (Sensitive Admin Path Access)** flagging the SQL injection payload.

### Beat B: Sensitive Admin Path Access
1. In the dummy app, click **Admin** or visit `http://127.0.0.1:5000/admin`.
2. Show the **403 Forbidden** restricted notice.
3. In `/logs`, show the `NETWORK_CONNECTION` with status `BLOCKED` on path `/admin`.
4. Forward to SIEM to demonstrate firewall/access control monitoring.

### Beat C: Scanner User-Agent Detection (sqlmap)
1. On the dummy app home page (`http://127.0.0.1:5000`), click **"⚡ Probe as 'sqlmap/1.6'"**.
2. Alternatively, run via PowerShell:
   ```powershell
   curl.exe -H "User-Agent: sqlmap/1.6#stable" http://127.0.0.1:5000/admin
   ```
3. Forward the generated event to the SIEM.
4. In the SIEM Alerts page, observe **Rule-012 (Scanner User-Agent Detected)**.

---

## 7. Running the Test Suite

To run the automated tests for the dummy application:
```powershell
cd dummy-target-app
python -m pytest tests/test_dummy_app.py -v
```
All 11 tests will pass, confirming:
- Healthy localhost binding.
- Route and page generation.
- Pattern matching detection without vulnerability execution.
- Brute-force event generation matching SIEM criteria.
- Forwarding client contract compliance.
