"""
FastAPI application for the controlled, local-only demo attack target.
Provides interactive routes for:
  - Benign activity (Home, Files)
  - Brute Force Login attempts (Login)
  - Safe pattern-detected Suspicious Input (Search)
  - Sensitive Path Access (Admin)
  - Scanner User-Agent detection
  - In-app /logs inspector & SIEM forwarding controls
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from config import (
    SIEM_INGEST_URL,
    DUMMY_APP_HOST,
    DUMMY_APP_PORT,
    AUTO_FORWARD,
)
from logger import (
    create_security_log,
    get_buffered_events,
    get_raw_buffer,
    clear_buffered_events,
)
from forwarder import forward_logs_to_siem

app = FastAPI(
    title="Controlled SIEM Demo Target App",
    description="Local-only target application for safely demonstrating SIEM detection rules",
    version="1.0.0",
)

# Shared Dark Cyber Theme CSS
STYLE_CSS = """
:root {
  --bg-primary: #0b0f19;
  --bg-secondary: #111827;
  --bg-card: #1f2937;
  --border-color: #374151;
  --text-main: #f9fafb;
  --text-muted: #9ca3af;
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --accent-red: #ef4444;
  --accent-amber: #f59e0b;
  --accent-green: #10b981;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
body { background: var(--bg-primary); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }
header { background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
.brand { display: flex; align-items: center; gap: 0.75rem; font-weight: 700; font-size: 1.15rem; color: var(--text-main); }
.brand-badge { background: #064e3b; color: #34d399; font-size: 0.7rem; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; border: 1px solid #059669; }
nav { display: flex; gap: 1.25rem; }
nav a { color: var(--text-muted); text-decoration: none; font-size: 0.95rem; transition: color 0.15s; }
nav a:hover, nav a.active { color: var(--accent-cyan); font-weight: 600; }
.container { max-width: 1000px; margin: 2rem auto; padding: 0 1.5rem; width: 100%; flex: 1; }
.card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2); }
h1, h2, h3 { color: var(--text-main); margin-bottom: 0.75rem; }
p { color: var(--text-muted); line-height: 1.5; margin-bottom: 1rem; }
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem; background: var(--accent-blue); color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; cursor: pointer; font-size: 0.9rem; font-weight: 500; text-decoration: none; transition: background 0.15s; }
.btn:hover { background: #2563eb; }
.btn-cyan { background: var(--accent-cyan); color: #082f49; font-weight: 600; }
.btn-cyan:hover { background: #0891b2; color: white; }
.btn-red { background: var(--accent-red); }
.btn-red:hover { background: #dc2626; }
.btn-amber { background: var(--accent-amber); color: #451a03; }
.btn-amber:hover { background: #d97706; color: white; }
.btn-secondary { background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); }
.btn-secondary:hover { background: #374151; }
.form-group { margin-bottom: 1.2rem; }
label { display: block; margin-bottom: 0.4rem; color: var(--text-main); font-size: 0.875rem; font-weight: 500; }
input[type="text"], input[type="password"] { width: 100%; padding: 0.65rem 0.85rem; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; color: white; font-size: 0.9rem; }
input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: var(--accent-cyan); }
.banner-info { background: rgba(59, 130, 246, 0.1); border: 1px solid #1e3a8a; border-radius: 6px; padding: 0.85rem 1rem; color: #93c5fd; margin-bottom: 1.25rem; font-size: 0.875rem; }
.banner-warn { background: rgba(245, 158, 11, 0.1); border: 1px solid #78350f; border-radius: 6px; padding: 0.85rem 1rem; color: #fcd34d; margin-bottom: 1.25rem; font-size: 0.875rem; }
.banner-danger { background: rgba(239, 68, 68, 0.1); border: 1px solid #7f1d1d; border-radius: 6px; padding: 0.85rem 1rem; color: #fca5a5; margin-bottom: 1.25rem; font-size: 0.875rem; }
.banner-success { background: rgba(16, 185, 129, 0.1); border: 1px solid #064e3b; border-radius: 6px; padding: 0.85rem 1rem; color: #6ee7b7; margin-bottom: 1.25rem; font-size: 0.875rem; }
.table-container { overflow-x: auto; margin-top: 1rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border-color); }
th { background: var(--bg-card); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; }
tr:hover td { background: rgba(255,255,255,0.02); }
.badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
.badge-red { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #b91c1c; }
.badge-green { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #059669; }
.badge-amber { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #d97706; }
.badge-blue { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #2563eb; }
.grid-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; margin-top: 1rem; }
.action-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 1.25rem; display: flex; flex-direction: column; justify-content: space-between; }
.action-card h3 { font-size: 1rem; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem; }
footer { background: var(--bg-secondary); border-top: 1px solid var(--border-color); padding: 1rem 2rem; font-size: 0.8rem; color: var(--text-muted); text-align: center; margin-top: auto; }
code { background: #111827; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85em; color: #38bdf8; }
"""

def render_layout(title: str, active_nav: str, content: str) -> str:
    """Wrap content in global layout with navigation."""
    nav_links = [
        ("/", "Home", active_nav == "home"),
        ("/files", "Documents", active_nav == "files"),
        ("/search", "Search", active_nav == "search"),
        ("/login", "Login", active_nav == "login"),
        ("/admin", "Admin", active_nav == "admin"),
        ("/logs", f"Logs ({len(get_raw_buffer())})", active_nav == "logs"),
    ]
    nav_html = "".join(
        f'<a href="{path}" class="{"active" if active else ""}">{label}</a>'
        for path, label, active in nav_links
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — SIEM Demo Target</title>
  <style>{STYLE_CSS}</style>
</head>
<body>
  <header>
    <div class="brand">
      <span>🛡️ Apex Portal</span>
      <span class="brand-badge">Controlled Demo Target</span>
    </div>
    <nav>{nav_html}</nav>
  </header>
  <main class="container">
    {content}
  </main>
  <footer>
    Controlled demonstration target application running locally on 127.0.0.1:{DUMMY_APP_PORT}. Forwarding logs to SIEM at {SIEM_INGEST_URL}.
  </footer>
</body>
</html>"""


# ============================================================================
# 1. HOME & BENIGN FILES ROUTES
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def page_home(request: Request):
    # Log benign landing page visit
    ua = request.headers.get("user-agent", "Mozilla/5.0")
    client_ip = request.client.host if request.client else "127.0.0.1"
    create_security_log(
        event_type="FILE_ACCESS",
        status="SUCCESS",
        source_ip=client_ip,
        username="anonymous",
        message="Accessed corporate home portal",
        parsed_fields={"protocol": "HTTP", "request_path": "/", "user_agent": ua},
    )

    buf_count = len(get_raw_buffer())
    content = f"""
    <div class="banner-info">
      <strong>🎯 Controlled Demo Environment:</strong> This target application runs strictly on <code>127.0.0.1</code>. It contains no real database or vulnerabilities. Suspicious inputs are pattern-matched and logged as structured security events for SIEM evaluation.
    </div>

    <div class="card">
      <h2>Welcome to Apex Enterprise Portal</h2>
      <p>This web application represents a typical enterprise web service. Reviewers can execute normal user activities or simulated threat patterns, inspect the generated telemetry, and forward it directly into the SIEM pipeline.</p>
      
      <div style="display:flex; gap:0.75rem; align-items:center; margin-top:1rem;">
        <a href="/login" class="btn btn-cyan">Go to Login Page</a>
        <a href="/search" class="btn btn-secondary">Test Search Query</a>
        <a href="/logs" class="btn btn-secondary">Inspect Buffer ({buf_count} events)</a>
      </div>
    </div>

    <h2>Interactive Attack Scenarios</h2>
    <div class="grid-cards">
      <div class="action-card">
        <div>
          <h3>🔑 Brute Force Attack</h3>
          <p>Simulate rapid authentication failures from an external IP to trigger SIEM Rule-001 (threshold: &ge;10 failed attempts within 60s).</p>
        </div>
        <form action="/api/simulate-brute-force" method="post" style="margin-top:1rem;">
          <input type="hidden" name="source_ip" value="198.51.100.90">
          <input type="hidden" name="redirect_to" value="/logs">
          <button type="submit" class="btn btn-red" style="width:100%;">⚡ Run 11 Failed Logins</button>
        </form>
      </div>

      <div class="action-card">
        <div>
          <h3>💉 SQL Injection Probe</h3>
          <p>Submit common SQL injection signatures into the search field to trigger SIEM Rule-010 (Admin/Exploit Path Probe).</p>
        </div>
        <form action="/api/simulate-sqli" method="post" style="margin-top:1rem;">
          <input type="hidden" name="redirect_to" value="/logs">
          <button type="submit" class="btn btn-amber" style="width:100%;">⚡ Submit ' UNION SELECT Probe</button>
        </form>
      </div>

      <div class="action-card">
        <div>
          <h3>🚫 Sensitive Admin Access</h3>
          <p>Simulate unauthorized probing of restricted administrative endpoints to generate blocked connection security alerts.</p>
        </div>
        <a href="/admin" class="btn btn-secondary" style="width:100%; margin-top:1rem;">⚡ Request /admin Path</a>
      </div>

      <div class="action-card">
        <div>
          <h3>🤖 Scanner User-Agent</h3>
          <p>Simulate reconnaissance using automated vulnerability scanning tools (sqlmap/nikto) to trigger SIEM Rule-012.</p>
        </div>
        <form action="/api/simulate-scanner" method="post" style="margin-top:1rem;">
          <input type="hidden" name="redirect_to" value="/logs">
          <button type="submit" class="btn btn-blue" style="width:100%;">⚡ Probe as 'sqlmap/1.6'</button>
        </form>
      </div>
    </div>
    """
    return render_layout("Home", "home", content)


@app.get("/files", response_class=HTMLResponse)
def page_files(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Mozilla/5.0")
    create_security_log(
        event_type="FILE_ACCESS",
        status="SUCCESS",
        source_ip=client_ip,
        username="employee_staff",
        message="Accessed corporate document directory",
        parsed_fields={"protocol": "HTTP", "request_path": "/files", "user_agent": ua},
    )

    content = """
    <div class="card">
      <h2>Corporate Document Repository (Benign Baseline)</h2>
      <p>Accessing and downloading documents in this section generates normal, benign baseline logs (<code>FILE_ACCESS</code> with status <code>SUCCESS</code>) to demonstrate non-malicious background traffic.</p>

      <div class="table-container">
        <table>
          <thead>
            <tr><th>File Name</th><th>Category</th><th>Classification</th><th>Action</th></tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Q3_Security_Compliance_Report.pdf</strong></td>
              <td>Governance</td>
              <td><span class="badge badge-blue">Internal</span></td>
              <td><a href="/files/download?file=Q3_Security_Compliance_Report.pdf" class="btn btn-secondary" style="padding:0.3rem 0.6rem; font-size:0.8rem;">Download</a></td>
            </tr>
            <tr>
              <td><strong>Enterprise_Architecture_Overview.png</strong></td>
              <td>Engineering</td>
              <td><span class="badge badge-blue">Internal</span></td>
              <td><a href="/files/download?file=Enterprise_Architecture_Overview.png" class="btn btn-secondary" style="padding:0.3rem 0.6rem; font-size:0.8rem;">Download</a></td>
            </tr>
            <tr>
              <td><strong>Employee_Handbook_2026.docx</strong></td>
              <td>HR</td>
              <td><span class="badge badge-green">Public</span></td>
              <td><a href="/files/download?file=Employee_Handbook_2026.docx" class="btn btn-secondary" style="padding:0.3rem 0.6rem; font-size:0.8rem;">Download</a></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    """
    return render_layout("Documents", "files", content)


@app.get("/files/download")
def download_file(file: str = Query("document.pdf"), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Mozilla/5.0") if request else "Mozilla/5.0"
    create_security_log(
        event_type="FILE_ACCESS",
        status="SUCCESS",
        source_ip=client_ip,
        username="employee_staff",
        message=f"Downloaded file: {file}",
        parsed_fields={"protocol": "HTTP", "request_path": f"/files/download?file={file}", "user_agent": ua},
    )
    return RedirectResponse(url="/files?status=downloaded")


# ============================================================================
# 2. LOGIN & BRUTE FORCE SCENARIO
# ============================================================================

@app.get("/login", response_class=HTMLResponse)
def page_login(status: Optional[str] = Query(None), msg: Optional[str] = Query(None)):
    banner = ""
    if status == "success":
        banner = f'<div class="banner-success"><strong>✅ Authentication Successful:</strong> {msg or "Welcome, demo_user!"}</div>'
    elif status == "failed":
        banner = f'<div class="banner-danger"><strong>❌ Authentication Failed:</strong> {msg or "Invalid username or password. This failure was logged."}</div>'

    content = f"""
    {banner}
    <div class="card" style="max-width:550px; margin:0 auto;">
      <h2>Employee Single Sign-On</h2>
      <p>Simulate standard credential authentication. Demo valid credentials are: <code>demo_user</code> / <code>DemoPass123!</code>.</p>

      <form action="/login" method="post">
        <div class="form-group">
          <label>Simulated Attacker Source IP</label>
          <input type="text" name="source_ip" value="198.51.100.90" required>
          <small style="color:var(--text-muted); display:block; margin-top:0.25rem;">
            Use this to simulate distinct attacker IPs for the SIEM's correlation engine.
          </small>
        </div>

        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" value="admin" required>
        </div>

        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" placeholder="Enter password" required>
        </div>

        <div style="display:flex; gap:0.75rem; align-items:center; margin-top:1.5rem;">
          <button type="submit" class="btn btn-blue">Sign In</button>
          <a href="/login" class="btn btn-secondary">Reset Form</a>
        </div>
      </form>

      <div style="margin-top:2rem; padding-top:1.5rem; border-top:1px solid var(--border-color);">
        <h3>⚡ Reviewer Fast-Track: Brute Force Attack</h3>
        <p>The SIEM requires <strong>&ge;10 failed logins within 60 seconds</strong> from the same IP to trigger Rule-001. Click below to instantly generate 11 consecutive failures:</p>
        <form action="/api/simulate-brute-force" method="post">
          <input type="hidden" name="source_ip" value="198.51.100.90">
          <input type="hidden" name="redirect_to" value="/logs">
          <button type="submit" class="btn btn-red" style="width:100%;">Run 11 Failed Logins from 198.51.100.90</button>
        </form>
      </div>
    </div>
    """
    return render_layout("Login", "login", content)


@app.post("/login")
def handle_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    source_ip: str = Form("127.0.0.1"),
):
    ua = request.headers.get("user-agent", "Mozilla/5.0")
    # Controlled demo credentials (NEVER real credentials)
    if username == "demo_user" and password == "DemoPass123!":
        create_security_log(
            event_type="LOGIN",
            status="SUCCESS",
            source_ip=source_ip,
            username=username,
            message=f"Successful authentication for {username}",
            parsed_fields={"protocol": "HTTP", "request_path": "/login", "user_agent": ua},
        )
        return RedirectResponse(url="/login?status=success&msg=Authenticated+successfully", status_code=303)
    else:
        create_security_log(
            event_type="LOGIN_FAILED",
            status="FAILURE",
            source_ip=source_ip,
            username=username,
            message=f"Failed login attempt for {username} with invalid credentials",
            parsed_fields={"protocol": "HTTP", "request_path": "/login", "user_agent": ua},
        )
        return RedirectResponse(url="/login?status=failed&msg=Invalid+credentials+recorded", status_code=303)


# ============================================================================
# 3. SEARCH & SUSPICIOUS INPUT DETECTION (SAFE PATTERN-MATCHING)
# ============================================================================

# Strictly pattern detection — NO REAL SQL OR EXECUTION
INJECTION_SIGNATURES = [
    "union select",
    "drop table",
    "' or '1'='1",
    "or 1=1",
    "--",
    "/*",
    "../",
    "..\\",
    "backup.sql",
    "phpmyadmin",
    "<script",
]

@app.get("/search", response_class=HTMLResponse)
def page_search(q: Optional[str] = Query(None), detected: Optional[bool] = Query(False)):
    banner = ""
    if detected:
        banner = """
        <div class="banner-warn">
          <strong>⚠️ Suspicious Input Pattern Detected & Logged:</strong> The input contained signatures characteristic of SQL injection or directory traversal. 
          <em>(Note: Input was NOT executed — safely logged as a structured event matching SIEM Rule-010).</em>
        </div>
        """
    elif q is not None:
        banner = f"""
        <div class="banner-info">
          <strong>🔍 Benign Search:</strong> Searched for <code>{q}</code>. Returned 3 standard documents. Normal <code>FILE_ACCESS</code> event logged.
        </div>
        """

    content = f"""
    {banner}
    <div class="card">
      <h2>Enterprise Knowledge Base Search</h2>
      <p>Search corporate documents. Safe regex/pattern matching intercepts exploit-like tokens without any database interaction, generating realistic security alerts for the SIEM.</p>

      <form action="/search" method="post">
        <div class="form-group">
          <label>Search Query</label>
          <input type="text" name="query" value="{q or ''}" placeholder="e.g. employee policies or ' UNION SELECT 1,2,3--" required>
        </div>

        <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:1rem;">
          <button type="button" class="btn btn-secondary" onclick="document.querySelector('input[name=query]').value='quarterly financial review'">Benign: 'quarterly financial review'</button>
          <button type="button" class="btn btn-secondary" onclick="document.querySelector('input[name=query]').value='admin\\' UNION SELECT 1,2,3--'">Exploit: '' UNION SELECT 1,2,3--'</button>
          <button type="button" class="btn btn-secondary" onclick="document.querySelector('input[name=query]').value='../../etc/passwd'">Traversal: '../../etc/passwd'</button>
        </div>

        <button type="submit" class="btn btn-blue">Search Knowledge Base</button>
      </form>
    </div>
    """
    return render_layout("Search", "search", content)


@app.post("/search")
def handle_search(request: Request, query: str = Form(...)):
    ua = request.headers.get("user-agent", "Mozilla/5.0")
    client_ip = request.client.host if request.client else "127.0.0.1"
    q_lower = query.lower()

    # Pattern-match inspection only (zero SQL interpolation or execution)
    matched_pattern = next((sig for sig in INJECTION_SIGNATURES if sig in q_lower), None)

    if matched_pattern:
        # Log as structured security event targeting SIEM Rule-010
        create_security_log(
            event_type="FILE_ACCESS",
            status="SUCCESS",
            source_ip=client_ip,
            username="investigator",
            message=f"Suspicious input pattern '{matched_pattern}' detected in search query",
            parsed_fields={
                "protocol": "HTTP",
                "request_path": f"/search?q={query}",
                "user_agent": ua,
                "detection": "exploit_pattern_matched",
            },
        )
        return RedirectResponse(url=f"/search?q={query}&detected=true", status_code=303)
    else:
        create_security_log(
            event_type="FILE_ACCESS",
            status="SUCCESS",
            source_ip=client_ip,
            username="investigator",
            message=f"Benign search query: {query}",
            parsed_fields={
                "protocol": "HTTP",
                "request_path": f"/search?q={query}",
                "user_agent": ua,
            },
        )
        return RedirectResponse(url=f"/search?q={query}", status_code=303)


# ============================================================================
# 4. SENSITIVE PATH ACCESS (ADMIN)
# ============================================================================

@app.get("/admin", response_class=HTMLResponse)
def page_admin(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Mozilla/5.0")

    # Accessing unlinked administrative path triggers blocked connection log
    create_security_log(
        event_type="NETWORK_CONNECTION",
        status="BLOCKED",
        source_ip=client_ip,
        username="unauthenticated",
        message="Unauthorized access attempt to restricted /admin route",
        parsed_fields={
            "protocol": "HTTP",
            "request_path": "/admin",
            "user_agent": ua,
            "action": "blocked",
        },
    )

    content = """
    <div class="banner-danger">
      <strong>🚫 403 Forbidden — Restricted Administrative Console:</strong>
      This unlinked sensitive path is monitored. Your IP and access attempt have been logged and submitted to the Security Operations Center.
    </div>

    <div class="card">
      <h2>Administrative Console Access Denied</h2>
      <p>Public access to <code>/admin</code> is strictly prohibited. The attempt generated a <code>NETWORK_CONNECTION</code> event with status <code>BLOCKED</code> and action <code>blocked</code>, satisfying SOC sensitive-path detection criteria.</p>

      <div style="margin-top:1.5rem; display:flex; gap:0.75rem;">
        <a href="/" class="btn btn-secondary">Return to Portal Home</a>
        <a href="/logs" class="btn btn-cyan">View Logged Security Event</a>
      </div>
    </div>
    """
    return render_layout("Admin Prohibited", "admin", content)


# ============================================================================
# 5. IN-APP LOG INSPECTOR & FORWARDING CONTROLS (/logs)
# ============================================================================

@app.get("/logs", response_class=HTMLResponse)
def page_logs(msg: Optional[str] = Query(None), error: Optional[str] = Query(None)):
    events = get_buffered_events()
    banner = ""
    if msg:
        banner = f'<div class="banner-success"><strong>🚀 SIEM Forwarding Result:</strong> {msg}</div>'
    if error:
        banner = f'<div class="banner-danger"><strong>⚠️ Forwarding Notice:</strong> {error}</div>'

    rows_html = ""
    for ev in events:
        sev_badge = "badge-blue"
        if ev["event_type"] == "LOGIN_FAILED":
            sev_badge = "badge-red"
        elif ev["status"] == "BLOCKED":
            sev_badge = "badge-amber"
        elif ev["event_type"] == "LOGIN":
            sev_badge = "badge-green"

        rows_html += f"""
        <tr>
          <td><code>{ev['timestamp'][11:19]}</code></td>
          <td><code>{ev['source_ip']}</code></td>
          <td><span class="badge {sev_badge}">{ev['event_type']}</span></td>
          <td><code>{ev['status']}</code></td>
          <td>{ev['username'] or '—'}</td>
          <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{ev['message']}</td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">No logs in buffer yet. Perform actions above to generate events.</td></tr>'

    content = f"""
    {banner}
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;">
        <div>
          <h2>Security Log Telemetry Buffer</h2>
          <p>Shows events held in memory and written to <code>logs/dummy_app_events.jsonl</code> ready for SIEM ingestion.</p>
        </div>
        <div style="display:flex; gap:0.5rem;">
          <form action="/api/logs/forward" method="post">
            <button type="submit" class="btn btn-cyan">🚀 Send {len(events)} Logs to SIEM Now</button>
          </form>
          <form action="/api/logs/clear" method="post">
            <button type="submit" class="btn btn-secondary">Clear Buffer</button>
          </form>
        </div>
      </div>

      <div style="background:var(--bg-primary); padding:0.75rem 1rem; border-radius:6px; border:1px solid var(--border-color); margin-top:1rem; font-size:0.85rem; display:flex; justify-content:space-between;">
        <span><strong>Target SIEM Ingest URL:</strong> <code>{SIEM_INGEST_URL}</code></span>
        <span><strong>Events in Buffer:</strong> {len(events)}</span>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Event Type</th>
              <th>Status</th>
              <th>User</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </div>
    """
    return render_layout("Logs & SIEM Forwarder", "logs", content)


# ============================================================================
# 6. REST APIS (FORWARDING, SIMULATION, HEALTH)
# ============================================================================

@app.get("/api/logs")
def api_get_logs():
    """Retrieve all buffered logs as JSON."""
    return {"count": len(get_raw_buffer()), "events": get_raw_buffer()}


@app.post("/api/logs/forward")
def api_forward_logs():
    """Trigger manual forward of all buffered events to the SIEM."""
    events = get_raw_buffer()
    result = forward_logs_to_siem(events)
    if result["success"]:
        return RedirectResponse(url=f"/logs?msg={result['message']}", status_code=303)
    else:
        return RedirectResponse(url=f"/logs?error={result['message']}", status_code=303)


@app.post("/api/logs/clear")
def api_clear_logs():
    """Clear buffer."""
    clear_buffered_events()
    return RedirectResponse(url="/logs", status_code=303)


@app.post("/api/simulate-brute-force")
def api_simulate_brute_force(
    source_ip: str = Form("198.51.100.90"),
    redirect_to: Optional[str] = Form(None),
):
    """
    Simulate 11 failed logins in quick succession from the same IP.
    Meets the SIEM threshold: >= 10 failed logins within 60s (Rule-001).
    """
    base_time = datetime.now(timezone.utc) - timedelta(seconds=22)
    generated = []
    for i in range(11):
        ts = base_time + timedelta(seconds=i * 2)
        log = create_security_log(
            event_type="LOGIN_FAILED",
            status="FAILURE",
            source_ip=source_ip,
            username="admin",
            message=f"Automated credential failure attempt {i+1}/11",
            parsed_fields={"protocol": "HTTP", "request_path": "/login", "user_agent": "Mozilla/5.0"},
            timestamp=ts,
        )
        generated.append(log)

    if AUTO_FORWARD:
        forward_logs_to_siem(generated)

    if redirect_to:
        return RedirectResponse(url=f"{redirect_to}?msg=Generated+11+failed+logins+from+{source_ip}", status_code=303)
    return {"status": "success", "generated_count": len(generated), "source_ip": source_ip}


@app.post("/api/simulate-sqli")
def api_simulate_sqli(redirect_to: Optional[str] = Form(None)):
    """Simulate a SQL injection probe in the search field (Rule-010)."""
    log = create_security_log(
        event_type="FILE_ACCESS",
        status="SUCCESS",
        source_ip="198.51.100.90",
        username="attacker",
        message="Search exploit payload probe matching signature 'union select'",
        parsed_fields={
            "protocol": "HTTP",
            "request_path": "/search?q=admin' union select 1,2,3--",
            "user_agent": "Mozilla/5.0",
            "detection": "exploit_pattern_matched",
        },
    )
    if AUTO_FORWARD:
        forward_logs_to_siem([log])

    if redirect_to:
        return RedirectResponse(url=f"{redirect_to}?msg=Generated+SQL+injection+probe+event", status_code=303)
    return {"status": "success", "event": log}


@app.post("/api/simulate-scanner")
def api_simulate_scanner(redirect_to: Optional[str] = Form(None)):
    """Simulate a scanner tool (sqlmap) probing a sensitive path (Rule-012)."""
    log = create_security_log(
        event_type="NETWORK_CONNECTION",
        status="BLOCKED",
        source_ip="198.51.100.90",
        username="scanner_tool",
        message="Vulnerability scanner signature identified probing /admin",
        parsed_fields={
            "protocol": "HTTP",
            "request_path": "/admin",
            "user_agent": "sqlmap/1.6.11#stable (https://sqlmap.org)",
            "action": "blocked",
        },
    )
    if AUTO_FORWARD:
        forward_logs_to_siem([log])

    if redirect_to:
        return RedirectResponse(url=f"{redirect_to}?msg=Generated+sqlmap+scanner+event+on+/admin", status_code=303)
    return {"status": "success", "event": log}


@app.get("/health")
def health_check():
    return {"status": "ok", "app": "dummy-target-app", "host": DUMMY_APP_HOST, "port": DUMMY_APP_PORT}
