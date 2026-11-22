"""IoT Hunter v4.0 web/API layer.

The v3.1 discovery and fingerprint modules remain the scanning engine.
Only private IPv4 ranges up to /24 are accepted by this service.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from modules import fingerprint
from modules.discovery import scan_target_network

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"
DATA_DIR = Path(os.getenv("IOT_HUNTER_DATA", PROJECT_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = Path(os.getenv("IOT_HUNTER_CONFIG", BACKEND_DIR / "config.yaml"))
DB_PATH = Path(os.getenv("IOT_HUNTER_DB", DATA_DIR / "iot.db"))
CONFIG = yaml.safe_load(CONFIG_PATH.read_text()) if CONFIG_PATH.exists() else {}
SCAN_CFG = CONFIG.get("scan", {})
ALLOWED_PORTS = {21, 22, 23, 53, 80, 139, 443, 445, 1883, 8883, 8080, 8443}

@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    startup()
    try:
        yield
    finally:
        shutdown()


app = FastAPI(title="IoT Hunter API", version="4.0.0", lifespan=lifespan,
              description="Defensive IoT inventory for explicitly authorized private networks.")
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")
scheduler = BackgroundScheduler(timezone="UTC")
executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
jobs: dict[str, dict[str, Any]] = {}
jobs_lock = threading.Lock()
auth_failures: dict[str, list[float]] = {}
auth_lock = threading.Lock()
AUTH_MAX_FAILURES = 5
AUTH_WINDOW_SEC = 300
MAX_TRACKED_JOBS = 200
schedule_jobs: dict[str, dict[str, Any]] = {}


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
          ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, hostname TEXT,
          device_type TEXT, open_ports TEXT, cves TEXT, last_seen TEXT,
          subnet TEXT, online INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY, created_at TEXT, subnet TEXT, status TEXT,
          results TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT,
          kind TEXT, message TEXT, payload TEXT
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
          token_hash TEXT PRIMARY KEY, created_at TEXT, expires_at REAL
        );
        CREATE TABLE IF NOT EXISTS api_rate_limits (
          token_hash TEXT PRIMARY KEY, window_start REAL NOT NULL, request_count INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS schedules (
          id TEXT PRIMARY KEY, cron_expr TEXT NOT NULL, subnet TEXT NOT NULL,
          ports TEXT NOT NULL, timeout REAL NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cve_cache (
          cache_key TEXT PRIMARY KEY, cached_at REAL, payload TEXT
        );
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(api_tokens)")}
        if "expires_at" not in columns:
            conn.execute("ALTER TABLE api_tokens ADD COLUMN expires_at REAL")
            ttl = int(CONFIG.get("api", {}).get("token_ttl_hours", 24)) * 3600
            conn.execute("UPDATE api_tokens SET expires_at = strftime('%s', created_at) + ? WHERE expires_at IS NULL", (ttl,))


init_db()


def startup():
    if not scheduler.running:
        scheduler.start()

    schedule_jobs.clear()
    with db() as conn:
        rows = conn.execute(
            "SELECT id,cron_expr,subnet,ports,timeout FROM schedules ORDER BY created_at"
        ).fetchall()

    from apscheduler.triggers.cron import CronTrigger

    for row in rows:
        schedule_id = row["id"]
        try:
            trigger = CronTrigger.from_crontab(row["cron_expr"])
            ports = json.loads(row["ports"] or "[]")
            scheduler.add_job(
                launch_scan,
                trigger,
                id=schedule_id,
                args=[row["subnet"], ports, float(row["timeout"])],
                replace_existing=True,
            )
            schedule_jobs[schedule_id] = {
                "id": schedule_id,
                "cron_expr": row["cron_expr"],
                "subnet": row["subnet"],
                "ports": ports,
            }
        except (ValueError, json.JSONDecodeError):
            continue


def shutdown():
    if scheduler.running:
        scheduler.shutdown(wait=False)


class ScanRequest(BaseModel):
    subnet: str = Field(min_length=1, max_length=512)
    ports: list[int] = Field(default_factory=lambda: SCAN_CFG.get("default_ports", [22, 80, 443, 8080]))
    timeout: float = Field(default=3, ge=0.5, le=5)
    authorized: bool = False


class AlertConfig(BaseModel):
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = ""
    smtp_password: str = ""
    webhook_enabled: bool = False
    webhook_url: str = ""


class ScheduleRequest(BaseModel):
    cron_expr: str = Field(min_length=9, max_length=100)
    subnet: str = Field(min_length=1, max_length=512)
    ports: list[int] = Field(default_factory=lambda: SCAN_CFG.get("default_ports", [22, 80, 443]))


def validate_subnets(value: str) -> list[str]:
    parsed = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise HTTPException(400, f"Invalid subnet: {raw}") from exc
        if (not isinstance(network, ipaddress.IPv4Network) or
                not network.is_private or network.is_multicast or network.is_loopback or
                network.num_addresses > 256):
            raise HTTPException(400, "Only private IPv4 networks with at most 256 addresses (/24 or smaller) are allowed.")
        parsed.append(str(network))
    if not parsed or len(parsed) > 4:
        raise HTTPException(400, "Provide 1–4 authorized private subnets.")
    return list(dict.fromkeys(parsed))


def validate_ports(ports: list[int]) -> list[int]:
    if not ports or len(ports) > 30 or any(p not in ALLOWED_PORTS for p in ports):
        raise HTTPException(400, "Choose up to 30 ports from the documented safe port allow-list.")
    return sorted(set(ports))


def record_alert(kind: str, message: str, payload: dict | None = None):
    with db() as conn:
        conn.execute("INSERT INTO alerts(created_at,kind,message,payload) VALUES(?,?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), kind, message,
                      json.dumps(payload or {})))


def scan_worker(job_id: str, subnets: list[str], ports: list[int], timeout: float):
    all_devices = []
    try:
        with jobs_lock:
            jobs[job_id]["status"] = "running"
        # At most four concurrent private /24-sized network jobs.
        futures = {executor.submit(scan_target_network, net, ports, timeout): net for net in subnets}
        for future in concurrent.futures.as_completed(futures):
            net = futures[future]
            try:
                found = future.result()
                for device in found:
                    device["subnet"] = net
                all_devices.extend(found)
            except Exception as exc:
                record_alert("scan_error", f"Scan failed for {net}: {exc}")
            with jobs_lock:
                jobs[job_id]["completed_subnets"] += 1
                jobs[job_id]["progress"] = int(100 * jobs[job_id]["completed_subnets"] / len(futures))
        # Fingerprinting and NVD lookups are inherited from the v3.1 module.
        enriched = fingerprint.run_fingerprint(all_devices)
        now = datetime.now(timezone.utc).isoformat()
        with db() as conn:
            placeholders = ",".join("?" for _ in subnets)
            previous = {r["ip"]: dict(r) for r in conn.execute(
                f"SELECT * FROM devices WHERE subnet IN ({placeholders})", tuple(subnets)  # nosec B608 - only '?' placeholders are interpolated
            )}
            current_ips = set()
            for item in enriched:
                ip = item["ip"]
                current_ips.add(ip)
                old = previous.get(ip)
                changed = old and (json.loads(old["open_ports"] or "[]") != item.get("open_ports", []))
                conn.execute("""INSERT OR REPLACE INTO devices
                    (ip,mac,vendor,hostname,device_type,open_ports,cves,last_seen,subnet,online)
                    VALUES(?,?,?,?,?,?,?,?,?,1)""",
                    (ip, item.get("mac"), item.get("vendor"), item.get("hostname"),
                     item.get("device_type"), json.dumps(item.get("open_ports", [])),
                     json.dumps(item.get("cves", [])), now, item.get("subnet")))
                if not old:
                    record_alert("new_device", f"New device detected: {ip}", item)
                elif changed:
                    record_alert("device_changed", f"Device ports changed: {ip}", item)
            for ip, old in previous.items():
                if ip not in current_ips:
                    conn.execute("UPDATE devices SET online=0 WHERE ip=? AND subnet IN (" + placeholders + ")", (ip, *subnets))  # nosec B608 - only '?' placeholders are interpolated
                    if old["online"]:
                        record_alert("device_offline", f"Device went offline: {ip}", {"ip": ip})
            conn.execute("INSERT OR REPLACE INTO scans(id,created_at,subnet,status,results) VALUES(?,?,?,?,?)",
                         (job_id, now, ",".join(subnets), "completed", json.dumps(enriched)))
        with jobs_lock:
            jobs[job_id].update(status="completed", progress=100, results=enriched, finished_at=now)
    except Exception as exc:
        with jobs_lock:
            jobs[job_id].update(status="failed", error=str(exc))


def launch_scan(subnet: str, ports: list[int], timeout: float = 3) -> str:
    nets = validate_subnets(subnet)
    checked_ports = validate_ports(ports)
    job_id = uuid.uuid4().hex
    with jobs_lock:
        # Finished jobs are persisted in SQLite, so cap the in-memory copies.
        finished = [k for k, v in jobs.items() if v.get("status") in ("completed", "failed")]
        for old_id in finished[:max(0, len(jobs) - MAX_TRACKED_JOBS)]:
            jobs.pop(old_id, None)
        jobs[job_id] = {"id": job_id, "status": "queued", "progress": 0,
                        "completed_subnets": 0, "total_subnets": len(nets),
                        "results": [], "created_at": datetime.now(timezone.utc).isoformat()}
    threading.Thread(target=scan_worker, args=(job_id, nets, checked_ports, timeout), daemon=True).start()
    return job_id


def validate_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization[7:].strip()
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    with db() as conn:
        valid = conn.execute("SELECT expires_at FROM api_tokens WHERE token_hash=?", (digest,)).fetchone()
        if not valid or not valid["expires_at"] or float(valid["expires_at"]) <= now:
            if valid:
                conn.execute("DELETE FROM api_tokens WHERE token_hash=?", (digest,))
                conn.execute("DELETE FROM api_rate_limits WHERE token_hash=?", (digest,))
            raise HTTPException(401, "Invalid or expired token")
        limit = int(CONFIG.get("api", {}).get("rate_limit", 100))
        row = conn.execute("SELECT window_start,request_count FROM api_rate_limits WHERE token_hash=?", (digest,)).fetchone()
        if not row or now - float(row["window_start"]) >= 60:
            conn.execute("INSERT OR REPLACE INTO api_rate_limits(token_hash,window_start,request_count) VALUES(?,?,1)", (digest, now))
        elif int(row["request_count"]) >= limit:
            raise HTTPException(429, "Rate limit exceeded")
        else:
            conn.execute("UPDATE api_rate_limits SET request_count=request_count+1 WHERE token_hash=?", (digest,))
    return digest


def rate_limited_token(authorization: str | None = Header(default=None)):
    validate_bearer_token(authorization)
    return True


@app.middleware("http")
async def protect_dashboard_api(request: Request, call_next):
    path = request.url.path
    is_versioned_api = path.startswith("/api/") or path.startswith("/v1/")
    is_auth_route = path in ("/api/auth/token", "/v1/auth/token")
    if is_versioned_api and not is_auth_route:
        try:
            validate_bearer_token(request.headers.get("authorization"))
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    page = FRONTEND_DIR / "index.html"
    if not page.exists():
        return HTMLResponse("<h1>IoT Hunter v4.0</h1><p>Dashboard asset missing.</p>", status_code=500)
    return HTMLResponse(page.read_text(encoding="utf-8"))


@app.post("/api/auth/token")
def issue_api_token(request: Request, x_admin_secret: str | None = Header(default=None)):
    now = time.time()
    configured_secret = os.getenv("IOT_HUNTER_ADMIN_SECRET")
    if not configured_secret:
        raise HTTPException(503, "IOT_HUNTER_ADMIN_SECRET is not configured.")

    client_key = request.client.host if request.client else "unknown"
    with auth_lock:
        failures = [timestamp for timestamp in auth_failures.get(client_key, []) if now - timestamp < AUTH_WINDOW_SEC]
        if len(failures) >= AUTH_MAX_FAILURES:
            auth_failures[client_key] = failures
            retry_after = max(1, int(AUTH_WINDOW_SEC - (now - failures[0])))
            raise HTTPException(429, "Too many authentication failures.", headers={"Retry-After": str(retry_after)})

    if not x_admin_secret or not secrets.compare_digest(x_admin_secret, configured_secret):
        with auth_lock:
            auth_failures.setdefault(client_key, []).append(now)
        raise HTTPException(401, "Invalid administrator secret.")

    with auth_lock:
        auth_failures.pop(client_key, None)

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    ttl = int(CONFIG.get("api", {}).get("token_ttl_hours", 24)) * 3600
    created_at = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO api_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
            (digest, created_at, now + ttl),
        )
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


@app.get("/api/devices")
def devices():
    with db() as conn:
        return [dict(r) | {"open_ports": json.loads(r["open_ports"] or "[]"),
                           "cves": json.loads(r["cves"] or "[]")}
                for r in conn.execute("SELECT * FROM devices ORDER BY online DESC, ip")]


@app.post("/api/scan")
def start_scan(body: ScanRequest):
    if not body.authorized:
        raise HTTPException(400, "Confirm that you are authorized to assess these networks.")
    job_id = launch_scan(body.subnet, body.ports, body.timeout)
    return {"id": job_id, "status": "queued"}


@app.get("/api/scan/{scan_id}/status")
def scan_status(scan_id: str):
    with jobs_lock:
        job = jobs.get(scan_id)
    if not job:
        with db() as conn:
            row = conn.execute("SELECT id,status,created_at FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found")
        return dict(row) | {"progress": 100}
    return {k: v for k, v in job.items() if k != "results"}


@app.get("/api/scan/{scan_id}/results")
def scan_results(scan_id: str):
    with jobs_lock:
        job = jobs.get(scan_id)
    if job:
        return {"id": scan_id, "status": job["status"], "results": job.get("results", [])}
    with db() as conn:
        row = conn.execute("SELECT status,results FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return {"id": scan_id, "status": row["status"], "results": json.loads(row["results"] or "[]")}


@app.post("/api/alerts/config")
def set_alert_config(body: AlertConfig):
    # Secrets are accepted only at runtime and never returned or written to logs.
    os.environ["IOT_HUNTER_ALERT_CONFIG"] = body.model_dump_json()
    return {"saved": True, "message": "Alert settings loaded for this process. Configure environment secrets for persistent deployments."}


@app.post("/api/schedule")
def add_schedule(body: ScheduleRequest):
    nets = validate_subnets(body.subnet)
    ports = validate_ports(body.ports)
    try:
        from apscheduler.triggers.cron import CronTrigger
        trigger = CronTrigger.from_crontab(body.cron_expr)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid cron expression: {exc}") from exc
    schedule_id = uuid.uuid4().hex[:12]
    timeout = float(SCAN_CFG.get("default_timeout", 3))
    scheduler.add_job(launch_scan, trigger, id=schedule_id, args=[",".join(nets), ports, timeout], replace_existing=True)
    schedule_jobs[schedule_id] = {"id": schedule_id, "cron_expr": body.cron_expr,
                                  "subnet": ",".join(nets), "ports": ports}
    with db() as conn:
        conn.execute("INSERT INTO schedules(id,cron_expr,subnet,ports,timeout,created_at) VALUES(?,?,?,?,?,?)",
                     (schedule_id, body.cron_expr, ",".join(nets), json.dumps(ports), timeout, datetime.now(timezone.utc).isoformat()))
    return schedule_jobs[schedule_id]


@app.get("/api/schedule")
def list_schedules():
    return list(schedule_jobs.values())


@app.delete("/api/schedule/{schedule_id}")
def delete_schedule(schedule_id: str):
    if schedule_id not in schedule_jobs:
        raise HTTPException(404, "Schedule not found")
    scheduler.remove_job(schedule_id)
    del schedule_jobs[schedule_id]
    with db() as conn:
        conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    return {"deleted": True}


# Backward-compatible versioned API aliases.
@app.post("/v1/auth/token")
def issue_v1_api_token(request: Request, x_admin_secret: str | None = Header(default=None)):
    return issue_api_token(request, x_admin_secret)


@app.get("/v1/devices")
def v1_devices():
    return devices()


@app.post("/v1/scan")
def v1_start_scan(body: ScanRequest):
    return start_scan(body)


@app.get("/v1/scan/{scan_id}/status")
def v1_scan_status(scan_id: str):
    return scan_status(scan_id)


@app.get("/v1/scan/{scan_id}/results")
def v1_scan_results(scan_id: str):
    return scan_results(scan_id)


@app.post("/v1/alerts/config")
def v1_set_alert_config(body: AlertConfig):
    return set_alert_config(body)


@app.post("/v1/schedule")
def v1_add_schedule(body: ScheduleRequest):
    return add_schedule(body)


@app.get("/v1/schedule")
def v1_list_schedules():
    return list_schedules()


@app.delete("/v1/schedule/{schedule_id}")
def v1_delete_schedule(schedule_id: str):
    return delete_schedule(schedule_id)


@app.get("/api/report/{scan_id}/pdf")
def report_pdf(scan_id: str):
    # Scan IDs are generated as UUID hex strings; reject any other path parameter.
    if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
        raise HTTPException(400, "Invalid scan ID")
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    import tempfile
    results = json.loads(row["results"] or "[]")
    # Create the output file inside the fixed data directory. The request value
    # is never used to construct a filesystem path.
    report_file = tempfile.NamedTemporaryFile(
        mode="wb", suffix=".pdf", prefix="iot-hunter-report-",
        dir=str(DATA_DIR), delete=False
    )
    path = report_file.name
    report_file.close()
    styles = getSampleStyleSheet()
    story = [Paragraph("IoT Hunter v4.0 — Security Report", styles["Title"]),
             Paragraph(f"Timestamp: {row['created_at']}", styles["Normal"]),
             Paragraph(f"Scan parameters: {row['subnet']}", styles["Normal"]),
             Spacer(1, .5 * cm),
             Paragraph("Scan Summary", styles["Heading2"]),
             Paragraph(f"Discovered devices: {len(results)}", styles["Normal"]),
             Paragraph("Device Inventory & Open Ports", styles["Heading2"])]
    rows = [["IP", "Ports", "Device Type", "Hostname"]]
    for item in results:
        rows.append([
            str(item.get("ip", "")),
            ", ".join(str(port) for port in item.get("open_ports", [])),
            str(item.get("device_type", "")),
            str(item.get("hostname", "")),
        ])

    table = Table(rows)
    story.append(table)

    doc = SimpleDocTemplate(path, pagesize=A4)
    doc.build(story)

    return FileResponse(
        path,
        filename=f"iot-hunter-{scan_id}.pdf",
        media_type="application/pdf",
        background=BackgroundTask(lambda: os.unlink(path)),
    )


@app.get("/v1/report/{scan_id}/pdf")
def v1_report_pdf(scan_id: str):
    return report_pdf(scan_id)
