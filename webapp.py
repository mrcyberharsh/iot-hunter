"""IoT Hunter v4.0 web/API layer.

The v3.1 discovery and fingerprint modules remain the scanning engine.
Only private IPv4 ranges up to /24 are accepted by this service.
"""
from __future__ import annotations

import concurrent.futures
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
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from modules import fingerprint
from modules.discovery import scan_target_network

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("IOT_HUNTER_DATA", ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = Path(os.getenv("IOT_HUNTER_CONFIG", ROOT / "config.yaml"))
DB_PATH = Path(os.getenv("IOT_HUNTER_DB", DATA_DIR / "iot.db"))
CONFIG = yaml.safe_load(CONFIG_PATH.read_text()) if CONFIG_PATH.exists() else {}
SCAN_CFG = CONFIG.get("scan", {})
ALLOWED_PORTS = {21, 22, 23, 53, 80, 139, 443, 445, 1883, 8883, 8080, 8443}

app = FastAPI(title="IoT Hunter API", version="4.0.0",
              description="Defensive IoT inventory for explicitly authorized private networks.")
scheduler = BackgroundScheduler(timezone="UTC")
executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
jobs: dict[str, dict[str, Any]] = {}
jobs_lock = threading.Lock()
rate_state: dict[str, list[float]] = {}
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
                f"SELECT * FROM devices WHERE subnet IN ({placeholders})", tuple(subnets)
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
                    conn.execute("UPDATE devices SET online=0 WHERE ip=? AND subnet IN (" + placeholders + ")", (ip, *subnets))
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
    if path.startswith("/api/") and path != "/api/auth/token":
        try:
            validate_bearer_token(request.headers.get("authorization"))
        except HTTPException as exc:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    page = ROOT / "web" / "index.html"
    if not page.exists():
        return HTMLResponse("<h1>IoT Hunter v4.0</h1><p>Dashboard asset missing.</p>", status_code=500)
    return HTMLResponse(page.read_text(encoding="utf-8"))


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
    rows = [["IP", "Vendor", "Type", "Open ports"]]
    rows += [[d.get("ip", ""), d.get("vendor", ""), d.get("device_type", ""),
              ", ".join(map(str, d.get("open_ports", [])))] for d in results]
    table = Table(rows, repeatRows=1)
    table.setStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#25203a")),
                    ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                    ("GRID", (0,0), (-1,-1), .4, colors.grey)])
    story += [table, Spacer(1, .4 * cm), Paragraph("CVE Findings", styles["Heading2"])]
    for d in results:
        for service in d.get("cves", []):
            for cve in service.get("cves", []):
                story.append(Paragraph(f"{d.get('ip')} — {cve.get('id')}: {cve.get('description','')[:300]}", styles["Normal"]))
    story += [Paragraph("Compliance Status", styles["Heading2"]),
              Paragraph("Manual review required: this report does not attempt default credentials or make unsupported CERT-In compliance claims.", styles["Normal"]),
              Paragraph("Recommendations", styles["Heading2"]),
              Paragraph("Review exposed services, disable unused management interfaces, update firmware using vendor advisories, and validate CVE matches against exact product/version information.", styles["Normal"])]
    SimpleDocTemplate(str(path), pagesize=A4).build(story)
    return FileResponse(path, media_type="application/pdf", filename=f"iot-hunter-{scan_id}.pdf")


def create_api_token():
    secret = os.getenv("IOT_HUNTER_ADMIN_SECRET", "")
    return secret


@app.post("/api/auth/token")
def issue_token(request: Request, x_admin_secret: str | None = Header(default=None)):
    expected = os.getenv("IOT_HUNTER_ADMIN_SECRET", "")
    if not expected or not x_admin_secret or not secrets.compare_digest(expected, x_admin_secret):
        raise HTTPException(401, "Valid X-Admin-Secret header required")
    token = secrets.token_urlsafe(32)
    digest = __import__("hashlib").sha256(token.encode()).hexdigest()
    ttl = max(1, int(CONFIG.get("api", {}).get("token_ttl_hours", 24))) * 3600
    created = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute("INSERT INTO api_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
                     (digest, created, time.time() + ttl))
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


# Public versioned API. The local dashboard endpoints remain available on /api.
app.get("/v1/devices", dependencies=[Depends(rate_limited_token)])(devices)
app.post("/v1/scan", dependencies=[Depends(rate_limited_token)])(start_scan)
app.get("/v1/scan/{scan_id}/status", dependencies=[Depends(rate_limited_token)])(scan_status)
app.get("/v1/scan/{scan_id}/results", dependencies=[Depends(rate_limited_token)])(scan_results)
app.get("/v1/schedule", dependencies=[Depends(rate_limited_token)])(list_schedules)
app.post("/v1/schedule", dependencies=[Depends(rate_limited_token)])(add_schedule)
app.delete("/v1/schedule/{schedule_id}", dependencies=[Depends(rate_limited_token)])(delete_schedule)
app.get("/v1/report/{scan_id}/pdf", dependencies=[Depends(rate_limited_token)])(report_pdf)


@app.on_event("startup")
def startup():
    scheduler.start()
    from apscheduler.triggers.cron import CronTrigger
    with db() as conn:
        rows = conn.execute("SELECT * FROM schedules").fetchall()
    for row in rows:
        try:
            trigger = CronTrigger.from_crontab(row["cron_expr"])
            ports = json.loads(row["ports"])
            scheduler.add_job(launch_scan, trigger, id=row["id"], replace_existing=True,
                              args=[row["subnet"], ports, float(row["timeout"])])
            schedule_jobs[row["id"]] = {"id": row["id"], "cron_expr": row["cron_expr"], "subnet": row["subnet"], "ports": ports}
        except (ValueError, TypeError, KeyError):
            continue


@app.on_event("shutdown")
def shutdown():
    scheduler.shutdown(wait=False)
    executor.shutdown(wait=False)
