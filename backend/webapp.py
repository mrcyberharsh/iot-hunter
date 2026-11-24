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
import logging
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
from xml.sax.saxutils import escape

import yaml
from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from modules.discovery import scan_target_network
from modules.reporting import sanitize_report_data
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from modules import fingerprint

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
logger = logging.getLogger(__name__)

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
MIN_ADMIN_SECRET_LENGTH = 32
MAX_TRACKED_JOBS = 200
schedule_jobs: dict[str, dict[str, Any]] = {}


def get_configured_admin_secret() -> str | None:
    secret = os.getenv("IOT_HUNTER_ADMIN_SECRET")
    if (
        not secret
        or len(secret) < MIN_ADMIN_SECRET_LENGTH
        or secret == "replace-with-a-long-random-secret"
    ):
        return None
    return secret


def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
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
          results TEXT, errors TEXT NOT NULL DEFAULT '[]'
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
          ports TEXT NOT NULL, timeout REAL NOT NULL DEFAULT 3,
          created_at TEXT NOT NULL, last_run_at TEXT, last_status TEXT,
          last_error TEXT, last_scan_id TEXT
        );
        CREATE TABLE IF NOT EXISTS cve_cache (
          cache_key TEXT PRIMARY KEY, cached_at REAL, payload TEXT
        );
        """)

        migrations = (
            ("api_tokens", "expires_at", "REAL"),
            ("scans", "errors", "TEXT NOT NULL DEFAULT '[]'"),
            ("schedules", "timeout", "REAL NOT NULL DEFAULT 3"),
            ("schedules", "last_run_at", "TEXT"),
            ("schedules", "last_status", "TEXT"),
            ("schedules", "last_error", "TEXT"),
            ("schedules", "last_scan_id", "TEXT"),
        )
        for table, column, declaration in migrations:
            columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if column not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

        ttl = int(CONFIG.get("api", {}).get("token_ttl_hours", 24)) * 3600
        conn.execute(
            "UPDATE api_tokens SET expires_at = strftime('%s', created_at) + ? "
            "WHERE expires_at IS NULL",
            (ttl,),
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_expires_at ON api_tokens(expires_at)"
        )


init_db()


def startup():
    if not get_configured_admin_secret():
        raise RuntimeError(
            "IOT_HUNTER_ADMIN_SECRET must be configured with at least "
            f"{MIN_ADMIN_SECRET_LENGTH} characters."
        )
    if not scheduler.running:
        scheduler.start()

    schedule_jobs.clear()
    with db() as conn:
        interruption = "Process restarted before the scan completed."
        conn.execute(
            "UPDATE scans SET status='failed', errors=? "
            "WHERE status IN ('queued', 'running')",
            (json.dumps([{"error": interruption}]),),
        )
        conn.execute(
            "UPDATE schedules SET last_status='interrupted', last_error=? "
            "WHERE last_status='running'",
            (interruption,),
        )
        rows = conn.execute(
            "SELECT id,cron_expr,subnet,ports,timeout,last_run_at,last_status,"
            "last_error,last_scan_id FROM schedules ORDER BY created_at"
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
                args=[row["subnet"], ports, float(row["timeout"]), schedule_id],
                replace_existing=True,
            )
            schedule_jobs[schedule_id] = {
                "id": schedule_id,
                "cron_expr": row["cron_expr"],
                "subnet": row["subnet"],
                "ports": ports,
                "timeout": float(row["timeout"]),
                "last_run_at": row["last_run_at"],
                "last_status": row["last_status"],
                "last_error": row["last_error"],
                "last_scan_id": row["last_scan_id"],
            }
        except (TypeError, ValueError, json.JSONDecodeError):
            logger.exception("Could not restore scheduled scan %s", schedule_id)
            with db() as conn:
                conn.execute(
                    "UPDATE schedules SET last_status='invalid', "
                    "last_error='Stored schedule configuration is invalid' WHERE id=?",
                    (schedule_id,),
                )
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
    timeout: float = Field(
        default_factory=lambda: float(SCAN_CFG.get("default_timeout", 3)),
        ge=0.5,
        le=5,
    )


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


def _insert_alert(conn: sqlite3.Connection, kind: str, message: str, payload: dict | None = None):
    conn.execute(
        "INSERT INTO alerts(created_at,kind,message,payload) VALUES(?,?,?,?)",
        (
            datetime.now(timezone.utc).isoformat(),
            kind,
            message,
            json.dumps(payload or {}),
        ),
    )


def record_alert(kind: str, message: str, payload: dict | None = None):
    with db() as conn:
        _insert_alert(conn, kind, message, payload)


def _update_schedule_run(
    conn: sqlite3.Connection,
    schedule_id: str,
    scan_id: str,
    status: str,
    error: str | None = None,
    run_at: str | None = None,
):
    if run_at is None:
        conn.execute(
            "UPDATE schedules SET last_status=?,last_error=?,last_scan_id=? WHERE id=?",
            (status, error, scan_id, schedule_id),
        )
    else:
        conn.execute(
            "UPDATE schedules SET last_run_at=?,last_status=?,last_error=?,last_scan_id=? "
            "WHERE id=?",
            (run_at, status, error, scan_id, schedule_id),
        )


def scan_worker(
    job_id: str,
    subnets: list[str],
    ports: list[int],
    timeout: float,
    schedule_id: str | None = None,
):
    all_devices = []
    successful_subnets = []
    errors = []
    alert_events = []
    try:
        with jobs_lock:
            jobs[job_id]["status"] = "running"
        with db() as conn:
            conn.execute("UPDATE scans SET status='running' WHERE id=?", (job_id,))
            if schedule_id:
                _update_schedule_run(
                    conn,
                    schedule_id,
                    job_id,
                    "running",
                    run_at=datetime.now(timezone.utc).isoformat(),
                )

        # At most four concurrent private /24-sized network jobs.
        futures = {executor.submit(scan_target_network, net, ports, timeout): net for net in subnets}
        for future in concurrent.futures.as_completed(futures):
            net = futures[future]
            try:
                found = future.result()
                for device in found:
                    device["subnet"] = net
                all_devices.extend(found)
                successful_subnets.append(net)
            except Exception as exc:
                errors.append({"subnet": net, "error": str(exc)})
                alert_events.append(("scan_error", f"Scan failed for {net}: {exc}", {"subnet": net}))
            with jobs_lock:
                jobs[job_id]["completed_subnets"] += 1
                jobs[job_id]["progress"] = int(100 * jobs[job_id]["completed_subnets"] / len(futures))

        if not successful_subnets:
            now = datetime.now(timezone.utc).isoformat()
            error = "; ".join(item["error"] for item in errors) or "No subnet scan completed."
            with db() as conn:
                conn.execute(
                    "UPDATE scans SET status='failed',results='[]',errors=? WHERE id=?",
                    (json.dumps(errors), job_id),
                )
                for kind, message, payload in alert_events:
                    _insert_alert(conn, kind, message, payload)
                if schedule_id:
                    _update_schedule_run(conn, schedule_id, job_id, "failed", error)
            with jobs_lock:
                jobs[job_id].update(
                    status="failed",
                    progress=100,
                    results=[],
                    errors=errors,
                    error=error,
                    finished_at=now,
                )
            return

        # Fingerprinting and NVD lookups are inherited from the v3.1 module.
        enriched = fingerprint.run_fingerprint(all_devices)
        now = datetime.now(timezone.utc).isoformat()
        final_status = "partial" if errors else "completed"
        with db() as conn:
            placeholders = ",".join("?" for _ in successful_subnets)
            previous = {r["ip"]: dict(r) for r in conn.execute(
                f"SELECT * FROM devices WHERE subnet IN ({placeholders})", tuple(successful_subnets)  # nosec B608 - only '?' placeholders are interpolated
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
                    alert_events.append(("new_device", f"New device detected: {ip}", item))
                elif changed:
                    alert_events.append(("device_changed", f"Device ports changed: {ip}", item))
            for ip, old in previous.items():
                if ip not in current_ips:
                    conn.execute("UPDATE devices SET online=0 WHERE ip=? AND subnet IN (" + placeholders + ")", (ip, *successful_subnets))  # nosec B608 - only '?' placeholders are interpolated
                    if old["online"]:
                        alert_events.append(
                            ("device_offline", f"Device went offline: {ip}", {"ip": ip})
                        )
            conn.execute(
                "UPDATE scans SET status=?,results=?,errors=? WHERE id=?",
                (final_status, json.dumps(enriched), json.dumps(errors), job_id),
            )
            if schedule_id:
                error = "; ".join(item["error"] for item in errors) if errors else None
                _update_schedule_run(conn, schedule_id, job_id, final_status, error)
            for kind, message, payload in alert_events:
                _insert_alert(conn, kind, message, payload)
        with jobs_lock:
            jobs[job_id].update(
                status=final_status,
                progress=100,
                results=enriched,
                errors=errors,
                finished_at=now,
            )
    except Exception as exc:
        now = datetime.now(timezone.utc).isoformat()
        error = str(exc)
        try:
            with db() as conn:
                conn.execute(
                    "UPDATE scans SET status='failed',errors=? WHERE id=?",
                    (json.dumps([{"error": error}]), job_id),
                )
                if schedule_id:
                    _update_schedule_run(conn, schedule_id, job_id, "failed", error)
        except sqlite3.Error:
            logger.exception("Could not persist failed scan %s", job_id)
            error = f"{error}; failure status could not be persisted"
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id].update(
                    status="failed",
                    error=error,
                    errors=errors or [{"error": error}],
                    finished_at=now,
                )


def launch_scan(
    subnet: str,
    ports: list[int],
    timeout: float = 3,
    schedule_id: str | None = None,
) -> str:
    nets = validate_subnets(subnet)
    checked_ports = validate_ports(ports)
    job_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO scans(id,created_at,subnet,status,results,errors) "
            "VALUES(?,?,?,'queued','[]','[]')",
            (job_id, created_at, ",".join(nets)),
        )
    with jobs_lock:
        # Finished jobs are persisted in SQLite, so cap the in-memory copies.
        finished = [
            k for k, v in jobs.items()
            if v.get("status") in ("completed", "partial", "failed")
        ]
        for old_id in finished[:max(0, len(jobs) - MAX_TRACKED_JOBS)]:
            jobs.pop(old_id, None)
        jobs[job_id] = {"id": job_id, "status": "queued", "progress": 0,
                        "completed_subnets": 0, "total_subnets": len(nets),
                        "results": [], "errors": [], "created_at": created_at}
    try:
        threading.Thread(
            target=scan_worker,
            args=(job_id, nets, checked_ports, timeout, schedule_id),
            daemon=True,
        ).start()
    except RuntimeError as exc:
        with db() as conn:
            conn.execute(
                "UPDATE scans SET status='failed',errors=? WHERE id=?",
                (json.dumps([{"error": str(exc)}]), job_id),
            )
            if schedule_id:
                _update_schedule_run(conn, schedule_id, job_id, "failed", str(exc))
        with jobs_lock:
            jobs[job_id].update(status="failed", error=str(exc), finished_at=created_at)
        raise
    return job_id


def validate_bearer_token(authorization: str | None) -> str:
    parts = authorization.split(None, 1) if authorization else []
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(401, "Bearer token required")
    token = parts[1].strip()
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


def rate_limited_token(
    request: Request,
    authorization: str | None = Header(default=None),
):
    validated = getattr(request.state, "validated_token_hash", None)
    if validated is None:
        validated = validate_bearer_token(authorization)
        request.state.validated_token_hash = validated
    return validated


def _is_api_path(path: str) -> bool:
    return path in {"/api", "/v1"} or path.startswith(("/api/", "/v1/"))


def _api_error_response(
    status_code: int,
    detail: Any,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=headers,
    )


@app.exception_handler(HTTPException)
async def handle_http_exception(_request: Request, exc: HTTPException):
    return _api_error_response(exc.status_code, exc.detail, exc.headers)


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_request: Request, exc: RequestValidationError):
    sanitized_errors = [
        {
            "loc": error["loc"],
            "msg": error["msg"],
            "type": error["type"],
        }
        for error in exc.errors()
    ]
    return _api_error_response(422, sanitized_errors)


@app.middleware("http")
async def protect_dashboard_api(request: Request, call_next):
    path = request.url.path
    is_versioned_api = _is_api_path(path)
    is_auth_route = path in ("/api/auth/token", "/v1/auth/token")
    if is_versioned_api and not is_auth_route:
        try:
            rate_limited_token(request, request.headers.get("authorization"))
        except HTTPException as exc:
            response = _api_error_response(exc.status_code, exc.detail, exc.headers)
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    if is_versioned_api:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Vary"] = "Authorization"
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard():
    page = FRONTEND_DIR / "index.html"
    if not page.exists():
        return HTMLResponse("<h1>IoT Hunter v4.0</h1><p>Dashboard asset missing.</p>", status_code=500)
    return HTMLResponse(page.read_text(encoding="utf-8"))


@app.post("/api/auth/token")
def issue_api_token(request: Request, x_admin_secret: str | None = Header(default=None)):
    now = time.time()
    configured_secret = get_configured_admin_secret()
    if not configured_secret:
        raise HTTPException(
            503,
            "Administrator authentication is not configured securely.",
        )

    client_key = request.client.host if request.client else "unknown"
    with auth_lock:
        for key, timestamps in list(auth_failures.items()):
            recent = [
                timestamp
                for timestamp in timestamps
                if now - timestamp < AUTH_WINDOW_SEC
            ]
            if recent:
                auth_failures[key] = recent
            else:
                auth_failures.pop(key, None)
        failures = [timestamp for timestamp in auth_failures.get(client_key, []) if now - timestamp < AUTH_WINDOW_SEC]
        if len(failures) >= AUTH_MAX_FAILURES:
            auth_failures[client_key] = failures
            retry_after = max(1, int(AUTH_WINDOW_SEC - (now - failures[0])))
            raise HTTPException(429, "Too many authentication failures.", headers={"Retry-After": str(retry_after)})

    if not x_admin_secret or not secrets.compare_digest(
        x_admin_secret.encode("utf-8"),
        configured_secret.encode("utf-8"),
    ):
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
            "DELETE FROM api_tokens WHERE expires_at IS NULL OR expires_at <= ?",
            (now,),
        )
        conn.execute(
            "DELETE FROM api_rate_limits WHERE window_start <= ? "
            "OR token_hash NOT IN (SELECT token_hash FROM api_tokens)",
            (now - 60,),
        )
        conn.execute(
            "INSERT OR REPLACE INTO api_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
            (digest, created_at, now + ttl),
        )
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


@app.get("/api/devices", dependencies=[Depends(rate_limited_token)])
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
            row = conn.execute(
                "SELECT id,status,created_at,errors FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found")
        result = dict(row)
        result["errors"] = json.loads(result.pop("errors") or "[]")
        result["progress"] = 100 if result["status"] in {"completed", "partial", "failed"} else 0
        return result
    return {k: v for k, v in job.items() if k != "results"}


@app.get("/api/scan/{scan_id}/results")
def scan_results(scan_id: str):
    with jobs_lock:
        job = jobs.get(scan_id)
    if job:
        return {
            "id": scan_id,
            "status": job["status"],
            "results": job.get("results", []),
            "errors": job.get("errors", []),
        }
    with db() as conn:
        row = conn.execute(
            "SELECT status,results,errors FROM scans WHERE id=?",
            (scan_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return {
        "id": scan_id,
        "status": row["status"],
        "results": json.loads(row["results"] or "[]"),
        "errors": json.loads(row["errors"] or "[]"),
    }


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
    timeout = body.timeout
    with db() as conn:
        conn.execute(
            "INSERT INTO schedules(id,cron_expr,subnet,ports,timeout,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                schedule_id,
                body.cron_expr,
                ",".join(nets),
                json.dumps(ports),
                timeout,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    job_registered = False
    try:
        scheduler.add_job(
            launch_scan,
            trigger,
            id=schedule_id,
            args=[",".join(nets), ports, timeout, schedule_id],
            replace_existing=True,
        )
        job_registered = True
    finally:
        if not job_registered:
            with db() as conn:
                conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    schedule_jobs[schedule_id] = {
        "id": schedule_id,
        "cron_expr": body.cron_expr,
        "subnet": ",".join(nets),
        "ports": ports,
        "timeout": timeout,
        "last_run_at": None,
        "last_status": None,
        "last_error": None,
        "last_scan_id": None,
    }
    return schedule_jobs[schedule_id]


@app.get("/api/schedule")
def list_schedules():
    with db() as conn:
        rows = conn.execute(
            "SELECT id,cron_expr,subnet,ports,timeout,last_run_at,last_status,"
            "last_error,last_scan_id FROM schedules ORDER BY created_at"
        ).fetchall()
    return [
        {
            "id": row["id"],
            "cron_expr": row["cron_expr"],
            "subnet": row["subnet"],
            "ports": json.loads(row["ports"] or "[]"),
            "timeout": float(row["timeout"]),
            "last_run_at": row["last_run_at"],
            "last_status": row["last_status"],
            "last_error": row["last_error"],
            "last_scan_id": row["last_scan_id"],
        }
        for row in rows
    ]


@app.delete("/api/schedule/{schedule_id}")
def delete_schedule(schedule_id: str):
    with db() as conn:
        exists = conn.execute("SELECT 1 FROM schedules WHERE id=?", (schedule_id,)).fetchone()
    if not exists:
        raise HTTPException(404, "Schedule not found")
    try:
        scheduler.remove_job(schedule_id)
    except JobLookupError:
        pass
    schedule_jobs.pop(schedule_id, None)
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
    import tempfile

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table
    results = sanitize_report_data(json.loads(row["results"] or "[]"))
    if not isinstance(results, list) or any(
        not isinstance(item, dict) for item in results
    ):
        raise HTTPException(500, "Stored scan results are invalid.")
    # Create the output file inside the fixed data directory. The request value
    # is never used to construct a filesystem path.
    report_file = tempfile.NamedTemporaryFile(
        mode="wb", suffix=".pdf", prefix="iot-hunter-report-",
        dir=str(DATA_DIR), delete=False
    )
    path = report_file.name
    report_file.close()
    try:
        styles = getSampleStyleSheet()
        story = [Paragraph("IoT Hunter v4.0 — Security Report", styles["Title"]),
                 Paragraph(f"Timestamp: {escape(str(row['created_at'] or 'N/A'))}", styles["Normal"]),
                 Paragraph(f"Scan parameters: {escape(str(row['subnet'] or 'N/A'))}", styles["Normal"]),
                 Spacer(1, .5 * cm),
                 Paragraph("Scan Summary", styles["Heading2"]),
                 Paragraph(f"Discovered devices: {len(results)}", styles["Normal"]),
                 Paragraph("Device Inventory & Open Ports", styles["Heading2"])]
        rows = [["IP", "Ports", "Device Type", "Hostname"]]
        for item in results:
            ports = item.get("open_ports", []) or []
            if not isinstance(ports, (list, tuple, set)):
                ports = [ports]
            rows.append([
                escape(str(item.get("ip", ""))),
                escape(", ".join(str(port) for port in ports)),
                escape(str(item.get("device_type", ""))),
                escape(str(item.get("hostname", ""))),
            ])

        story.append(Table(rows))
        doc = SimpleDocTemplate(path, pagesize=A4)
        doc.build(story)
    except Exception as exc:
        Path(path).unlink(missing_ok=True)
        logger.exception("PDF report generation failed for scan %s", scan_id)
        raise HTTPException(500, "Unable to generate PDF report.") from exc

    return FileResponse(
        path,
        filename=f"iot-hunter-{scan_id}.pdf",
        media_type="application/pdf",
        background=BackgroundTask(lambda: Path(path).unlink(missing_ok=True)),
    )


@app.get("/v1/report/{scan_id}/pdf")
def v1_report_pdf(scan_id: str):
    return report_pdf(scan_id)
