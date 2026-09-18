"""Local alerting: SMTP email and Slack webhook. No third-party SaaS."""
from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Any, Dict, List

from .models import Finding, severity_at_least

log = logging.getLogger(__name__)


class Alerter:
    def __init__(self, config: Dict[str, Any]):
        cfg = config.get("alerting", {}) or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.min_severity = str(cfg.get("min_severity", "high")).lower()
        self.email_cfg = cfg.get("email", {}) or {}
        self.slack_cfg = cfg.get("slack", {}) or {}

    # ------------------------------------------------------------------ #
    def dispatch(self, findings: List[Finding], context: str = "") -> Dict[str, int]:
        if not self.enabled:
            log.debug("Alerting disabled")
            return {"email": 0, "slack": 0}

        eligible = [f for f in findings if severity_at_least(f.severity, self.min_severity)]
        if not eligible:
            log.info("No findings at or above severity '%s' — nothing to alert", self.min_severity)
            return {"email": 0, "slack": 0}

        sent = {"email": 0, "slack": 0}

        if self.email_cfg.get("enabled"):
            sent["email"] = self._send_email(eligible, context)
        if self.slack_cfg.get("enabled"):
            sent["slack"] = self._send_slack(eligible, context)

        return sent

    # ------------------------------------------------------------------ #
    def _send_email(self, findings: List[Finding], context: str) -> int:
        cfg = self.email_cfg
        host = cfg.get("smtp_host", "localhost")
        port = int(cfg.get("smtp_port", 587))
        username = cfg.get("username", "")
        password = cfg.get("password", "")
        from_addr = cfg.get("from_addr", "iot-hunter@localhost")
        to_addrs = cfg.get("to_addrs", []) or []
        use_tls = bool(cfg.get("use_tls", False))
        use_starttls = bool(cfg.get("use_starttls", True))

        if not to_addrs:
            log.warning("Email alerting enabled but no recipients configured")
            return 0

        msg = EmailMessage()
        msg["Subject"] = (
            f"[iot-hunter] {len(findings)} finding(s) — {context or 'IoT security alert'}"
        )
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        lines = [f"iot-hunter alert — {context}", ""]
        for f in sorted(findings, key=lambda x: x.severity, reverse=True):
            lines.append(f"[{f.severity.upper()}] {f.title}")
            lines.append(f"  Asset:    {f.asset or 'n/a'}")
            lines.append(f"  Category: {f.category}")
            lines.append(f"  Time:     {f.timestamp}")
            lines.append(f"  Detail:   {f.description}")
            lines.append("")
        msg.set_content("\n".join(lines))

        try:
            if use_tls:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(host, port, timeout=20, context=ctx) as s:
                    if username:
                        s.login(username, password)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=20) as s:
                    s.ehlo()
                    if use_starttls:
                        s.starttls(context=ssl.create_default_context())
                        s.ehlo()
                    if username:
                        s.login(username, password)
                    s.send_message(msg)
            log.info("Email alert sent to %s", ", ".join(to_addrs))
            return 1
        except Exception as exc:
            log.error("Email alert failed: %s", exc)
            return 0

    # ------------------------------------------------------------------ #
    def _send_slack(self, findings: List[Finding], context: str) -> int:
        cfg = self.slack_cfg
        url = cfg.get("webhook_url", "")
        if not url:
            log.warning("Slack alerting enabled but no webhook URL configured")
            return 0

        channel = cfg.get("channel", "")
        username = cfg.get("username", "iot-hunter")

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"iot-hunter — {len(findings)} finding(s)",
                },
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": context or "IoT security alert"}],
            },
            {"type": "divider"},
        ]

        for f in findings[:25]:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                     "low": "🔵", "info": "⚪"}.get(f.severity, "•")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{f.title}*\n"
                        f"*Asset:* `{f.asset or 'n/a'}`  "
                        f"*Severity:* {f.severity.upper()}\n"
                        f"{f.description[:400]}"
                    ),
                },
            })

        if len(findings) > 25:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"…and {len(findings) - 25} more finding(s). See the full report.",
                }],
            })

        payload: Dict[str, Any] = {"text": f"iot-hunter: {len(findings)} finding(s)", "blocks": blocks}
        if channel:
            payload["channel"] = channel
        if username:
            payload["username"] = username

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                if 200 <= resp.status < 300:
                    log.info("Slack alert delivered")
                    return 1
                log.error("Slack webhook returned HTTP %s", resp.status)
        except urllib.error.HTTPError as exc:
            log.error("Slack webhook HTTP error: %s", exc)
        except urllib.error.URLError as exc:
            log.error("Slack webhook unreachable: %s", exc)
        except Exception as exc:
            log.error("Slack alert failed: %s", exc)
        return 0
