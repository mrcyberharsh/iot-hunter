"""Logging and small shared helpers."""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Any, Dict


def setup_logging(cfg: Dict[str, Any]) -> logging.Logger:
    """Configure root logger with console + rotating file handler (audit trail)."""
    lcfg = cfg.get("logging", {}) or {}
    level = getattr(logging, str(lcfg.get("level", "INFO")).upper(), logging.INFO)
    log_file = lcfg.get("file", "./logs/iothunter.log")

    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-22s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = RotatingFileHandler(
        log_file,
        maxBytes=int(lcfg.get("max_bytes", 5 * 1024 * 1024)),
        backupCount=int(lcfg.get("backup_count", 5)),
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logging.getLogger("iothunter")


def human_bytes(n: int) -> str:
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    v = float(n)
    for u in units:
        if v < step:
            return f"{v:.1f} {u}"
        v /= step
    return f"{v:.1f} PB"


def normalize_mac(mac: str) -> str:
    return (mac or "").replace("-", ":").replace(".", ":").lower()
