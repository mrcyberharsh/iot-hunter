"""Local IoT asset inventory snapshots and change tracking."""
from __future__ import annotations

import json
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_SNAPSHOTS = 50


def _normalize_open_ports(value: Any) -> list[int]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("open_ports must be an iterable of TCP/UDP port numbers.")

    ports = set()
    for raw_port in value:
        if isinstance(raw_port, bool):
            raise TypeError(f"Invalid port value: {raw_port!r}")
        if isinstance(raw_port, int):
            port = raw_port
        elif isinstance(raw_port, str) and raw_port.isascii() and raw_port.isdecimal():
            port = int(raw_port)
        else:
            raise ValueError(f"Invalid port value: {raw_port!r}")
        if not 1 <= port <= 65535:
            raise ValueError(f"Port must be between 1 and 65535: {raw_port!r}")
        ports.add(port)
    return sorted(ports)


def _device_key(device: dict[str, Any]) -> str:
    return str(device.get("mac") or device.get("ip") or "").strip().lower()


def compare_inventory(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare two inventories without probing devices or retaining credentials."""
    old = {_device_key(item): item for item in previous if _device_key(item)}
    new = {_device_key(item): item for item in current if _device_key(item)}
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    missing = [old[key] for key in sorted(old.keys() - new.keys())]
    changed = []
    for key in sorted(old.keys() & new.keys()):
        before, after = old[key], new[key]
        old_ports = sorted(set(before.get("open_ports", [])))
        new_ports = sorted(set(after.get("open_ports", [])))
        fields = []
        for field in ("vendor", "hostname", "device_type"):
            if before.get(field) != after.get(field):
                fields.append(field)
        if old_ports != new_ports:
            fields.append("open_ports")
        if fields:
            changed.append({
                "device": after.get("ip") or after.get("mac") or key,
                "changed_fields": fields,
                "previous_open_ports": old_ports,
                "current_open_ports": new_ports,
            })
    return {"new_devices": added, "missing_devices": missing, "changed_devices": changed}


def load_snapshots(path: str | Path = "data/inventory-history.json") -> list[dict[str, Any]]:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    return payload[:MAX_SNAPSHOTS] if isinstance(payload, list) else []


def record_inventory(devices: list[dict[str, Any]], path: str | Path = "data/inventory-history.json") -> dict[str, Any]:
    """Persist a bounded snapshot and return a comparison with the previous run."""
    snapshots = load_snapshots(path)
    previous = snapshots[0].get("devices", []) if snapshots else []
    safe_devices = []
    for device in devices:
        safe_devices.append({
            "ip": str(device.get("ip", "")),
            "mac": str(device.get("mac", "")),
            "vendor": str(device.get("vendor", "")),
            "hostname": str(device.get("hostname", "")),
            "device_type": str(device.get("device_type", "unknown")),
            "open_ports": _normalize_open_ports(device.get("open_ports", [])),
        })
    changes = compare_inventory(previous, safe_devices)
    snapshot = {
        "timestamp": datetime.now(UTC).isoformat(),
        "device_count": len(safe_devices),
        "devices": safe_devices,
    }
    snapshots.insert(0, snapshot)
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = file_path.with_suffix(file_path.suffix + ".tmp")
    temporary.write_text(json.dumps(snapshots[:MAX_SNAPSHOTS], indent=2), encoding="utf-8")
    os.replace(temporary, file_path)
    return {
        "timestamp": snapshot["timestamp"],
        "device_count": len(safe_devices),
        "new_devices": len(changes["new_devices"]),
        "missing_devices": len(changes["missing_devices"]),
        "changed_devices": len(changes["changed_devices"]),
        "details": changes,
    }
