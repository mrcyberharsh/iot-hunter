"""Configuration loading and automatic interface / subnet detection."""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Any, Dict, List, Optional, Tuple

import psutil
import yaml

log = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when configuration cannot be resolved."""


# --------------------------------------------------------------------------- #
# Config file
# --------------------------------------------------------------------------- #
def load_config(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise ConfigError(f"Configuration file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    if not isinstance(cfg, dict):
        raise ConfigError("Configuration root must be a mapping")
    return cfg


# --------------------------------------------------------------------------- #
# Interface detection
# --------------------------------------------------------------------------- #
def _primary_ip() -> Optional[str]:
    """
    Return the local IP that would be used to reach the default route.
    UDP connect() performs no network I/O — it only consults the routing table.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed on the wire
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def list_interfaces() -> List[Dict[str, Any]]:
    """Return every UP IPv4 interface with a usable address."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    out: List[Dict[str, Any]] = []

    for name, addr_list in addrs.items():
        st = stats.get(name)
        if st is None or not st.isup:
            continue
        for a in addr_list:
            if a.family != socket.AF_INET:
                continue
            if not a.address or a.address.startswith("127."):
                continue
            if a.address.startswith("169.254."):
                continue  # link-local, not routable
            netmask = a.netmask or "255.255.255.0"
            try:
                net = ipaddress.IPv4Network(f"{a.address}/{netmask}", strict=False)
            except ValueError:
                continue
            out.append(
                {
                    "name": name,
                    "ip": a.address,
                    "netmask": netmask,
                    "network": str(net),
                    "prefixlen": net.prefixlen,
                }
            )
    return out


def resolve_interface_and_subnet(
    cfg: Dict[str, Any]
) -> Tuple[Dict[str, Any], ipaddress.IPv4Network]:
    """
    Resolve the interface + subnet from config, auto-detecting when set to "auto".
    Returns (interface_info, network).
    """
    iface_cfg = str(cfg.get("interface", "auto")).strip()
    subnet_cfg = str(cfg.get("subnet", "auto")).strip()

    interfaces = list_interfaces()
    if not interfaces:
        raise ConfigError(
            "No active IPv4 interface with a routable address was found. "
            "Bring an interface up or set 'interface' explicitly."
        )

    chosen: Optional[Dict[str, Any]] = None

    if iface_cfg and iface_cfg.lower() != "auto":
        for i in interfaces:
            if i["name"] == iface_cfg:
                chosen = i
                break
        if chosen is None:
            names = ", ".join(sorted({i["name"] for i in interfaces}))
            raise ConfigError(
                f"Interface '{iface_cfg}' is not UP or has no IPv4 address. "
                f"Available: {names}"
            )
    else:
        primary = _primary_ip()
        if primary:
            for i in interfaces:
                if i["ip"] == primary:
                    chosen = i
                    break
        if chosen is None:
            chosen = interfaces[0]
            log.warning(
                "Could not determine default-route interface; falling back to %s",
                chosen["name"],
            )

    if subnet_cfg and subnet_cfg.lower() != "auto":
        try:
            network = ipaddress.IPv4Network(subnet_cfg, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid subnet '{subnet_cfg}': {exc}") from exc
    else:
        network = ipaddress.IPv4Network(chosen["network"], strict=False)

    max_hosts = int((cfg.get("scan") or {}).get("max_hosts", 1024))
    if network.num_addresses - 2 > max_hosts:
        raise ConfigError(
            f"Subnet {network} contains {network.num_addresses - 2} hosts which exceeds "
            f"scan.max_hosts={max_hosts}. Narrow the subnet or raise the limit."
        )

    return chosen, network
