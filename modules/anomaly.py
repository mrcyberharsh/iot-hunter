"""Real-time traffic anomaly detection using Scapy.

Detects beaconing, port scanning, data exfiltration and protocol drift against a
learned baseline. Pure statistics — no hardcoded IPs, no external services.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import statistics
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from .models import Finding
from .utils import human_bytes

log = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff, conf as scapy_conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    SCAPY_AVAILABLE = False
    log.error("scapy unavailable — anomaly detection disabled: %s", exc)


class AnomalyDetector:
    def __init__(self, config: Dict[str, Any], local_network: ipaddress.IPv4Network):
        cfg = config.get("anomaly", {}) or {}
        self.iface: Optional[str] = None
        self.local_network = local_network
        self.bpf = cfg.get("bpf_filter", "ip")

        self.flow_window = int(cfg.get("flow_window_seconds", 60))
        self.beacon_min_samples = int(cfg.get("beacon_min_samples", 8))
        self.beacon_tol = float(cfg.get("beacon_interval_tolerance", 0.15))
        self.port_scan_threshold = int(cfg.get("port_scan_threshold", 20))
        self.exfil_threshold = int(cfg.get("exfil_bytes_threshold", 10_485_760))
        self.zscore_threshold = float(cfg.get("zscore_threshold", 3.0))
        self.baseline_path = cfg.get("baseline_path", "./data/baseline.json")

        self.baseline: Dict[str, Any] = self._load_baseline()
        self.findings: List[Finding] = []
        self._reset_live_state()

    # ------------------------------------------------------------------ #
    # Baseline persistence
    # ------------------------------------------------------------------ #
    def _load_baseline(self) -> Dict[str, Any]:
        if self.baseline_path and os.path.isfile(self.baseline_path):
            try:
                with open(self.baseline_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                log.info("Loaded baseline from %s", self.baseline_path)
                return data
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("Could not read baseline: %s", exc)
        return {}

    def _save_baseline(self, data: Dict[str, Any]) -> None:
        if not self.baseline_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.baseline_path)), exist_ok=True)
        with open(self.baseline_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        log.info("Baseline saved to %s", self.baseline_path)

    # ------------------------------------------------------------------ #
    # Live state
    # ------------------------------------------------------------------ #
    def _reset_live_state(self) -> None:
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.packet_count = 0
        self.byte_count = 0

        # (src, dst) -> deque[(ts, bytes)]
        self.flow_bytes: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=2000)
        )
        # (src, dst) -> {"ports": set, "first": ts, "alerted": bool}
        self.port_scan_state: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # (src, dst, dport) -> deque[ts]
        self.flow_times: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(
            lambda: deque(maxlen=256)
        )
        self._alerted: Set[str] = set()
        self._baseline_protocols: Set[str] = set(self.baseline.get("protocols", []))
        self._baseline_destinations: Set[str] = set(self.baseline.get("destinations", []))
        self._baseline_flow_bytes: Dict[str, float] = self.baseline.get("flow_bytes", {})

    # ------------------------------------------------------------------ #
    # Packet handling
    # ------------------------------------------------------------------ #
    @staticmethod
    def _classify(pkt) -> Tuple[str, Optional[int]]:
        if TCP in pkt:
            return "tcp", int(pkt[TCP].dport)
        if UDP in pkt:
            return "udp", int(pkt[UDP].dport)
        if ICMP in pkt:
            return "icmp", None
        return str(getattr(pkt[IP], "proto", "other")), None

    def _on_packet(self, pkt) -> None:
        try:
            if IP not in pkt:
                return
            ip = pkt[IP]
            ts = float(getattr(pkt, "time", time.time()))
            src, dst = ip.src, ip.dst
            size = len(pkt)
            proto, dport = self._classify(pkt)

            self.packet_count += 1
            self.byte_count += size
            self.protocol_counts[proto] += 1

            # --- flow byte accounting -------------------------------------- #
            flow = self.flow_bytes[(src, dst)]
            flow.append((ts, size))
            cutoff = ts - self.flow_window
            while flow and flow[0][0] < cutoff:
                flow.popleft()
            window_bytes = sum(b for _, b in flow)

            # --- per-flow timing (beaconing) ------------------------------- #
            if dport is not None:
                self.flow_times[(src, dst, dport)].append(ts)

            # --- evaluations ------------------------------------------------ #
            self._check_port_scan(src, dst, dport, ts)
            self._check_beaconing(src, dst, dport, ts)
            self._check_exfiltration(src, dst, window_bytes)
            self._check_protocol_drift(proto, src, dst)
            self._check_new_destination(src, dst)
        except Exception as exc:  # never let a callback kill the sniffer
            log.debug("Anomaly packet handler error: %s", exc)

    # ------------------------------------------------------------------ #
    # Detections
    # ------------------------------------------------------------------ #
    def _emit(self, key: str, finding: Finding) -> None:
        if key in self._alerted:
            return
        self._alerted.add(key)
        self.findings.append(finding)
        log.warning("[ANOMALY] %s — %s", finding.severity.upper(), finding.title)

    def _check_port_scan(self, src: str, dst: str, dport: Optional[int], ts: float) -> None:
        if dport is None:
            return
        key = (src, dst)
        state = self.port_scan_state.get(key)
        if state is None or (ts - state["first"]) > self.flow_window:
            state = {"ports": set(), "first": ts, "alerted": False}
            self.port_scan_state[key] = state
        state["ports"].add(dport)

        if (
            not state["alerted"]
            and len(state["ports"]) >= self.port_scan_threshold
            and (ts - state["first"]) <= self.flow_window
        ):
            state["alerted"] = True
            self._emit(
                f"portscan-{src}-{dst}",
                Finding(
                    id=f"anomaly-portscan-{src}-{dst}",
                    title="Possible port scan detected",
                    severity="high",
                    category="anomaly_portscan",
                    description=(
                        f"{src} contacted {len(state['ports'])} distinct ports on {dst} "
                        f"within {self.flow_window}s — consistent with a port scan."
                    ),
                    asset=src,
                    evidence={
                        "source": src,
                        "destination": dst,
                        "distinct_ports": len(state["ports"]),
                        "window_seconds": self.flow_window,
                    },
                ),
            )

    def _check_beaconing(
        self, src: str, dst: str, dport: Optional[int], ts: float
    ) -> None:
        if dport is None:
            return
        key = (src, dst, dport)
        times = self.flow_times[key]
        if len(times) < self.beacon_min_samples:
            return
        intervals = [b - a for a, b in zip(times, list(times)[1:]) if b > a]
        if len(intervals) < self.beacon_min_samples - 1:
            return
        mean = statistics.fmean(intervals)
        if mean <= 0:
            return
        try:
            stdev = statistics.pstdev(intervals)
        except statistics.StatisticsError:
            return
        jitter = stdev / mean
        if jitter <= self.beacon_tol:
            self._emit(
                f"beacon-{src}-{dst}-{dport}",
                Finding(
                    id=f"anomaly-beacon-{src}-{dst}-{dport}",
                    title="Periodic beaconing detected (possible C2)",
                    severity="high",
                    category="anomaly_beaconing",
                    description=(
                        f"{src} is contacting {dst}:{dport} at a highly regular interval "
                        f"(mean {mean:.2f}s, jitter {jitter:.2%}) over {len(times)} samples."
                    ),
                    asset=src,
                    evidence={
                        "source": src,
                        "destination": dst,
                        "dport": dport,
                        "mean_interval_s": round(mean, 3),
                        "jitter_ratio": round(jitter, 4),
                        "samples": len(times),
                    },
                ),
            )

    def _check_exfiltration(self, src: str, dst: str, window_bytes: int) -> None:
        if window_bytes < self.exfil_threshold:
            return
        # Only alert on outbound traffic from the local network
        try:
            if ipaddress.IPv4Address(src) not in self.local_network:
                return
        except ValueError:
            return
        self._emit(
            f"exfil-{src}-{dst}",
            Finding(
                id=f"anomaly-exfil-{src}-{dst}",
                title="Possible data exfiltration",
                severity="critical",
                category="anomaly_exfiltration",
                description=(
                    f"{src} sent {human_bytes(window_bytes)} to {dst} within "
                    f"{self.flow_window}s, exceeding the configured threshold "
                    f"({human_bytes(self.exfil_threshold)})."
                ),
                asset=src,
                evidence={
                    "source": src,
                    "destination": dst,
                    "bytes_in_window": window_bytes,
                    "window_seconds": self.flow_window,
                },
            ),
        )

    def _check_protocol_drift(self, proto: str, src: str, dst: str) -> None:
        if not self._baseline_protocols:
            return
        if proto in self._baseline_protocols:
            return
        self._emit(
            f"proto-{proto}-{src}",
            Finding(
                id=f"anomaly-proto-{proto}-{src}",
                title=f"Protocol not present in baseline: {proto}",
                severity="medium",
                category="anomaly_protocol",
                description=(
                    f"Observed {proto} traffic from {src} to {dst} that does not appear "
                    "in the learned baseline."
                ),
                asset=src,
                evidence={"protocol": proto, "source": src, "destination": dst},
            ),
        )

    def _check_new_destination(self, src: str, dst: str) -> None:
        if not self._baseline_destinations:
            return
        if dst in self._baseline_destinations:
            return
        try:
            if ipaddress.IPv4Address(dst) in self.local_network:
                return
        except ValueError:
            return
        self._emit(
            f"newdst-{src}-{dst}",
            Finding(
                id=f"anomaly-newdst-{src}-{dst}",
                title="New external destination contacted",
                severity="medium",
                category="anomaly_new_destination",
                description=(
                    f"{src} contacted external address {dst}, which was not observed "
                    "during baseline learning."
                ),
                asset=src,
                evidence={"source": src, "destination": dst},
            ),
        )

    # ------------------------------------------------------------------ #
    # Modes
    # ------------------------------------------------------------------ #
    def learn_baseline(
        self, interface: str, duration_seconds: int
    ) -> Dict[str, Any]:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for anomaly detection")

        self.iface = interface
        scapy_conf.iface = interface
        self._reset_live_state()

        log.info(
            "Learning baseline on %s for %d seconds — DO NOT attack the network now",
            interface, duration_seconds,
        )
        deadline = time.time() + duration_seconds
        chunk = 30
        while time.time() < deadline:
            remaining = max(1, int(deadline - time.time()))
            sniff(
                iface=interface,
                filter=self.bpf,
                prn=self._on_packet,
                store=False,
                timeout=min(chunk, remaining),
            )
            log.info(
                "Baseline progress: %d packets / %s captured",
                self.packet_count, human_bytes(self.byte_count),
            )

        # Do not persist findings produced during learning
        self.findings.clear()

        total = max(1, self.packet_count)
        baseline = {
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "interface": interface,
            "duration_seconds": duration_seconds,
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "protocols": sorted(self.protocol_counts.keys()),
            "protocol_share": {
                k: round(v / total, 6) for k, v in self.protocol_counts.items()
            },
            "destinations": sorted({dst for (_, dst) in self.flow_bytes.keys()}),
            "flow_bytes": {
                f"{s}->{d}": sum(b for _, b in flow)
                for (s, d), flow in self.flow_bytes.items()
            },
        }
        self.baseline = baseline
        self._baseline_protocols = set(baseline["protocols"])
        self._baseline_destinations = set(baseline["destinations"])
        self._baseline_flow_bytes = baseline["flow_bytes"]
        self._save_baseline(baseline)
        return baseline

    def monitor(self, interface: str, duration_seconds: int) -> List[Finding]:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for anomaly detection")

        self.iface = interface
        scapy_conf.iface = interface
        self.findings = []
        self._alerted.clear()

        log.info("Monitoring %s for %d seconds", interface, duration_seconds)
        deadline = time.time() + duration_seconds
        while time.time() < deadline:
            remaining = max(1, int(deadline - time.time()))
            sniff(
                iface=interface,
                filter=self.bpf,
                prn=self._on_packet,
                store=False,
                timeout=min(30, remaining),
            )
            log.info(
                "Monitoring: %d packets, %d finding(s) so far",
                self.packet_count, len(self.findings),
            )

        return list(self.findings)
