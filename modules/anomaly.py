"""
anomaly.py - Real-time traffic monitoring & anomaly detection
Built by MR CYBER (Harsh Saini)
Statistical thresholds, rolling window, no hardcoded IPs.
"""
import time
import logging
from collections import defaultdict, deque

logger = logging.getLogger("iothunter.anomaly")

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class TrafficBaseline:
    def __init__(self, window_sec=60):
        self.window_sec = window_sec
        self.conn_times = defaultdict(lambda: deque())   # src -> timestamps (beaconing)
        self.port_hits = defaultdict(lambda: deque())     # src -> (ts, dst_port) for scan detection
        self.byte_counts = defaultdict(lambda: deque())   # src -> (ts, bytes) for exfil detection

    def _trim(self, dq, now):
        while dq and now - dq[0][0] > self.window_sec if dq and isinstance(dq[0], tuple) else False:
            dq.popleft()

    def record(self, pkt_time, src, dst_port, size):
        self.conn_times[src].append(pkt_time)
        self.port_hits[src].append((pkt_time, dst_port))
        self.byte_counts[src].append((pkt_time, size))

    def check_portscan(self, src, now, threshold_per_min):
        hits = self.port_hits[src]
        while hits and now - hits[0][0] > 60:
            hits.popleft()
        distinct_ports = len(set(p for _, p in hits))
        return distinct_ports >= threshold_per_min

    def check_exfil(self, src, now, threshold_bytes_per_min):
        counts = self.byte_counts[src]
        while counts and now - counts[0][0] > 60:
            counts.popleft()
        total = sum(b for _, b in counts)
        return total >= threshold_bytes_per_min

    def check_beacon(self, src, now, variance_threshold):
        times = self.conn_times[src]
        while times and now - times[0] > self.window_sec:
            times.popleft()
        if len(times) < 5:
            return False
        intervals = [t2 - t1 for t1, t2 in zip(times, list(times)[1:])]
        if not intervals:
            return False
        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return False
        variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
        std = variance ** 0.5
        cv = std / mean
        return cv < variance_threshold  # low variance = regular beaconing


def run_anomaly_monitor(config, duration_sec=None):
    if not SCAPY_OK:
        raise RuntimeError("scapy is required for anomaly monitoring. Install with: pip install scapy")

    thresholds = config.get("thresholds", {})
    baseline = TrafficBaseline(window_sec=thresholds.get("window_sec", 60))
    alerts = []
    start = time.time()
    duration = duration_sec or thresholds.get("baseline_duration_sec", 60)

    def handle_packet(pkt):
        if IP not in pkt:
            return
        now = time.time()
        src = pkt[IP].src
        size = len(pkt)
        dst_port = pkt[TCP].dport if TCP in pkt else 0

        baseline.record(now, src, dst_port, size)

        if baseline.check_portscan(src, now, thresholds.get("portscan_ports_per_min", 15)):
            alerts.append({"time": now, "type": "port_scan", "src": src})
            logger.warning("Port scan suspected from %s", src)

        if baseline.check_exfil(src, now, thresholds.get("exfil_bytes_per_min", 5_000_000)):
            alerts.append({"time": now, "type": "data_exfiltration", "src": src})
            logger.warning("Possible exfiltration from %s", src)

        if baseline.check_beacon(src, now, thresholds.get("beacon_interval_variance", 0.15)):
            alerts.append({"time": now, "type": "beaconing", "src": src})
            logger.warning("Beaconing pattern from %s", src)

    print(f"[*] Capturing live traffic for {duration}s (real packets, no simulated data)...")
    sniff(prn=handle_packet, timeout=duration, store=False)

    return alerts
