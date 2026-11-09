"""Bounded, passive heuristics. Thresholds are illustrative and require lab tuning."""
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime


@dataclass
class RuleHit:
    rule_id: str
    title: str
    severity: str
    description: str
    indicators: list[str]


class RuleEngine:
    def __init__(self):
        self.windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=1024))
        self.last_timestamp = 0.0

    def reset(self):
        self.windows.clear()
        self.last_timestamp = 0.0

    def inspect(self, record: dict, *, port_scan_eligible: bool = True) -> list[RuleHit]:
        ts = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).timestamp()
        # Historical logs may be unsorted. Begin a new analysis window on large rewinds.
        if ts < self.last_timestamp - 60:
            self.windows.clear()
            self.last_timestamp = ts
        self.last_timestamp = max(ts, self.last_timestamp)
        if len(self.windows) > 10000:
            self.windows.clear()
        events = self.windows[record["src_ip"]]
        while events and events[0][0] < ts - 60:
            events.popleft()
        events.append((ts, record["dst_ip"], record["dst_port"], record["status"], port_scan_eligible))
        hits = []
        ports = {e[2] for e in events if e[1] == record["dst_ip"] and e[4]}
        if port_scan_eligible and len(ports) >= 8:
            hits.append(RuleHit("port_scan", "Port scan indicators", "high", "A source contacted many destination ports within one minute.", [f"{len(ports)} distinct ports in 60 seconds", f"Target {record['dst_ip']}"]))
        if len(events) >= 25:
            hits.append(RuleHit("connection_frequency", "Unusual connection frequency", "medium", "The source exceeded the demonstration connection-frequency threshold.", [f"{len(events)} connections in 60 seconds", "Threshold: 25 connections per source"]))
        failed = sum(e[3] in {"S0", "REJ", "RSTO", "RSTR", "failed", "rejected"} for e in events)
        if failed >= 6 and record["status"] in {"S0", "REJ", "RSTO", "RSTR", "failed", "rejected"}:
            hits.append(RuleHit("failed_connections", "Repeated failed connections", "high", "Repeated connection failures can indicate misconfiguration or reconnaissance; investigate before attributing intent.", [f"{failed} failures in 60 seconds", f"Current state: {record['status']}"]))
        if record["protocol"] == "tcp" and record["dst_port"] in {23, 2323, 4444, 31337}:
            hits.append(RuleHit("unexpected_port", "Unexpected destination port", "medium", "Traffic used a port on the fixed demonstration review list. Port alone does not establish malicious activity.", [f"TCP destination port {record['dst_port']}"]))
        if record["protocol"] == "udp" and record["dst_port"] in {22, 80, 443, 3389}:
            # UDP/443 commonly means QUIC; it is deliberately excluded.
            if record["dst_port"] != 443:
                hits.append(RuleHit("protocol_mismatch", "Unexpected protocol and port", "low", "A protocol/port pairing differs from common service conventions.", [f"UDP destination port {record['dst_port']}"]))
        if record["bytes_sent"] >= 5_000_000:
            hits.append(RuleHit("traffic_spike", "Large outbound transfer", "high", "Outbound volume exceeded the fixed lab review threshold. A legitimate backup can also trigger this rule.", [f"{record['bytes_sent']:,} bytes sent", "Threshold: 5 MB per connection"]))
        return hits
