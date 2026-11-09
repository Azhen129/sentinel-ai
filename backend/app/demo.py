"""Deterministic, wholly synthetic documentation-address traffic. No network I/O."""
from datetime import datetime, timedelta, timezone
import random


def demo_records(total: int = 360, anchor: datetime | None = None) -> list[dict]:
    rng = random.Random(129)
    start = anchor or (datetime.now(timezone.utc) - timedelta(minutes=18))
    records = []
    services = [(443, "tcp", "https"), (53, "udp", "dns"), (80, "tcp", "http"), (22, "tcp", "ssh"), (123, "udp", "ntp")]
    for i in range(total):
        port, protocol, service = rng.choices(services, weights=[62, 22, 8, 5, 3])[0]
        record = dict(timestamp=(start + timedelta(seconds=i * 3)).isoformat(), src_ip=f"192.0.2.{rng.randint(10, 24)}", dst_ip=f"198.51.100.{rng.choice([8, 20, 42, 80, 101])}", src_port=rng.randint(32000, 65000), dst_port=port, protocol=protocol, duration=round(rng.uniform(0.03, 8), 3), bytes_sent=rng.randint(80, 15000), bytes_received=rng.randint(400, 240000), status="SF", service=service, scenario="routine")
        phase = i % 120
        if 48 <= phase < 62:
            record.update(src_ip="192.0.2.77", dst_ip="198.51.100.42", dst_port=20 + phase, bytes_sent=64, bytes_received=0, duration=0.001, status="S0", service="unknown", scenario="port_scan")
        elif phase == 82:
            record.update(src_ip="192.0.2.18", dst_ip="203.0.113.66", dst_port=4444, bytes_sent=18_400_000, bytes_received=1024, duration=95, status="SF", service="unknown", scenario="large_transfer")
        elif 94 <= phase < 102:
            record.update(src_ip="192.0.2.44", dst_ip="198.51.100.20", dst_port=22, status="REJ", bytes_received=0, bytes_sent=48, duration=0, scenario="failed_connections")
        records.append(record)
    return records
