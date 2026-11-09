"""Evidence-based, collection-scoped live metadata rules. No network or model I/O."""
from collections import OrderedDict, deque
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

from .rules import RuleEngine, RuleHit

LIVE_POLICY = {
    "version": "live-metadata-v1",
    "baseline_model": "informational_only",
    "baseline_alert_eligible": False,
    "rules": ["port_scan", "connection_frequency", "traffic_spike"],
    "window_seconds": 60,
    "cooldown_seconds": 60,
    "scope": "source, peer and collection; unique flow identifiers",
    "notice": "Live findings are observed rule conditions for review, not confirmed attacks. The historical Isolation Forest remains an unvalidated live reference.",
}
_PRIVATE = tuple(ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
_DOCUMENTATION = tuple(ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def _scope(value):
    try:
        address = ip_address(value)
    except (TypeError, ValueError):
        return "unknown"
    if address.is_multicast:
        return "multicast"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if any(address.version == network.version and address in network for network in _DOCUMENTATION):
        return "documentation"
    if any(address.version == network.version and address in network for network in _PRIVATE):
        return "private"
    return "public" if address.is_global else "other_non_global"


def evaluate_context(record):
    """Descriptive hints, never a protocol verification, whitelist or threat verdict."""
    protocol = str(record.get("protocol", "")).lower()
    ports = {record.get("src_port"), record.get("dst_port")}
    destination_scope = _scope(record.get("dst_ip"))
    label, basis = "Unidentified application", "No application protocol was verified from this metadata"
    if protocol == "udp" and 1900 in ports:
        label = "Possible SSDP discovery" if destination_scope == "multicast" else "Possible SSDP-related traffic"
        basis = "UDP port 1900 was observed; application payload was not inspected"
    elif protocol in {"tcp", "udp"} and 53 in ports:
        label, basis = "Possible DNS", "Port 53 was observed; query names, responses and DNS validity were not inspected"
    elif protocol == "udp" and ports.intersection({67, 68, 546, 547}):
        label, basis = "Possible DHCP", "A conventional DHCP port was observed; no lease or DHCP message was verified"
    elif protocol == "udp" and 5353 in ports:
        label, basis = "Possible mDNS discovery", "UDP port 5353 was observed; discovery messages were not inspected"
    elif protocol == "udp" and 5355 in ports:
        label, basis = "Possible LLMNR discovery", "UDP port 5355 was observed; name-resolution messages were not inspected"
    elif protocol == "tcp" and 443 in ports:
        label, basis = "Possible TLS/HTTPS", "TCP port 443 was observed; encryption, application and software-update purpose were not verified"
    elif protocol == "udp" and 443 in ports:
        label, basis = "Possible QUIC/HTTPS", "UDP port 443 was observed; QUIC or HTTPS was not verified"
    elif protocol == "tcp" and 7680 in ports:
        label, basis = "Possible Windows delivery-optimization traffic", "TCP port 7680 was observed; software identity and update legitimacy were not verified"
    notes = ["Port/address context is descriptive and does not exempt traffic from any live rule."]
    if destination_scope == "private":
        notes.append("The peer is RFC1918/ULA private space. Its router role, ownership and trust are not inferred from its address.")
    elif destination_scope == "multicast":
        notes.append("Multicast can support discovery but can also be abused; its address alone establishes neither benignness nor an attack.")
    elif destination_scope == "documentation":
        notes.append("The peer uses a documentation address; this label is useful for test fixtures, not real-device attribution.")
    provenance = record.get("provenance") or {}
    limits = [
        "Only bounded flow metadata is available; no authentication outcome, process identity, payload content or malicious intent is established.",
        "Header-derived transport length counters include observed retransmissions and are not verified unique application-content volume.",
        "Protocol labels are port-based hints. An ordinary-looking protocol or private/multicast peer is not whitelisted.",
    ]
    if provenance.get("capture_window_limited") or provenance.get("duration_is_lower_bound") or provenance.get("midstream_start"):
        limits.append("Collection may omit the beginning/end of sessions; observed durations are lower bounds and captures can have gaps or truncated headers.")
    if provenance.get("local_role") != "initiator":
        limits.append("The local host is not established as this TCP flow's initiator; it cannot supply initiator-only scan/burst evidence.")
    evidence = ["Identify the local process and expected destination/service using separately authorized host evidence.",
                "Compare representative benign activity across independent time windows before making behavior-change or false-positive claims."]
    if 53 in ports:
        evidence.append("If authorized, resolver logs with query names and response outcomes can distinguish routine DNS from misuse; connection metadata alone cannot.")
    if ports.intersection({1900, 5353, 5355}):
        evidence.append("If authorized, application/discovery logs and device ownership can confirm the purpose of discovery traffic.")
    evidence.append("Authentication failures require actual application authentication logs; TCP state or missing responses are insufficient.")
    return {"protocol_context": {"label": label, "basis": basis, "destination_scope": destination_scope, "notes": notes},
            "observation_limits": limits, "additional_evidence": evidence}


def _epoch(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _lineage(collection, events):
    flow_ids = list(dict.fromkeys(event["identity"][1] for event in events))
    suffix = f" (first 32 of {len(flow_ids)})" if len(flow_ids) > 32 else ""
    result = [f"Collection: {collection}", "Evidence flow IDs: " + ", ".join(flow_ids[:32]) + suffix]
    if len(flow_ids) > 1:
        result.append("The incident connection anchor is one flow; the finding also uses the other listed flow observations.")
    return result


class LiveRuleEngine(RuleEngine):
    """Three predeclared review rules; all state is bounded and deepcopy-safe.

    Separate collections are not combined because capture overlap/gaps and repeated
    session observations cannot be reliably reconciled. This conservative scope
    can miss slow or cross-window activity and UDP/midstream scans.
    """
    max_events = 5000
    max_peer_events = 1024
    cooldown = 60

    def __init__(self):
        super().__init__()
        self.windows = OrderedDict()
        self._seen = OrderedDict()
        self._alerted = OrderedDict()

    def reset(self):
        super().reset()
        self._seen.clear()
        self._alerted.clear()

    def _may_alert(self, rule, key, timestamp):
        identity = (rule, *key)
        previous = self._alerted.get(identity)
        if previous is not None and timestamp - previous < self.cooldown:
            return False
        self._alerted[identity] = timestamp
        self._alerted.move_to_end(identity)
        while len(self._alerted) > self.max_events:
            self._alerted.popitem(last=False)
        return True

    def inspect(self, record, *, port_scan_eligible=True):
        provenance = record.get("provenance") or {}
        collection, flow_id = provenance.get("collection_id"), provenance.get("flow_id")
        if not collection or not flow_id:
            return []  # Missing lineage cannot become counted live evidence.
        identity = (collection, flow_id)
        if identity in self._seen:
            return []
        first = _epoch(record["timestamp"])
        last = _epoch(provenance.get("last_seen", record["timestamp"]))
        if last < first:
            return []
        if first < self.last_timestamp - 60:
            self.windows.clear()
            self._alerted.clear()
            self.last_timestamp = first
        self.last_timestamp = max(self.last_timestamp, first)
        self._seen[identity] = None
        while len(self._seen) > self.max_events:
            self._seen.popitem(last=False)
        key = (record["src_ip"], collection, record["dst_ip"])
        events = self.windows.setdefault(key, deque(maxlen=self.max_peer_events))
        self.windows.move_to_end(key)
        eligible = bool(port_scan_eligible and record.get("protocol") == "tcp" and provenance.get("local_role") == "initiator")
        event = {"first": first, "last": last, "port": record["dst_port"], "eligible": eligible,
                 "bytes": record["bytes_sent"], "identity": identity}
        events.append(event)
        # Max1024 entries per peer and max5000 total event entries, including volume state.
        while sum(len(values) for values in self.windows.values()) > self.max_events:
            self.windows.popitem(last=False)
        starts = [e for e in events if first-60 <= e["first"] <= first and e["eligible"]]
        ports = {e["port"] for e in starts}
        context = evaluate_context(record)["protocol_context"]["label"]
        scope_note = "Unique flow IDs within one collection; partial capture can miss activity."
        hits = []
        scanning = eligible and len(ports) >= 8
        if scanning and self._may_alert("port_scan", key, first):
            hits.append(RuleHit("port_scan", "Port scan indicators", "high",
                "The local host was observed initiating TCP flows to many ports on one peer. Authorized discovery can produce the same pattern; investigate intent.",
                [f"{len(ports)} distinct ports in 60 seconds", f"{len(starts)} unique locally initiated TCP flow observations",
                 "Destination ports: " + ", ".join(map(str, sorted(ports)[:32])), scope_note, f"Context hint: {context}"] + _lineage(collection, starts)))
        # A port sweep already explains this burst; avoid a second finding for it.
        if eligible and not scanning and len(starts) >= 25 and self._may_alert("connection_frequency", key, first):
            hits.append(RuleHit("connection_frequency", "Burst of initiated TCP flows", "medium",
                "At least 25 unique initiated TCP flow observations targeted one peer inside 60 seconds. Legitimate browsers, updates and retries can also cause bursts.",
                [f"{len(starts)} unique initiated TCP flow observations to one peer in 60 seconds",
                 f"Observed start span: {first-min(e['first'] for e in starts):.3f} seconds; not a complete connection-rate measurement",
                 scope_note, f"Context hint: {context}"] + _lineage(collection, starts)))
        # Only wholly contained flow intervals can contribute their full counters
        # to a60-second aggregate. No uniform distribution within a long flow is invented.
        contained = [e for e in events if last-60 <= e["first"] and e["last"] <= last]
        volume = sum(e["bytes"] for e in contained)
        volume_indicators = None
        if volume >= 5_000_000:
            span = max(e["last"] for e in contained)-min(e["first"] for e in contained)
            volume_indicators = [f"{volume:,} header-derived outbound transport length bytes across {len(contained)} whole flow observations within 60 seconds",
                                 f"Observed contributing interval span: {span:.3f} seconds"]
            volume_indicators += _lineage(collection, contained)
        elif event["bytes"] >= 5_000_000:
            volume_indicators = [f"{event['bytes']:,} header-derived outbound transport length bytes over this bounded flow observation",
                                 f"Observed span: {last-first:.3f} seconds; this finding is not a 60-second rate claim"]
            volume_indicators += _lineage(collection, [event])
        if volume_indicators is not None and self._may_alert("traffic_spike", key, last):
            hits.append(RuleHit("traffic_spike", "Large outbound observation", "medium",
                "Observed outbound transport length counters reached the fixed 5,000,000-byte review threshold. A legitimate upload or retransmissions can trigger it; this does not establish exfiltration.",
                volume_indicators + ["Threshold: 5,000,000 observed outbound bytes", "Retransmissions may be counted; payload/content and intent were not inspected.",
                                     scope_note, f"Context hint: {context}"]))
        return hits
