"""Constructed metadata scenarios, never captured traffic or a training corpus.

Labels describe the author's scenario intent for a regression exercise. They do
not make these examples representative of operational attacks or benign traffic.
Two deliberately indistinguishable upload examples expose an intent blind spot.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from uuid import NAMESPACE_URL, uuid5


def evaluation_cases():
    cases = []
    anchor = datetime(2025, 1, 1, tzinfo=timezone.utc)

    def case(name, label, description, specs):
        collection = str(uuid5(NAMESPACE_URL, "sentinel-constructed-evaluation/" + name))
        records = []
        for index, spec in enumerate(specs):
            start = anchor + timedelta(seconds=spec.get("at", index))
            end = start + timedelta(seconds=spec.get("duration", 0.1))
            role = spec.get("role", "unknown")
            protocol = spec.get("protocol", "tcp")
            record = dict(timestamp=start.isoformat(), src_ip="192.0.2.19",
                dst_ip=spec.get("peer", "198.51.100.20"), src_port=spec.get("local_port", 48000 + index),
                dst_port=spec.get("port", 443), protocol=protocol,
                duration=spec.get("duration", 0.1), bytes_sent=spec.get("sent", 1000),
                bytes_received=spec.get("received", 5000), status="syn_observed" if role == "initiator" else "observed",
                service="unknown", scenario="live_ethernet",
                provenance=dict(collector="dumpcap+tshark", interface_label="Constructed fixture",
                    measurement_semantics="transport_payload_bytes", observation_scope="selected_interface_passive",
                    flow_semantics="tcp_stream_window" if protocol == "tcp" else "udp_stream_window",
                    process_scope="interface_only_no_process_attribution",
                    flow_id=sha1(f"{name}:{index}".encode()).hexdigest(), collection_id=collection,
                    first_seen=start.isoformat(), last_seen=end.isoformat(),
                    window_end=(anchor + timedelta(seconds=120)).isoformat(),
                    packet_count=spec.get("packets", 10), local_role=role,
                    midstream_start=role != "initiator", duration_is_lower_bound=True,
                    capture_window_limited=True, retransmissions_included=True, direction_basis="local_host",
                    transport_flags_observed="SYN,ACK" if role == "initiator" else "ACK" if protocol == "tcp" else ""))
            records.append(record)
        cases.append(dict(case_id=name, label=label, description=description,
            ground_truth="constructed_scenario_intent_not_observed_attack", records=records))

    case("routine_https", 0, "Several small intended benign HTTPS-port observations; application not verified.",
        [dict(at=i, sent=2000, received=30000) for i in range(6)])
    case("routine_quic_port", 0, "Small intended benign UDP/443 observation; QUIC is only a port hypothesis.",
        [dict(protocol="udp", sent=1500, received=12000, packets=12)])
    case("routine_dns_udp", 0, "Small intended benign UDP/53 query-like observation without a captured response.",
        [dict(protocol="udp", port=53, peer="192.0.2.1", sent=96, received=0, packets=2)])
    case("routine_dns_tcp", 0, "Small intended benign TCP/53 observation.", [dict(port=53, sent=200, received=800)])
    case("routine_ssdp", 0, "Small intended benign discovery-like multicast observation.",
        [dict(protocol="udp", port=1900, peer="239.255.255.250", sent=512, received=0, packets=2)])
    case("routine_dhcp_renewal", 0, "Constructed assigned-address DHCP renewal-like metadata.",
        [dict(protocol="udp", local_port=68, port=67, peer="192.0.2.1", sent=320, received=320, packets=2)])
    case("routine_mdns", 0, "Small intended benign mDNS-like observation.",
        [dict(protocol="udp", port=5353, peer="224.0.0.251", sent=400, received=0, packets=3)])
    case("routine_llmnr", 0, "Small intended benign local name-resolution-like observation.",
        [dict(protocol="udp", port=5355, peer="224.0.0.252", sent=120, received=0, packets=2)])
    case("local_web_peer", 0, "Intended benign local administrative web activity; peer is not assumed to be a router.",
        [dict(peer="192.0.2.1", sent=2500, received=12000, role="initiator")])
    case("routine_upload", 0, "Intended benign one-megabyte upload.",
        [dict(sent=1_000_000, received=5000, packets=800, duration=5, role="initiator")])
    case("routine_download", 0, "Intended benign six-megabyte download; outbound counter stays small.",
        [dict(sent=5000, received=6_000_000, packets=4500, duration=10)])
    case("software_update_like", 0, "Intended benign download across several web-port observations.",
        [dict(at=i * 3, sent=3000, received=1_000_000, packets=800, duration=2) for i in range(3)])
    case("benign_parallel_https", 0, "Known nuisance case: legitimate parallel connections can exceed a fixed burst threshold.",
        [dict(at=i / 2, role="initiator", sent=1000, received=2000, packets=3) for i in range(30)])
    case("benign_large_backup", 0, "Known nuisance case: a legitimate large upload can trigger volume review.",
        [dict(sent=6_000_000, received=5000, packets=4500, duration=10, role="initiator")])
    case("tcp_port_sweep", 1, "Constructed local-initiation port-probing pattern on one disposable documentation target.",
        [dict(at=i, port=2100+i, role="initiator", sent=0, received=0, packets=1) for i in range(8)])
    case("private_peer_port_sweep", 1, "The same probing pattern is not exempted for a private peer.",
        [dict(at=i, peer="10.42.0.1", port=3100+i, role="initiator", sent=0, received=0, packets=1) for i in range(8)])
    case("connection_burst", 1, "Constructed repeated initiator connections to one target/service.",
        [dict(at=i / 2, port=8443, role="initiator", sent=0, received=0, packets=1) for i in range(30)])
    case("large_outbound", 1, "Constructed six-megabyte outbound observation for investigation; not proof of exfiltration.",
        [dict(sent=6_000_000, received=1000, packets=4500, duration=10, role="initiator")])
    case("split_outbound", 1, "Three individually sub-threshold transfers sum to six megabytes to one peer.",
        [dict(at=i * 10, sent=2_000_000, received=1000, packets=1600, duration=5, role="initiator") for i in range(3)])
    case("large_discovery_port", 1, "Abnormally large discovery-port traffic must not inherit a multicast exemption.",
        [dict(protocol="udp", port=1900, peer="239.255.255.250", sent=6_000_000, received=0, packets=4500, duration=10)])
    case("large_dns_port", 1, "Large DNS-port observation is not exempted by its service hint.",
        [dict(protocol="udp", port=53, peer="192.0.2.1", sent=6_000_000, received=0, packets=4500, duration=10)])
    case("long_outbound_observation", 1, "Ninety-second single-flow volume may be reviewed without inventing a 60-second rate.",
        [dict(sent=6_000_000, received=1000, packets=4500, duration=90, role="initiator")])
    case("slow_port_sweep", 1, "Known miss: eight ports spread beyond a single 60-second rule window.",
        [dict(at=i * 15, port=4100+i, role="initiator", sent=0, received=0, packets=1) for i in range(8)])
    case("udp_port_sweep", 1, "Known miss: UDP observations provide no TCP initiator handshake evidence.",
        [dict(at=i, protocol="udp", port=5100+i, sent=0, received=0, packets=1) for i in range(8)])
    case("midstream_port_pattern", 1, "Known miss: role-unknown TCP windows cannot establish local initiation.",
        [dict(at=i, port=6100+i, sent=0, received=0, packets=1) for i in range(8)])
    case("low_volume_intent", 1, "Intent blind spot: these observable features are identical to a benign small upload.",
        [dict(sent=200_000, received=5000, packets=160, duration=5, role="initiator")])
    case("benign_identical_upload", 0, "Benign counterpart of the intent-blind-spot case; metadata is deliberately identical.",
        [dict(sent=200_000, received=5000, packets=160, duration=5, role="initiator")])
    return cases
