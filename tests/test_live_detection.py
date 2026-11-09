"""Predeclared synthetic rule cases; these do not estimate real-network accuracy."""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from backend.app.live_detection import LIVE_POLICY, LiveRuleEngine, evaluate_context
from backend.app.main import Runtime, create_app


class FlagEveryBaseline:
    ready = True

    def __init__(self):
        self.metadata = {"threshold": 0.6, "model_version": "unit-test-baseline"}

    def predict(self, record):
        return {"score": 0.9, "is_anomaly": True, "indicators": ["Synthetic baseline test heuristic"]}


def live(i=1, *, seconds=None, duration=1, protocol="tcp", port=443, role="initiator", sent=1000,
         destination="198.51.100.20", collection="00000000-0000-0000-0000-000000000001"):
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=i if seconds is None else seconds)
    return dict(timestamp=first.isoformat(), src_ip="192.0.2.10", dst_ip=destination,
        src_port=50000+i, dst_port=port, protocol=protocol, duration=duration,
        bytes_sent=sent, bytes_received=500, status="syn_observed" if role=="initiator" else "observed", service="unknown",
        scenario="live_ethernet", provenance=dict(collector="dumpcap+tshark", interface_label="Ethernet",
            measurement_semantics="transport_payload_bytes", observation_scope="selected_interface_passive",
            flow_semantics="tcp_stream_window" if protocol=="tcp" else "udp_stream_window",
            process_scope="interface_only_no_process_attribution", flow_id=f"{i:040x}", collection_id=collection,
            first_seen=first.isoformat(), last_seen=(first+timedelta(seconds=duration)).isoformat(),
            window_end=(first+timedelta(seconds=max(120,duration))).isoformat(), packet_count=3,
            local_role=role, midstream_start=role!="initiator", duration_is_lower_bound=True,
            capture_window_limited=True, retransmissions_included=True, direction_basis="local_host",
            transport_flags_observed="SYN,ACK" if protocol=="tcp" and role=="initiator" else ""))


def ids(hits):
    return {h.rule_id for h in hits}


@pytest.mark.parametrize("protocol,port,destination,hint", [
    ("udp",1900,"239.255.255.250","SSDP"), ("udp",53,"10.42.0.1","DNS"),
    ("udp",67,"10.42.0.1","DHCP"), ("udp",5353,"224.0.0.251","mDNS"),
    ("udp",5355,"224.0.0.252","LLMNR"), ("tcp",443,"198.51.100.20","TLS/HTTPS"),
    ("udp",443,"198.51.100.20","QUIC"), ("tcp",7680,"192.168.1.20","delivery-optimization"),
])
def test_small_routine_shaped_traffic_is_context_not_a_whitelist(protocol, port, destination, hint):
    record = live(protocol=protocol, port=port, destination=destination, role="unknown", sent=100)
    context = evaluate_context(record)
    assert hint in context["protocol_context"]["label"]
    assert context["protocol_context"]["label"].startswith("Possible")
    assert LiveRuleEngine().inspect(record) == []
    assert context["observation_limits"] and context["additional_evidence"]
    assert any("not exempt" in note for note in context["protocol_context"]["notes"])


def test_address_scope_does_not_invent_router_or_treat_documentation_as_rfc1918():
    private = evaluate_context(live(destination="10.42.0.1"))["protocol_context"]
    assert private["destination_scope"] == "private"
    assert any("router role" in note and "not inferred" in note for note in private["notes"])
    assert evaluate_context(live())["protocol_context"]["destination_scope"] == "documentation"
    assert evaluate_context(live(destination="fd00::1"))["protocol_context"]["destination_scope"] == "private"


def test_scan_threshold_then_cooldown_and_retry_deduplication():
    engine = LiveRuleEngine()
    for i in range(1,8):
        assert "port_scan" not in ids(engine.inspect(live(i,port=1000+i)))
    hit = engine.inspect(live(8,port=1008))
    assert len(hit) == 1 and hit[0].rule_id == "port_scan" and hit[0].severity == "high"
    assert "8 distinct ports in 60 seconds" in hit[0].indicators
    assert any("Collection: 00000000-0000-0000-0000-000000000001" == text for text in hit[0].indicators)
    assert any(f"{8:040x}" in text and "Evidence flow IDs" in text for text in hit[0].indicators)
    assert engine.inspect(live(8,port=1008)) == []
    assert "port_scan" not in ids(engine.inspect(live(9,port=1009)))


@pytest.mark.parametrize("role", ["unknown","responder"])
def test_response_ephemeral_ports_and_partial_role_do_not_become_scan_evidence(role):
    engine=LiveRuleEngine()
    assert not any(engine.inspect(live(i,port=45000+i,role=role)) for i in range(1,9))
    assert not engine.inspect(live(9,port=443,role="initiator"))


def test_burst_requires_unique_initiator_flows_to_one_peer_and_can_flag_legitimate_burst():
    engine=LiveRuleEngine()
    for i in range(1,25):
        assert not engine.inspect(live(i,port=443))
    hits=engine.inspect(live(25,port=443))
    assert ids(hits)=={"connection_frequency"}
    assert "Legitimate browsers" in hits[0].description
    assert engine.inspect(live(26,port=443)) == []
    other=LiveRuleEngine()
    assert not any(other.inspect(live(i,destination=f"198.51.100.{i}")) for i in range(1,26))


def test_scan_does_not_add_redundant_burst_finding():
    engine=LiveRuleEngine(); hits=[]
    for i in range(1,26):
        hits.extend(engine.inspect(live(i,port=1000+i%8)))
    assert [h.rule_id for h in hits] == ["port_scan"]


def test_slow_scan_and_cross_collection_scan_remain_documented_misses():
    engine=LiveRuleEngine()
    assert not any(engine.inspect(live(i,seconds=i*11,port=1000+i)) for i in range(1,9))
    engine=LiveRuleEngine()
    for i in range(1,9):
        collection="00000000-0000-0000-0000-000000000001" if i<=4 else "00000000-0000-0000-0000-000000000002"
        assert not engine.inspect(live(i,port=1000+i,collection=collection))


@pytest.mark.parametrize("destination,protocol,port", [("239.255.255.250","udp",1900),("10.42.0.1","udp",53),("198.51.100.20","tcp",443)])
def test_volume_still_flags_normally_legitimate_contexts_without_calling_them_exfiltration(destination,protocol,port):
    hits=LiveRuleEngine().inspect(live(sent=6*1024*1024,destination=destination,protocol=protocol,port=port,role="unknown"))
    assert ids(hits)=={"traffic_spike"}
    assert hits[0].severity=="medium" and hits[0].title=="Large outbound observation"
    assert "does not establish exfiltration" in hits[0].description
    assert "legitimate upload" in hits[0].description


def test_split_volume_aggregates_only_complete_intervals_inside_sixty_seconds():
    engine=LiveRuleEngine(); hits=[]
    for i in range(1,6):
        hits=engine.inspect(live(i,sent=1_000_000))
    assert ids(hits)=={"traffic_spike"}
    assert any("5,000,000" in text and "5 whole flow" in text and "within 60" in text for text in hits[0].indicators)
    lineage = next(text for text in hits[0].indicators if text.startswith("Evidence flow IDs:"))
    assert all(f"{i:040x}" in lineage for i in range(1,6))
    assert any("anchor is one flow" in text for text in hits[0].indicators)
    assert engine.inspect(live(6,sent=1_000_000))==[]


def test_long_observation_has_no_invented_sixty_second_rate():
    hits=LiveRuleEngine().inspect(live(duration=90,sent=6_000_000))
    assert ids(hits)=={"traffic_spike"}
    assert any("90.000" in text and "not a 60-second rate" in text for text in hits[0].indicators)
    engine=LiveRuleEngine()
    assert not engine.inspect(live(1,duration=90,sent=3_000_000))
    assert not engine.inspect(live(2,duration=90,sent=3_000_000))


def test_out_of_order_flow_ends_cannot_move_future_bytes_into_earlier_window():
    engine=LiveRuleEngine()
    assert not engine.inspect(live(1,seconds=1,duration=50,sent=2_000_000))
    assert not engine.inspect(live(2,seconds=2,duration=1,sent=3_000_000))
    assert "traffic_spike" in ids(engine.inspect(live(3,seconds=3,duration=49,sent=0)))


def test_low_volume_intent_and_udp_scan_cannot_be_inferred_from_metadata():
    engine=LiveRuleEngine()
    for i in range(1,9):
        assert not engine.inspect(live(i,protocol="udp",role="unknown",port=1000+i,sent=100))
    # Bytes alone do not reveal stolen data or malicious content.
    assert not LiveRuleEngine().inspect(live(sent=100))


def test_large_clock_rewind_starts_new_window_without_future_evidence():
    engine=LiveRuleEngine()
    engine.inspect(live(50,seconds=1000,port=1000))
    hits=[]
    for i in range(1,9):
        hits=engine.inspect(live(i,seconds=i,port=2000+i))
    assert ids(hits)=={"port_scan"}


def test_live_engine_state_remains_bounded():
    engine=LiveRuleEngine(); engine.max_events=32
    for i in range(1,100):
        engine.inspect(live(i,destination=f"198.51.100.{i}"))
    assert sum(map(len,engine.windows.values()))<=32
    assert len(engine._seen)<=32 and len(engine._alerted)<=32


def test_live_model_exceedance_is_stored_reference_only_demo_and_lab_unchanged(tmp_path):
    rt=Runtime(str(tmp_path/'monitor.db'),seed=False,monitor_mode=True,detector=FlagEveryBaseline())
    rt.ingest_metadata('new-1',[live()])
    record=rt.store.connections()['items'][0]
    assert record['anomaly_score']==0.9 and record['model_assessment']['above_threshold'] is True
    assert record['model_assessment']['alert_eligible'] is False and record['is_anomaly'] is False
    assert record['model_assessment']['threshold_source']=='stored_at_ingest'
    assert record['live_policy']==LIVE_POLICY['version'] and rt.store.incidents()['total']==0
    rt.detector.metadata['threshold']=0.95
    assert rt.connection_view(record)['analysis']['model_assessment']['threshold']==0.6
    rt.store.close()
    # Each test instance gets independent metadata so reference mutation cannot leak.
    for origin in ('demo','lab'):
        model=FlagEveryBaseline(); model.metadata={'threshold':0.6,'model_version':'unit-test'}
        old=Runtime(str(tmp_path/f'{origin}.db'),seed=False,detector=model,allow_lab_data=origin=='lab')
        payload,hits=old.prepare_record(live(),origin)
        assert 'ml_anomaly' in {h['rule_id'] for h in hits}
        assert payload['is_anomaly'] is True and 'live_policy' not in payload
        old.store.close()


def test_legacy_views_attach_actual_anchor_without_rewriting_score_incident_or_history(tmp_path):
    model=FlagEveryBaseline(); model.metadata={'threshold':0.6,'model_version':'unit-test'}
    rt=Runtime(str(tmp_path/'monitor.db'),seed=False,monitor_mode=True,detector=model)
    legacy=dict(live(role='unknown',protocol='udp',port=53,destination='10.42.0.1'),anomaly_score=0.9,is_anomaly=True)
    connection_id=rt.store.insert(legacy,'live',[dict(rule_id='ml_anomaly',title='Original historical title',description='Original description',severity='medium',detection_source='ml',indicators=['Original heuristic'])])
    incident=rt.store.incidents()['items'][0]
    rt.store.patch_incident(incident['id'],'investigating','Preserve this original investigation note.')
    before=rt.store.get_incident(incident['id'])
    payload_before=rt.store.db.execute('SELECT payload FROM connections WHERE id=?',(connection_id,)).fetchone()[0]
    view=rt.incident_view(before)
    assert view['connection']['id']==connection_id and view['connection']['dst_port']==53
    assert view['analysis']['historical_alert'] is True
    assert view['analysis']['model_assessment']['score']==0.9
    assert view['analysis']['model_assessment']['threshold_source']=='current_baseline_reference'
    assert view['analysis']['explanation_kind']=='benchmark_heuristic'
    assert 'DNS' in view['analysis']['protocol_context']['label']
    for field in ('title','description','severity','status','indicators','notes','history'):
        assert view[field]==before[field]
    assert rt.store.get_incident(incident['id'])==before
    assert rt.store.db.execute('SELECT payload FROM connections WHERE id=?',(connection_id,)).fetchone()[0]==payload_before
    rt.store.close()


def test_batch_failure_rolls_back_new_live_rule_cooldown_and_incidents(tmp_path):
    rt=Runtime(str(tmp_path/'monitor.db'),seed=False,monitor_mode=True,detector=FlagEveryBaseline())
    rt.ingest_metadata('first',[live(i,port=1000+i) for i in range(1,8)])
    with pytest.raises(HTTPException) as duplicate:
        rt.ingest_metadata('bad',[live(8,port=1008),live(1,port=1001)])
    assert duplicate.value.status_code==409 and rt.store.live_count()==7
    assert rt.store.incidents()['total']==0
    rt.ingest_metadata('good',[live(8,port=1008)])
    assert rt.store.live_count()==8
    incidents=rt.store.incidents()['items']
    assert len(incidents)==1 and incidents[0]['rule_id']=='port_scan'
    rt.store.close()


def test_api_enriches_records_and_incident_after_note_save_without_rescoring(tmp_path):
    model=FlagEveryBaseline(); model.metadata={'threshold':0.6,'model_version':'unit-test'}
    with TestClient(create_app(str(tmp_path/'monitor.db'),monitor_mode=True,api_key='test-key',detector=model),client=('127.0.0.1',51000), base_url='http://127.0.0.1') as client:
        result=client.post('/api/ingest/metadata',json={'batch_id':'large','records':[live(sent=6_000_000)]},headers={'X-Sentinel-Key':'test-key'})
        assert result.status_code==200
        record=client.get('/api/connections').json()['items'][0]
        assert record['analysis']['model_assessment']['alert_eligible'] is False
        assert client.get('/api/overview').json()['live_detection_policy']['version']=='live-metadata-v1'
        incident=client.get('/api/incidents').json()['items'][0]
        detail=client.get(f"/api/incidents/{incident['id']}").json()
        assert detail['connection']['id']==record['id'] and detail['analysis']['explanation_kind']=='rule_trigger'
        saved=client.patch(f"/api/incidents/{incident['id']}",json={'note':'Reviewed actual metadata.','status':'investigating'}).json()
        assert saved['connection']['id']==record['id'] and saved['analysis']['historical_alert'] is False
        assert saved['status']=='investigating' and saved['notes'][-1]['note']=='Reviewed actual metadata.'
        assert client.get('/api/model').json()['live_detection_policy']['baseline_alert_eligible'] is False
