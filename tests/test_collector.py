"""Pure metadata/CLI tests; no real interfaces or network calls are opened."""
import csv
import io
import json
from pathlib import Path
from unittest.mock import Mock
import subprocess

import pytest

from detection import collector as c
from scripts import monitor_windows as cli

INTERFACE = r"\Device\NPF_{00000000-0000-4000-8000-000000000001}"
LOCAL, PEER = "192.0.2.10", "198.51.100.5"
END = "2023-11-14T22:15:00+00:00"
COLLECTION = "00000000-0000-4000-8000-000000000002"


def config(**kwargs):
    return c.CaptureConfig(INTERFACE, (LOCAL,), **kwargs)


def line(**kwargs):
    fields = {"frame.time_epoch": "1700000000", "ip.src": LOCAL, "ip.dst": PEER,
              "tcp.srcport": "49000", "tcp.dstport": "443", "tcp.len": "0", "tcp.stream": "0",
              "tcp.flags.syn": "1", "tcp.flags.ack": "0", "tcp.flags.reset": "0", "tcp.flags.fin": "0"}
    fields.update(kwargs)
    buffer = io.StringIO()
    csv.writer(buffer).writerow([fields.get(name, "") for name in c.TSHARK_FIELDS])
    return buffer.getvalue().strip()


def arguments(*extra):
    return ["--interface", INTERFACE, "--local-address", LOCAL, *extra]


@pytest.mark.parametrize("interface", ["Ethernet", "1", r"\Device\NPF_Loopback", "rpcap://host/eth0", INTERFACE + " & whoami"])
def test_interface_must_be_exact_npf_uuid(interface):
    with pytest.raises(c.CollectorError):
        c.CaptureConfig(interface, (LOCAL,))


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "0.0.0.0", "224.0.0.251", "example.com", "192.0.2.1 or host 198.51.100.1"])
def test_local_address_validation_prevents_bpf_injection(address):
    with pytest.raises(c.CollectorError):
        c.CaptureConfig(INTERFACE, (address,))


def test_ipv6_scope_normalizes_within_explicit_interface():
    settings = c.CaptureConfig(INTERFACE, (LOCAL, "fe80::abcd%22", "fe80::abcd%22"))
    assert settings.local_addresses == (LOCAL, "fe80::abcd")
    assert "%" not in settings.capture_filter
    assert settings.capture_filter == "(host 192.0.2.10 or host fe80::abcd) and (tcp or udp)"


@pytest.mark.parametrize("setting,value", [("duration", 0), ("duration", 121), ("max_packets", 5001), ("max_flows", 1001)])
def test_capture_bounds_are_enforced(setting, value):
    with pytest.raises(c.CollectorError):
        config(**{setting: value})


def test_commands_use_only_memory_pipe_and_allowlisted_metadata():
    capture, decoder = c.capture_command(config(), "dumpcap.exe"), c.decoder_command("tshark.exe")
    assert capture[capture.index("-w") + 1] == "-"
    assert capture[capture.index("-s") + 1] == "128"
    assert capture[capture.index("-i") + 1] == INTERFACE
    assert "-p" in capture
    assert capture[capture.index("-f") + 1] == config().capture_filter
    assert decoder[decoder.index("-r") + 1] == "-" and "-n" in decoder
    assert "-i" not in decoder and "-w" not in decoder
    assert "--temp-dir" not in capture + decoder
    assert not any("http." in item or "dns." in item or "tls." in item or item in {"-V", "-x", "--export-objects"} for item in capture + decoder)
    assert tuple(decoder[index + 1] for index, value in enumerate(decoder) if value == "-e") == c.TSHARK_FIELDS


def test_bidirectional_midstream_flow_always_uses_laptop_perspective():
    collector = c.FlowCollector(config(), COLLECTION)
    collector.consume(line(**{"ip.src": PEER, "ip.dst": LOCAL, "tcp.srcport": "443", "tcp.dstport": "49000", "tcp.len": "120", "tcp.flags.syn": "0", "tcp.flags.ack": "1"}))
    collector.consume(line(**{"frame.time_epoch": "1700000002", "tcp.len": "40", "tcp.flags.syn": "0", "tcp.flags.ack": "1"}))
    result = collector.finalize(END)
    assert len(result) == 1
    row = result[0]
    assert (row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"]) == (LOCAL, 49000, PEER, 443)
    assert (row["bytes_sent"], row["bytes_received"], row["duration"]) == (40, 120, 2)
    assert row["provenance"]["midstream_start"] is True
    assert row["provenance"]["local_role"] == "unknown"
    assert row["provenance"]["duration_is_lower_bound"] is True
    assert row["service"] == "unknown" and row["status"] == "observed"
    with pytest.raises(c.CollectorError):
        collector.finalize(END)
    with pytest.raises(c.CollectorError):
        collector.consume(line())


def test_tcp_stream_ids_separate_reused_tuple_without_repeated_snapshots():
    collector = c.FlowCollector(config(), COLLECTION)
    collector.consume(line())
    collector.consume(line(**{"tcp.stream": "1", "frame.time_epoch": "1700000005"}))
    records = collector.finalize(END)
    assert len(records) == 2
    assert len({row["provenance"]["flow_id"] for row in records}) == 2
    assert all(row["provenance"]["local_role"] == "initiator" for row in records)


def test_remote_syn_marks_local_responder_not_local_scanner():
    collector = c.FlowCollector(config(), COLLECTION)
    collector.consume(line(**{"ip.src": PEER, "ip.dst": LOCAL, "tcp.srcport": "49000", "tcp.dstport": "443"}))
    record = collector.finalize(END)[0]
    assert record["provenance"]["local_role"] == "responder"
    assert record["dst_port"] == 49000
    assert record["status"] == "syn_observed"


def test_udp_counts_transport_payload_and_ipv6_without_service_inference():
    collector = c.FlowCollector(c.CaptureConfig(INTERFACE, ("2001:db8::10",)), COLLECTION)
    collector.consume(line(**{"ip.src": "", "ip.dst": "", "ipv6.src": "2001:db8::10", "ipv6.dst": "2001:db8::20",
        "tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "49000", "udp.dstport": "53", "udp.length": "108", "udp.stream": "0"}))
    record = collector.finalize(END)[0]
    assert record["protocol"] == "udp" and record["bytes_sent"] == 100
    assert record["service"] == "unknown"
    assert record["provenance"]["flow_semantics"] == "udp_stream_window"


def test_ambiguity_nonlocal_truncation_and_limits_are_counted():
    collector = c.FlowCollector(config(max_packets=10, max_flows=1), COLLECTION)
    collector.consume(line(**{"ip.src": LOCAL + ";203.0.113.1"}))
    collector.consume(line(**{"ipv6.src": "2001:db8::1"}))
    collector.consume(line(**{"ip.src": "203.0.113.10"}))
    collector.consume(line(**{"tcp.stream": ""}))
    collector.consume(line())
    collector.consume(line(**{"tcp.stream": "1"}))
    collector.consume("truncated")
    assert len(collector.flows) == 1
    assert collector.stats["skipped_ambiguous"] == 2
    assert collector.stats["skipped_nonlocal"] == 1
    assert collector.stats["skipped_missing_stream"] == 1
    assert collector.stats["skipped_flow_limit"] == 1
    assert collector.stats["skipped_malformed"] == 1
    assert collector.stats["packets_accepted"] == 1


def test_retransmitted_payload_is_counted_with_explicit_semantics():
    collector = c.FlowCollector(config(), COLLECTION)
    collector.consume(line(**{"tcp.len": "20"}))
    collector.consume(line(**{"tcp.len": "20", "tcp.flags.syn": "0", "tcp.flags.reset": "1"}))
    record = collector.finalize(END)[0]
    assert record["bytes_sent"] == 40 and record["status"] == "reset_observed"
    assert record["provenance"]["retransmissions_included"] is True
    assert record["provenance"]["packet_count"] == 2


def test_final_records_sorted_and_split_into_stable_batches_at_most_fifty():
    records = [{"id": index} for index in range(101)]
    batches = list(c.metadata_batches(records, COLLECTION))
    assert [len(batch["records"]) for batch in batches] == [50, 50, 1]
    assert [batch["batch_id"] for batch in batches] == [COLLECTION + ":0", COLLECTION + ":1", COLLECTION + ":2"]


@pytest.mark.parametrize("base", ["http://localhost:8000", "http://192.0.2.1:8000", "http://127.0.0.1.evil/", "http://x:y@127.0.0.1:8000", "http://127.0.0.1:8000/api", "http://127.0.0.1/?target=elsewhere"])
def test_api_url_is_literal_loopback_without_forwarding(base):
    with pytest.raises(c.CollectorError):
        cli.loopback_api(base)


def test_redirects_disabled_and_environment_proxies_not_used(monkeypatch):
    handlers = []
    fake = Mock()
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = b'{"enabled":true}'
    fake.open.return_value = response
    monkeypatch.setattr(cli, "build_opener", lambda *items: handlers.extend(items) or fake)
    cli.api_request("http://127.0.0.1:8000", "/api/monitor/status", "test-key")
    assert any(isinstance(handler, cli.ProxyHandler) and handler.proxies == {} for handler in handlers)
    assert any(isinstance(handler, cli.NoRedirects) for handler in handlers)
    assert cli.NoRedirects().redirect_request(None, None, 302, "", {}, "https://example.com") is None


def test_default_and_dry_run_never_launch_or_request(monkeypatch, capsys):
    capture, request = Mock(side_effect=AssertionError("capture forbidden")), Mock(side_effect=AssertionError("network forbidden"))
    monkeypatch.setattr(cli, "collect_window", capture)
    monkeypatch.setattr(cli, "api_request", request)
    monkeypatch.setattr(c.subprocess, "Popen", capture)
    assert cli.main([]) == 0
    assert cli.main(arguments()) == 0
    assert not capture.called and not request.called
    output = capsys.readouterr().out
    assert '"capture_enabled": false' in output and '"-w"' in output and '"-r"' in output


def test_invalid_key_and_api_profile_stop_before_capture(monkeypatch):
    capture = Mock(side_effect=AssertionError("capture forbidden"))
    monkeypatch.setattr(cli, "collect_window", capture)
    monkeypatch.setattr(cli, "resolve_tshark", lambda _: "tshark.exe")
    monkeypatch.setattr(cli, "resolve_dumpcap", lambda *_: "dumpcap.exe")
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    assert cli.main(arguments("--enable-capture", "--ingest")) == 1
    monkeypatch.setenv("SENTINEL_API_KEY", "x" * 32)
    monkeypatch.setattr(cli, "api_request", lambda *_: {"mode": "demo", "enabled": False})
    assert cli.main(arguments("--enable-capture", "--ingest")) == 1
    assert not capture.called


def test_private_metadata_output_is_ignored_subtree_only(tmp_path):
    assert cli.private_output(tmp_path / "data/monitoring/test.json", tmp_path).is_relative_to(tmp_path / "data/monitoring")
    for path in (tmp_path / "export.json", tmp_path / "data/examples/conn.json", tmp_path / "data/monitoring/raw.pcap"):
        with pytest.raises(c.CollectorError):
            cli.private_output(path, tmp_path)


class FakeProcess:
    def __init__(self, output, *, binary=False, code=0):
        self.stdout = io.BytesIO(output if isinstance(output, bytes) else output.encode()) if binary else io.StringIO(output)
        self.stderr = io.BytesIO(b"private diagnostic must not print") if binary else io.StringIO("private diagnostic must not print")
        self.code = code
        self.pid = 1

    def wait(self, timeout=None):
        return self.code

    def poll(self):
        return self.code


@pytest.mark.parametrize("capture_code,decoder_code", [(0, 0), (1, 0), (0, 1)])
def test_memory_pipeline_requires_both_success_and_never_gives_children_api_key(monkeypatch, capture_code, decoder_code, capsys):
    capture = FakeProcess(b"not-read-by-parent", binary=True, code=capture_code)
    decoder = FakeProcess(line() + "\n", code=decoder_code)
    calls, processes = [], iter((capture, decoder))
    def popen(command, **kwargs):
        calls.append((command, kwargs))
        return next(processes)
    monkeypatch.setenv("SENTINEL_API_KEY", "never-in-child")
    monkeypatch.setattr(c.subprocess, "Popen", popen)
    if capture_code or decoder_code:
        with pytest.raises(c.CollectorError, match="Capture unavailable"):
            c.collect_window(config(duration=1), "tshark.exe", "dumpcap.exe")
    else:
        result = c.collect_window(config(duration=1), "tshark.exe", "dumpcap.exe")
        assert result["flow_record_count"] == 1
        assert result["raw_pcap_persisted"] is False
        assert result["snapshot_length_bytes"] == 128
    assert calls[1][1]["stdin"] is capture.stdout
    assert all(options["shell"] is False and "SENTINEL_API_KEY" not in options["env"] for _, options in calls)
    assert not capsys.readouterr().out


def test_finalized_collector_record_satisfies_backend_metadata_contract():
    from backend.app.schemas import MetadataBatch
    collector = c.FlowCollector(config(), COLLECTION)
    collector.consume(line())
    records = collector.finalize(END)
    batch = next(c.metadata_batches(records, COLLECTION))
    parsed = MetadataBatch.model_validate(batch)
    assert len(parsed.records) == 1
    assert parsed.records[0].provenance.collector == "dumpcap+tshark"


class RunningProcess(FakeProcess):
    def __init__(self, output, *, binary=False):
        super().__init__(output, binary=binary, code=None)
        self.killed = False

    def wait(self, timeout=None):
        if self.code is None:
            raise subprocess.TimeoutExpired("owned-child", timeout)
        return self.code

    def kill(self):
        self.killed, self.code = True, -9


def test_decoder_start_failure_stops_the_owned_capture_tree(monkeypatch):
    capture = RunningProcess(b"never-read-raw-data", binary=True)
    calls, tree_commands = [], []
    def popen(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            return capture
        raise OSError("decoder could not start")
    monkeypatch.setattr(c.subprocess, "Popen", popen)
    monkeypatch.setattr(c.subprocess, "run", lambda command, **kwargs: tree_commands.append(command))
    with pytest.raises(OSError):
        c.collect_window(config(duration=1), "tshark.exe", "dumpcap.exe")
    assert capture.killed
    assert capture.stdout.closed and capture.stderr.closed
    if hasattr(c.subprocess, "CREATE_NO_WINDOW"):
        assert tree_commands == [["taskkill", "/PID", "1", "/T", "/F"]]


def test_unstopped_pipeline_cleans_both_processes_without_real_taskkill(monkeypatch):
    capture = RunningProcess(b"not-read", binary=True)
    decoder = RunningProcess("")
    children = iter((capture, decoder))
    monkeypatch.setattr(c.subprocess, "Popen", lambda *args, **kwargs: next(children))
    monkeypatch.setattr(c.subprocess, "run", lambda *args, **kwargs: None)
    with pytest.raises(c.CollectorError, match="did not stop"):
        c.collect_window(config(duration=1), "tshark.exe", "dumpcap.exe")
    assert capture.killed and decoder.killed


def test_packet_limit_and_udp_fallback_never_invent_header_bytes():
    collector = c.FlowCollector(config(max_packets=1), COLLECTION)
    collector.consume(line(**{"tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "50000", "udp.dstport": "53", "udp.length": "8", "udp.stream": ""}))
    collector.consume(line())
    row = collector.finalize(END)[0]
    assert row["bytes_sent"] == 0
    assert row["provenance"]["flow_semantics"] == "udp_5tuple_window"
    assert collector.stats["skipped_packet_limit"] == 1


def test_success_summary_does_not_print_addresses_or_private_records(monkeypatch, capsys):
    result = {"collection_id": COLLECTION, "started_at": END, "ended_at": END,
        "flow_record_count": 1, "counters": {"packets_accepted": 1},
        "records": [{"src_ip": LOCAL, "dst_ip": PEER}], "limitations": ["bounded window"]}
    monkeypatch.setattr(cli, "resolve_tshark", lambda _: "tshark.exe")
    monkeypatch.setattr(cli, "resolve_dumpcap", lambda *_: "dumpcap.exe")
    monkeypatch.setattr(cli, "collect_window", lambda *_: result)
    request = Mock(side_effect=AssertionError("no --ingest; no network"))
    monkeypatch.setattr(cli, "api_request", request)
    assert cli.main(arguments("--enable-capture")) == 0
    output = capsys.readouterr().out
    assert LOCAL not in output and PEER not in output and '"records"' not in output
    assert not request.called


def test_ingestion_follows_capture_and_uses_fifty_finalized_records_per_batch(monkeypatch):
    records = [{"example": index} for index in range(51)]
    result = {"collection_id": COLLECTION, "started_at": END, "ended_at": END,
        "flow_record_count": 51, "counters": {"packets_accepted": 51}, "records": records, "limitations": []}
    events = []
    monkeypatch.setenv("SENTINEL_API_KEY", "x" * 32)
    monkeypatch.setattr(cli, "resolve_tshark", lambda _: "tshark.exe")
    monkeypatch.setattr(cli, "resolve_dumpcap", lambda *_: "dumpcap.exe")
    def capture(*_):
        events.append("capture")
        return result
    def request(base, path, key, payload=None):
        if path == "/api/monitor/status":
            events.append("preflight")
            return {"mode": "monitor", "enabled": True, "ingestion_enabled": True, "database_isolated": True}
        events.append(("ingest", len(payload["records"])))
        return {"origin": "live", "ingested": len(payload["records"]), "duplicate": False}
    monkeypatch.setattr(cli, "collect_window", capture)
    monkeypatch.setattr(cli, "api_request", request)
    assert cli.main(arguments("--enable-capture", "--ingest")) == 0
    assert events == ["preflight", "capture", ("ingest", 50), ("ingest", 1)]
