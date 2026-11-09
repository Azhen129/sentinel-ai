from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Connection(BaseModel):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp", "icmp"]
    duration: float = Field(default=0, ge=0, le=31536000)
    bytes_sent: int = Field(default=0, ge=0, le=10**15)
    bytes_received: int = Field(default=0, ge=0, le=10**15)
    status: str = Field(default="unknown", max_length=40)
    service: str = Field(default="unknown", max_length=80)
    scenario: str = Field(default="lab", max_length=80)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ip_address(value))

    @field_validator("timestamp")
    @classmethod
    def valid_timestamp(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        return parsed.astimezone(timezone.utc).isoformat()


class IncidentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "resolved"] | None = None
    note: str | None = Field(default=None, min_length=1, max_length=4000)


class SimulationStart(BaseModel):
    speed: float = Field(default=4, ge=0.25, le=20)


class ZeekUpload(BaseModel):
    content: str = Field(min_length=1, max_length=2_000_000)
    format: Literal["json", "tsv"] = "json"


class PassiveProvenance(BaseModel):
    """Only approved metadata fields; packet payloads and credentials are rejected."""
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    collector: Literal["tshark", "dumpcap+tshark"]
    interface_label: str = Field(min_length=1, max_length=80)
    interface_id: str | None = Field(default=None, max_length=80)
    measurement_semantics: Literal["transport_payload_bytes"]
    observation_scope: Literal["selected_interface_passive"]
    flow_semantics: Literal["tcp_stream_window", "udp_stream_window", "udp_5tuple_window"]
    process_scope: Literal["interface_only_no_process_attribution"]
    flow_id: str = Field(pattern=r"^[a-f0-9]{40}$")
    collection_id: str = Field(pattern=r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
    first_seen: str
    last_seen: str
    window_end: str
    packet_count: int = Field(ge=1, le=5000)
    local_role: Literal["initiator", "responder", "unknown"]
    midstream_start: bool
    duration_is_lower_bound: Literal[True]
    capture_window_limited: Literal[True]
    retransmissions_included: Literal[True]
    direction_basis: Literal["local_host"]
    transport_flags_observed: str = Field(max_length=40, pattern=r"^(?:(?:SYN|ACK|RST|FIN)(?:,(?:SYN|ACK|RST|FIN))*)?$")

    @field_validator("first_seen", "last_seen", "window_end")
    @classmethod
    def valid_time(cls, value):
        return Connection.valid_timestamp(value)

    @model_validator(mode="after")
    def ordered_window(self):
        if not datetime.fromisoformat(self.first_seen) <= datetime.fromisoformat(self.last_seen) <= datetime.fromisoformat(self.window_end):
            raise ValueError("Observed times must satisfy first_seen <= last_seen <= window_end")
        return self


class PassiveConnection(Connection):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    protocol: Literal["tcp", "udp"]
    status: Literal["observed", "syn_observed", "reset_observed", "fin_observed"]
    scenario: Literal["live_ethernet"] = "live_ethernet"
    provenance: PassiveProvenance

    @model_validator(mode="after")
    def consistent_first_seen(self):
        if self.timestamp != self.provenance.first_seen:
            raise ValueError("timestamp must be the observed first_seen time")
        return self


class MetadataBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9:_-]+$")
    records: list[PassiveConnection] = Field(min_length=1, max_length=250)

    @model_validator(mode="after")
    def one_collection(self):
        contexts = {(r.provenance.collection_id, r.provenance.interface_label, r.provenance.collector) for r in self.records}
        if len(contexts) != 1:
            raise ValueError("A metadata batch must belong to one collection and interface")
        return self
