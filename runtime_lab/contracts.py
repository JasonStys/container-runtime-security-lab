"""Jason Stys: bounded JSONL, exact policy/health types, UTC clocks and pseudonymized Falco alert contracts."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_LINE — line 102
# variable: MAX_EVENTS — line 103
# variable: MAX_BYTES — line 104
# variable: CATALOG — line 105
# variable: PRIORITIES — line 115
# definition: Alert — line 128
# variable: event — line 131
# variable: source — line 132
# variable: rule — line 133
# variable: priority — line 134
# variable: time — line 135
# variable: namespace — line 136
# variable: subject — line 137
# definition: Health — line 141
# variable: source — line 144
# variable: last_seen — line 145
# variable: received — line 146
# variable: dropped — line 147
# variable: complete — line 148
# definition: Policy — line 152
# variable: sources — line 155
# variable: max_age_seconds — line 156
# definition: clock — line 159
# parameter: value — line 159
# variable: parsed — line 164
# definition: text — line 172
# parameter: maximum — line 172
# parameter: value — line 172
# variable: char — line 177
# definition: fields — line 183
# parameter: required — line 183
# parameter: value — line 183
# definition: count — line 190
# parameter: upper — line 190
# parameter: value — line 190
# definition: source — line 197
# parameter: value — line 197
# definition: alias — line 204
# parameter: key — line 204
# parameter: kind — line 204
# parameter: value — line 204
# definition: parse_policy — line 215
# parameter: value — line 215
# variable: data — line 217
# variable: item — line 220
# variable: sources — line 220
# variable: age — line 221
# definition: parse_health — line 227
# parameter: value — line 227
# variable: observations — line 231
# variable: item — line 232
# variable: data — line 233
# variable: item — line 245
# definition: parse_alert — line 250
# parameter: key — line 250
# parameter: value — line 250
# variable: origin — line 260
# variable: rule — line 261
# variable: priority — line 262
# variable: output — line 265
# variable: event_id — line 269
# variable: namespace — line 270
# variable: subject — line 271
# variable: container — line 274
# variable: pid — line 275
# variable: event_id — line 278
# variable: namespace — line 279
# variable: subject — line 280
# definition: unique_pairs — line 292
# parameter: pairs — line 292
# variable: result — line 294
# variable: name — line 295
# variable: value — line 295
# definition: reject_constant — line 302
# parameter: value — line 302
# definition: decode — line 307
# parameter: data — line 307
# definition: read_records — line 321
# parameter: path — line 321
# variable: records — line 325
# variable: consumed — line 326
# variable: stream — line 327
# variable: line — line 328
# variable: consumed — line 329
# definition: read_config — line 341
# parameter: path — line 341
# variable: stream — line 345
# END CODE MAP

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_LINE = 65536
MAX_EVENTS = 10000
MAX_BYTES = 8 * 1024 * 1024
CATALOG = {
    "CRSL Privileged Pod": "k8s_audit",
    "CRSL Host Namespace": "k8s_audit",
    "CRSL HostPath Mount": "k8s_audit",
    "CRSL Pod Exec": "k8s_audit",
    "CRSL Secret Read": "k8s_audit",
    "CRSL Wildcard Role": "k8s_audit",
    "CRSL Marker Read": "syscall",
    "CRSL Marker Write": "syscall",
}
PRIORITIES = {
    "Emergency",
    "Alert",
    "Critical",
    "Error",
    "Warning",
    "Notice",
    "Informational",
    "Debug",
}


@dataclass(frozen=True)
class Alert:
    """Minimal alert with pseudonymized event/namespace/workload IDs; raw output/actors are never retained."""

    event: str
    source: str
    rule: str
    priority: str
    time: datetime
    namespace: str
    subject: str


@dataclass(frozen=True)
class Health:
    """Explicit source observations supplied by an operator; declarations are not authenticated sensor attestations."""

    source: str
    last_seen: datetime
    received: int
    dropped: int
    complete: bool


@dataclass(frozen=True)
class Policy:
    """Expected event sources and maximum sensor age; no allowlist silently suppresses matching detections."""

    sources: tuple[str, ...]
    max_age_seconds: int


def clock(value: object) -> datetime:
    """Parse bounded ISO-8601 with timezone into UTC; naive, invalid and UTC-overflow clocks fail closed."""
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("bounded timestamp required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError) as error:
        raise ValueError("invalid UTC timestamp") from error


def text(value: object, maximum: int = 256) -> str:
    """Require nonempty bounded strings without control characters, never coerce arbitrary values."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("bounded text required")
    return value


def fields(value: object, required: set[str]) -> dict[str, Any]:
    """Require exact configuration keys; reject unknown settings that could appear to be effective."""
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("incorrect configuration fields")
    return value


def count(value: object, upper: int = 10**9) -> int:
    """Reject bool-as-int and negative/overflow telemetry counters."""
    if type(value) is not int or not 0 <= value <= upper:
        raise ValueError("bounded nonnegative counter required")
    return value


def source(value: object) -> str:
    """Only the two explicitly implemented Falco event sources are supported."""
    if not isinstance(value, str) or value not in {"k8s_audit", "syscall"}:
        raise ValueError("unsupported event source")
    return value


def alias(key: bytes, kind: str, value: str) -> str:
    """Use domain-separated per-review HMAC pseudonyms; key is never written into an evidence bundle."""
    if len(key) < 32:
        raise ValueError("privacy key must contain at least 32 bytes")
    return (
        kind
        + "-"
        + hmac.new(key, (kind + "\0" + value).encode(), hashlib.sha256).hexdigest()[:24]
    )


def parse_policy(value: object) -> Policy:
    """Validate expected source coverage with unique nonempty source list and bounded freshness."""
    data = fields(value, {"sources", "max_age_seconds"})
    if not isinstance(data["sources"], list) or not 1 <= len(data["sources"]) <= 2:
        raise ValueError("one or two expected sources required")
    sources = tuple(source(item) for item in data["sources"])
    age = count(data["max_age_seconds"], 86400)
    if len(set(sources)) != len(sources) or age == 0:
        raise ValueError("duplicate sources or zero freshness")
    return Policy(tuple(sorted(sources)), age)


def parse_health(value: object) -> tuple[Health, ...]:
    """Validate duplicate-free operator observations separately from detections; missing sources stay unknown."""
    if not isinstance(value, list) or len(value) > 2:
        raise ValueError("bounded source health array required")
    observations = []
    for item in value:
        data = fields(item, {"source", "last_seen", "received", "dropped", "complete"})
        if type(data["complete"]) is not bool:
            raise ValueError("complete must be boolean")
        observations.append(
            Health(
                source(data["source"]),
                clock(data["last_seen"]),
                count(data["received"]),
                count(data["dropped"]),
                data["complete"],
            )
        )
    if len({item.source for item in observations}) != len(observations):
        raise ValueError("duplicate source health")
    return tuple(observations)


def parse_alert(value: object, key: bytes) -> Alert:
    """Extract allowlisted fields only from Falco JSON; extra envelope/field values never enter reports."""
    if not isinstance(value, dict) or not {
        "rule",
        "source",
        "priority",
        "time",
        "output_fields",
    } <= set(value):
        raise ValueError("Falco JSON envelope required")
    origin = source(value["source"])
    rule = text(value["rule"], 128)
    priority = text(value["priority"], 32)
    if priority not in PRIORITIES:
        raise ValueError("unknown Falco priority")
    output = value["output_fields"]
    if not isinstance(output, dict):
        raise ValueError("Falco output_fields must be an object")
    if origin == "k8s_audit":
        event_id = text(output.get("ka.auditid"), 128)
        namespace = text(output.get("ka.target.namespace", "cluster-scope"))
        subject = text(output.get("ka.target.name", "unknown-object"))
    else:
        # A syscall event has no Kubernetes auditID. Keying by native event time + container + PID avoids cross-container merging.
        container = text(output.get("container.id"), 128)
        pid = output.get("proc.pid")
        if type(pid) is not int or not 1 <= pid <= 2**31 - 1:
            raise ValueError("positive native PID required")
        event_id = str(pid) + ":" + container + ":" + text(value["time"], 40)
        namespace = "runtime"
        subject = container
    return Alert(
        alias(key, "event", event_id),
        origin,
        rule,
        priority,
        clock(value["time"]),
        alias(key, "scope", namespace),
        alias(key, "object", subject),
    )


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before configuration or event parsing."""
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def reject_constant(value: str) -> None:
    """Reject nonstandard NaN/Infinity JSON values even in ignored metadata."""
    raise ValueError("nonstandard JSON numeric constant")


def decode(data: bytes) -> object:
    """Decode one bounded JSON object/value; encoding, deep recursion and malformed input fail explicitly."""
    if len(data) > MAX_LINE:
        raise ValueError("JSON record size cap")
    try:
        return json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("invalid JSON record") from error


def read_records(path: Path) -> list[object]:
    """Read regular nonsymlink bounded JSONL; blank lines ignored, malformed/oversized records never silently skipped."""
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("regular private input required")
    records = []
    consumed = 0
    with path.open("rb") as stream:
        while line := stream.readline(MAX_LINE + 1):
            consumed += len(line)
            if len(line) > MAX_LINE:
                raise ValueError("JSONL line size cap")
            if consumed > MAX_BYTES:
                raise ValueError("stream byte cap")
            if line.strip():
                records.append(decode(line))
                if len(records) > MAX_EVENTS:
                    raise ValueError("stream event cap")
    return records


def read_config(path: Path) -> object:
    """Read one bounded regular UTF-8 JSON policy/health file; no YAML execution or arbitrary deserialization."""
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("regular configuration required")
    with path.open("rb") as stream:
        return decode(stream.read(MAX_LINE + 1))
