"""Jason Stys: bounded JSONL, exact policy/health types, UTC clocks and pseudonymized Falco alert contracts."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_LINE — line 105
# variable: MAX_EVENTS — line 106
# variable: MAX_BYTES — line 107
# variable: CATALOG — line 108
# variable: PRIORITIES — line 118
# definition: Alert — line 131
# variable: event — line 134
# variable: source — line 135
# variable: rule — line 136
# variable: priority — line 137
# variable: time — line 138
# variable: namespace — line 139
# variable: subject — line 140
# definition: Health — line 144
# variable: source — line 147
# variable: last_seen — line 148
# variable: received — line 149
# variable: dropped — line 150
# variable: complete — line 151
# definition: Policy — line 155
# variable: sources — line 158
# variable: max_age_seconds — line 159
# definition: clock — line 162
# parameter: value — line 162
# variable: parsed — line 167
# definition: text — line 175
# parameter: maximum — line 175
# parameter: value — line 175
# variable: char — line 180
# definition: fields — line 186
# parameter: required — line 186
# parameter: value — line 186
# definition: count — line 193
# parameter: upper — line 193
# parameter: value — line 193
# definition: source — line 200
# parameter: value — line 200
# definition: alias — line 207
# parameter: key — line 207
# parameter: kind — line 207
# parameter: value — line 207
# definition: parse_policy — line 218
# parameter: value — line 218
# variable: data — line 220
# variable: item — line 223
# variable: sources — line 223
# variable: age — line 224
# definition: parse_health — line 230
# parameter: value — line 230
# variable: observations — line 234
# variable: item — line 235
# variable: data — line 236
# variable: item — line 248
# definition: optional_text — line 253
# parameter: fallback — line 253
# parameter: value — line 253
# definition: parse_alert — line 258
# parameter: key — line 258
# parameter: value — line 258
# variable: origin — line 268
# variable: rule — line 269
# variable: priority — line 270
# variable: output — line 273
# variable: event_id — line 277
# variable: namespace — line 278
# variable: subject — line 281
# variable: container — line 284
# variable: pid — line 285
# variable: event_id — line 288
# variable: namespace — line 289
# variable: subject — line 290
# definition: unique_pairs — line 302
# parameter: pairs — line 302
# variable: result — line 304
# variable: name — line 305
# variable: value — line 305
# definition: reject_constant — line 312
# parameter: value — line 312
# definition: decode — line 317
# parameter: data — line 317
# definition: read_records — line 331
# parameter: path — line 331
# variable: records — line 335
# variable: consumed — line 336
# variable: stream — line 337
# variable: line — line 338
# variable: consumed — line 339
# definition: read_config — line 351
# parameter: path — line 351
# variable: stream — line 355
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


def optional_text(value: object, fallback: str) -> str:
    """Only missing/null/empty optional metadata gets an unavailable label; malformed types still fail."""
    return fallback if value is None or value == "" else text(value)


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
        namespace = optional_text(
            output.get("ka.target.namespace"), "scope-unavailable"
        )
        subject = optional_text(output.get("ka.target.name"), "unknown-object")
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
