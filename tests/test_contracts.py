"""Jason Stys: strict parser boundaries, pseudonym privacy and hostile bounded JSONL/property cases."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: KEY — line 58
# variable: AT — line 59
# definition: sample — line 62
# definition: test_bad_clock — line 84
# parameter: value — line 84
# definition: test_equivalent_clock — line 90
# definition: test_bad_text — line 96
# parameter: value — line 96
# definition: test_bad_counter — line 103
# parameter: value — line 103
# definition: test_bad_policy — line 124
# parameter: value — line 124
# definition: test_bad_health_shape — line 131
# parameter: value — line 131
# definition: test_health_fields — line 137
# variable: item — line 139
# definition: test_bad_alert_envelope — line 158
# parameter: field — line 158
# parameter: value — line 158
# variable: item — line 160
# definition: test_missing_envelope — line 167
# parameter: value — line 167
# definition: test_syscall_identity — line 173
# variable: item — line 175
# variable: first — line 181
# variable: pid — line 184
# definition: test_privacy_allowlist_and_key — line 190
# variable: item — line 192
# variable: model — line 193
# definition: test_optional_native_metadata — line 205
# parameter: field — line 205
# parameter: value — line 205
# variable: item — line 207
# definition: test_optional_metadata_wrong_types — line 213
# parameter: value — line 213
# definition: test_alias_property — line 226
# parameter: value — line 226
# variable: first — line 228
# definition: test_bad_json — line 238
# parameter: data — line 238
# definition: test_files_and_caps — line 244
# parameter: monkeypatch — line 244
# parameter: tmp_path — line 244
# variable: path — line 246
# parameter: self — line 268
# END CODE MAP

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from runtime_lab import contracts as c

KEY = b"synthetic-contract-key-32-bytes!!!"
AT = "2026-10-14T00:00:00Z"


def sample() -> dict[str, object]:
    """Return a fresh synthetic Falco envelope including deliberately private-looking ignored metadata."""
    return {
        "time": AT,
        "rule": "CRSL Secret Read",
        "source": "k8s_audit",
        "priority": "Warning",
        "output": "PRIVATE-OUTPUT",
        "hostname": "PRIVATE-HOST",
        "output_fields": {
            "ka.auditid": "synthetic-1",
            "ka.target.namespace": "PRIVATE-NAMESPACE",
            "ka.target.name": "PRIVATE-WORKLOAD",
            "ka.user.name": "PRIVATE-ACTOR",
            "secret": "PRIVATE-CONTENT",
        },
    }


@pytest.mark.parametrize(
    "value", [None, 1, "bad", "2026-10-14", "x" * 41, "0001-01-01T00:00:00+01:00"]
)
def test_bad_clock(value: object) -> None:
    """Reject naive, malformed, nonstring, oversized and UTC-overflow timestamps."""
    with pytest.raises(ValueError):
        c.clock(value)


def test_equivalent_clock() -> None:
    """Timezone offsets represent instants consistently."""
    assert c.clock(AT) == c.clock("2026-10-14T01:00:00+01:00")


@pytest.mark.parametrize("value", [None, 1, "", "x" * 257, "\n", "bad\ttext"])
def test_bad_text(value: object) -> None:
    """Bounds and control-character checks reject dangerous/uninterpretable fields."""
    with pytest.raises(ValueError):
        c.text(value)


@pytest.mark.parametrize("value", [True, -1, 10**9 + 1, 1.5, "10"])
def test_bad_counter(value: object) -> None:
    """Counters are actual bounded integers, not booleans or truthy input."""
    with pytest.raises(ValueError):
        c.count(value)


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [],
        ["x"],
        {"sources": [], "max_age_seconds": 1},
        {"sources": ["syscall", "syscall"], "max_age_seconds": 1},
        {"sources": ["unknown"], "max_age_seconds": 1},
        {"sources": ["syscall"], "max_age_seconds": 0},
        {"sources": ["syscall"], "max_age_seconds": 86401},
        {"sources": ["syscall"], "max_age_seconds": True},
    ],
)
def test_bad_policy(value: object) -> None:
    """Unknown/missing/duplicate configuration never silently becomes an effective scope."""
    with pytest.raises(ValueError):
        c.parse_policy(value)


@pytest.mark.parametrize("value", [None, {}, [{}, {}], [{}, {}, {}]])
def test_bad_health_shape(value: object) -> None:
    """Health must be a small exact array of typed observations."""
    with pytest.raises(ValueError):
        c.parse_health(value)


def test_health_fields() -> None:
    """Boolean and duplicate source validation are independent of unknown/missing source review."""
    item = dict(source="syscall", last_seen=AT, received=1, dropped=0, complete=True)
    assert c.parse_health([item])[0].received == 1
    with pytest.raises(ValueError):
        c.parse_health([{**item, "complete": 1}])
    with pytest.raises(ValueError):
        c.parse_health([item, item])
    assert c.parse_health([]) == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("priority", "unknown"),
        ("output_fields", []),
        ("source", "unknown"),
        ("rule", ""),
        ("time", "bad"),
    ],
)
def test_bad_alert_envelope(field: str, value: object) -> None:
    """Falco envelope/source/priority fields and clocks are validated before any reporting."""
    item = sample()
    item[field] = value
    with pytest.raises(ValueError):
        c.parse_alert(item, KEY)


@pytest.mark.parametrize("value", [None, [], {}, {"rule": "x"}])
def test_missing_envelope(value: object) -> None:
    """Required Falco JSON fields are never guessed from free text."""
    with pytest.raises(ValueError):
        c.parse_alert(value, KEY)


def test_syscall_identity() -> None:
    """Event identity includes native container/PID/time, not just PID reused across containers."""
    item = sample()
    item.update(
        source="syscall",
        rule="CRSL Marker Read",
        output_fields={"container.id": "synthetic-container", "proc.pid": 123},
    )
    first = c.parse_alert(item, KEY)
    item["output_fields"]["container.id"] = "different"
    assert c.parse_alert(item, KEY).event != first.event
    for pid in (0, -1, True, "123", 2**31):
        item["output_fields"]["proc.pid"] = pid
        with pytest.raises(ValueError):
            c.parse_alert(item, KEY)


def test_privacy_allowlist_and_key() -> None:
    """Discard raw output, actor names, hostnames and unallowlisted nested fields; rotate pseudonyms across keys."""
    item = sample()
    model = c.parse_alert(item, KEY)
    assert "PRIVATE" not in repr(model)
    assert c.parse_alert(item, b"x" * 32).event != model.event
    with pytest.raises(ValueError):
        c.parse_alert(item, b"short")
    item["output_fields"].pop("ka.target.namespace")
    item["output_fields"].pop("ka.target.name")
    assert c.parse_alert(item, KEY).namespace.startswith("scope-")


@pytest.mark.parametrize("field", ["ka.target.namespace", "ka.target.name"])
@pytest.mark.parametrize("value", [None, ""])
def test_optional_native_metadata(field: str, value: object) -> None:
    """Actual Falco missing optional fields can be null/empty, but do not prove cluster scope or object identity."""
    item = sample()
    item["output_fields"][field] = value
    assert c.parse_alert(item, KEY).namespace.startswith("scope-")


@pytest.mark.parametrize("value", [False, 0, 1, [], {}, "bad\ntext"])
def test_optional_metadata_wrong_types(value: object) -> None:
    """Do not convert arbitrary falsy metadata into unavailable labels."""
    with pytest.raises(ValueError):
        c.optional_text(value, "unavailable")


@given(
    st.text(
        alphabet=st.characters(min_codepoint=32, max_codepoint=126),
        min_size=1,
        max_size=128,
    )
)
def test_alias_property(value: str) -> None:
    """Pseudonyms are fixed-size alphanumeric/hyphen labels, deterministic per key/domain."""
    first = c.alias(KEY, "event", value)
    assert first == c.alias(KEY, "event", value)
    assert first != c.alias(KEY, "object", value)
    assert len(first) == 30


@pytest.mark.parametrize(
    "data",
    [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"{oops", b"\xff", b"[" * 2000],
)
def test_bad_json(data: bytes) -> None:
    """Duplicate keys, encoding errors, nonstandard numbers and nesting bombs fail explicitly."""
    with pytest.raises(ValueError):
        c.decode(data)


def test_files_and_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Read real temporary JSONL/config files, including BOM and blank lines, with all independent caps."""
    path = tmp_path / "stream.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"a":1}\n\n{"b":2}\n')
    assert c.read_records(path) == [{"a": 1}, {"b": 2}]
    assert c.read_config(Path("examples/policy.json"))["sources"] == [
        "k8s_audit",
        "syscall",
    ]
    with pytest.raises(ValueError):
        c.read_records(tmp_path)
    with pytest.raises(ValueError):
        c.read_config(tmp_path)
    monkeypatch.setattr(c, "MAX_EVENTS", 1)
    with pytest.raises(ValueError):
        c.read_records(path)
    monkeypatch.setattr(c, "MAX_BYTES", 2)
    with pytest.raises(ValueError):
        c.read_records(path)
    monkeypatch.setattr(c, "MAX_LINE", 2)
    with pytest.raises(ValueError):
        c.read_records(path)
    with pytest.raises(ValueError):
        c.read_config(path)
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with pytest.raises(ValueError):
        c.read_records(path)
    with pytest.raises(ValueError):
        c.read_config(path)
