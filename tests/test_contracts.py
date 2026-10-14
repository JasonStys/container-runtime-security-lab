"""Jason Stys: strict parser boundaries, pseudonym privacy and hostile bounded JSONL/property cases."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: KEY — line 52
# variable: AT — line 53
# definition: sample — line 56
# definition: test_bad_clock — line 78
# parameter: value — line 78
# definition: test_equivalent_clock — line 84
# definition: test_bad_text — line 90
# parameter: value — line 90
# definition: test_bad_counter — line 97
# parameter: value — line 97
# definition: test_bad_policy — line 118
# parameter: value — line 118
# definition: test_bad_health_shape — line 125
# parameter: value — line 125
# definition: test_health_fields — line 131
# variable: item — line 133
# definition: test_bad_alert_envelope — line 152
# parameter: field — line 152
# parameter: value — line 152
# variable: item — line 154
# definition: test_missing_envelope — line 161
# parameter: value — line 161
# definition: test_syscall_identity — line 167
# variable: item — line 169
# variable: first — line 175
# variable: pid — line 178
# definition: test_privacy_allowlist_and_key — line 184
# variable: item — line 186
# variable: model — line 187
# definition: test_alias_property — line 204
# parameter: value — line 204
# variable: first — line 206
# definition: test_bad_json — line 216
# parameter: data — line 216
# definition: test_files_and_caps — line 222
# parameter: monkeypatch — line 222
# parameter: tmp_path — line 222
# variable: path — line 224
# parameter: self — line 246
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
