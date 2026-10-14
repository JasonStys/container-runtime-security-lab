"""Jason Stys: deduplication/coverage/clock contracts, input-order properties and no-alerts-not-safe regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: KEY — line 72
# variable: AT — line 73
# definition: inputs — line 76
# variable: item — line 81
# definition: test_examples_and_json — line 88
# variable: alerts — line 90
# variable: health — line 90
# variable: policy — line 90
# variable: result — line 91
# variable: item — line 99
# definition: test_health_gaps — line 111
# parameter: field — line 111
# parameter: reason — line 111
# parameter: value — line 111
# variable: _ — line 113
# variable: health — line 113
# variable: policy — line 113
# variable: first — line 114
# variable: result — line 115
# variable: item — line 117
# definition: test_missing_source_and_scope — line 120
# variable: alerts — line 122
# variable: health — line 122
# variable: policy — line 122
# variable: item — line 123
# variable: scoped — line 126
# variable: result — line 127
# variable: item — line 128
# variable: unknown — line 129
# variable: item — line 130
# definition: test_bad_clock — line 138
# variable: alerts — line 140
# variable: health — line 140
# variable: policy — line 140
# variable: future — line 143
# variable: boundary — line 148
# definition: test_duplicates — line 152
# variable: alerts — line 154
# variable: health — line 154
# variable: policy — line 154
# variable: early — line 155
# variable: rows — line 156
# variable: result — line 157
# variable: field — line 161
# definition: test_order_independence — line 172
# parameter: order — line 172
# variable: alerts — line 174
# variable: health — line 174
# variable: policy — line 174
# variable: index — line 175
# END CODE MAP

from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from runtime_lab.contracts import (
    clock,
    parse_alert,
    parse_health,
    parse_policy,
    read_config,
    read_records,
)
from runtime_lab.review import review

KEY = b"synthetic-review-key-32-bytes!!!!!"
AT = clock("2026-10-14T00:00:00Z")


def inputs() -> tuple:
    """Fresh parsed synthetic examples; no current PC/cluster information is collected."""
    return (
        [
            parse_alert(item, KEY)
            for item in read_records(Path("examples/alerts.jsonl"))
        ],
        parse_health(read_config(Path("examples/health.json"))),
        parse_policy(read_config(Path("examples/policy.json"))),
    )


def test_examples_and_json() -> None:
    """Actual review counts/attribution and privacy-safe JSON times are stable."""
    alerts, health, policy = inputs()
    result = review(alerts, health, policy, AT)
    assert (
        result.complete
        and result.unique == 3
        and result.received == 3
        and result.duplicates == 0
    )
    assert result.to_dict()["author"] == "Jason Stys"
    assert all(isinstance(item["time"], str) for item in result.to_dict()["alerts"])


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("complete", False, "capture-incomplete"),
        ("received", 0, "source-empty"),
        ("dropped", 1, "events-dropped"),
        ("last_seen", clock("2026-10-13T23:57:59Z"), "source-stale"),
    ],
)
def test_health_gaps(field: str, value: object, reason: str) -> None:
    """No detections can still mean degraded/missing observation, never automatically safe."""
    _, health, policy = inputs()
    first = replace(health[0], **{field: value})
    result = review([], (first, health[1]), policy, AT)
    assert not result.complete
    assert {item.reason for item in result.gaps} == {reason}


def test_missing_source_and_scope() -> None:
    """Missing sources, unconfigured alert sources and unknown/mismatched rule sources become review gaps."""
    alerts, health, policy = inputs()
    assert {item.reason for item in review([], (), policy, AT).gaps} == {
        "source-missing"
    }
    scoped = replace(policy, sources=("syscall",))
    result = review(alerts, health, scoped, AT)
    assert {item.reason for item in result.gaps} == {"outside-configured-scope"}
    unknown = replace(alerts[0], rule="unrecognized")
    assert {item.reason for item in review([unknown], health, policy, AT).gaps} == {
        "unrecognized-rule-source"
    }
    assert review(
        [], health, policy, AT
    ).complete  # coverage complete is explicitly NOT a safety verdict


def test_bad_clock() -> None:
    """Future alert/sensor clocks and naive references never produce trusted results."""
    alerts, health, policy = inputs()
    with pytest.raises(ValueError):
        review(alerts, health, policy, AT.replace(tzinfo=None))
    future = clock("2026-10-15T00:00:00Z")
    with pytest.raises(ValueError):
        review([replace(alerts[0], time=future)], health, policy, AT)
    with pytest.raises(ValueError):
        review(alerts, (replace(health[0], last_seen=future), health[1]), policy, AT)
    boundary = replace(health[0], last_seen=clock("2026-10-13T23:58:00Z"))
    assert review(alerts, (boundary, health[1]), policy, AT).complete


def test_duplicates() -> None:
    """Same API audit ID/rule is idempotent across stages; conflicts in semantic fields are not overwritten."""
    alerts, health, policy = inputs()
    early = replace(alerts[0], time=clock("2026-10-13T23:59:59Z"))
    for rows in ([alerts[0], early], [early, alerts[0]], [early, early]):
        result = review(rows, health, policy, AT)
        assert (
            result.unique == 1 and result.duplicates == 1 and result.alerts[0] == early
        )
    for field in ("priority", "namespace", "subject"):
        with pytest.raises(ValueError):
            review(
                [alerts[0], replace(alerts[0], **{field: "different"})],
                health,
                policy,
                AT,
            )


@given(st.permutations([0, 1, 2]))
def test_order_independence(order: list[int]) -> None:
    """Equivalent alert input ordering produces deterministic evidence after one key-scoped normalization."""
    alerts, health, policy = inputs()
    assert review([alerts[index] for index in order], health, policy, AT) == review(
        alerts, health, policy, AT
    )
