"""Jason Stys: independent episode continuity, private review binding and reasoned-triage regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: fixture — line 68
# parameter: gaps — line 68
# variable: at — line 70
# variable: alerts — line 71
# variable: i — line 81
# variable: t — line 81
# definition: test_episode_boundary_original_preserved_and_source_loss — line 88
# variable: original — line 90
# variable: result — line 91
# variable: e — line 92
# variable: lost — line 98
# variable: e — line 100
# variable: other_source — line 106
# variable: different — line 108
# definition: test_reasoned_triage_and_exact_binding — line 125
# variable: r — line 127
# variable: base — line 128
# variable: episode — line 129
# variable: decision — line 130
# variable: result — line 140
# variable: field — line 146
# variable: value — line 146
# variable: bad — line 147
# variable: change — line 151
# variable: bad — line 157
# variable: bad — line 161
# variable: bad — line 165
# variable: other — line 171
# variable: a — line 172
# variable: template — line 176
# definition: test_saved_review_contract — line 199
# parameter: mutation — line 199
# variable: value — line 201
# definition: test_safe_load_publish_and_actual_cli — line 224
# parameter: tmp_path — line 224
# variable: p — line 226
# variable: out — line 228
# variable: args — line 229
# variable: result — line 232
# variable: template — line 233
# variable: triage — line 237
# variable: original — line 256
# variable: clean — line 273
# variable: seconds — line 281
# definition: test_omitted_unknown_rule_gap_rejects — line 286
# variable: unknown — line 288
# variable: a — line 290
# variable: observed — line 294
# END CODE MAP

import copy
import json
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from runtime_lab.contracts import Alert, clock
from runtime_lab.episodes import group, load, main, publish, restore
from runtime_lab.review import Gap, Review


def fixture(gaps=()):
    """Four independent same-object alerts straddle the30-second inclusive episode gap."""
    at = clock("2026-10-14T00:00:00Z")
    alerts = tuple(
        Alert(
            "event-" + f"{i:024x}",
            "k8s_audit",
            "CRSL Pod Exec",
            "Warning",
            at + timedelta(seconds=t),
            "scope-" + "a" * 24,
            "object-" + "b" * 24,
        )
        for i, t in enumerate((0, 30, 61, 62))
    )
    return Review(
        (at + timedelta(seconds=120)).isoformat(), 5, 4, 1, not gaps, alerts, gaps
    )


def test_episode_boundary_original_preserved_and_source_loss():
    """Healthy exact gap merges0/30 and61/62; unlocated dropped-event intervals forbid inferring continuity."""
    original = fixture()
    result = group(original)
    assert [len(e["event_ids"]) for e in result["episodes"]] == [2, 2]
    assert (
        result["original_review"] == original.to_dict()
        and len(result["unreviewed_episode_ids"]) == 2
    )
    assert result == group(restore(json.loads(json.dumps(original.to_dict()))))
    lost = group(fixture((Gap("k8s_audit", "events-dropped"),)))
    assert len(lost["episodes"]) == 4 and all(
        e["continuity"] == "SOURCE_GAP_NO_CONTINUITY_INFERRED" for e in lost["episodes"]
    )
    assert (
        lost["original_review"]["duplicates"] == 1
        and lost["original_review"]["received"] == 5
    )
    other_source = group(fixture((Gap("syscall", "source-missing"),)))
    assert len(other_source["episodes"]) == 2
    different = replace(
        original,
        alerts=(
            original.alerts[0],
            replace(original.alerts[1], subject="object-" + "c" * 24),
            *original.alerts[2:],
        ),
    )
    assert len(group(different)["episodes"]) == 3
    assert (
        group(replace(original, received=0, unique=0, duplicates=0, alerts=()))[
            "episodes"
        ]
        == []
    )


def test_reasoned_triage_and_exact_binding():
    """False-positive assertions never delete original detections; changed review/episode/threshold cannot replay a disposition."""
    r = fixture()
    base = group(r)
    episode = base["episodes"][0]["id"]
    decision = {
        "review_sha256": base["review_sha256"],
        "episodes": [
            {
                "episode_id": episode,
                "disposition": "expected_activity",
                "reason": "Fictional approved exercise ticket42 verified.",
            }
        ],
    }
    result = group(r, triage=decision)
    assert (
        result["episodes"][0]["disposition"] == "expected_activity"
        and result["original_review"] == base["original_review"]
    )
    assert len(result["unreviewed_episode_ids"]) == 1
    for field, value in (("review_sha256", "0" * 64),):
        bad = copy.deepcopy(decision)
        bad[field] = value
        with pytest.raises(ValueError):
            group(r, triage=bad)
    for change in (
        {"episode_id": "0" * 64},
        {"disposition": "approve-everything"},
        {"reason": "  "},
        {"reason": "x" * 501},
    ):
        bad = copy.deepcopy(decision)
        bad["episodes"][0].update(change)
        with pytest.raises(ValueError):
            group(r, triage=bad)
    bad = copy.deepcopy(decision)
    bad["episodes"] *= 2
    with pytest.raises(ValueError):
        group(r, triage=bad)
    bad = copy.deepcopy(decision)
    bad["episodes"] *= 3
    with pytest.raises(ValueError):
        group(r, triage=bad)
    with pytest.raises(ValueError):
        group(r, 10, decision)
    other = replace(
        r, alerts=tuple(replace(a, subject="object-" + "d" * 24) for a in r.alerts)
    )
    with pytest.raises(ValueError):
        group(other, triage=decision)
    template = {
        "review_sha256": base["review_sha256"],
        "episodes": [
            {"episode_id": episode, "disposition": "unreviewed", "reason": ""}
        ],
    }
    assert len(group(r, triage=template)["unreviewed_episode_ids"]) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "fields",
        "alias",
        "priority",
        "future",
        "duplicate",
        "gap",
        "counts",
        "coverage",
    ],
)
def test_saved_review_contract(mutation):
    """Private normalized inputs must retain their exact count, coverage, pseudonym and alert-field contracts."""
    value = json.loads(json.dumps(fixture().to_dict()))
    if mutation == "schema":
        value["schema"] = True
    if mutation == "fields":
        value["alerts"][0]["raw_output"] = "do not retain"
    if mutation == "alias":
        value["alerts"][0]["namespace"] = "private raw name"
    if mutation == "priority":
        value["alerts"][0]["priority"] = "invented"
    if mutation == "future":
        value["alerts"][0]["time"] = "2027-01-01T00:00:00Z"
    if mutation == "duplicate":
        value["alerts"].append(copy.deepcopy(value["alerts"][0]))
    if mutation == "gap":
        value["gaps"] = [{"source": "not-supported", "reason": "x"}]
    if mutation == "counts":
        value["received"] = 4
    if mutation == "coverage":
        value["complete"] = False
    with pytest.raises(ValueError):
        restore(value)


def test_safe_load_publish_and_actual_cli(tmp_path: Path):
    """Real saved-review command remains private/inert, preserves original files and has review/clean/error exit semantics."""
    p = tmp_path / "saved.json"
    p.write_text(json.dumps(fixture().to_dict()), encoding="utf-8")
    out = tmp_path / "episodes"
    args = ["episodes", "--review", str(p), "--output", str(out)]
    with patch.object(sys, "argv", args):
        assert main() == 1
    result = json.loads((out / "episodes.json").read_text())
    template = json.loads((out / "triage-template.json").read_text())
    template["episodes"][0].update(
        disposition="false_positive", reason="<script>Fictional reason</script>"
    )
    triage = tmp_path / "triage.json"
    triage.write_text(json.dumps(template))
    with patch.object(
        sys,
        "argv",
        [
            "episodes",
            "--review",
            str(p),
            "--triage",
            str(triage),
            "--output",
            str(tmp_path / "triaged"),
        ],
    ):
        assert main() == 1
    assert "&lt;script&gt;" in (tmp_path / "triaged/episodes.html").read_text(
        encoding="utf-8"
    )
    original = (out / "episodes.json").read_bytes()
    with patch.object(sys, "argv", args):
        assert main() == 2
    assert (out / "episodes.json").read_bytes() == original
    with patch.object(Path, "is_symlink", return_value=True), pytest.raises(ValueError):
        load(p)
    with (
        patch.object(Path, "is_junction", return_value=True),
        pytest.raises(ValueError),
    ):
        publish(result, tmp_path / "linked")
    p.write_bytes(b"x" * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValueError):
        load(p)
    p.write_bytes(b'{"a":1,"a":2}')
    with pytest.raises(ValueError):
        load(p)
    clean = replace(fixture(), received=0, unique=0, duplicates=0, alerts=())
    p.write_text(json.dumps(clean.to_dict()))
    with patch.object(
        sys,
        "argv",
        ["episodes", "--review", str(p), "--output", str(tmp_path / "clean")],
    ):
        assert main() == 0
    for seconds in (0, True, 301):
        with pytest.raises(ValueError):
            group(clean, seconds)


def test_omitted_unknown_rule_gap_rejects():
    """Editing a saved unknown rule cannot manufacture declared complete continuity."""
    unknown = replace(
        fixture(),
        alerts=tuple(replace(a, rule="Unknown lab rule") for a in fixture().alerts),
    )
    with pytest.raises(ValueError, match="unknown-rule"):
        restore(unknown.to_dict())
    observed = replace(
        unknown, complete=False, gaps=(Gap("k8s_audit", "unrecognized-rule-source"),)
    )
    assert len(group(observed)["episodes"]) == 4
