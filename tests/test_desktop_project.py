"""Actual privacy/coverage/episode/triage adapter scenarios with independent counts and refusal oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: workspace — line 135
# parameter: tmp_path — line 135
# variable: state — line 137
# definition: execute — line 144
# parameter: changes — line 144
# parameter: index — line 144
# parameter: save — line 144
# parameter: state — line 144
# parameter: tmp_path — line 144
# variable: values — line 146
# variable: stage — line 148
# variable: files — line 150
# variable: kind — line 150
# variable: summary — line 150
# variable: identity — line 151
# definition: test_raw_review_uses_actual_privacy_and_independent_denominators — line 159
# parameter: duplicates — line 160
# parameter: gaps — line 160
# parameter: index — line 160
# parameter: tmp_path — line 160
# parameter: unique — line 160
# parameter: workspace — line 160
# variable: _identity — line 163
# variable: files — line 163
# variable: summary — line 163
# variable: result — line 164
# variable: word — line 174
# variable: name — line 181
# variable: rows — line 182
# variable: row — line 183
# definition: test_reingestion_pseudonyms_change_but_saved_snapshot_stays_exact — line 187
# parameter: tmp_path — line 188
# parameter: workspace — line 188
# variable: _summary — line 191
# variable: one — line 191
# variable: original — line 191
# variable: _other — line 192
# variable: _summary — line 192
# variable: changed — line 192
# definition: test_explicit_freshness_override_changes_only_the_declared_assumption — line 206
# parameter: tmp_path — line 207
# parameter: workspace — line 207
# variable: original — line 210
# variable: _id — line 211
# variable: _summary — line 211
# variable: files — line 211
# variable: result — line 212
# variable: context — line 213
# definition: test_episode_continuity_and_reasoned_cumulative_triage — line 220
# parameter: tmp_path — line 220
# parameter: workspace — line 220
# variable: _summary — line 222
# variable: continuous — line 222
# variable: original — line 222
# variable: _files — line 223
# variable: _summary — line 223
# variable: gapped — line 223
# variable: _summary — line 224
# variable: files — line 224
# variable: grouped — line 224
# variable: result — line 227
# variable: row — line 229
# variable: _id — line 231
# variable: _summary — line 231
# variable: source_gaps — line 231
# variable: _id — line 235
# variable: _summary — line 235
# variable: small_gap — line 235
# variable: selected — line 239
# variable: _summary — line 240
# variable: first — line 240
# variable: triaged — line 240
# variable: one — line 253
# variable: _id — line 257
# variable: _summary — line 257
# variable: second — line 257
# variable: two — line 269
# variable: row — line 270
# definition: test_external_saved_review_and_strict_triage_hash — line 280
# parameter: tmp_path — line 280
# parameter: workspace — line 280
# variable: _id — line 282
# variable: _summary — line 282
# variable: files — line 282
# variable: supplied — line 283
# variable: _id — line 285
# variable: _summary — line 285
# variable: grouped — line 285
# variable: triage — line 291
# definition: test_bad_operation_clock_or_policy_cannot_save_clean_result — line 312
# parameter: change — line 313
# parameter: tmp_path — line 313
# parameter: workspace — line 313
# definition: test_ambiguous_changed_or_incomplete_triage_refuses — line 321
# parameter: tmp_path — line 321
# parameter: workspace — line 321
# variable: _files — line 323
# variable: _summary — line 323
# variable: selected — line 323
# variable: _summary — line 324
# variable: files — line 324
# variable: grouped — line 324
# variable: episode — line 327
# variable: base — line 328
# variable: changed — line 335
# definition: test_inactive_external_field_never_retargets_local_episode — line 346
# parameter: tmp_path — line 346
# parameter: workspace — line 346
# variable: _files — line 348
# variable: _summary — line 348
# variable: selected — line 348
# variable: _summary — line 349
# variable: files — line 349
# variable: grouped — line 349
# variable: episode — line 352
# variable: _id — line 353
# variable: _summary — line 353
# variable: changed — line 353
# definition: test_jsonl_byte_line_record_and_decoder_caps — line 371
# variable: raw — line 374
# END CODE MAP

import json

import pytest

from runtime_lab import desktop_project as project
from runtime_lab.desktop_io import Rejected
from runtime_lab.desktop_state import Workspace


@pytest.fixture
def workspace(tmp_path):
    """Keep all synthetic evidence in one exclusively owned temporary local profile."""
    state = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    try:
        yield state
    finally:
        state.close()


def execute(state, tmp_path, index, changes=None, save=False):
    """Call original normalization/episode cores and optionally commit a real immutable history bundle."""
    values = project.scenario(project.SCENARIOS[index])
    values.update(changes or {})
    stage = tmp_path / ("analysis-" + str(len(list(tmp_path.glob("analysis-*")))))
    stage.mkdir()
    kind, summary, files = project.analyze(state, values, stage)
    identity = state.save(kind, summary, values, files) if save else None
    return identity, summary, files


@pytest.mark.parametrize(
    "index,unique,duplicates,gaps",
    [(0, 3, 0, 0), (1, 3, 0, 2), (2, 5, 1, 0), (3, 5, 1, 2), (4, 0, 0, 0)],
)
def test_raw_review_uses_actual_privacy_and_independent_denominators(
    workspace, tmp_path, index, unique, duplicates, gaps
):
    """Raw data is processed by the original engine, not stored or mislabeled live evidence."""
    _identity, summary, files = execute(workspace, tmp_path, index)
    result = json.loads(files["review.json"])
    assert (result["unique"], result["duplicates"], len(result["gaps"])) == (
        unique,
        duplicates,
        gaps,
    )
    assert result["complete"] is (gaps == 0)
    assert "no live capture" in summary
    assert not any(
        word in b"".join(files.values())
        for word in [
            b"synthetic-workload",
            b"synthetic-container-1",
            b"fake-secret",
            b"/tmp/crsl-sensitive-marker",
        ]
    )
    assert all(not name.endswith(".jsonl") for name in files)
    for rows in project.views(files).values():
        for row in rows:
            assert len(project.cells(row)) == 4


def test_reingestion_pseudonyms_change_but_saved_snapshot_stays_exact(
    workspace, tmp_path
):
    """New raw review keys never persist or silently link independent reviews."""
    one, _summary, original = execute(workspace, tmp_path, 0, save=True)
    _other, _summary, changed = execute(workspace, tmp_path, 0)
    assert (
        json.loads(original["review.json"])["alerts"]
        != json.loads(changed["review.json"])["alerts"]
    )
    assert workspace.files(one) == original
    assert set(json.loads(original["input-scope.json"])["input_sha256"]) == {
        "alerts",
        "health",
        "original_policy",
        "effective_policy",
    }


def test_explicit_freshness_override_changes_only_the_declared_assumption(
    workspace, tmp_path
):
    """An explicit200-second threshold admits180-second health, keeps all3alerts and records the effective policy."""
    original = (project.ROOT / "examples/policy.json").read_bytes()
    _id, _summary, files = execute(workspace, tmp_path, 1, {"max_age_seconds": "200"})
    result = json.loads(files["review.json"])
    context = json.loads(files["source-context.json"])
    assert result["unique"] == 3 and result["gaps"] == []
    assert context["effective_policy"]["max_age_seconds"] == 200
    assert context["health_declarations"][0]["last_seen"] == "2026-10-14T00:00:00Z"
    assert (project.ROOT / "examples/policy.json").read_bytes() == original


def test_episode_continuity_and_reasoned_cumulative_triage(workspace, tmp_path):
    """Continuous repeated objects group3-to1; source drops block it, and a disposition cannot suppress original alerts."""
    continuous, _summary, original = execute(workspace, tmp_path, 2, save=True)
    gapped, _summary, _files = execute(workspace, tmp_path, 3, save=True)
    grouped, _summary, files = execute(
        workspace, tmp_path, 5, {"saved_run": str(continuous)}, save=True
    )
    result = json.loads(files["episodes.json"])
    assert len(result["episodes"]) == 3
    assert sorted(len(row["event_ids"]) for row in result["episodes"]) == [1, 1, 3]
    assert result["original_review"] == json.loads(original["review.json"])
    _id, _summary, source_gaps = execute(
        workspace, tmp_path, 6, {"saved_run": str(gapped)}
    )
    assert len(json.loads(source_gaps["episodes.json"])["episodes"]) == 5
    _id, _summary, small_gap = execute(
        workspace, tmp_path, 7, {"saved_run": str(continuous)}
    )
    assert len(json.loads(small_gap["episodes.json"])["episodes"]) == 5
    selected = result["episodes"][0]["id"]
    triaged, _summary, first = execute(
        workspace,
        tmp_path,
        5,
        {
            "mode": project.MODES[2],
            "saved_run": str(grouped),
            "episode_id": selected,
            "disposition": "expected_activity",
            "reason": "Authorized synthetic maintenance requires owner confirmation",
        },
        save=True,
    )
    one = json.loads(first["episodes.json"])
    assert one["original_review"] == result["original_review"]
    assert len(one["unreviewed_episode_ids"]) == 2
    assert one["episodes"][0]["disposition"] == "expected_activity"
    _id, _summary, second = execute(
        workspace,
        tmp_path,
        5,
        {
            "mode": project.MODES[2],
            "saved_run": str(triaged),
            "episode_id": result["episodes"][1]["id"],
            "disposition": "needs_context",
            "reason": "Review against the approved change record",
        },
    )
    two = json.loads(second["episodes.json"])
    assert [row["disposition"] for row in two["episodes"]][:2] == [
        "expected_activity",
        "needs_context",
    ]
    assert (
        two["original_review"]["unique"] == 5
        and len(two["unreviewed_episode_ids"]) == 1
    )


def test_external_saved_review_and_strict_triage_hash(workspace, tmp_path):
    """A supported normalized file is accepted; wrong imported triage binding cannot change it."""
    _id, _summary, files = execute(workspace, tmp_path, 0)
    supplied = tmp_path / "normalized.json"
    supplied.write_bytes(files["review.json"])
    _id, _summary, grouped = execute(
        workspace, tmp_path, 5, {"saved_run": "", "saved_review": str(supplied)}
    )
    assert json.loads(grouped["episodes.json"])["original_review"] == json.loads(
        files["review.json"]
    )
    triage = tmp_path / "wrong-triage.json"
    triage.write_text('{"review_sha256":"' + "0" * 64 + '","episodes":[]}')
    with pytest.raises(ValueError, match="triage review binding"):
        execute(
            workspace,
            tmp_path,
            5,
            {"saved_review": str(supplied), "triage": str(triage)},
        )


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "live capture"},
        {"clock": "invalid"},
        {"max_age_seconds": "0"},
        {"max_age_seconds": "86401"},
        {"max_age_seconds": "１２"},
    ],
)
def test_bad_operation_clock_or_policy_cannot_save_clean_result(
    workspace, tmp_path, change
):
    """Invalid source settings remain errors rather than successful empty observations."""
    with pytest.raises((Rejected, ValueError)):
        execute(workspace, tmp_path, 0, change)
    assert not workspace.history()


def test_ambiguous_changed_or_incomplete_triage_refuses(workspace, tmp_path):
    """Unknown episode/blank reason/changed gap and nonlocal disposition sources do not reuse an approval."""
    selected, _summary, _files = execute(workspace, tmp_path, 0, save=True)
    grouped, _summary, files = execute(
        workspace, tmp_path, 5, {"saved_run": str(selected)}, save=True
    )
    episode = json.loads(files["episodes.json"])["episodes"][0]["id"]
    base = {
        "mode": project.MODES[2],
        "saved_run": str(grouped),
        "episode_id": episode,
        "disposition": "investigate",
        "reason": "Check approved source evidence",
    }
    for changed in [
        {"episode_id": "0" * 64},
        {"reason": " "},
        {"gap_seconds": "5"},
        {"saved_run": "", "saved_review": "not-local"},
    ]:
        with pytest.raises((ValueError, Rejected, OSError)):
            execute(workspace, tmp_path, 5, {**base, **changed})
    assert len(workspace.history()) == 2


def test_inactive_external_field_never_retargets_local_episode(workspace, tmp_path):
    """A stale hidden file choice cannot override the explicitly selected local run during disposition."""
    selected, _summary, _files = execute(workspace, tmp_path, 0, save=True)
    grouped, _summary, files = execute(
        workspace, tmp_path, 5, {"saved_run": str(selected)}, save=True
    )
    episode = json.loads(files["episodes.json"])["episodes"][0]["id"]
    _id, _summary, changed = execute(
        workspace,
        tmp_path,
        5,
        {
            "mode": project.MODES[2],
            "saved_run": str(grouped),
            "saved_review": "this-inactive-path-does-not-exist",
            "episode_id": episode,
            "disposition": "investigate",
            "reason": "Inspect original authorized change evidence",
        },
    )
    assert json.loads(changed["episodes.json"])["original_review"] == json.loads(
        files["review.json"]
    )


def test_jsonl_byte_line_record_and_decoder_caps():
    """Limits reject invalid input without dropping oversized/malformed records."""
    assert project.records(b"\n \n") == []
    for raw in [
        b"x" * (project.MAX_BYTES + 1),
        b"x" * (project.MAX_LINE + 1),
        b"{}\n" * (project.MAX_EVENTS + 1),
        b'{"a":1,"a":2}\n',
        b'{"a":NaN}\n',
    ]:
        with pytest.raises(ValueError):
            project.records(raw)
    with pytest.raises(Rejected):
        project.scenario("unknown")
