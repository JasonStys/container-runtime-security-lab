"""Real offline Falco evidence, coverage-aware episodes and reasoned local triage for the desktop. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 108
# variable: PRODUCT — line 109
# variable: PROFILE — line 109
# variable: TITLE — line 110
# variable: VERSION — line 110
# variable: COLUMNS — line 111
# variable: RESOURCES — line 117
# variable: RESOURCE_LIMITS — line 130
# variable: MODES — line 131
# variable: REVIEW_MODE — line 136
# variable: CHOICES — line 137
# variable: FIELDS — line 146
# variable: ACTIVE_FIELDS — line 164
# variable: SCENARIOS — line 169
# variable: HELP — line 179
# definition: scenario — line 185
# parameter: name — line 185
# variable: index — line 189
# variable: _kind — line 190
# variable: _label — line 190
# variable: key — line 190
# variable: result — line 190
# definition: integer — line 226
# parameter: maximum — line 226
# parameter: value — line 226
# definition: records — line 233
# parameter: raw — line 233
# variable: result — line 237
# variable: line — line 238
# definition: saved_review — line 248
# parameter: parameters — line 249
# parameter: state — line 249
# variable: selected — line 256
# variable: files — line 257
# definition: analyze — line 261
# parameter: parameters — line 262
# parameter: stage — line 262
# parameter: state — line 262
# variable: mode — line 265
# variable: output — line 266
# variable: alerts — line 268
# variable: health — line 269
# variable: policy — line 270
# variable: effective — line 271
# variable: key — line 278
# variable: result — line 279
# variable: item — line 280
# variable: files — line 286
# variable: path — line 287
# variable: scope — line 289
# variable: source_parameters — line 317
# variable: original — line 320
# variable: previous — line 320
# variable: gap — line 321
# variable: triage — line 322
# variable: baseline — line 328
# variable: prior — line 330
# variable: entries — line 336
# variable: row — line 342
# variable: entries — line 345
# variable: selected — line 346
# variable: entries — line 347
# variable: row — line 347
# variable: triage — line 355
# variable: grouped — line 356
# variable: files — line 358
# variable: path — line 358
# definition: views — line 384
# parameter: files — line 384
# variable: original — line 386
# variable: result — line 387
# variable: row — line 389
# variable: row — line 391
# variable: grouped — line 407
# variable: result — line 408
# variable: row — line 411
# definition: cells — line 418
# parameter: row — line 418
# END CODE MAP

from __future__ import annotations

import hashlib
import secrets
import sys
from pathlib import Path
from typing import Any

from .contracts import (
    MAX_BYTES,
    MAX_EVENTS,
    MAX_LINE,
    clock,
    decode,
    parse_alert,
    parse_health,
    parse_policy,
)
from .desktop_io import Rejected, canonical, json_value
from .desktop_state import Workspace
from .episodes import group, publish, restore
from .evidence import write_bundle
from .inputs import read_source
from .review import Review, review

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "container-runtime-security-lab", "ContainerRuntimeSecurityLab"
TITLE, VERSION = "Container Runtime Security Workbench", "1.1.0"
COLUMNS = (
    "UTC / episode",
    "Rule / source",
    "Evidence / continuity",
    "Disposition / coverage",
)
RESOURCES = (
    "examples/alerts.jsonl",
    "examples/health.json",
    "examples/policy.json",
    "examples/desktop/episode-alerts.jsonl",
    "examples/desktop/health-current.json",
    "examples/desktop/health-drops.json",
    "examples/desktop/empty-alerts.jsonl",
    "sql/evidence.sql",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
RESOURCE_LIMITS: dict[str, int] = {}
MODES = (
    "Review authorized Falco JSONL and source health",
    "Group exact saved review into episodes",
    "Record selected episode disposition",
)
REVIEW_MODE = "episode-disposition"
CHOICES = {
    "disposition": (
        "investigate",
        "expected_activity",
        "false_positive",
        "needs_context",
        "unreviewed",
    )
}
FIELDS = (
    ("alerts", "Authorized Falco JSONL (raw input is not retained)", "file"),
    ("health", "Authorized source-health observations JSON", "file"),
    ("policy", "Expected source/freshness policy JSON", "file"),
    ("clock", "Explicit UTC as-of, such as 2026-10-14T00:00:30Z", "text"),
    ("max_age_seconds", "Freshness override seconds (blank preserves policy)", "text"),
    ("saved_run", "Exact local saved analysis number (or choose file below)", "text"),
    (
        "saved_review",
        "External normalized review JSON (blank uses saved number)",
        "file",
    ),
    ("gap_seconds", "Episode gap 1–300 seconds; same-review grouping only", "text"),
    ("triage", "Optional exact-review triage JSON (grouping operation)", "file"),
    ("episode_id", "Exact selected episode ID", "text"),
    ("disposition", "Local analyst assertion; never suppresses detection", "choice"),
    ("reason", "Reason for disposition, 5–500 characters", "text"),
)
ACTIVE_FIELDS = {
    MODES[0]: ("alerts", "health", "policy", "clock", "max_age_seconds"),
    MODES[1]: ("saved_run", "saved_review", "gap_seconds", "triage"),
    MODES[2]: ("saved_run", "gap_seconds", "episode_id", "disposition", "reason"),
}
SCENARIOS = (
    "Three fictional alerts with current source health",
    "Same alerts with explicitly stale sources",
    "Repeated-object episode input and duplicate",
    "Same episode input with declared source drops",
    "No alerts with declared coverage (not proof of safety)",
    "Group saved repeated-object review with 30-second gaps",
    "Group saved gapped-source review without merging",
    "Split saved repeated objects with five-second gaps",
)
HELP = """Review authorized local Falco JSONL, source-health assertions and a policy with an explicit as-of clock using this project's original normalization, pseudonymization and coverage engine. No Docker, driver, Falco binary, live container, cluster, host capture, network request or enforcement is started by the GUI. It reviews supplied observations; the original actual Falco/kernel CI lanes remain separate.
Each raw review uses a new in-memory HMAC key. Raw actor/command/output/namespace/object values, raw input bytes and the privacy key are not saved; normalized pseudonymized evidence and source/policy hashes are retained. Independent re-ingestion intentionally changes aliases. Use the exact saved normalized review for episodes and triage, not a new ingestion. Sources marked stale/incomplete/dropped cannot establish continuity. A gap may prevent grouping even when two times are close.
Choose a saved analysis number or external normalized review, set the episode gap and inspect Episodes. Review selected episode fills the exact saved number, gap and episode ID into ordinary disposition controls; supply a reason and Run to create a NEW immutable analysis. Existing reasons carry forward only for the same saved review and gap. A changed gap, unknown ID, mismatched triage hash or blank reason rejects. A false-positive assertion does not remove an alert or clear a coverage gap. Dispositions are local assertions, not authenticated identities or adjudicated truth.
Prepared cases are optional inputs in this same application. Grouping examples leave the saved selection blank deliberately: open the exact wanted analysis, use Group this exact saved review, or enter its visible history number/choose an external normalized file. No old run is guessed from its position. Search/filter, inspect complete details, export exact private bundles and reopen saved history. Status zero/no alerts never proves safety; normal owner-local files are plaintext and sensitive. Exit waits for owned analysis and storage cleanup."""


def scenario(name: str) -> dict[str, str]:
    """Populate editable controls with explicit fictional files and visible saved-review dependencies."""
    if name not in SCENARIOS:
        raise Rejected("unknown prepared review")
    index = SCENARIOS.index(name)
    result = {key: "" for key, _label, _kind in FIELDS}
    result.update(
        mode=MODES[0],
        alerts=str(ROOT / "examples/alerts.jsonl"),
        health=str(ROOT / "examples/health.json"),
        policy=str(ROOT / "examples/policy.json"),
        clock="2026-10-14T00:00:00Z",
        gap_seconds="30",
        disposition="investigate",
    )
    if index == 1:
        result["clock"] = "2026-10-14T00:03:00Z"
    if index in (2, 3):
        result.update(
            alerts=str(ROOT / "examples/desktop/episode-alerts.jsonl"),
            health=str(
                ROOT
                / (
                    "examples/desktop/health-drops.json"
                    if index == 3
                    else "examples/desktop/health-current.json"
                )
            ),
            clock="2026-10-14T00:00:30Z",
        )
    if index == 4:
        result["alerts"] = str(ROOT / "examples/desktop/empty-alerts.jsonl")
    if index >= 5:
        result.update(
            mode=MODES[1],
            saved_run="",
            gap_seconds="5" if index == 7 else "30",
        )
    return result


def integer(value: str, maximum: int) -> int:
    """Reject non-ASCII, missing or out-of-bounds operator numbers before core execution."""
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= maximum:
        raise Rejected("bounded positive setting required")
    return int(value)


def records(raw: bytes) -> list[object]:
    """Apply the original strict JSON decoder and all original line/event/total bounds to stable bytes."""
    if len(raw) > MAX_BYTES:
        raise Rejected("alert stream byte cap")
    result = []
    for line in raw.splitlines(keepends=True):
        if len(line) > MAX_LINE:
            raise Rejected("alert line byte cap")
        if line.strip():
            result.append(decode(line))
            if len(result) > MAX_EVENTS:
                raise Rejected("alert event cap")
    return result


def saved_review(
    state: Workspace, parameters: dict[str, str]
) -> tuple[Review, dict[str, bytes]]:
    """Select one explicit normalized snapshot; never re-ingest raw alerts or infer a latest matching run."""
    if parameters.get("saved_review", "").strip():
        return restore(
            json_value(read_source(Path(parameters["saved_review"]), 8 * 1024**2))
        ), {}
    selected = integer(parameters.get("saved_run", "").strip(), 2**63 - 1)
    files = state.files(selected)
    return restore(json_value(files["review.json"])), files


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Use actual review/group/publish contracts; triage cannot rewrite original counts or coverage."""
    mode = parameters.get("mode")
    output = stage / "runtime-evidence"
    if mode == MODES[0]:
        alerts = read_source(Path(parameters["alerts"]), MAX_BYTES)
        health = read_source(Path(parameters["health"]), MAX_LINE)
        policy = read_source(Path(parameters["policy"]), MAX_LINE)
        effective = json_value(policy)
        if parameters.get("max_age_seconds", "").strip():
            if not isinstance(effective, dict):
                raise Rejected("policy object required")
            effective["max_age_seconds"] = integer(
                parameters["max_age_seconds"].strip(), 86400
            )
        key = secrets.token_bytes(32)
        result = review(
            [parse_alert(item, key) for item in records(alerts)],
            parse_health(json_value(health)),
            parse_policy(effective),
            clock(parameters["clock"].strip()),
        )
        write_bundle(result, output)
        files = {
            path.name: read_source(path, 32 * 1024**2) for path in output.iterdir()
        }
        scope = {
            "schema": 1,
            "kind": "supplied-observation-review",
            "input_sha256": {
                "alerts": hashlib.sha256(alerts).hexdigest(),
                "health": hashlib.sha256(health).hexdigest(),
                "original_policy": hashlib.sha256(policy).hexdigest(),
                "effective_policy": hashlib.sha256(canonical(effective)).hexdigest(),
            },
            "scope": "New per-review HMAC key is never persisted; raw input and original identities are not exported. Supplied source health is not authenticated sensor identity.",
        }
        files["input-scope.json"] = canonical(scope)
        files["source-context.json"] = canonical(
            {
                "schema": 1,
                "as_of": result.as_of,
                "effective_policy": effective,
                "health_declarations": json_value(health),
                "scope": "Validated operator declarations, not authenticated sensor evidence. Original raw alert identities are not retained.",
            }
        )
        return (
            "private-runtime-review",
            f"{result.unique} unique alerts / {result.duplicates} duplicates; {len(result.gaps)} source gaps; supplied observations, no live capture",
            files,
        )
    if mode not in MODES[1:]:
        raise Rejected("unsupported runtime review operation")
    source_parameters = (
        {**parameters, "saved_review": ""} if mode == MODES[2] else parameters
    )
    original, previous = saved_review(state, source_parameters)
    gap = integer(parameters.get("gap_seconds", "").strip(), 300)
    triage = (
        json_value(read_source(Path(parameters["triage"]), 8 * 1024**2))
        if mode == MODES[1] and parameters.get("triage", "").strip()
        else None
    )
    if mode == MODES[2]:
        baseline = group(original, gap)
        if "episodes.json" in previous:
            prior = json_value(previous["episodes.json"])
            if (
                prior["gap_seconds"] != gap
                or prior["review_sha256"] != baseline["review_sha256"]
            ):
                raise Rejected("saved episode grouping changed")
            entries = [
                {
                    "episode_id": row["id"],
                    "disposition": row["disposition"],
                    "reason": row["reason"],
                }
                for row in prior["episodes"]
            ]
        else:
            entries = []
        selected = parameters.get("episode_id", "").strip()
        entries = [row for row in entries if row["episode_id"] != selected]
        entries.append(
            {
                "episode_id": selected,
                "disposition": parameters.get("disposition", ""),
                "reason": parameters.get("reason", ""),
            }
        )
        triage = {"review_sha256": baseline["review_sha256"], "episodes": entries}
    grouped = group(original, gap, triage)
    publish(grouped, output)
    files = {path.name: read_source(path, 32 * 1024**2) for path in output.iterdir()}
    files["review.json"] = canonical(original.to_dict())
    files["source-context.json"] = previous.get(
        "source-context.json",
        canonical(
            {
                "schema": 1,
                "state": "UNAVAILABLE_EXTERNAL_NORMALIZED_REVIEW",
                "scope": "No source-health/policy declarations are reconstructed from absent external provenance.",
            }
        ),
    )
    files["input-scope.json"] = canonical(
        {
            "schema": 1,
            "review_sha256": grouped["review_sha256"],
            "scope": "Exact normalized snapshot and original alert/gap denominator retained. Local dispositions are assertions, never suppression or live enforcement.",
        }
    )
    return (
        "coverage-aware-episode-review",
        f"{len(grouped['episodes'])} episodes / {len(grouped['unreviewed_episode_ids'])} unreviewed; original {original.unique} alerts / {len(original.gaps)} gaps unchanged",
        files,
    )


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Make original alert, health and episode denominators visible together; no clean result is manufactured."""
    original: dict[str, Any] = restore(json_value(files["review.json"])).to_dict()
    result = {
        "Original normalized alerts": [
            {"kind": "alert", **row} for row in original["alerts"]
        ],
        "Source coverage gaps": [{"kind": "gap", **row} for row in original["gaps"]],
        "Whole review and privacy scope": [
            {
                "kind": "scope",
                "as_of": original["as_of"],
                "received": original["received"],
                "unique": original["unique"],
                "duplicates": original["duplicates"],
                "complete": original["complete"],
                "interpretation": original["interpretation"],
                "input_scope": json_value(files["input-scope.json"]),
                "source_context": json_value(files["source-context.json"]),
            }
        ],
    }
    if "episodes.json" in files:
        grouped = json_value(files["episodes.json"])
        result = {
            "Coverage-aware episodes": [
                {"kind": "episode", **row, "gap_seconds": grouped["gap_seconds"]}
                for row in grouped["episodes"]
            ],
            **result,
        }
    return result


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Render compact literal facts while complete normalized records remain selectable and exportable."""
    if row["kind"] == "alert":
        return (
            str(row["time"]),
            str(row["rule"]),
            str(row["source"]),
            str(row["priority"]),
        )
    if row["kind"] == "gap":
        return (
            "source gap",
            str(row["source"]),
            str(row["reason"]),
            "coverage incomplete",
        )
    if row["kind"] == "episode":
        return (
            str(row["start"]),
            str(row["rule"]),
            f"{len(row['event_ids'])} alerts / {row['continuity']}",
            str(row["disposition"]),
        )
    return (
        str(row["as_of"]),
        f"{row['unique']} unique / {row['duplicates']} duplicate",
        "declared complete" if row["complete"] else "coverage incomplete",
        "not proof of compromise or safety",
    )
