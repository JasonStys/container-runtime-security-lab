"""Jason Stys: coverage-aware saved-review episodes and reasoned analyst dispositions without altering detections."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: load — line 106
# parameter: path — line 106
# variable: p — line 111
# variable: stream — line 116
# variable: raw — line 117
# definition: restore — line 125
# parameter: value — line 125
# variable: data — line 127
# variable: at — line 154
# variable: alerts — line 155
# variable: seen — line 156
# variable: item — line 157
# variable: row — line 158
# variable: key — line 162
# variable: prefix — line 162
# variable: priority — line 171
# variable: instant — line 172
# variable: alert — line 175
# variable: identity — line 184
# variable: gaps — line 189
# variable: item — line 190
# variable: row — line 191
# variable: alert — line 196
# variable: duplicates — line 199
# variable: received — line 199
# variable: unique — line 199
# variable: name — line 200
# parameter: a — line 215
# definition: group — line 220
# parameter: gap_seconds — line 221
# parameter: review — line 221
# parameter: triage — line 221
# variable: review — line 226
# variable: original — line 227
# variable: fingerprint — line 228
# variable: bad_sources — line 231
# variable: g — line 231
# variable: streams — line 232
# variable: alert — line 233
# variable: episodes — line 234
# variable: rows — line 243
# variable: episodes — line 244
# variable: key — line 244
# variable: members — line 245
# variable: identity — line 246
# variable: m — line 248
# variable: m — line 261
# variable: m — line 262
# variable: index — line 270
# variable: r — line 270
# variable: supplied — line 272
# variable: seen_ids — line 279
# variable: item — line 280
# variable: row — line 281
# variable: name — line 282
# variable: reason — line 297
# variable: r — line 315
# definition: publish — line 321
# parameter: output — line 321
# parameter: result — line 321
# variable: target — line 323
# variable: p — line 324
# variable: text — line 327
# variable: template — line 329
# variable: r — line 333
# variable: rows — line 339
# variable: value — line 343
# variable: row — line 354
# variable: page — line 356
# definition: main — line 366
# variable: parser — line 368
# variable: args — line 375
# variable: result — line 377
# END CODE MAP

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from runtime_lab.contracts import (
    CATALOG,
    MAX_BYTES,
    MAX_EVENTS,
    PRIORITIES,
    Alert,
    clock,
    count,
    fields,
    reject_constant,
    source,
    text,
    unique_pairs,
)
from runtime_lab.review import Gap, Review


def load(path: Path) -> Any:
    """Read bounded duplicate-free JSON data from explicit ordinary nonlinked paths; no code/network execution."""
    if (
        any(
            p.is_symlink() or p.is_junction()
            for p in (path.absolute(), *path.absolute().parents)
        )
        or not path.is_file()
    ):
        raise ValueError("ordinary private input required")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("saved review byte cap")
    return json.loads(
        raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant
    )


def restore(value: object) -> Review:
    """Validate this tool's normalized pseudonym-only saved review; never accept raw Falco fields or invented clean counts."""
    data = fields(
        value,
        {
            "schema",
            "author",
            "interpretation",
            "as_of",
            "received",
            "unique",
            "duplicates",
            "complete",
            "alerts",
            "gaps",
        },
    )
    if (
        type(data["schema"]) is not int
        or data["schema"] != 1
        or data["author"] != "Jason Stys"
        or data["interpretation"]
        != "detection evidence, not proof of compromise or safety"
        or not isinstance(data["alerts"], list)
        or len(data["alerts"]) > MAX_EVENTS
        or not isinstance(data["gaps"], (list, tuple))
        or len(data["gaps"]) > 20
    ):
        raise ValueError("saved review contract")
    at = clock(data["as_of"])
    alerts = []
    seen = set()
    for item in data["alerts"]:
        row = fields(
            item,
            {"event", "source", "rule", "priority", "time", "namespace", "subject"},
        )
        for key, prefix in (
            ("event", "event"),
            ("namespace", "scope"),
            ("subject", "object"),
        ):
            if not isinstance(row[key], str) or not re.fullmatch(
                prefix + r"-[0-9a-f]{24}", row[key]
            ):
                raise ValueError("saved pseudonym contract")
        priority = text(row["priority"], 32)
        instant = clock(row["time"])
        if priority not in PRIORITIES or instant > at:
            raise ValueError("saved alert metadata")
        alert = Alert(
            row["event"],
            source(row["source"]),
            text(row["rule"], 128),
            priority,
            instant,
            row["namespace"],
            row["subject"],
        )
        identity = alert.source, alert.event, alert.rule
        if identity in seen:
            raise ValueError("duplicate saved detection")
        seen.add(identity)
        alerts.append(alert)
    gaps = []
    for item in data["gaps"]:
        row = fields(item, {"source", "reason"})
        gaps.append(Gap(source(row["source"]), text(row["reason"], 80)))
    if any(
        CATALOG.get(alert.rule) != alert.source
        and Gap(alert.source, "unrecognized-rule-source") not in gaps
        for alert in alerts
    ):
        raise ValueError("saved review omitted unknown-rule coverage gap")
    received, unique, duplicates = (
        count(data[name], MAX_EVENTS) for name in ("received", "unique", "duplicates")
    )
    if (
        unique != len(alerts)
        or received != unique + duplicates
        or type(data["complete"]) is not bool
        or data["complete"] != (not gaps)
    ):
        raise ValueError("contradictory saved review counts/coverage")
    return Review(
        at.isoformat(),
        received,
        unique,
        duplicates,
        data["complete"],
        tuple(sorted(alerts, key=lambda a: (a.time, a.source, a.event, a.rule))),
        tuple(sorted(gaps)),
    )


def group(
    review: Review, gap_seconds: int = 30, triage: object | None = None
) -> dict[str, Any]:
    """Cluster only continuous-source same-rule/object observations; source gaps force individual episodes, never bridge loss."""
    if type(gap_seconds) is not int or not 1 <= gap_seconds <= 300:
        raise ValueError("episode gap bounds")
    review = restore(review.to_dict())
    original = review.to_dict()
    fingerprint = hashlib.sha256(
        json.dumps(original, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    bad_sources = {g.source for g in review.gaps}
    streams: dict[tuple[str, str, str, str], list[list[Alert]]] = defaultdict(list)
    for alert in review.alerts:
        episodes = streams[(alert.source, alert.namespace, alert.subject, alert.rule)]
        if (
            alert.source in bad_sources
            or not episodes
            or (alert.time - episodes[-1][-1].time).total_seconds() > gap_seconds
        ):
            episodes.append([alert])
        else:
            episodes[-1].append(alert)
    rows = []
    for key, episodes in sorted(streams.items()):
        for members in episodes:
            identity = hashlib.sha256(
                json.dumps(
                    [fingerprint, gap_seconds, key, [m.event for m in members]],
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            rows.append(
                {
                    "id": identity,
                    "source": key[0],
                    "namespace": key[1],
                    "subject": key[2],
                    "rule": key[3],
                    "start": members[0].time.isoformat(),
                    "end": members[-1].time.isoformat(),
                    "event_ids": [m.event for m in members],
                    "priorities": sorted({m.priority for m in members}),
                    "continuity": "SOURCE_GAP_NO_CONTINUITY_INFERRED"
                    if key[0] in bad_sources
                    else "DECLARED_SOURCE_CONTINUITY",
                    "disposition": "unreviewed",
                    "reason": "",
                }
            )
    index = {r["id"]: r for r in rows}
    if triage is not None:
        supplied = fields(triage, {"review_sha256", "episodes"})
        if (
            supplied["review_sha256"] != fingerprint
            or not isinstance(supplied["episodes"], list)
            or len(supplied["episodes"]) > len(rows)
        ):
            raise ValueError("triage review binding")
        seen_ids = set()
        for item in supplied["episodes"]:
            row = fields(item, {"episode_id", "disposition", "reason"})
            name = row["episode_id"]
            if (
                not isinstance(name, str)
                or name not in index
                or name in seen_ids
                or row["disposition"]
                not in (
                    "unreviewed",
                    "investigate",
                    "expected_activity",
                    "false_positive",
                    "needs_context",
                )
            ):
                raise ValueError("triage episode/disposition")
            reason = (
                ""
                if row["disposition"] == "unreviewed" and row["reason"] == ""
                else text(row["reason"], 500)
            )
            if row["disposition"] != "unreviewed" and len(reason.strip()) < 5:
                raise ValueError("reasoned analyst disposition required")
            seen_ids.add(name)
            index[name].update(disposition=row["disposition"], reason=reason)
    return {
        "schema": 1,
        "author": "Jason Stys",
        "kind": "coverage_aware_episode_review",
        "review_sha256": fingerprint,
        "gap_seconds": gap_seconds,
        "original_review": original,
        "episodes": rows,
        "unreviewed_episode_ids": [
            r["id"] for r in rows if r["disposition"] == "unreviewed"
        ],
        "scope": "Human observation grouping, not incident attribution or suppressed detection. Original alerts, priorities, counts and source gaps remain unchanged. A source gap has no known exact loss interval, so no same-source observations are merged. Dispositions are local analyst assertions requiring reasons, not adjudicated truth. Pseudonyms and episode IDs belong to this exact saved review; no cross-review linkage or privacy key persistence is introduced.",
    }


def publish(result: dict[str, Any], output: Path) -> None:
    """Create new private metadata-only review, blank triage template and escaped inert HTML; preserve old evidence."""
    target = output.absolute()
    if any(p.is_symlink() or p.is_junction() for p in (target, *target.parents)):
        raise ValueError("linked episode output")
    target.mkdir(mode=0o700)
    text = json.dumps(result, sort_keys=True, indent=2)
    (target / "episodes.json").write_text(text + "\n", encoding="utf-8")
    template = {
        "review_sha256": result["review_sha256"],
        "episodes": [
            {"episode_id": r["id"], "disposition": "unreviewed", "reason": ""}
            for r in result["episodes"]
        ],
    }
    (target / "triage-template.json").write_text(
        json.dumps(template, indent=2) + "\n", encoding="utf-8"
    )
    rows = "".join(
        "<tr>"
        + "".join(
            "<td>" + html.escape(str(value)) + "</td>"
            for value in (
                row["rule"],
                row["start"],
                row["end"],
                len(row["event_ids"]),
                row["continuity"],
                row["disposition"],
                row["reason"],
            )
        )
        + "</tr>"
        for row in result["episodes"]
    )
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Runtime episode review — Jason Stys</title><main><h1>Runtime detection episode review</h1><p>Created by Jason Stys. Original findings remain intact; analyst dispositions do not suppress detections.</p><table><caption>Same-review observation episodes and analyst decisions</caption><thead><tr><th scope="col">Rule</th><th scope="col">Start</th><th scope="col">End</th><th scope="col">Alerts</th><th scope="col">Continuity</th><th scope="col">Disposition</th><th scope="col">Reason</th></tr></thead><tbody>'
        + rows
        + "</tbody></table><h2>Review help</h2><p>Use browser Find to locate a rule or disposition. Fill a private copy of triage-template.json and rerun this saved review into a new output directory. Keep original gaps and findings in view; a false-positive assertion never changes the original count.</p><details><summary>Exact evidence, hashes, pseudonyms and coverage boundaries</summary><pre>"
        + html.escape(text)
        + "</pre></details></main></html>"
    )
    (target / "episodes.html").write_text(page, encoding="utf-8")


def main() -> int:
    """Review one saved pseudonymized evidence bundle; never rerun capture or reuse a privacy key."""
    parser = argparse.ArgumentParser(
        description="Jason Stys — private saved runtime episode review"
    )
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--gap-seconds", type=int, default=30)
    parser.add_argument("--triage", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = group(
            restore(load(args.review)),
            args.gap_seconds,
            load(args.triage) if args.triage else None,
        )
        publish(result, args.output)
        print(
            json.dumps(
                {
                    "episodes": len(result["episodes"]),
                    "unreviewed": len(result["unreviewed_episode_ids"]),
                    "original_alerts": result["original_review"]["unique"],
                }
            )
        )
        return 1 if result["episodes"] or result["original_review"]["gaps"] else 0
    except (OSError, ValueError, TypeError, RecursionError):
        print(
            "Saved episode review rejected; check private contracts and new output directory."
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
