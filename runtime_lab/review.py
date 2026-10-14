"""Jason Stys: deterministic alert deduplication, explicit coverage gaps and stable source/rule triage."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Gap — line 45
# variable: source — line 48
# variable: reason — line 49
# definition: Review — line 53
# variable: as_of — line 56
# variable: received — line 57
# variable: unique — line 58
# variable: duplicates — line 59
# variable: complete — line 60
# variable: alerts — line 61
# variable: gaps — line 62
# definition: to_dict — line 64
# parameter: self — line 64
# variable: item — line 66
# variable: rows — line 66
# definition: review — line 76
# parameter: alerts — line 77
# parameter: as_of — line 77
# parameter: health — line 77
# parameter: policy — line 77
# variable: gaps — line 82
# variable: item — line 83
# variable: observed — line 83
# variable: origin — line 84
# variable: observation — line 85
# variable: seen — line 99
# variable: item — line 100
# variable: identity — line 107
# variable: previous — line 108
# variable: unique — line 121
# parameter: item — line 124
# END CODE MAP

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from runtime_lab.contracts import CATALOG, Alert, Health, Policy


@dataclass(frozen=True, order=True)
class Gap:
    """One named scope/clock/telemetry problem; no alert absence is interpreted as proof of safety."""

    source: str
    reason: str


@dataclass(frozen=True)
class Review:
    """One pseudonymized review with explicit raw/unique counts, coverage state and no enforcement decisions."""

    as_of: str
    received: int
    unique: int
    duplicates: int
    complete: bool
    alerts: tuple[Alert, ...]
    gaps: tuple[Gap, ...]

    def to_dict(self) -> dict[str, object]:
        """Return JSON-safe UTC evidence and stable author/interpretation attribution."""
        rows = [{**asdict(item), "time": item.time.isoformat()} for item in self.alerts]
        return {
            **asdict(self),
            "alerts": rows,
            "schema": 1,
            "author": "Jason Stys",
            "interpretation": "detection evidence, not proof of compromise or safety",
        }


def review(
    alerts: list[Alert], health: tuple[Health, ...], policy: Policy, as_of: datetime
) -> Review:
    """Use O(N) hash dedup plus deterministic sort; conflicting identities fail rather than silently overwrite."""
    if as_of.tzinfo is None:
        raise ValueError("reference time must carry timezone")
    gaps: set[Gap] = set()
    observed = {item.source: item for item in health}
    for origin in policy.sources:
        observation = observed.get(origin)
        if observation is None:
            gaps.add(Gap(origin, "source-missing"))
            continue
        if observation.last_seen > as_of:
            raise ValueError("sensor clock after reference")
        if (as_of - observation.last_seen).total_seconds() > policy.max_age_seconds:
            gaps.add(Gap(origin, "source-stale"))
        if not observation.complete:
            gaps.add(Gap(origin, "capture-incomplete"))
        if observation.dropped:
            gaps.add(Gap(origin, "events-dropped"))
        if observation.received == 0:
            gaps.add(Gap(origin, "source-empty"))
    seen: dict[tuple[str, str, str], Alert] = {}
    for item in alerts:
        if item.time > as_of:
            raise ValueError("alert clock after reference")
        if item.source not in policy.sources:
            gaps.add(Gap(item.source, "outside-configured-scope"))
        if CATALOG.get(item.rule) != item.source:
            gaps.add(Gap(item.source, "unrecognized-rule-source"))
        identity = (item.source, item.event, item.rule)
        previous = seen.get(identity)
        if previous is not None:
            if (previous.priority, previous.namespace, previous.subject) != (
                item.priority,
                item.namespace,
                item.subject,
            ):
                raise ValueError("conflicting duplicate identity")
            # ResponseStarted/ResponseComplete can produce duplicate rule evidence; retain earliest observed time.
            if item.time < previous.time:
                seen[identity] = item
        else:
            seen[identity] = item
    unique = tuple(
        sorted(
            seen.values(),
            key=lambda item: (item.time, item.source, item.event, item.rule),
        )
    )
    return Review(
        as_of.isoformat(),
        len(alerts),
        len(unique),
        len(alerts) - len(unique),
        not gaps,
        unique,
        tuple(sorted(gaps)),
    )
