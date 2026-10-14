"""Jason Stys: deterministic bounded HMAC/alert-review benchmark, descriptive rather than hardware-dependent CI gate."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 40
# variable: example — line 42
# variable: rows — line 43
# variable: index — line 44
# variable: row — line 45
# variable: policy — line 53
# variable: health — line 54
# variable: as_of — line 55
# variable: key — line 56
# variable: samples — line 57
# variable: _ — line 58
# variable: started — line 59
# variable: result — line 60
# variable: row — line 60
# variable: row — line 63
# variable: _ — line 64
# variable: peak — line 64
# END CODE MAP

import json
import platform
import statistics
import time
import tracemalloc
from pathlib import Path

from runtime_lab.contracts import (
    clock,
    parse_alert,
    parse_health,
    parse_policy,
    read_config,
    read_records,
)
from runtime_lab.review import review


def main() -> None:
    """Measure parsing+pseudonymization+dedup of 1000 synthetic alerts, 15 samples and Python-only allocation peak."""
    example = read_records(Path("examples/alerts.jsonl"))[0]
    rows = []
    for index in range(1000):
        row = {
            **example,
            "output_fields": {
                **example["output_fields"],
                "ka.auditid": f"synthetic-{index}",
            },
        }
        rows.append(row)
    policy = parse_policy(read_config(Path("examples/policy.json")))
    health = parse_health(read_config(Path("examples/health.json")))
    as_of = clock("2026-10-14T00:00:00Z")
    key = b"synthetic-benchmark-key-32-bytes!!"
    samples = []
    for _ in range(15):
        started = time.perf_counter_ns()
        result = review([parse_alert(row, key) for row in rows], health, policy, as_of)
        samples.append((time.perf_counter_ns() - started) / 1e6)
    tracemalloc.start()
    review([parse_alert(row, key) for row in rows], health, policy, as_of)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert result.unique == 1000
    print(
        json.dumps(
            dict(
                author="Jason Stys",
                python=platform.python_version(),
                system=platform.system(),
                events=1000,
                samples=15,
                median_ms=statistics.median(samples),
                min_ms=min(samples),
                max_ms=max(samples),
                python_peak_bytes=peak,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
