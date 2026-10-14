"""Jason Stys: actual Falco rule validation/replay and safe marker-only live container capture on disposable Linux CI."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 77
# variable: FALCO — line 78
# definition: run — line 81
# parameter: args — line 81
# parameter: timeout — line 81
# variable: result — line 83
# definition: json_alerts — line 96
# parameter: text — line 96
# variable: rows — line 98
# variable: line — line 99
# variable: data — line 102
# definition: replay — line 108
# variable: corpus — line 110
# variable: destination — line 111
# variable: stream — line 113
# variable: _ — line 114
# variable: event — line 114
# variable: args — line 116
# variable: started — line 126
# variable: result — line 127
# variable: alerts — line 128
# variable: expected — line 129
# variable: _ — line 130
# variable: event — line 130
# variable: rule — line 130
# variable: rules — line 130
# variable: actual — line 132
# variable: row — line 133
# variable: key — line 139
# variable: row — line 140
# variable: _ — line 161
# variable: name — line 161
# variable: rules — line 161
# definition: live — line 166
# variable: lock — line 173
# variable: image — line 174
# variable: name — line 176
# variable: output — line 177
# variable: stderr_path — line 179
# variable: stdout_path — line 179
# variable: started — line 180
# variable: stderr — line 193
# variable: stdout — line 193
# variable: monitor — line 194
# variable: returncode — line 248
# variable: rows — line 265
# variable: counts — line 266
# variable: row — line 266
# variable: key — line 271
# variable: row — line 272
# variable: fields — line 273
# variable: summary — line 280
# variable: drops — line 281
# variable: value — line 282
# definition: main — line 304
# variable: parser — line 306
# variable: args — line 308
# END CODE MAP

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import time
from collections import Counter
from pathlib import Path

from examples.audit_cases import cases
from runtime_lab.contracts import parse_alert

ROOT = Path(__file__).resolve().parents[1]
FALCO = str(ROOT / ".tools/falco")


def run(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run fixed trusted argument arrays, no shell interpolation, bounded waits and captured diagnostics."""
    result = subprocess.run(
        args, cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(
            "native command failed: "
            + " ".join(args[:2])
            + "\n"
            + result.stderr[-8000:]
        )
    return result


def json_alerts(text: str) -> list[dict[str, object]]:
    """Extract real Falco JSON alerts from its mixed stdout stream; nonalert summaries are not mistaken for findings."""
    rows = []
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        data = json.loads(line)
        if "rule" in data:
            rows.append(data)
    return rows


def replay() -> dict[str, object]:
    """Require exact native (auditID,rule) matches for all hand-labeled positive/negative/blind-spot cases."""
    corpus = cases()
    destination = ROOT / "out"
    destination.mkdir(exist_ok=True, mode=0o700)
    with (destination / "audit.jsonl").open("w", encoding="utf-8") as stream:
        for _, event, _ in corpus:
            stream.write(json.dumps(event) + "\n")
    args = [
        FALCO,
        "-c",
        "configs/replay.yaml",
        "-r",
        "rules/kubernetes.yaml",
        "--disable-source",
        "syscall",
    ]
    run([*args, "--validate", "rules/kubernetes.yaml"])
    started = time.perf_counter()
    result = run(args)
    alerts = json_alerts(result.stdout)
    expected = Counter(
        (event["auditID"], rule) for _, event, rules in corpus for rule in rules
    )
    actual = Counter(
        (row["output_fields"]["ka.auditid"], row["rule"]) for row in alerts
    )
    assert actual == expected, {
        "unexpected": list((actual - expected).items()),
        "missed": list((expected - actual).items()),
    }
    key = b"synthetic-native-review-key-32bytes"
    for row in alerts:
        parse_alert(row, key)
    return dict(
        author="Jason Stys",
        mode="native Falco offline audit replay",
        falco="0.45.0",
        k8saudit="0.18.0",
        cases=len(corpus),
        expected_alerts=sum(expected.values()),
        actual_alerts=len(alerts),
        unexpected_rule_events=0,
        missed_expected_rule_events=0,
        exact_match=True,
        elapsed_ms=(time.perf_counter() - started) * 1000,
        known_blind_spots=[
            "Metadata-only pod body",
            "JSONPatch expansion",
            "sensitive hostPath subpaths",
        ],
        outcomes=[
            dict(name=name, expected=sorted(rules), passed=True)
            for name, _, rules in corpus
        ],
    )


def live() -> dict[str, object]:
    """Observe fake file markers in a no-network/no-capability container; host/BPF authority confined to Linux CI."""
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "Linux"
    ):
        raise ValueError("live probe is restricted to disposable Linux GitHub runners")
    lock = json.loads((ROOT / "tools.lock.json").read_text())
    image = lock["probe_image"]
    run(["docker", "pull", image], 120)
    name = "crsl-probe-" + str(os.getpid())
    output = ROOT / "out"
    output.mkdir(exist_ok=True, mode=0o700)
    stdout_path, stderr_path = output / "live-alerts.jsonl", output / "live-falco.log"
    started = time.perf_counter()
    run(
        [
            "sudo",
            FALCO,
            "-c",
            "configs/live.yaml",
            "-r",
            "rules/syscall.yaml",
            "--validate",
            "rules/syscall.yaml",
        ]
    )
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        monitor = subprocess.Popen(
            [
                "sudo",
                FALCO,
                "-c",
                "configs/live.yaml",
                "-r",
                "rules/syscall.yaml",
                "-M",
                "15",
            ],
            cwd=ROOT,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            time.sleep(3)
            if monitor.poll() is not None:
                raise RuntimeError(
                    "Falco capture exited before fixture: "
                    + stderr_path.read_text()[-8000:]
                )
            run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "32",
                    "--memory",
                    "64m",
                    "--user",
                    "65534:65534",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=4m,mode=1777",
                    "--mount",
                    "type=bind,src="
                    + str(ROOT / "examples/crsl-probe.sh")
                    + ",dst=/lab/crsl-probe.sh,readonly",
                    image,
                    "sh",
                    "/lab/crsl-probe.sh",
                ]
            )
            returncode = monitor.wait(timeout=30)
        finally:
            if monitor.poll() is None:
                os.killpg(monitor.pid, signal.SIGTERM)
                monitor.wait(timeout=15)
            # Only the uniquely named owned disposable fixture may be removed if a failed run left it behind.
            subprocess.run(
                ["docker", "rm", "-f", name],
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
    if returncode != 0:
        raise RuntimeError(
            "Falco live capture failed: " + stderr_path.read_text()[-8000:]
        )
    rows = json_alerts(stdout_path.read_text())
    counts = Counter(row["rule"] for row in rows)
    assert (
        set(counts) == {"CRSL Marker Read", "CRSL Marker Write"}
        and min(counts.values()) >= 1
    ), counts
    key = b"synthetic-native-review-key-32bytes"
    for row in rows:
        fields = row["output_fields"]
        assert fields["container.id"] != "host", "host probe must not match"
        assert fields["fd.name"] in {
            "/tmp/crsl-sensitive-marker",
            "/tmp/crsl-config-marker",
        }
        parse_alert(row, key)
    summary = stdout_path.read_text() + "\n" + stderr_path.read_text()
    drops = re.findall(r"Driver Drops:\s*(\d+)", summary)
    assert drops and all(int(value) == 0 for value in drops), (
        "missing/positive drop evidence"
    )
    return dict(
        author="Jason Stys",
        mode="native modern-eBPF disposable-container probe",
        falco="0.45.0",
        alerts=dict(counts),
        container_scope=True,
        benign_control_alerts=0,
        dropped_events=0,
        elapsed_ms=(time.perf_counter() - started) * 1000,
        safety=dict(
            network="none",
            read_only=True,
            capabilities="none",
            user="65534",
            synthetic_markers_only=True,
        ),
    )


def main() -> None:
    """Print synthetic-only native measurements, never whole runner logs or unsanitized unrelated capture data."""
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["replay", "live"])
    args = parser.parse_args()
    print(json.dumps(replay() if args.mode == "replay" else live(), indent=2))


if __name__ == "__main__":
    main()
