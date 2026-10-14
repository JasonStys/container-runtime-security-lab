"""Jason Stys: actual CLI/bundle round trips, escaping, SQL injection safety, output preservation and safe diagnostics."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_bundle_and_escape — line 58
# parameter: tmp_path — line 58
# variable: alerts — line 60
# variable: health — line 60
# variable: policy — line 60
# variable: result — line 64
# variable: output — line 65
# variable: hashes — line 66
# variable: digest — line 68
# variable: name — line 68
# variable: connection — line 70
# variable: page — line 73
# definition: test_complete_report_and_links — line 79
# parameter: monkeypatch — line 80
# parameter: tmp_path — line 80
# variable: alerts — line 83
# variable: health — line 83
# variable: policy — line 83
# variable: result — line 84
# variable: page — line 85
# parameter: self — line 89
# definition: test_cli_statuses — line 94
# parameter: capsys — line 94
# parameter: tmp_path — line 94
# variable: args — line 96
# variable: empty — line 111
# definition: test_database_error — line 121
# parameter: capsys — line 122
# parameter: monkeypatch — line 122
# parameter: tmp_path — line 122
# definition: denied — line 126
# parameter: args — line 126
# parameter: kwargs — line 126
# definition: test_public_module_entry — line 151
# variable: error — line 173
# END CODE MAP

import hashlib
import json
import runpy
import sqlite3
import sys
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from runtime_lab.cli import main
from runtime_lab.evidence import render, write_bundle
from runtime_lab.review import review
from tests.test_review import AT, inputs


def test_bundle_and_escape(tmp_path: Path) -> None:
    """All evidence fields/hashes agree, attack-like values remain data and existing reports cannot be overwritten."""
    alerts, health, policy = inputs()
    alerts[0] = replace(
        alerts[0], rule="<script>alert(1)</script>", subject="'; DROP TABLE alert;--"
    )
    result = review(alerts, health, policy, AT)
    output = tmp_path / "evidence"
    hashes = write_bundle(result, output)
    assert hashes == json.loads((output / "manifest.json").read_text())
    for name, digest in hashes.items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    with closing(sqlite3.connect(output / "evidence.sqlite")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alert").fetchone() == (3,)
        assert connection.execute("SELECT COUNT(*) FROM gap").fetchone() == (1,)
    page = (output / "review.html").read_text()
    assert "<script>" not in page and "&lt;script&gt;" in page and "Jason Stys" in page
    with pytest.raises(FileExistsError):
        write_bundle(result, output)


def test_complete_report_and_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clean coverage view is inert and output links rejected independently of input-link checks."""
    alerts, health, policy = inputs()
    result = review(alerts, health, policy, AT)
    page = render(result)
    assert "Declared source coverage complete" in page
    assert "<script" not in page and "<img" not in page and "<iframe" not in page
    assert "default-src 'none'" in page and "no-referrer" in page
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with pytest.raises(ValueError):
        write_bundle(result, tmp_path / "linked")


def test_cli_statuses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Real CLI distinguishes detections, clean coverage, invalid inputs and no-overwrite without disclosing paths."""
    args = [
        "--alerts",
        "examples/alerts.jsonl",
        "--health",
        "examples/health.json",
        "--policy",
        "examples/policy.json",
        "--as-of",
        AT.isoformat(),
        "--output",
        str(tmp_path / "first"),
    ]
    assert main(args) == 1
    assert main(args) == 2
    assert str(tmp_path) not in capsys.readouterr().err
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    args[1] = str(empty)
    args[-1] = str(tmp_path / "clean")
    assert main(args) == 0
    empty.write_bytes(b"\xff")
    args[-1] = str(tmp_path / "invalid")
    assert main(args) == 2


def test_database_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """OS database failure cannot become a false successful bundle or leak error contents."""

    def denied(*args: object, **kwargs: object) -> None:
        """Raise a deliberately sensitive operational diagnostic for privacy regression testing."""
        raise sqlite3.OperationalError("PRIVATE-DATABASE-PATH")

    monkeypatch.setattr(sqlite3, "connect", denied)
    assert (
        main(
            [
                "--alerts",
                "examples/alerts.jsonl",
                "--health",
                "examples/health.json",
                "--policy",
                "examples/policy.json",
                "--as-of",
                AT.isoformat(),
                "--output",
                str(tmp_path / "failed"),
            ]
        )
        == 2
    )
    assert "PRIVATE-DATABASE-PATH" not in capsys.readouterr().err


def test_public_module_entry() -> None:
    """Exercise python -m entry point with actual bounded input validation."""
    with patch.dict(sys.modules):
        sys.modules.pop("runtime_lab.cli", None)
        with (
            patch.object(
                sys,
                "argv",
                [
                    "runtime_lab.cli",
                    "--alerts",
                    "NONEXISTENT",
                    "--health",
                    "examples/health.json",
                    "--policy",
                    "examples/policy.json",
                    "--as-of",
                    AT.isoformat(),
                    "--output",
                    "UNUSED",
                ],
            ),
            pytest.raises(SystemExit) as error,
        ):
            runpy.run_module("runtime_lab.cli", run_name="__main__")
    assert error.value.code == 2
