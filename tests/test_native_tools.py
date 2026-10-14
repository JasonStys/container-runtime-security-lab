"""Jason Stys: supply-chain checksum/extraction boundaries and native harness guards tested without local Docker/BPF."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Response — line 43
# definition: test_download_integrity — line 47
# parameter: monkeypatch — line 47
# parameter: args — line 50
# parameter: kwargs — line 50
# definition: archive — line 67
# parameter: kind — line 67
# variable: output — line 69
# variable: bundle — line 70
# variable: info — line 71
# attribute: type — line 72
# attribute: size — line 74
# attribute: linkname — line 77
# definition: test_extraction — line 82
# parameter: monkeypatch — line 82
# parameter: tmp_path — line 82
# variable: target — line 84
# definition: test_native_scope_and_mixed_output — line 96
# parameter: monkeypatch — line 96
# definition: test_plugin_absolute_path — line 106
# variable: filename — line 108
# variable: mode — line 108
# variable: args — line 109
# definition: test_required_native_metrics — line 118
# variable: fields — line 122
# variable: content — line 128
# variable: field — line 134
# variable: value — line 134
# END CODE MAP

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from scripts import native, native_tools


class Response(io.BytesIO):
    """Small context-managed synthetic HTTP stream for checksum/size boundary tests."""


def test_download_integrity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Correct hashes accepted, tampered/oversized artifact bytes rejected before any native execution."""
    monkeypatch.setattr(
        native_tools, "urlopen", lambda *args, **kwargs: Response(b"safe")
    )
    assert (
        native_tools.download(
            "https://example.invalid/tool", hashlib.sha256(b"safe").hexdigest()
        )
        == b"safe"
    )
    with pytest.raises(ValueError):
        native_tools.download("https://example.invalid/tool", "0" * 64)
    monkeypatch.setattr(native_tools, "CAP", 3)
    with pytest.raises(ValueError):
        native_tools.download(
            "https://example.invalid/tool", hashlib.sha256(b"safe").hexdigest()
        )


def archive(kind: bytes = tarfile.REGTYPE) -> bytes:
    """Construct a synthetic archive with one selected member; no third-party code is downloaded/executed."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        info = tarfile.TarInfo("tool")
        info.type = kind
        if kind == tarfile.REGTYPE:
            info.size = 4
            bundle.addfile(info, io.BytesIO(b"safe"))
        else:
            info.linkname = "/etc/private"
            bundle.addfile(info)
    return output.getvalue()


def test_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exact regular members only, no archive paths/links or overwrite; expanded size enforced independently."""
    target = tmp_path / "tool"
    native_tools.member(archive(), "tool", target)
    assert target.read_bytes() == b"safe"
    with pytest.raises(FileExistsError):
        native_tools.member(archive(), "tool", target)
    with pytest.raises(ValueError):
        native_tools.member(archive(tarfile.SYMTYPE), "tool", tmp_path / "link")
    monkeypatch.setattr(native_tools, "CAP", 3)
    with pytest.raises(ValueError):
        native_tools.member(archive(), "tool", tmp_path / "large")


def test_native_scope_and_mixed_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Host monitoring refuses ordinary local execution; summary text cannot masquerade as native alerts."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(ValueError):
        native.live()
    assert native.json_alerts('status\n{"version":"test"}\n{"rule":"synthetic"}\n') == [
        {"rule": "synthetic"}
    ]


def test_plugin_absolute_path() -> None:
    """Falco must receive absolute plugin paths; validation and capture share the same reviewed command builder."""
    for mode, filename in (("replay", "libk8saudit.so"), ("live", "libcontainer.so")):
        args = native.command(mode)
        assert args[-1] == "plugins[0].library_path=" + str(
            native.ROOT / ".tools" / filename
        )
        assert Path(args[-1].split("=", 1)[1]).is_absolute()
    with pytest.raises(ValueError):
        native.command("unknown")


def test_required_native_metrics() -> None:
    """Zero-drop evidence must be present, numeric and cover the completed fixture, not inferred from missing text."""
    import json

    fields = {
        "scap.n_drops": 0,
        "scap.n_evts": 12,
        "falco.outputs_queue_num_drops": 0,
        "evt.time": 100,
    }
    content = json.dumps({"output_fields": fields})
    assert native.check_metrics(content, 99)["post_fixture_sample"]
    with pytest.raises(ValueError):
        native.check_metrics("", 99)
    with pytest.raises(ValueError):
        native.check_metrics(content, 101)
    for field, value in (
        ("scap.n_drops", 1),
        ("falco.outputs_queue_num_drops", 1),
        ("scap.n_evts", 0),
        ("scap.n_drops", None),
        ("evt.time", True),
    ):
        with pytest.raises(ValueError):
            native.check_metrics(
                json.dumps({"output_fields": {**fields, field: value}}), 99
            )
