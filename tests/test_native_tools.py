"""Jason Stys: supply-chain checksum/extraction boundaries and native harness guards tested without local Docker/BPF."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Response — line 34
# definition: test_download_integrity — line 38
# parameter: monkeypatch — line 38
# parameter: args — line 41
# parameter: kwargs — line 41
# definition: archive — line 58
# parameter: kind — line 58
# variable: output — line 60
# variable: bundle — line 61
# variable: info — line 62
# attribute: type — line 63
# attribute: size — line 65
# attribute: linkname — line 68
# definition: test_extraction — line 73
# parameter: monkeypatch — line 73
# parameter: tmp_path — line 73
# variable: target — line 75
# definition: test_native_scope_and_mixed_output — line 87
# parameter: monkeypatch — line 87
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
