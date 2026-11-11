"""Jason Stys: independent real-ZIP publication privacy boundary and unknown-file rejection regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: write_document — line 55
# parameter: content — line 56
# parameter: extra — line 56
# parameter: root — line 56
# variable: path — line 59
# variable: package — line 61
# variable: name — line 65
# variable: value — line 65
# definition: test_actual_word_xml_and_relationships_remain_inspected — line 70
# parameter: monkeypatch — line 70
# parameter: tmp_path — line 70
# variable: path — line 73
# variable: result — line 76
# definition: test_actual_main_still_rejects_credentials_in_word_parts — line 82
# parameter: monkeypatch — line 83
# parameter: part — line 83
# parameter: tmp_path — line 83
# variable: token — line 86
# parameter: args — line 99
# parameter: kwargs — line 99
# definition: test_only_exact_reviewed_filename_receives_office_handling — line 105
# parameter: monkeypatch — line 105
# parameter: tmp_path — line 105
# variable: path — line 108
# variable: unknown — line 109
# variable: source — line 113
# definition: test_unsupported_or_unbounded_real_packages_fail — line 122
# parameter: defect — line 122
# parameter: monkeypatch — line 122
# parameter: tmp_path — line 122
# variable: extras — line 125
# variable: extras — line 133
# variable: i — line 133
# variable: path — line 134
# variable: package — line 136
# variable: package — line 141
# definition: test_current_installed_edition_is_inspected — line 148
# parameter: monkeypatch — line 148
# parameter: tmp_path — line 148
# variable: historical — line 151
# variable: current — line 152
# variable: unknown — line 155
# END CODE MAP

from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts import validate_repo as policy


def write_document(
    root: Path, content: str, extra: dict[str, str] | None = None
) -> Path:
    """Create actual small ZIP bytes independently of the production reader."""
    path = root / "docs/reports/project-guide.docx"
    path.parent.mkdir(parents=True)
    with ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("word/document.xml", content)
        package.writestr("word/_rels/document.xml.rels", "<Relationships/>")
        for name, value in (extra or {}).items():
            package.writestr(name, value)
    return path


def test_actual_word_xml_and_relationships_remain_inspected(tmp_path, monkeypatch):
    """A real ZIP yields its XML and relationship text, not a metadata placeholder."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    path = write_document(
        tmp_path, "<document>Read the scoped source evidence.</document>"
    )
    result = policy.public_text(path)
    assert "Read the scoped source evidence." in result
    assert "<Relationships/>" in result and "<Types/>" in result


@pytest.mark.parametrize("part", ["document", "relationship"])
def test_actual_main_still_rejects_credentials_in_word_parts(
    tmp_path, monkeypatch, part
):
    """Run the genuine existing credential guard over actual ZIP XML/relationships before later gates."""
    token = "ghp_" + "A" * 32
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    if part == "document":
        write_document(tmp_path, "<document>" + token + "</document>")
    else:
        write_document(
            tmp_path,
            "<document>Public.</document>",
            {"_rels/.rels": "<Relationship Target='" + token + "'/>"},
        )
    monkeypatch.setattr(
        policy.subprocess,
        "check_output",
        lambda *args, **kwargs: b"docs/reports/project-guide.docx\0",
    )
    with pytest.raises((AssertionError, ValueError), match="possible credential"):
        policy.main()


def test_only_exact_reviewed_filename_receives_office_handling(tmp_path, monkeypatch):
    """A renamed unknown DOCX remains rejected by strict UTF-8 handling; ordinary source stays readable."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    path = write_document(tmp_path, "<document>Public.</document>")
    unknown = path.with_name("unreviewed.docx")
    unknown.write_bytes(path.read_bytes() + b"\xff")
    with pytest.raises(UnicodeDecodeError):
        policy.public_text(unknown)
    source = tmp_path / "source.md"
    source.write_text("Public source.", encoding="utf-8")
    assert policy.public_text(source) == "Public source."


@pytest.mark.parametrize(
    "defect",
    ["missing-main", "macro", "embedded", "xml-budget", "member-budget", "duplicate"],
)
def test_unsupported_or_unbounded_real_packages_fail(tmp_path, monkeypatch, defect):
    """Independent malformed ZIP fixtures cannot become uninspected accepted documentation."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    extras = {}
    if defect == "macro":
        extras["word/vbaProject.bin"] = "inert test bytes"
    elif defect == "embedded":
        extras["word/embeddings/inert.bin"] = "inert test bytes"
    elif defect == "xml-budget":
        extras["word/extra.xml"] = "x" * (2 * 1024 * 1024)
    elif defect == "member-budget":
        extras = {f"word/part{i}.xml": "<x/>" for i in range(256)}
    path = write_document(tmp_path, "<document/>", extras)
    if defect == "missing-main":
        with ZipFile(path, "w") as package:
            package.writestr("[Content_Types].xml", "<Types/>")
    elif defect == "duplicate":
        with (
            pytest.warns(UserWarning, match="Duplicate name"),
            ZipFile(path, "a") as package,
        ):
            package.writestr("word/document.xml", "<document/>")
    with pytest.raises(ValueError):
        policy.public_text(path)


def test_current_installed_edition_is_inspected(tmp_path, monkeypatch):
    """The exact current Word edition exposes XML; an arbitrary renamed binary still fails."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    historical = write_document(tmp_path, "<document>current-review-marker</document>")
    current = historical.with_name("windows-application-guide-1.1.0.docx")
    current.write_bytes(historical.read_bytes())
    assert "current-review-marker" in policy.public_text(current)
    unknown = current.with_name("unknown-current.docx")
    unknown.write_bytes(current.read_bytes() + b"\xff")
    with pytest.raises(UnicodeDecodeError):
        policy.public_text(unknown)
