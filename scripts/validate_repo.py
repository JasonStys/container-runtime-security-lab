"""Jason Stys: tracked-file privacy, passive-runtime imports and zero-artifact/cache workflow guards."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 39
# definition: public_text — line 42
# parameter: path — line 42
# variable: package — line 46
# variable: members — line 47
# variable: member — line 48
# variable: names — line 48
# variable: member — line 52
# variable: item — line 57
# variable: inspected — line 61
# variable: member — line 62
# variable: member — line 64
# variable: member — line 68
# definition: main — line 71
# variable: names — line 73
# variable: name — line 79
# variable: part — line 82
# variable: path — line 89
# variable: text — line 92
# variable: imports — line 101
# variable: node — line 102
# variable: alias — line 104
# variable: path — line 120
# variable: text — line 121
# variable: action — line 128
# variable: codeql — line 131
# variable: flag — line 132
# END CODE MAP

import ast
import json
import re
import subprocess
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def public_text(path: Path) -> str:
    """Inspect all XML/relationships in the one authored Word path; unknown binary files still fail closed."""
    if path.relative_to(ROOT).as_posix() != "docs/reports/project-guide.docx":
        return path.read_text(encoding="utf-8")
    with ZipFile(path) as package:
        members = package.infolist()
        names = [member.filename for member in members]
        if (
            len(members) > 256
            or len(set(names)) != len(names)
            or sum(member.file_size for member in members) > 8 * 1024 * 1024
            or "word/document.xml" not in names
            or "[Content_Types].xml" not in names
            or any(
                "vbaProject" in item or item.startswith("word/embeddings/")
                for item in names
            )
        ):
            raise ValueError("Invalid or unsupported reviewed Word package")
        inspected = [
            member for member in members if member.filename.endswith((".xml", ".rels"))
        ]
        if sum(member.file_size for member in inspected) > 2 * 1024 * 1024:
            raise ValueError("Reviewed Word XML exceeds inspection budget")
        if package.testzip() is not None:
            raise ValueError("Reviewed Word package integrity failed")
        return "\n".join(package.read(member).decode("utf-8") for member in inspected)


def main() -> None:
    """Inspect reviewed source only; imported offline runtime must not gain active network/process capabilities."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    for name in names:
        if any(
            part in {"out", ".venv", ".tools", "__pycache__"}
            for part in name.split("/")
        ) or name.lower().endswith(
            (".pcap", ".pcapng", ".sqlite", ".db", ".key", ".pem", ".env")
        ):
            raise ValueError(
                "private capture/database/credential or generated file is tracked"
            )
        path = ROOT / name
        if path.is_symlink() or path.is_junction():
            raise ValueError("tracked links are forbidden")
        text = public_text(path)
        if re.search(
            r"(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            text,
        ):
            raise ValueError("possible credential in tracked source")
        if name.endswith(".json"):
            json.loads(text)
        if name.startswith("runtime_lab/") and name.endswith(".py"):
            imports = []
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append((node.module or "").split(".")[0])
            if set(imports) & {
                "socket",
                "subprocess",
                "urllib",
                "http",
                "requests",
                "ftplib",
                "telnetlib",
                "paramiko",
            }:
                raise ValueError(
                    "passive offline runtime cannot import active network/process modules"
                )
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if (
            "upload-artifact@" in text
            or "actions/cache@" in text
            or re.search(r"^\s+cache:", text, re.M)
        ):
            raise ValueError("Actions artifact/cache use is disabled")
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            if not re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action):
                raise ValueError("remote action must be pinned to a reviewed commit")
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    for flag in ("trap-caching", "dependency-caching", "upload-database"):
        if flag + ": false" not in codeql:
            raise ValueError("CodeQL cache/database opt-out missing")
    print(
        f"Privacy, passive import and workflow storage guards passed: {len(names)} tracked files"
    )


if __name__ == "__main__":
    main()
