"""Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 35
# variable: BEGIN — line 36
# variable: END — line 36
# variable: SPECIAL — line 37
# definition: purpose — line 53
# parameter: name — line 53
# variable: text — line 57
# variable: lines — line 62
# variable: index — line 63
# variable: line — line 63
# variable: description — line 65
# variable: continuation — line 67
# variable: description — line 73
# definition: main — line 78
# variable: parser — line 80
# variable: args — line 82
# variable: names — line 83
# variable: rows — line 91
# variable: name — line 92
# variable: label — line 93
# variable: path — line 95
# variable: original — line 96
# variable: end — line 97
# variable: start — line 97
# variable: expected — line 98
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN FILE GUIDE -->", "<!-- END FILE GUIDE -->"
SPECIAL = {
    ".gitignore": "Exclude private audit/alert streams, output bundles, credentials and tools.",
    ".gitattributes": "Consistent LF text across operating systems.",
    "LICENSE": "MIT license for Jason Stys's authored code.",
    "requirements-dev.lock": "Complete universal hash-locked development graph.",
    "tools.lock.json": "Reviewed official Falco/plugin/container/scanner digests.",
    "examples/policy.json": "Synthetic detector scope and sensor freshness policy.",
    "examples/health.json": "Synthetic source-health assertions, not live sensor attestations.",
    "examples/alerts.jsonl": "Synthetic normalized-input Falco-shaped alerts; no real account data.",
    "docs/reports/ci.json": "Immutable accepted-source CI snapshot.",
    "docs/reports/native.json": "Actual Falco replay and disposable-container probe results.",
    "docs/reports/benchmark.json": "Actual bounded alert processing latency and allocation measurement.",
    "docs/reports/example.html": "Generated inert synthetic detection evidence report.",
}


def purpose(name: str) -> str:
    """Read the authored module/header/title purpose or explicit noncommentable-file description."""
    if name in SPECIAL:
        return SPECIAL[name]
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".py"):
        return (ast.get_docstring(ast.parse(text)) or "").splitlines()[0]
    if name.endswith(".md"):
        return text.splitlines()[0].lstrip("# ") + "."
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "Jason Stys:" in line:
            description = line.lstrip("#!/- ")
            if name.endswith((".cpp", ".hpp", ".rs")):
                for continuation in lines[index + 1 :]:
                    if (
                        not continuation.startswith("//")
                        or "BEGIN CODE MAP" in continuation
                    ):
                        break
                    description += " " + continuation.lstrip("/! ")
            return description
    raise ValueError("Tracked-file purpose missing: " + name)


def main() -> None:
    """Generate/check an exact full tracked-file table after staging only reviewed nonprivate files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if names == [""]:
        raise ValueError("Stage reviewed files first")
    rows = ["| File | Purpose |", "| --- | --- |"]
    for name in sorted(names):
        label = name.replace("_", "\\_")
        rows.append(f"| [{label}]({name}) | {purpose(name).replace('|', '/')} |")
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    start, end = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:start] + "\n\n" + "\n".join(rows) + "\n\n" + original[end:]
    if args.check and expected != original:
        raise ValueError("README file guide stale")
    if not args.check:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README complete inventory: {len(names)}")


if __name__ == "__main__":
    main()
