"""Jason Stys: fresh privacy-minimized JSON/HTML/SQLite evidence and integrity manifests."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: render — line 33
# parameter: result — line 33
# variable: rows — line 35
# variable: item — line 37
# variable: gaps — line 39
# variable: item — line 40
# variable: state — line 42
# definition: write_bundle — line 58
# parameter: output — line 58
# parameter: result — line 58
# variable: schema — line 67
# variable: connection — line 68
# variable: item — line 93
# variable: item — line 98
# variable: hashes — line 100
# variable: name — line 102
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from html import escape
from pathlib import Path

from runtime_lab.review import Review


def render(result: Review) -> str:
    """Render escaped findings with no scripts, remote assets, telemetry, forms or raw Falco output."""
    rows = "".join(
        f"<tr><td>{escape(item.rule)}</td><td>{escape(item.priority)}</td><td>{escape(item.source)}</td><td>{escape(item.namespace)}</td><td>{escape(item.subject)}</td><td>{escape(item.time.isoformat())}</td></tr>"
        for item in result.alerts
    )
    gaps = "".join(
        f"<li>{escape(item.source)}: {escape(item.reason)}</li>" for item in result.gaps
    )
    state = (
        "Declared source coverage complete"
        if result.complete
        else "Coverage incomplete — review gaps"
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="referrer" content="no-referrer">
<title>Container runtime evidence · Jason Stys</title><style>body{{background:#101b2a;color:#eff6ff;font:16px system-ui;max-width:1150px;margin:2rem auto;padding:0 1rem}}header{{border-bottom:3px solid #5ce0c4}}a{{color:#5ce0c4}}table{{border-collapse:collapse;width:100%;font-size:.9rem}}td,th{{padding:.7rem;border-bottom:1px solid #446;text-align:left;vertical-align:top}}section{{overflow:auto}}.state{{color:#ffcc77}}</style></head>
<body><header><p>FALCO / CONTROLLED RUNTIME DETECTION LAB</p><h1>Runtime detection evidence</h1><p>Created by <a href="https://github.com/JasonStys" rel="noreferrer">Jason Stys</a> · <a href="https://www.linkedin.com/in/jason-stys-31b30b351/" rel="noreferrer">Contact</a></p></header>
<p class="state">{state}</p><p>{result.received} raw alerts · {result.unique} unique · {result.duplicates} duplicate rule events</p>
<p>Alerts need investigation. No alerts do not prove safety. Source-health declarations are not authenticated attestations.</p><ul>{gaps}</ul>
<section aria-label="Runtime alerts"><table><caption>Pseudonymized detection findings</caption><thead><tr><th>Rule</th><th>Priority</th><th>Source</th><th>Scope</th><th>Object</th><th>UTC event time</th></tr></thead><tbody>{rows}</tbody></table></section>
<footer><p>Help: verify capture health, inspect the private original evidence, and review authorized change context. The tool neither blocks nor remediates workloads. Keep real evidence private.</p></footer></body></html>
"""


def write_bundle(result: Review, output: Path) -> dict[str, str]:
    """Make a new no-overwrite private directory; existing evidence and caller-owned parent ACLs are preserved."""
    if output.is_symlink() or output.is_junction():
        raise ValueError("output link forbidden")
    output.mkdir(mode=0o700, parents=False)
    (output / "review.json").write_text(
        json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    (output / "review.html").write_text(render(result), encoding="utf-8")
    schema = Path(__file__).resolve().parents[1] / "sql/evidence.sql"
    with closing(sqlite3.connect(output / "evidence.sqlite")) as connection:
        connection.executescript(schema.read_text(encoding="utf-8"))
        with connection:
            connection.execute(
                "INSERT INTO review VALUES (?, ?, ?, ?, ?)",
                (
                    result.as_of,
                    result.received,
                    result.unique,
                    result.duplicates,
                    int(result.complete),
                ),
            )
            connection.executemany(
                "INSERT INTO alert VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        item.event,
                        item.rule,
                        item.source,
                        item.priority,
                        item.namespace,
                        item.subject,
                        item.time.isoformat(),
                    )
                    for item in result.alerts
                ],
            )
            connection.executemany(
                "INSERT INTO gap VALUES (?, ?)",
                [(item.source, item.reason) for item in result.gaps],
            )
    hashes = {
        name: hashlib.sha256((output / name).read_bytes()).hexdigest()
        for name in ("review.json", "review.html", "evidence.sqlite")
    }
    (output / "manifest.json").write_text(
        json.dumps(hashes, indent=2) + "\n", encoding="utf-8"
    )
    return hashes
