"""Jason Stys: explicit offline alert/health review CLI, random per-review privacy keys and content-free diagnostics."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 31
# parameter: argv — line 31
# variable: parser — line 33
# variable: args — line 41
# variable: key — line 43
# variable: result — line 44
# variable: item — line 45
# END CODE MAP

import argparse
import json
import secrets
import sqlite3
import sys
from pathlib import Path

from runtime_lab.contracts import (
    clock,
    parse_alert,
    parse_health,
    parse_policy,
    read_config,
    read_records,
)
from runtime_lab.evidence import write_bundle
from runtime_lab.review import review


def main(argv: list[str] | None = None) -> int:
    """Return 0=complete/no alerts, 1=review alerts/gaps, 2=input or operational failure; never uploads data."""
    parser = argparse.ArgumentParser(
        description="Offline Falco evidence review by Jason Stys"
    )
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--health", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        key = secrets.token_bytes(32)
        result = review(
            [parse_alert(item, key) for item in read_records(args.alerts)],
            parse_health(read_config(args.health)),
            parse_policy(read_config(args.policy)),
            clock(args.as_of),
        )
        write_bundle(result, args.output)
        print(
            json.dumps(
                dict(
                    author="Jason Stys",
                    complete=result.complete,
                    alerts=result.unique,
                    gaps=len(result.gaps),
                )
            )
        )
        return int(bool(result.alerts or result.gaps))
    except (ValueError, TypeError, OSError, sqlite3.Error) as error:
        print(
            "Review failed safely: "
            + type(error).__name__
            + "; inspect private inputs/permissions.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
