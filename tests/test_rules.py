"""Jason Stys: structural rule/output/audit-policy safety contracts, separate from actual native Falco engine validation."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_rule_catalog_and_sources — line 35
# variable: rules — line 37
# variable: path — line 38
# variable: item — line 40
# variable: item — line 42
# variable: item — line 43
# definition: test_audit_policy_and_native_config — line 52
# variable: policy — line 54
# variable: row — line 59
# variable: name — line 61
# variable: config — line 62
# variable: replay — line 65
# definition: test_independent_corpus_structure — line 69
# variable: corpus — line 71
# variable: _ — line 73
# variable: item — line 73
# variable: _ — line 74
# variable: expected — line 74
# variable: _ — line 75
# variable: by_name — line 75
# variable: expected — line 75
# variable: name — line 75
# END CODE MAP

from pathlib import Path

import yaml

from examples.audit_cases import cases
from runtime_lab.contracts import CATALOG


def test_rule_catalog_and_sources() -> None:
    """Documented catalog equals actual YAML rules; templates never output actors or secret bodies."""
    rules = []
    for path in Path("rules").glob("*.yaml"):
        rules.extend(
            item for item in yaml.safe_load(path.read_text()) if "rule" in item
        )
    assert {item["rule"]: item["source"] for item in rules} == CATALOG
    for item in rules:
        assert item["desc"] and item["condition"] and item["priority"]
        assert (
            "%ka.user" not in item["output"]
            and "%jevt" not in item["output"]
            and "%proc.cmdline" not in item["output"]
        )


def test_audit_policy_and_native_config() -> None:
    """Secret bodies never requested, no Falco listeners/remote outputs, and replay cannot open a webhook."""
    policy = yaml.safe_load(Path("configs/audit-policy.yaml").read_text())
    assert policy["rules"][0]["level"] == "Metadata"
    assert "secrets" in policy["rules"][0]["resources"][0]["resources"]
    assert all(
        "secrets" not in row.get("resources", [{}])[0].get("resources", [])
        for row in policy["rules"][1:]
    )
    for name in ("replay", "live"):
        config = yaml.safe_load(Path(f"configs/{name}.yaml").read_text())
        assert not config["webserver"]["enabled"] and not config["log_syslog"]
        assert config["rule_matching"] == "all"
    replay = yaml.safe_load(Path("configs/replay.yaml").read_text())
    assert "://" not in replay["plugins"][0]["open_params"]


def test_independent_corpus_structure() -> None:
    """Case labels/UUIDs are distinct; blind spots remain documented negatives, not claimed covered threats."""
    corpus = cases()
    assert len(corpus) == 27
    assert len({item["auditID"] for _, item, _ in corpus}) == 27
    assert all(set(expected) <= set(CATALOG) for _, _, expected in corpus)
    by_name = {name: expected for name, _, expected in corpus}
    assert by_name["jsonpatch-blindspot"] == set()
    assert by_name["hostpath-subpath-blindspot"] == set()
    assert by_name["metadata-only"] == set()
    assert len(by_name["multiple-findings"]) == 3
