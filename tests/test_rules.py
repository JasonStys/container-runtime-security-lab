"""Jason Stys: structural rule/output/audit-policy safety contracts, separate from actual native Falco engine validation."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_rule_catalog_and_sources — line 43
# variable: rules — line 45
# variable: path — line 46
# variable: item — line 48
# variable: item — line 50
# variable: item — line 51
# definition: test_audit_policy_and_native_config — line 60
# variable: policy — line 62
# variable: row — line 67
# definition: test_metric_output_private_and_enabled — line 71
# variable: config — line 73
# variable: metrics — line 74
# variable: name — line 78
# variable: config — line 79
# variable: replay — line 82
# definition: test_container_engine_schema_scope — line 86
# variable: config — line 90
# variable: engines — line 91
# variable: name — line 104
# variable: settings — line 104
# definition: test_independent_corpus_structure — line 109
# variable: corpus — line 111
# variable: _ — line 113
# variable: item — line 113
# variable: _ — line 114
# variable: expected — line 114
# variable: _ — line 115
# variable: by_name — line 115
# variable: expected — line 115
# variable: name — line 115
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


def test_metric_output_private_and_enabled() -> None:
    """Required drop metrics stay repo-local and do not become alert streams or change kernel BPF-stat settings."""
    config = yaml.safe_load(Path("configs/live.yaml").read_text())
    metrics = config["metrics"]
    assert metrics["enabled"] and metrics["kernel_event_counters_enabled"]
    assert not metrics["output_rule"] and not metrics["libbpf_stats_enabled"]
    assert metrics["output_file"] == "out/live-metrics.jsonl"
    for name in ("replay", "live"):
        config = yaml.safe_load(Path(f"configs/{name}.yaml").read_text())
        assert not config["webserver"]["enabled"] and not config["log_syslog"]
        assert config["rule_matching"] == "all"
    replay = yaml.safe_load(Path("configs/replay.yaml").read_text())
    assert "://" not in replay["plugins"][0]["open_params"]


def test_container_engine_schema_scope() -> None:
    """Specify every supported engine explicitly, enabling only the disposable runner's Docker socket."""
    import json

    config = yaml.safe_load(Path("configs/live.yaml").read_text())
    engines = json.loads(config["plugins"][0]["init_config"])["engines"]
    assert set(engines) == {
        "docker",
        "podman",
        "containerd",
        "cri",
        "lxc",
        "libvirt_lxc",
        "bpm",
    }
    assert engines["docker"] == {"enabled": True, "sockets": ["/var/run/docker.sock"]}
    assert all(
        not settings["enabled"]
        for name, settings in engines.items()
        if name != "docker"
    )


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
