"""Jason Stys: independent exact Falco rule oracles for synthetic Kubernetes audit events, including known blind spots."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: AT — line 23
# definition: event — line 26
# parameter: name — line 26
# definition: cases — line 64
# variable: rows — line 66
# variable: names — line 67
# variable: name — line 96
# variable: item — line 97
# variable: spec — line 98
# variable: expected — line 99
# variable: expected — line 187
# variable: expected — line 190
# variable: expected — line 193
# variable: expected — line 197
# END CODE MAP

from copy import deepcopy
from typing import Any
from uuid import NAMESPACE_URL, uuid5

AT = "2026-10-14T00:00:00Z"


def event(name: str) -> dict[str, Any]:
    """Construct one realistic synthetic API audit record; no actual cluster, secret or identity is referenced."""
    return {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "Request",
        "auditID": str(uuid5(NAMESPACE_URL, "jason-stys-crsl:" + name)),
        "stage": "ResponseComplete",
        "verb": "create",
        "requestURI": "/api/v1/namespaces/crsl-lab/pods",
        "user": {"username": "synthetic-operator", "groups": ["synthetic-reviewers"]},
        "objectRef": {
            "resource": "pods",
            "namespace": "crsl-lab",
            "name": "synthetic-workload",
            "apiVersion": "v1",
        },
        "requestObject": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "synthetic-workload", "namespace": "crsl-lab"},
            "spec": {
                "containers": [
                    {
                        "name": "worker",
                        "image": "synthetic.invalid/worker:demo",
                        "securityContext": {"privileged": False},
                    }
                ]
            },
        },
        "responseStatus": {"code": 201},
        "requestReceivedTimestamp": AT,
        "stageTimestamp": AT,
        "annotations": {"authorization.k8s.io/decision": "allow"},
    }


def cases() -> list[tuple[str, dict[str, Any], set[str]]]:
    """Expected rule sets are hand-specified, not calculated by a Python reimplementation of Falco conditions."""
    rows = []
    names = [
        "benign-pod",
        "privileged",
        "init-privileged",
        "ephemeral-privileged",
        "host-pid",
        "host-ipc",
        "host-network",
        "hostpath",
        "pod-exec",
        "pod-attach",
        "secret-get",
        "secret-list",
        "secret-watch",
        "wildcard-role",
        "wildcard-clusterrole",
        "multiple-findings",
        "denied",
        "outside-scope",
        "request-received",
        "metadata-only",
        "explicit-false",
        "safe-role",
        "safe-hostpath",
        "hostpath-subpath-blindspot",
        "jsonpatch-blindspot",
        "exec-started",
        "secret-denied",
    ]
    for name in names:
        item = event(name)
        spec = item["requestObject"]["spec"]
        expected: set[str] = set()
        if name in {
            "privileged",
            "denied",
            "outside-scope",
            "request-received",
            "multiple-findings",
            "metadata-only",
        }:
            spec["containers"][0]["securityContext"]["privileged"] = True
            expected.add("CRSL Privileged Pod")
        if name in {"init-privileged", "ephemeral-privileged"}:
            spec[
                "initContainers" if name == "init-privileged" else "ephemeralContainers"
            ] = [
                {
                    "name": "additional",
                    "image": "synthetic.invalid/additional:demo",
                    "securityContext": {"privileged": True},
                }
            ]
            expected.add("CRSL Privileged Pod")
        if name in {"host-pid", "host-ipc", "host-network", "multiple-findings"}:
            spec[
                {"host-pid": "hostPID", "host-ipc": "hostIPC"}.get(name, "hostNetwork")
            ] = True
            expected.add("CRSL Host Namespace")
        if name in {
            "hostpath",
            "safe-hostpath",
            "hostpath-subpath-blindspot",
            "multiple-findings",
        }:
            spec["volumes"] = [
                {
                    "name": "host",
                    "hostPath": {
                        "path": "/etc"
                        if name in {"hostpath", "multiple-findings"}
                        else "/tmp"
                        if name == "safe-hostpath"
                        else "/etc/ssh"
                    },
                }
            ]
            if name in {"hostpath", "multiple-findings"}:
                expected.add("CRSL HostPath Mount")
        if name in {"pod-exec", "pod-attach", "exec-started"}:
            item["objectRef"]["subresource"] = (
                "attach" if name == "pod-attach" else "exec"
            )
            item["requestObject"] = {}
            item["responseStatus"]["code"] = 101
            if name == "exec-started":
                item["stage"] = "ResponseStarted"
            expected.add("CRSL Pod Exec")
        if name in {"secret-get", "secret-list", "secret-watch", "secret-denied"}:
            item.update(
                level="Metadata",
                verb={"secret-list": "list", "secret-watch": "watch"}.get(name, "get"),
            )
            item.pop("requestObject")
            item["objectRef"]["resource"] = "secrets"
            item["responseStatus"]["code"] = 200 if name != "secret-denied" else 403
            if name != "secret-denied":
                expected.add("CRSL Secret Read")
        if name in {"wildcard-role", "wildcard-clusterrole", "safe-role"}:
            item["objectRef"].update(
                resource="clusterroles" if name == "wildcard-clusterrole" else "roles",
                name="crsl-role",
            )
            if name == "wildcard-clusterrole":
                item["objectRef"].pop("namespace")
            item["requestObject"] = {
                "kind": "Role",
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["*" if name != "safe-role" else "pods"],
                        "verbs": ["get"],
                    }
                ],
            }
            if name != "safe-role":
                expected.add("CRSL Wildcard Role")
        if name == "denied":
            item["responseStatus"]["code"] = 403
            expected = set()
        elif name == "outside-scope":
            item["objectRef"]["namespace"] = "other-lab"
            expected = set()
        elif name == "request-received":
            item["stage"] = "RequestReceived"
            expected = set()
        elif name == "metadata-only":
            item.pop("requestObject")
            item["level"] = "Metadata"
            expected = set()
        elif name == "jsonpatch-blindspot":
            item["verb"] = "patch"
            item["requestObject"] = [
                {
                    "op": "add",
                    "path": "/spec/containers/0/securityContext/privileged",
                    "value": True,
                }
            ]
        rows.append((name, deepcopy(item), expected))
    return rows
