# ADR-001: separate native detectors from portable evidence review

Status: accepted. Date: 2026-10-14. Author/decider: Jason Stys.

Context: demonstrate practical runtime/Kubernetes detections and verifiable CI while avoiding host monitoring, Docker repairs, credentials, production clusters and cloud spend on the user's PC.

Decision: use Falco 0.45.0 and k8saudit 0.18.0 for actual rule evaluation; YAML defines detector conditions/configuration. Python provides typed bounded parsing, health-gap review, HMAC pseudonyms, tests and isolated orchestration. Bash generates harmless container file activity. SQLite preserves queryable evidence; inert HTML supports human review.

Boundaries:

1. Hand-labeled synthetic API events → official k8saudit plugin → actual Falco rules → exact native alert comparison.
2. No-network/non-root/capability-free disposable container → modern eBPF on CI host → marker-only Falco rules → actual capture assertions.
3. Falco JSONL + operator health declarations → portable offline validation/review → fresh private evidence bundle.

Alternative: implement detector conditions in Python. Rejected because it would validate a duplicate detector instead of Falco. Alternative: privileged local DaemonSet/remote hosted collector. Rejected here because it broadens host/cluster access without being needed for a portfolio lab.

Consequences: native detection only on Linux CI, portable evidence review on Windows/Linux/macOS. Kubernetes replay verifies API detection semantics, not live cluster audit transport/admission. Container probes verify actual syscall capture, not container-escape prevention. Modern eBPF/root authority exists only on the disposable runner; this is not a claim of unprivileged host monitoring.

Source-health declarations are explicit inputs, not cryptographically authenticated attestations. Missing/stale/empty/dropped/incomplete sources are review gaps. No alerts means no alerts observed, not secure state.

## Native owner-local workbench — 2026-11-11

`desktop.py` owns the actual Tk controls and one retained worker; `desktop_project.py` maps those settings to the original offline core. `desktop_state.py` owns pre-initialization profile admission, an exclusive lock and bounded immutable SQLite bundles; `inputs.py` supplies stable nonblocking bounded descriptor reads. `desktop_io.py` enforces finite/duplicate-free JSON. Review authorized Falco JSONL, declared source health and a selected policy/as-of time through the original privacy/coverage engine. Group exact saved normalized reviews into continuity-aware episodes and record reasoned local dispositions without suppressing original alerts or gaps. The desktop has no active collection/enforcement path. Source and portable entrypoints use the same domain adapter; package identity is checked before durable state opens.
