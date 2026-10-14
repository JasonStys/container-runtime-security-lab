# Validation evidence

Author: Jason Stys.

Accepted implementation: [7e8ea751b900d4b5869cd6082773f78790965788](https://github.com/JasonStys/container-runtime-security-lab/commit/7e8ea751b900d4b5869cd6082773f78790965788).

[Validate 38632090515](https://github.com/JasonStys/container-runtime-security-lab/actions/runs/38632090515) passed all six jobs. [CodeQL 38632090679](https://github.com/JasonStys/container-runtime-security-lab/actions/runs/38632090679) passed its Python job. Actual immutable run/job IDs are in [ci.json](reports/ci.json).

- 86 tests passed, zero skips, in every lane: Ubuntu 24.04/Python 3.12 and 3.14; Windows/Python 3.14; macOS Intel/Python 3.14.
- 100% combined runtime statement/branch coverage: all five modules, 262 statements and 90 branches, none missed. Native scripts/rules/Bash/kernel are not included in this Python coverage claim.
- Actual Falco 0.45.0 / k8saudit 0.18.0 rule validation and replay: 27 independent scenarios, exactly 18 expected alerts, zero missing/unexpected expected-rule events. Includes overlapping rule matches and explicitly documented out-of-scope/blind-spot negatives.
- Actual modern-eBPF capture: five synthetic marker read matches and five writes in the bounded no-network/non-root/capability-free/read-only container; no benign marker control alerts. All alert fields passed native-to-Python contract validation.
- 17 native JSON metric samples had zero kernel/output queue drops, nonzero kernel events and at least one sample after fixture completion. These are sampled counters, not a signed whole-host safety assertion. See [native.json](reports/native.json) and [native job](https://github.com/JasonStys/container-runtime-security-lab/actions/runs/38632090515/job/116085994906).
- Full locked Python dependency graph audit: no known vulnerabilities. Gitleaks: no leaks. actionlint: passed. CodeQL: zero open alerts at verification. These do not constitute a complete upstream native/OS vulnerability assessment.
- [Benchmark](reports/benchmark.json), Linux/Python 3.14.8: 1000 normalized/reviewed alerts, 15 samples, median 12.397785 ms, Python-only peak 460016 bytes. Native replay elapsed 125.830207 ms; live setup/capture elapsed 18815.612542 ms is not alert latency.

Local Windows/Python 3.14.6 also passed all 86 tests with 100% runtime coverage; no local native host capture or Docker changes were performed.

[Synthetic HTML report](reports/example.html) was inspected in a loopback browser: three pseudonymized rows, readable layout, attribution/contact/help, no scripts or remote media, restrictive CSP/no-referrer. Preview server/tabs were stopped/closed. Generated public example is synthetic only.

Preserved correction history:

1. [38630546596](https://github.com/JasonStys/container-runtime-security-lab/actions/runs/38630546596): relative plugin path resolved under Falco installation. Shared command builder now supplies verified absolute paths; regression added.
2. [38630998763](https://github.com/JasonStys/container-runtime-security-lab/actions/runs/38630998763): native cluster-scoped object emitted empty optional namespace. Null/empty/missing optional metadata becomes unavailable, not assumed cluster scope; invalid types/required IDs still fail.
3. [38631336926](https://github.com/JasonStys/container-runtime-security-lab/actions/runs/38631336926): plugin schema required BPM engine entry. Added explicitly disabled BPM; all non-Docker engines stay disabled and schema scope tested.
4. [38631584639](https://github.com/JasonStys/container-runtime-security-lab/actions/runs/38631584639): read/write detection succeeded, but legacy drop-summary text absent. Replaced text inference with documented JSON metrics; missing/malformed/positive counters and insufficient fixture time coverage remain failures.

All detector expectations and native gates remain in force. No failed history was deleted. Documentation is committed separately from this immutable accepted implementation and reruns all seven gates; inspect latest [main Actions](https://github.com/JasonStys/container-runtime-security-lab/actions) for final documentation-commit status.

Remaining scope limits: Kubernetes transport/admission not provisioned/tested; replay is real rule evaluation over synthetic API logs. Marker rules are narrow capture demonstrations, not production threat coverage. Metadata-only pod bodies, JSONPatch and hostPath subpaths remain uncovered. No enforcement, remote cluster installation, compliance certification or whole-security guarantee.
