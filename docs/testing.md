# Risk-based test strategy

Author: Jason Stys.

Portable unit/property/integration tests: JSON types/keys/limits/encoding/nesting/duplicate keys, time overflow, per-key/domain privacy properties, unknown/extra metadata, syscall identity, dedup conflict/order invariance, source completeness, future/stale/drop/empty gaps, fresh bundle/manifest/SQLite/CLI/module paths, SQL injection-looking values, escaped HTML and failure diagnostics.

Structural YAML tests check rule catalog/output privacy, secret Metadata audit policy, listeners/remote logs disabled, all-rule matching and independent oracle case structure. These do not replace Falco rule compilation/evaluation.

Independent native Linux lane: hash verification, actual Falco rule validation, 27 exact synthetic Kubernetes audit replay outcomes, actual modern-eBPF container read/write detections and no-network benign controls, native alert contract compatibility and drop evidence. No local PC monitoring.

CI matrix: Ubuntu 24.04 Python 3.12/3.14; Windows Python 3.14; macOS Intel Python 3.14. Ruff/mypy, exact code/file indexes, input/privacy/storage guards, complete Python dependency audit, Gitleaks/actionlint and security-extended CodeQL.

Combined Python runtime statement/branch coverage gate 95%; scripts/native binaries/rules/Bash/kernel coverage not included. Native observations are reported separately. Property tests are bounded; passing tests are not complete security proof.

Limitations retained as explicit negative oracles: Metadata-only pod records, JSONPatch, exact-hostPath subpaths. No actual Kubernetes cluster/audit webhook transport is provisioned/tested. No claim of zero real-world false negatives or production readiness.
