# Performance and complexity

Author: Jason Stys.

Native Falco detector performance is not inferred from Python timing. Native replay reports total fixture wall-clock time; live test includes initialization/capture duration and is not an alert-latency SLA.

Portable processing: O(N) bounded parse/HMAC/hash dedup, plus O(U log U) stable sorting for U unique alerts; memory O(N+U) because the bounded input list is retained. Strings/stream limits constrain memory. No database server or per-alert network calls.

Benchmark: 1000 synthetic Kubernetes alerts with HMAC normalization and review, 15 samples, median/min/max milliseconds and tracemalloc Python-only allocation peak. Excludes native kernel/Falco capture, disk writes, OS resident memory and cryptographic key generation. Descriptive results, no hardware-dependent flaky gate. Actual results belong in validation evidence.
