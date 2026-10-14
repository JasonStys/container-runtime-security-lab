# Performance and complexity

Author: Jason Stys.

Native Falco detector performance is not inferred from Python timing. Native replay reports total fixture wall-clock time; live test includes initialization/capture duration and is not an alert-latency SLA.

Portable processing: O(N) bounded parse/HMAC/hash dedup, plus O(U log U) stable sorting for U unique alerts; memory O(N+U) because the bounded input list is retained. Strings/stream limits constrain memory. No database server or per-alert network calls.

Benchmark: 1000 synthetic Kubernetes alerts with HMAC normalization and review, 15 samples, median/min/max milliseconds and tracemalloc Python-only allocation peak. Excludes native kernel/Falco capture, disk writes, OS resident memory and cryptographic key generation. Descriptive results, no hardware-dependent flaky gate. Actual results belong in validation evidence.

[Accepted Linux/Python 3.14.8 measurement](reports/benchmark.json): median 12.397785 ms, Python-only peak 460016 bytes. [Native evidence](reports/native.json): 27-case/18-alert replay took 125.830207 ms; live probe yielded five read and five write matches with 17 zero-drop metric samples spanning completion. Live elapsed time includes setup/capture and is not detection latency.
