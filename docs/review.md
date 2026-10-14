# Code review and release checklist

Author: Jason Stys.

Review focus: no detector simulation counted as native evidence; strict independent expected IDs/rules; overlapping matching retained; negative/known-uncovered scope explicit; missing health not “safe”; no untrusted source execution; discard sensitive output fields; HMAC key absent from bundles; data parameterized/escaped; fresh output; runtime imports remain offline.

Release gates: local unit/property/CLI/style/types/structural checks, exact tracked-file map and line maps, actionlint, hash-pinned native rule replay, actual container capture/drop evidence, full dependency audit/secrets scan, CodeQL and all final-main jobs green. Failed runs retained with cause/correction documentation; no skipping native proof or weakening test oracle.

No production deployment, migration, cloud account or privileged PC installation. Native authority only on disposable CI; no cluster applied. Rollback/cleanup affects only explicitly owned ephemeral fixture. See runbook.

Public reports cite immutable accepted implementation SHA/run/job IDs; final documentation push reruns the same gates. Account Actions billing details stay out of public source.

Corrections strengthened native integration rather than changing detector expectations: installation-relative plugin lookup replaced with explicit verified absolute paths; missing/null/empty optional native metadata normalized to unavailable rather than assuming cluster scope; explicit container-engine configuration includes the required disabled BPM entry; documented JSON metrics replace absent legacy text counters while keeping missing/positive drop evidence a failure. Regression tests cover each boundary.
