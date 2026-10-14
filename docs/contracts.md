# Input, output and status contracts

Author: Jason Stys.

Falco JSON requires time, rule, source, priority and output_fields. Sources: k8s_audit/syscall. Known priorities are Falco's eight named levels. Unknown envelope/metadata fields are discarded; malformed required fields, duplicate keys, invalid encoding/times, NaN/Infinity and nesting failures are rejected. Unknown rule/source combinations become coverage gaps, not silent acceptance.

Kubernetes identity: ka.auditid plus source/rule; namespace/name are pseudonymized. Missing/null/empty optional namespace/name use scope-unavailable/unknown-object placeholders, not an assumption of cluster scope. Wrong types/control strings still fail. Syscall identity: exact original native time, container.id and positive int PID plus source/rule; reused PIDs in another container are distinct. HMAC uses a fresh 32-byte per-review key with domain separation and 96-bit labels; key is never included in bundles. Pseudonyms intentionally do not join across reviews; pseudonymization is not full anonymization.

Dedup retains earliest time for identical event/source/rule. Conflicting priority/scope/object fields fail. Multiple rules on one event remain separate. Raw output, actor names, hostnames, command lines, request/response bodies and extra fields never enter normalized Alert records.

Limits: 64 KiB per JSON/config/JSONL line (including newline), 8 MiB total stream, 10000 records, 256-character metadata strings, 128-character rule/ID fields. All times must carry a timezone and normalize into UTC. Future alert/expected sensor clocks relative to explicit as-of fail.

Policy exact fields: sources (unique nonempty subset of supported two sources), max_age_seconds (integer 1..86400). Health: up to two unique source objects with source,last_seen,received,dropped,complete. Counters actual integers 0..1e9, complete actual boolean. Health is operator-supplied evidence, not a verified sensor signature.

Gaps: source-missing/source-stale/source-empty/capture-incomplete/events-dropped, outside-configured-scope and unrecognized-rule-source. Freshness is inclusive at threshold. Review.complete only describes declared configured source coverage. It does not attest audit transport, threat coverage, compromise status or absence of threats.

CLI: 0=declared complete coverage/no detections; 1=alerts or gaps for human review; 2=invalid input, conflicting duplicate or operational failure. Existing output is never overwritten. Partial output after a write failure is incomplete evidence, not a successful bundle. Manifests protect against accidental change only when trusted; they are not signatures.
