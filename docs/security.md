# Security, privacy and authority boundaries

Author: Jason Stys.

Protected assets: local source/audit streams, workload identities, rule integrity, evidence and host/cluster authority. Trust boundaries: untrusted Falco JSONL → strict parser; normalized values → parameterized SQL/escaped HTML; reviewed artifact digests → native executable loading; disposable CI host → bounded fixture.

Offline runtime has no network/process imports, no tracking, no credential/API configuration or enforcement. Required fields are validated, extra metadata discarded, identifiers HMAC-pseudonymized, report HTML has no scripts/remote media and restrictive CSP. Original private streams must remain outside public Git/Actions.

Pseudonyms/timestamps/rule names may still allow inferences; this is privacy minimization, not guaranteed anonymization. Unknown rule names are untrusted bounded text and escaped; keep real reports private. SQLite/JSON are not encrypted. Directory mode 0700 is not a Windows ACL guarantee: the owner must choose protected parent storage/ACLs and disk encryption. Same-user/admin malware, compromised providers, parent-link races and hostile filesystem replacement are outside this lab's protections.

Native replay reads synthetic files, with syscall source disabled. It opens no webhook. Native live capture uses root/modern eBPF on **disposable Linux CI only**, with Docker metadata access for that runner. The fixture has no network, non-root UID, no capabilities, no-new-privileges, read-only root, bounded resources and isolated tmpfs. It never accesses real secrets or host mounts. Only its script is mounted read-only. Guard flags prevent accidental local invocation, but environment flags are not an adversarial security boundary.

Artifacts: official HTTPS Falco tar is manually reviewed and digest-pinned; official plugin OCI manifest/layer digests checked before copying one regular library. No arbitrary archive extraction or shell installer. These are reproducibility/integrity checks, not verification of publisher signing identity. Upstream binaries/kernel/Docker are trusted external components; Python dependency audit is not a complete native vulnerability scan.

No listener, external alert forwarding, user accounts, public multiuser application, production cluster or PC security changes. Audit policy is illustrative; secret Metadata first prevents secret bodies. Request-level pod logs can still contain sensitive env/commands, so never apply broadly without owner/privacy review.

Public evidence is synthetic or summary-only. Do not attach real audit/alert streams to public issues. See SECURITY.md for reporting.

Raw native metrics can include runner hostname/network metadata even with optional utilization counters disabled. Metrics stay in ignored out/ on the disposable runner; only allowlisted numeric counter summaries are printed/published. Kernel/output counter sampling must span fixture completion; it is not authenticated whole-host evidence.
