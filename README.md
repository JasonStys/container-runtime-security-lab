# Container Runtime Security Lab

Created by [Jason Stys](https://github.com/JasonStys) · [Professional contact](https://www.linkedin.com/in/jason-stys-31b30b351/).

A defensive lab combining real **Falco** rule evaluation with typed, privacy-minimized evidence review. Kubernetes API audit replay and live container syscall probes are separate, explicitly measured lanes. It is not an enforcement agent, production SIEM, comprehensive container-escape detector or compliance certification.

## Features

- Six scoped Kubernetes audit rules: privileged containers (including init/ephemeral), host namespaces, exact sensitive hostPaths, exec/attach, secret reads and wildcard RBAC roles.
- Native Falco replay of independently hand-labeled positive, negative and known-uncovered scenarios—not a Python simulation of Falco.
- Two narrow syscall rules plus live modern-eBPF capture of fake file markers in a disposable no-network, non-root, capability-free container.
- Bounded Falco JSONL parsing, per-review HMAC pseudonyms, duplicate detection, UTC ordering and explicit health/coverage gaps.
- Fresh private JSON/HTML/SQLite bundles with no-overwrite behavior, manifests and inert, escaped analyst reports.
- Cross-platform Python tests, properties, strict types, security scans, commit/hash-pinned tooling and zero Actions artifact/cache uploads.

## Native Windows workbench

**Container Runtime Security Workbench 1.1.0** turns the existing offline engine into a complete one-file graphical application: real supported file/policy settings, meaningful evidence views, literal search/full details, bounded durable history, exact export, explicit retention controls and normal retained-worker close. Review authorized Falco JSONL, declared source health and a selected policy/as-of time through the original privacy/coverage engine. Group exact saved normalized reviews into continuity-aware episodes and record reasoned local dispositions without suppressing original alerts or gaps.

Eight optional prepared cases and the reasoned selected-episode workflow run inside this same application. They are optional inputs, not a separate demo or substitute for authorized files. The portable includes patched Python/Tk and fixed resources; no separate development tools or Docker are needed to use it. The existing CLI and real native assurance lanes remain available. [Application guide](docs/native-workbench.md) · [Actual dated validation](docs/reports/native-workbench-2026-11-11.md). Source/build, hosted validation, release publication and PC installation are distinct operations; this source change does not claim an unrun later release.

## Safe offline quickstart

Python 3.12+; no third-party runtime dependencies. This does not start Docker, capture your host, install a driver or contact any server.

```powershell
New-Item -ItemType Directory -Force out
python -m runtime_lab.cli --alerts examples/alerts.jsonl --health examples/health.json --policy examples/policy.json --as-of 2026-10-14T00:00:00Z --output out/review-01
```

The synthetic sample deliberately returns **1** (three alerts need review), not a software failure. Open `out/review-01/review.html` locally. Status 0=declared complete coverage/no alerts; 1=alerts or gaps; 2=input/operational error. **Status 0 is not proof of safety.**

## Review related alert episodes and analyst dispositions

After creating a normal private review, reuse its saved **pseudonymized** `review.json`:

```text
python -m runtime_lab.episodes --review out/review-01/review.json --gap-seconds 30 --output out/episode-review
```

Open `episodes.html` for a readable rule/time/count/continuity/disposition table and exact evidence details. Continuous-source observations with the same rule, scope and object may group within an inclusive gap of 1–300 seconds. Any source-level drop/incomplete/health gap prevents grouping that source: individual observations remain separate because the exact missing interval is unknown. Every original alert, priority, duplicate count and source gap remains in the output.

Fill a private copy of `triage-template.json` with `investigate`, `expected_activity`, `false_positive` or `needs_context` and a meaningful reason, then rerun with `--triage <private-file>` into a new directory. Missing entries stay unreviewed. Wrong saved-review hashes, unknown/duplicate episode IDs, changed grouping IDs and blank reasons reject. A disposition is a local analyst assertion; it cannot suppress original detections or manufacture a clean result. The command returns1 while original alerts/gaps exist, even if every episode is reviewed.

Use the same saved review for triage. Re-running raw ingestion deliberately creates new privacy pseudonyms; this workflow neither persists a privacy key nor links objects across independent reviews. Reports remain private plaintext, not authenticated sensor evidence or incident/compromise attribution.

## Development

Install hash-locked dev dependencies in a virtual environment: `python -m pip install --require-hashes -r requirements-dev.lock`. Run `python -m pytest --cov=runtime_lab`, `python -m ruff check .`, `python -m mypy`, and `python scripts/benchmark.py` with repo root on PYTHONPATH. Raw data and native outputs belong only in ignored private folders.

Native Linux tooling: `python scripts/native_tools.py` installs reviewed official artifacts **repo-locally**, without execution. Offline Falco replay: `PYTHONPATH=. python scripts/native.py replay`. Live monitoring is restricted by a guard to disposable Linux GitHub runners; it never runs on your PC as part of these instructions.

## Documentation

Accepted validation: **86 tests / 100% portable runtime statement-and-branch coverage** on all four OS/Python lanes; **27 native Falco scenarios / 18 exact alerts**; live eBPF captured five reads and five writes with zero sampled kernel/output drops. All seven accepted CI jobs passed. Read [measured evidence](docs/validation.md) and latest [Actions](https://github.com/JasonStys/container-runtime-security-lab/actions).

[Architecture/ADR](docs/architecture.md) · [contracts](docs/contracts.md) · [detector coverage](docs/detections.md) · [security/privacy](docs/security.md) · [operator runbook](docs/runbook.md) · [testing](docs/testing.md) · [performance](docs/performance.md) · [coding](docs/coding.md) · [primary research](docs/research.md) · [review/release](docs/review.md) · [validation](docs/validation.md).

Audit policy is illustrative and never applied to an existing cluster automatically. Real audit bodies can contain sensitive workload commands/environment data. Secret resources are Metadata-only in the example policy. Keep real streams and reports private. Native captures emit only these lab rules; the analyzer discards actor names, command lines, raw output and nonallowlisted fields.

## Every tracked file

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: portable evidence validation, actual Falco engine/probe and security gates; no artifacts/caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: security-extended Python analysis; explicitly disable trap/dependency caches and database uploads. |
| [.gitignore](.gitignore) | Exclude private audit/alert streams, output bundles, credentials and tools. |
| [CHANGELOG.md](CHANGELOG.md) | Changelog. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | Container Runtime Security Lab. |
| [SECURITY.md](SECURITY.md) | Security reporting. |
| [configs/audit-policy.yaml](configs/audit-policy.yaml) | Jason Stys: illustrative isolated-cluster audit policy; never applied to an existing cluster by this project. |
| [configs/live.yaml](configs/live.yaml) | Jason Stys: syscall-only modern eBPF on disposable CI runner; no listeners, no external outputs. |
| [configs/replay.yaml](configs/replay.yaml) | Jason Stys: offline Kubernetes audit JSONL replay, no listener, no syscall capture or external outputs. |
| [docs/architecture.md](docs/architecture.md) | ADR-001: separate native detectors from portable evidence review. |
| [docs/coding.md](docs/coding.md) | Coding and documentation conventions. |
| [docs/contracts.md](docs/contracts.md) | Input, output and status contracts. |
| [docs/detections.md](docs/detections.md) | Detector scope, ground truth and blind spots. |
| [docs/handbook.md](docs/handbook.md) | Container Runtime Security Lab handbook. |
| [docs/native-workbench.md](docs/native-workbench.md) | Container Runtime Security Workbench: Windows application. |
| [docs/performance.md](docs/performance.md) | Performance and complexity. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Actual bounded alert processing latency and allocation measurement. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source CI snapshot. |
| [docs/reports/documentation-refresh-2026-11-09.md](docs/reports/documentation-refresh-2026-11-09.md) | Documentation refresh — 2026-11-09. |
| [docs/reports/episodes-2026-11-09.md](docs/reports/episodes-2026-11-09.md) | Coverage-aware episode review validation — November 9, 2026. |
| [docs/reports/example.html](docs/reports/example.html) | Generated inert synthetic detection evidence report. |
| [docs/reports/installed-windows-1.1.0-2026-11-11.md](docs/reports/installed-windows-1.1.0-2026-11-11.md) | Installed Windows 1.1.0 validation — 11 November 2026. |
| [docs/reports/native-workbench-2026-11-11.md](docs/reports/native-workbench-2026-11-11.md) | Native offline workbench validation — 2026-11-11. |
| [docs/reports/native.json](docs/reports/native.json) | Actual Falco replay and disposable-container probe results. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/project-guide.docx](docs/reports/project-guide.docx) | Reviewed Word project guide bound to the documented source revision. |
| [docs/reports/publications.json](docs/reports/publications.json) | Exact Office digests, visual review scopes and immutable source baselines. |
| [docs/reports/windows-application-guide-1.1.0.docx](docs/reports/windows-application-guide-1.1.0.docx) | Current illustrated installed workbench guide with actual screenshots, exact source and measured limits. |
| [docs/reports/windows-application-guide-1.1.0.json](docs/reports/windows-application-guide-1.1.0.json) | Current Word, screenshot, immutable source and reviewed-page digests. |
| [docs/research.md](docs/research.md) | Official primary-source research and pinned native choices. |
| [docs/review.md](docs/review.md) | Code review and release checklist. |
| [docs/runbook.md](docs/runbook.md) | Runbook, safe operation and rollback. |
| [docs/security.md](docs/security.md) | Security, privacy and authority boundaries. |
| [docs/testing.md](docs/testing.md) | Risk-based test strategy. |
| [docs/validation.md](docs/validation.md) | Validation evidence. |
| [examples/alerts.jsonl](examples/alerts.jsonl) | Synthetic normalized-input Falco-shaped alerts; no real account data. |
| [examples/audit\_cases.py](examples/audit_cases.py) | Jason Stys: independent exact Falco rule oracles for synthetic Kubernetes audit events, including known blind spots. |
| [examples/crsl-probe.sh](examples/crsl-probe.sh) | Jason Stys: bounded fake-marker container probe, no real secrets, host mounts, network or privilege changes. |
| [examples/desktop/empty-alerts.jsonl](examples/desktop/empty-alerts.jsonl) | Intentionally empty authorized-input example; no alerts does not prove safety. |
| [examples/desktop/episode-alerts.jsonl](examples/desktop/episode-alerts.jsonl) | Fictional repeated-object and duplicate Falco-shaped inputs for the normal desktop workflow. |
| [examples/desktop/health-current.json](examples/desktop/health-current.json) | Explicit fictional source-health observations for repeated-object review. |
| [examples/desktop/health-drops.json](examples/desktop/health-drops.json) | Fictional incomplete/dropped-source assertions that forbid inferred continuity. |
| [examples/health.json](examples/health.json) | Synthetic source-health assertions, not live sensor attestations. |
| [examples/policy.json](examples/policy.json) | Synthetic detector scope and sensor freshness policy. |
| [pyproject.toml](pyproject.toml) | Jason Stys: zero-dependency offline runtime, strict types and combined statement/branch coverage. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: hash-locked tests, properties, typing, formatting and independent dependency/security tooling. |
| [requirements-dev.lock](requirements-dev.lock) | Complete universal hash-locked development graph. |
| [requirements-native.lock](requirements-native.lock) | Exact hash-locked portable freezing tools, separate from zero-dependency runtime. |
| [rules/kubernetes.yaml](rules/kubernetes.yaml) | Jason Stys: scoped Kubernetes API detections, successful response stages only; no secret bodies or actors output. |
| [rules/syscall.yaml](rules/syscall.yaml) | Jason Stys: live CI-only fake marker probes; narrowly scoped demonstrations, not production secret/config detection. |
| [runtime\_lab/\_\_init\_\_.py](runtime_lab/__init__.py) | Jason Stys: offline, privacy-minimized Falco evidence review; never an enforcement or live monitoring daemon. |
| [runtime\_lab/cli.py](runtime_lab/cli.py) | Jason Stys: explicit offline alert/health review CLI, random per-review privacy keys and content-free diagnostics. |
| [runtime\_lab/contracts.py](runtime_lab/contracts.py) | Jason Stys: bounded JSONL, exact policy/health types, UTC clocks and pseudonymized Falco alert contracts. |
| [runtime\_lab/desktop.py](runtime_lab/desktop.py) | Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys. |
| [runtime\_lab/desktop\_io.py](runtime_lab/desktop_io.py) | Bounded regular descriptor reads and strict finite JSON for owner-local desktop state. Jason Stys. |
| [runtime\_lab/desktop\_project.py](runtime_lab/desktop_project.py) | Real offline Falco evidence, coverage-aware episodes and reasoned local triage for the desktop. Jason Stys. |
| [runtime\_lab/desktop\_state.py](runtime_lab/desktop_state.py) | Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys. |
| [runtime\_lab/episodes.py](runtime_lab/episodes.py) | Jason Stys: coverage-aware saved-review episodes and reasoned analyst dispositions without altering detections. |
| [runtime\_lab/evidence.py](runtime_lab/evidence.py) | Jason Stys: fresh privacy-minimized JSON/HTML/SQLite evidence and integrity manifests. |
| [runtime\_lab/inputs.py](runtime_lab/inputs.py) | Bounded stable ordinary-file reads and streaming tool hashes for offline identity inputs. Jason Stys. |
| [runtime\_lab/review.py](runtime_lab/review.py) | Jason Stys: deterministic alert deduplication, explicit coverage gaps and stable source/rule triage. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: deterministic bounded HMAC/alert-review benchmark, descriptive rather than hardware-dependent CI gate. |
| [scripts/build\_native.py](scripts/build_native.py) | Build the complete real offline workbench as one Windows portable executable. Jason Stys. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and lexical Bash/workflow line indexes. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native.py](scripts/native.py) | Jason Stys: actual Falco rule validation/replay and safe marker-only live container capture on disposable Linux CI. |
| [scripts/native\_acceptance.py](scripts/native_acceptance.py) | Actual final portable widgets/core/native-window acceptance with independent oracles. Jason Stys. |
| [scripts/native\_common.py](scripts/native_common.py) | Actual patched Python/Tcl/Tk/PyInstaller runtime notices and authored portable icon. Jason Stys. |
| [scripts/native\_entry.py](scripts/native_entry.py) | Launch the actual bundled offline project workbench; no setup shell commands. Jason Stys. |
| [scripts/native\_tools.py](scripts/native_tools.py) | Jason Stys: official digest-pinned Falco and k8saudit native tooling, extracted as allowlisted regular files only. |
| [scripts/preview.py](scripts/preview.py) | Jason Stys: temporary loopback-only inert synthetic HTML preview for visual QA, not a hosted security service. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/test\_native\_app.py](scripts/test_native_app.py) | Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: tracked-file privacy, passive-runtime imports and zero-artifact/cache workflow guards. |
| [sql/evidence.sql](sql/evidence.sql) | Jason Stys: pseudonymized detection evidence with parameterized inserts; no raw audit objects/actors. |
| [tests/\_\_init\_\_.py](tests/__init__.py) | Jason Stys: shared synthetic-only test helpers; no host monitoring or external services on import. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: strict parser boundaries, pseudonym privacy and hostile bounded JSONL/property cases. |
| [tests/test\_desktop\_gui.py](tests/test_desktop_gui.py) | Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys. |
| [tests/test\_desktop\_io.py](tests/test_desktop_io.py) | Private state JSON and bounded descriptor-read boundary cases with actual file bytes. Jason Stys. |
| [tests/test\_desktop\_project.py](tests/test_desktop_project.py) | Actual privacy/coverage/episode/triage adapter scenarios with independent counts and refusal oracles. Jason Stys. |
| [tests/test\_desktop\_state.py](tests/test_desktop_state.py) | Independent offline desktop ownership, byte-bound, SQLite and non-overwrite regressions. Jason Stys. |
| [tests/test\_episodes.py](tests/test_episodes.py) | Jason Stys: independent episode continuity, private review binding and reasoned-triage regressions. |
| [tests/test\_evidence.py](tests/test_evidence.py) | Jason Stys: actual CLI/bundle round trips, escaping, SQL injection safety, output preservation and safe diagnostics. |
| [tests/test\_native\_inputs.py](tests/test_native_inputs.py) | Actual same-descriptor input bounds and ownership-change cases for selected offline reports. Jason Stys. |
| [tests/test\_native\_tools.py](tests/test_native_tools.py) | Jason Stys: supply-chain checksum/extraction boundaries and native harness guards tested without local Docker/BPF. |
| [tests/test\_profile\_admission.py](tests/test_profile_admission.py) | Actual pre-existing alias refusal and ordinary SQLite recovery continuity. Jason Stys. |
| [tests/test\_publication\_policy.py](tests/test_publication_policy.py) | Jason Stys: independent real-ZIP publication privacy boundary and unknown-file rejection regressions. |
| [tests/test\_review.py](tests/test_review.py) | Jason Stys: deduplication/coverage/clock contracts, input-order properties and no-alerts-not-safe regressions. |
| [tests/test\_rules.py](tests/test_rules.py) | Jason Stys: structural rule/output/audit-policy safety contracts, separate from actual native Falco engine validation. |
| [tools.lock.json](tools.lock.json) | Reviewed official Falco/plugin/container/scanner digests. |

<!-- END FILE GUIDE -->

## Documentation editions

Start with the [organized handbook](docs/handbook.md) for current usage, design, security and test guidance. Reviewed downloadable editions: [project-guide.docx](docs/reports/project-guide.docx).

[Publication identities and source scope](docs/reports/publications.json) · [Documentation validation record](docs/reports/documentation-refresh-2026-11-09.md). Historical results retain their own tested revision and date.


## Current Windows application guide

The published **1.1.0** app has a [four-page illustrated guide](docs/reports/windows-application-guide-1.1.0.docx) with actual installed screenshots, a worked user journey, source excerpts and operating limits. Read the [installed validation report](docs/reports/installed-windows-1.1.0-2026-11-11.md) and [review manifest](docs/reports/windows-application-guide-1.1.0.json) for exact scope. Historical editions remain unchanged.
