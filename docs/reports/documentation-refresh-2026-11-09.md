# Documentation refresh — 2026-11-09

By Jason Stys.

This documentation-only edition describes source `437ef271990ab763f3d988d7618a0c67346e72c0`. It does not change application behavior, accounts, private data, installers or published releases.

## Published editions and completed review

| File | Bytes | SHA-256 | Reviewed scope |
| --- | ---: | --- | --- |
| [project-guide.docx](project-guide.docx) | 44701 | `69be602fb716d7ee7689a7356d95ce68ddaf180e5b974c6f2c70c575cdac35c5` | 5 pages, each viewed individually |

Word review checked plain black titles, readable pagination, whole table rows, source references, practical limits and absence of clipping or overflow. Render receipts were matched to the current DOCX digest before approval.

## Evidence and change boundary

- Functional baseline: `437ef271990ab763f3d988d7618a0c67346e72c0`.
- Workflow observation: `2026-11-10T05:25:40.628667+00:00`; exact run URLs and source identities remain in [publications.json](publications.json).
- Local document-package validation verifies exact copied bytes, Office ZIP integrity, approved page/tab identities and internal documentation links. Repository-specific documentation and source-policy commands are run separately and recorded in the integration handoff.
- Source/index metadata is regenerated using the repository’s existing tools. Existing privacy, security, coverage and workflow gates are retained.
- PR and later main workflows must pass independently. This record does not claim future or unrun integration CI success.

## Interpretation

The Word files document the cited source; dated source reports retain their original execution scope. A passing workflow is distinct from completed analysis with zero findings, and neither establishes production suitability. Checksums identify exact bytes, not a signature or publisher attestation.

Use the [handbook](../handbook.md) to choose usage, design, security and test documentation. Keep editable Markdown and reviewed editions together; do not replace historical measurements with undated claims.

## Integration-local checks

Observed at `2026-11-10T07:57:44.374375+00:00` on Windows with this repository’s existing development tools. Python commands use its isolated development environment. The documentation source baseline remains the immutable revision above; these checks validate this documentation integration locally.

| Command | Observed result |
| --- | --- |
| `python scripts/code_map.py` | Passed, exit 0. |
| `python scripts/file_guide.py` | Passed, exit 0. |
| `python scripts/code_map.py --check` | Passed, exit 0. |
| `python scripts/file_guide.py --check` | Passed, exit 0. |
| `python -m ruff check .` | Passed, exit 0. |
| `python -m ruff format --check .` | Passed, exit 0. |
| `python -m mypy` | Passed, exit 0. |
| `python -m pytest --cov --cov-report=term-missing` | Passed, exit 0. |

The independent publication audit also matched every copied Office file to its approved SHA-256, checked ZIP package integrity and current page/tab approvals, compared immutable workflow/source metadata, and resolved every local handbook/report link within the repository. Hosted PR/main, browser, platform and container jobs remain separate required checks; they are not inferred from these local results.



The existing full Python suite passed 99 tests at 99.61% combined coverage, retaining the 95% floor. These local checks did not execute Falco or a live container syscall probe; those genuine separate hosted lanes remain required.
