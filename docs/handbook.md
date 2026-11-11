# Container Runtime Security Lab handbook

By Jason Stys.

Review declared container runtime events against defensive policies and assemble explainable investigation evidence. The lab does not attach to a production runtime, enforce policy on the PC or establish complete workload visibility.

Group coverage-aware runtime alert episodes and retain exact reasoned human dispositions without changing original alert priorities.

Makes alert triage practical while preserving evidence gaps and detection provenance.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [review](review.md)
- [runbook](runbook.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [performance](performance.md)
- [security](security.md)
- [testing](testing.md)
- [validation](validation.md)

## Historical results and reproduction

The reviewed source is [`437ef271990ab763f3d988d7618a0c67346e72c0`](https://github.com/JasonStys/container-runtime-security-lab/tree/437ef271990ab763f3d988d7618a0c67346e72c0). The observed functional workflow baseline is `437ef271990ab763f3d988d7618a0c67346e72c0`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/episodes-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/container-runtime-security-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- Source-health declarations and analyst dispositions are assertions, not attested incidents or proof of safety.
- Capture gaps lack exact timestamps, so source alerts are conservatively kept separate rather than merged across uncertain gaps.
- Pseudonyms and episode IDs apply to one exact saved review; no persistent key management or cross-review identity linkage is supplied.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.

## Current native usage

Use the [Windows application guide](native-workbench.md) for actual desktop inputs, original-engine interpretation, profile privacy, lifecycle and developer packaging. The [dated native validation](reports/native-workbench-2026-11-11.md) separates working-tree measurements from later exact clean-source and hosted outcomes. Older downloadable Office editions retain their documented historical source; they are not rewritten by this implementation.
