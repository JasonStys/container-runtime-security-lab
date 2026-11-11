# Installed Windows 1.1.0 validation — 11 November 2026

By Jason Stys. These observations refer to the independently downloaded, published **1.1.0** application built from `98ba4864a547428d7c41ba83a85e74a7a42bfd7b`. Historical Office editions and published assets remain unchanged.

## Observed validation

**Actual installed native journeys: Passed.** Two installed launches passed nine workflows, nine exact saved bundles, invalid-input preservation and normal exits.

**Original engines and security: Passed.** Original normalized-alert, source-health, grouping and triage tests, actual Falco/kernel integration on the disposable CI runner where configured, privacy checks and processed CodeQL passed on exact main.

**Package and runtime identity: Passed.** Five independently downloaded assets matched provider SHA-256. Actual installed bytes and source/runtime identities matched the reviewed clean-main proof.

**Launch and privacy boundary: Passed.** Individual Desktop and Start-menu link targets passed read-back. Installed EXEs were exercised separately with synthetic profiles; normal default-profile shortcut activation was not independently exercised.

## Illustrated workflow and implementation

The [four-page application guide](windows-application-guide-1.1.0.docx) contains two actual installed-app screenshots, a worked user journey, an immutable-source code excerpt and results/operating limits. Every final page was reviewed and OOXML schema validation passed. The [manifest](windows-application-guide-1.1.0.json) binds the document, screenshot, source and reviewed-page identities. Prepared examples are inputs inside the actual application.

## Installation, data and limits

Download the Windows EXE, checksum sidecar and notices. Verify the hash and launch the EXE. Retain old versions and stopped-profile backups; no Python setup or Docker is required.

Open the individual Desktop icon and read Help/notices. Quit through the app; prepared examples are inputs in the real application, never separate demo apps.

Supplied logs and health snapshots do not prove that a live workload is safe or fully observed. Dispositions cannot erase independent coverage gaps. This GUI starts no Docker, driver, kernel sensor or enforcement.

Unsigned Windows portable EXE with plaintext owner-local evidence. No multiuser authentication or same-OS-user isolation is claimed. No ordinary profile or Docker setting was changed.

Individual Desktop and Start-menu targets were read-back verified. Actual installed-executable testing is distinct from normal default-profile shortcut activation, which was not independently exercised. Normal profiles and Docker were unchanged. This documentation revision must pass its own hosted workflows and processed security analysis; historical runtime evidence does not certify later source changes.
