# Official primary-source research and pinned native choices

Author: Jason Stys. Reviewed 2026-10-14.

- [Falco overview](https://falco.org/docs/): native rule-based monitoring with syscall/plugin event sources. Motivates testing actual Falco rather than a Python condition clone.
- [k8saudit 0.18.0 source](https://github.com/falcosecurity/plugins/tree/43ec9491a5bf25140868a182734a022625eeb9dd/plugins/k8saudit): file replay, source k8s_audit and ka.* fields. Regular/init/ephemeral privilege fields need explicit full request bodies.
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/): event stages and audit levels constrain observable evidence. Our inference: missing request-body details cannot establish absence of privileged fields; success records are not proof of workload execution.
- [Falco 0.45.0 configuration](https://github.com/falcosecurity/falco/blob/0.45.0/falco.yaml): JSON output, matching mode, event-source configuration, disabled webserver/remote outputs.
- [Official Falco release](https://github.com/falcosecurity/falco/releases/tag/0.45.0): binary tar from download.falco.org reviewed/pinned at SHA256 6c8c591089db4ccf815c1761be28109b46f2c14d462a8414abcdd282249aeefe.
- [Official plugin registry index](https://falcosecurity.github.io/falcoctl/index.yaml): k8saudit official GHCR repository. Linux/amd64 0.18.0 OCI manifest ecfeb737816523d949660404d7a1a4a1dbcaecf785bfb84a1c48a06e899ebb85 and layer 180046ef8a1cf49fb042d86a51dc2a01e1fd19cc9b31a469bcca2272c2e0abcb pinned. Hashes are reviewed integrity/reproducibility constraints, not a publisher signature claim.

CI-only fixture uses digest-pinned official BusyBox 1.37.0; no fetched scripts, external target credentials, live production data or cloud charges.
