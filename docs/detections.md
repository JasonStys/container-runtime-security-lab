# Detector scope, ground truth and blind spots

Author: Jason Stys.

Kubernetes rules are scoped to crsl-lab; clusterroles additionally require crsl- name prefix. Success means ResponseComplete/ResponseStarted plus code starting with 2 or 101. RequestReceived or denied records cannot establish completed operations. An API success is not proof a container launched, a command ran or a permission became effective.

Six rules:

- CRSL Privileged Pod: any explicit privileged=true regular/init/ephemeral container in full pod request object.
- CRSL Host Namespace: explicit hostPID/hostIPC/hostNetwork=true.
- CRSL HostPath Mount: exact paths /, /etc, /proc, /sys, /var/run/docker.sock and /run/containerd/containerd.sock. Not all hostPaths or subpath/escape resolution.
- CRSL Pod Exec: successful create/get pods exec/attach request; command content not emitted.
- CRSL Secret Read: successful get/list/watch secret metadata; secret bodies never needed/output.
- CRSL Wildcard Role: explicit wildcard resource or verb in Role/ClusterRole request; not effective RBAC or binding evaluation.

Native oracle: 27 independent hand-labeled cases including overlapping matches, explicit false, denied/outside-scope/early-stage operations, init/ephemeral privileges and streaming exec. Matching mode all preserves overlapping findings. Oracle labels are separate from detector code; no Python reimplementation “proves” Falco.

Known-uncovered cases intentionally expect no alert: Metadata-only pod records (missing request body), JSONPatch list rather than full desired pod, and sensitive hostPath subpaths such as /etc/ssh. These are detector limitations, not “benign” traffic or zero security false negatives. Exact expected-rule agreement is reported; do not interpret it as universal precision/recall.

Syscall rules only observe open/openat/openat2 success for two fake /tmp marker paths, in non-host containers. They demonstrate actual read/write capture and negative controls. They are not production secret/config rules, mmap/descriptor reuse coverage, process-shell detection, network anomaly detection, host compromise or container-escape evaluation.

Transport/source gaps remain separate from native detector semantics. No AD/Cloud/IAM connector, daemon deployment, automated blocking, cluster remediation, security certification or production alert routing.
