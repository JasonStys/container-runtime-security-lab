# Runbook, safe operation and rollback

Author: Jason Stys.

Offline review:

1. Try the synthetic README sample. No host capture or Docker required.
2. Obtain owner authorization before using real Falco/audit exports. Keep inputs/policies/bundles in protected storage outside Git.
3. Explicitly select expected sources and review health declarations; do not manufacture “healthy” observations from an empty alert file.
4. Supply timezone-bearing as-of and a fresh output path with existing private parent.
5. Open inert review.html locally. Investigate coverage gaps first, then compare private originals against source context.
6. Use normal authorized change control. The tool neither blocks nor changes workloads.

Native development: supported lane is Ubuntu 24.04 x86_64 with reviewed Falco/plugin artifacts. native_tools.py copies regular binaries repo-locally into ignored .tools, never executes them or installs a driver. native.py replay uses only synthetic corpus with syscall disabled. It validates custom rules and exact oracle results.

Live mode requires disposable Linux GitHub Actions runner, root/sudo, kernel BTF/modern-eBPF support and Docker. Do not run against a user's PC/production host or spoof the guard. No fallback disables tests when capture is unavailable; supported CI must prove actual detection. Owned fixture is uniquely named, has no network/privileges, and is removed after the run. Monitor duration is bounded and owned process stopped on failure.

Troubleshooting: unsupported Falco fields/conditions → inspect versioned native compile error. Replay mismatch → inspect private synthetic event/rule IDs; keep oracle strict. Missing alerts → verify source/plugin and capture readiness; no permissive pass. Drops → fix workload/capture capacity; do not label complete. Status 2 → privately inspect exact types/limits/permissions; content-free diagnostics intentionally omit raw paths/errors.

Existing outputs/tools: choose fresh destinations; do not delete evidence or overwrite pinned binaries silently. Hash mismatch: stop, inspect official provenance, do not run. Dependency updates require exact hash regeneration, native regression and full CI.

Rollback: offline tool changes no accounts/settings. Stop using it and preserve private evidence per owner retention policy. CI terminates/removes only its owned ephemeral fixture. No remote cluster installation is performed.
