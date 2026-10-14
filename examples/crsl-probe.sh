#!/bin/sh
# Jason Stys: bounded fake-marker container probe, no real secrets, host mounts, network or privilege changes.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# shell loop/input: probe — line 12
# END CODE MAP
set -eu
# Benign controls must not match either rule.
printf 'SYNTHETIC ONLY\n' > /tmp/crsl-sensitive-marker
printf 'control\n' > /tmp/crsl-benign-marker
cat /tmp/crsl-benign-marker > /dev/null
# Repeat briefly to distinguish sensor readiness from a missed capture.
for probe in 1 2 3 4 5; do
  cat /tmp/crsl-sensitive-marker > /dev/null
  printf 'synthetic config iteration %s\n' "$probe" > /tmp/crsl-config-marker
  sleep 1
done
