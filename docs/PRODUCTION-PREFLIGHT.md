# Production preflight

Run from the repository root before every production activation:

```bash
PROVISIONING_IMAGE='ghcr.io/appolon1908-hue/codestra-provisioning-service@sha256:19d5fd3520c820ecb596e6ae4168cecdacbf5e1fb1ef2d7adbf6b7df0b495a61' \
  scripts/production_preflight.sh
```

The preflight prints names and status only. It never prints secret contents.
It fails closed if the image signature, complete protected secret bundle,
certificate profile, required Docker networks, backup/restore timers, or
production container are absent. A passing preflight does not replace live
readiness fault injection, integration canaries, DR, rollback, or soak tests.
