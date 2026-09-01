# Production preflight

Run from the repository root before every production activation:

```bash
scripts/production_preflight.sh
```

The preflight prints names and status only. It never prints secret contents.
The exact production digest is controlled by protected Git in both the Compose
manifest and preflight; a mismatched `PROVISIONING_IMAGE` override fails closed.
It fails closed if the image signature, complete protected secret bundle,
certificate profile, required Docker networks, backup/restore timers, or
production container are absent. A passing preflight does not replace live
readiness fault injection, integration canaries, DR, rollback, or soak tests.
