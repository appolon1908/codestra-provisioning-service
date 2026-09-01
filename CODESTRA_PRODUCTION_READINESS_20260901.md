# Codestra Production Readiness Gate — Provisioning Service

Status: NOT PRODUCTION CERTIFIED

Governed by `Infustruction-repo/CODESTRA_PRODUCTION_READINESS_WAVE_20260901.md`.

Required: exact-head CI; Critical=0; High=0; least-privilege provisioning authority; idempotent create/update operations; immutable desired-state inputs; OpenBao secret delivery; Keycloak service identity; audit trail; rollback/compensation; staging reconciliation proof; no destructive drift correction without explicit authority; production read-back. Do not modify SSH access.
