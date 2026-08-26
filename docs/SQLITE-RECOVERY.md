# Provisioning SQLite recovery

The authoritative provisioning state store is `/var/lib/codestra/provisioning.db`.
It is not interchangeable with the platform PostgreSQL service.

## Backup contract

Run `scripts/sqlite_lifecycle.py backup` at least daily using a dedicated 32-byte
key from the approved secret store. The command uses SQLite's online backup API,
runs integrity and quick checks on the snapshot, encrypts it with AES-256-GCM,
and writes checksum and retention metadata. Copy the encrypted artifact and its
metadata to the approved off-host repository. Never copy the live database file.

Alert if the latest successful off-host backup is older than 24 hours. Keep the
encryption key outside both the application volume and backup failure domain.
The source-controlled systemd units under `deploy/systemd` schedule daily online
backups and monthly isolated restore rehearsals. Their environment file must pin
`PROVISIONING_IMAGE` by registry digest; mutable tags are rejected by the restore
runner and must not be used for the backup unit.

## Recovery procedure

1. Make readiness fail and stop application writes. Record the incident time.
2. Preserve the failed database, WAL, and SHM files without modifying them.
3. Select the newest off-host backup whose encrypted SHA-256 matches its metadata.
4. Run `restore-verify` into an isolated filesystem. Require `integrity_check=ok`,
   `quick_check=ok`, and a non-empty application schema.
5. Start the approved application image against a disposable copy and verify
   repository initialization plus `/ready`; do not connect callbacks or adapters.
6. Confirm application/schema rollback compatibility before replacing state.
7. During an approved maintenance window, restore the validated database with
   owner `10001:10001`, directory mode `0700`, and database mode `0600`.
8. Start production, verify readiness and metrics, then reconcile pending steps,
   callbacks, compensations, and dead letters using their idempotency controls.
9. Record restore point, checksum, RPO, RTO, operator, and post-restore evidence.

Never restore over the active database, reuse an expired certificate, discard the
failed files, or replay workflow records without owner approval.
