#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_root=/var/backups/codestra/provisioning
key=/etc/codestra/secrets/provisioning-service-production/sqlite_backup_key
latest=$(find "$backup_root" -maxdepth 1 -type f -name 'provisioning-*.sqlite3.aes256gcm' -printf '%T@ %p\n' \
  | sort -nr | head -1 | cut -d' ' -f2-)
test -n "$latest"
test -f "$latest.json"
test -n "${PROVISIONING_IMAGE:-}"
test -n "${PROVISIONING_RELEASE_SHA:-}"
test -n "${PROVISIONING_RECOVERY_MAX_AGE_SECONDS:-}"
case "$PROVISIONING_IMAGE" in
  *@sha256:*) ;;
  *) echo "immutable PROVISIONING_IMAGE digest required" >&2; exit 2 ;;
esac
[[ "$PROVISIONING_RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "immutable PROVISIONING_RELEASE_SHA required" >&2; exit 2; }
[[ "$PROVISIONING_RECOVERY_MAX_AGE_SECONDS" =~ ^[1-9][0-9]*$ ]] || { echo "positive recovery age limit required" >&2; exit 2; }

# AES-GCM ciphertext is close to the SQLite snapshot size, while the restore
# needs room for both decrypted bytes and SQLite integrity-check scratch data.
# Scale from the exact backup with a safe floor and a hard memory ceiling.
backup_bytes=$(stat -c %s "$latest")
test "$backup_bytes" -gt 0
scratch_bytes=$((backup_bytes * 4))
minimum_scratch=$((64 * 1024 * 1024))
maximum_scratch=$((2 * 1024 * 1024 * 1024))
(( scratch_bytes >= minimum_scratch )) || scratch_bytes=$minimum_scratch
if (( scratch_bytes > maximum_scratch )); then
  echo "restore scratch requirement exceeds 2 GiB safety ceiling" >&2
  exit 3
fi
runtime_overhead=$((256 * 1024 * 1024))
memory_bytes=$((scratch_bytes + runtime_overhead))

docker run --rm \
  --name codestra-provisioning-sqlite-restore \
  --network none \
  --read-only \
  --tmpfs "/tmp:rw,noexec,nosuid,size=${scratch_bytes},uid=10001,gid=10001,mode=1777" \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --memory "${memory_bytes}b" \
  --cpus 0.5 \
  --entrypoint /opt/venv/bin/python \
  -v "$backup_root:/backups:rw" \
  -v "$key:/run/secrets/sqlite_backup_key:ro" \
  "$PROVISIONING_IMAGE" \
  /app/scripts/sqlite_lifecycle.py restore-verify \
  --backup "/backups/${latest##*/}" \
  --key-file /run/secrets/sqlite_backup_key \
  --temporary-directory /tmp \
  --expected-release-sha "$PROVISIONING_RELEASE_SHA" \
  --expected-image-reference "$PROVISIONING_IMAGE" \
  --max-age-seconds "$PROVISIONING_RECOVERY_MAX_AGE_SECONDS"
