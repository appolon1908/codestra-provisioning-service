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
case "$PROVISIONING_IMAGE" in
  *@sha256:*) ;;
  *) echo "immutable PROVISIONING_IMAGE digest required" >&2; exit 2 ;;
esac

docker run --rm \
  --name codestra-provisioning-sqlite-restore \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --memory 256m \
  --cpus 0.5 \
  --entrypoint /opt/venv/bin/python \
  -v "$backup_root:/backups:rw" \
  -v "$key:/run/secrets/sqlite_backup_key:ro" \
  "$PROVISIONING_IMAGE" \
  /app/scripts/sqlite_lifecycle.py restore-verify \
  --backup "/backups/${latest##*/}" \
  --key-file /run/secrets/sqlite_backup_key
