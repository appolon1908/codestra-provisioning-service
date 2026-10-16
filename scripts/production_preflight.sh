#!/usr/bin/env bash
set -uo pipefail

# Protected Git must adopt an accepted canonical release before activation.
canonical_image=''
requested_image=${PROVISIONING_IMAGE:-}
image=$canonical_image
secret_dir=${PROVISIONING_SECRET_DIR:-/etc/codestra/secrets/provisioning-service-production}
compose_file=${PROVISIONING_COMPOSE_FILE:-deploy/compose.production.yaml}
failures=0

pass() { printf 'PASS|%s\n' "$1"; }
fail() { printf 'FAIL|%s\n' "$1"; failures=$((failures + 1)); }
reject() { fail "$1"; printf 'SUMMARY|failures=%d\n' "$failures"; exit 1; }

canonical_reference() {
  [[ "$1" =~ ^ghcr\.io/appolon1908/codestra-provisioning-service@sha256:[0-9a-f]{64}$ ]] &&
    [[ "${1##*@sha256:}" =~ [1-9a-f] ]]
}

[ -n "$canonical_image" ] || reject canonical_release_adopted
canonical_reference "$canonical_image" || reject canonical_image_digest_pinned
pass canonical_release_adopted

canonical_reference "$requested_image" || reject image_digest_pinned
pass image_digest_pinned

if [ "$requested_image" = "$canonical_image" ]; then
  pass image_authority_match
else
  reject image_authority_match
fi

if docker compose -f "$compose_file" config --quiet &&
   [ "$(docker compose -f "$compose_file" config --images | sort -u)" = "$canonical_image" ]; then
  pass compose_validation
else
  fail compose_validation
fi

if docker manifest inspect "$image" >/dev/null 2>&1; then
  pass immutable_image_available
else
  fail immutable_image_available
fi

if command -v cosign >/dev/null 2>&1 && cosign verify \
  --certificate-identity 'https://github.com/appolon1908/codestra-provisioning-service/.github/workflows/ci.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$image" >/dev/null 2>&1; then
  pass image_signature
else
  fail image_signature
fi

if [ -d "$secret_dir" ] && [ "$(stat -c %a "$secret_dir")" = 700 ]; then
  pass secret_directory_mode
else
  fail secret_directory_mode
fi

required_secrets=(
  service.env keycloak_client_secret adapter_config.json jwt_public_key.pem
  credential_encryption_key odoo_callback_hmac ca.crt server.crt server.key
  sqlite_backup_key telephony_hmac_key telephony_client.crt
  telephony_client.key telephony_ca.crt turn_shared_secret
)
for name in "${required_secrets[@]}"; do
  path="$secret_dir/$name"
  if [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -c %a "$path")" = 600 ]; then
    pass "secret:$name"
  else
    fail "secret:$name"
  fi
done

if openssl verify -CAfile "$secret_dir/ca.crt" "$secret_dir/server.crt" >/dev/null 2>&1 &&
   openssl x509 -in "$secret_dir/server.crt" -checkhost provisioning-service-production -noout >/dev/null 2>&1 &&
   openssl x509 -in "$secret_dir/server.crt" -checkend $((30 * 86400)) -noout >/dev/null 2>&1; then
  pass production_server_certificate
else
  fail production_server_certificate
fi

for network in codestra-identity_identity_service codestra-provisioning-service_telephony_private; do
  if docker network inspect "$network" >/dev/null 2>&1; then
    pass "network:$network"
  else
    fail "network:$network"
  fi
done

if systemctl is-enabled --quiet codestra-provisioning-sqlite-backup.timer 2>/dev/null &&
   systemctl is-active --quiet codestra-provisioning-sqlite-backup.timer 2>/dev/null; then
  pass sqlite_backup_timer
else
  fail sqlite_backup_timer
fi

if systemctl is-enabled --quiet codestra-provisioning-sqlite-restore.timer 2>/dev/null &&
   systemctl is-active --quiet codestra-provisioning-sqlite-restore.timer 2>/dev/null; then
  pass sqlite_restore_timer
else
  fail sqlite_restore_timer
fi

if docker ps --format '{{.Names}}' | grep -Fxq codestra-provisioning-production-provisioning-service-1; then
  pass production_container_present
else
  fail production_container_present
fi

printf 'SUMMARY|failures=%d\n' "$failures"
exit "$((failures > 0))"
