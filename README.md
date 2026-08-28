# Codestra Provisioning Service

Private, staging-only identity and access provisioning orchestration for Odoo,
Keycloak, VICIdial, SIP, Agent Desktop, hosted email, protected credential
storage, verification, and reconciliation.

## Security boundary

- The service listens on TLS port 8443 only inside the Compose `private`
  network. No host port is published and the network is Docker-internal.
- Domain APIs require a Keycloak service JWT with exact issuer, audience,
  authorized client, route-specific scope, expiry, not-before, and unique `jti`.
- Request bodies are bounded and timestamp-fresh. JWT replay and rate-limit
  state are durable.
- Secrets are file-mounted through an ephemeral initializer. The host directory
  is `0700 root:root`; files are `0600 root:root`. The runtime receives
  read-only `0400` copies owned by UID 10001.
- Adapter URLs and callback URLs must be credential-free HTTPS.
- Logs and error responses are sanitized. Plaintext credentials are never
  persisted; the secret-storage adapter persists authenticated ciphertext and
  returns a protected reference.

## Step semantics

External accounts must be created with `create_disabled`, verified, then
activated. Each step is durably claimed and independently idempotent. Transient
errors use bounded exponential retries; permanent or exhausted steps enter the
dead-letter table. Restart recovery reclaims stale work. Retrying an execution
selects only the first failed step.

A later-step failure never deletes a successfully created identity.
Compensation updates Odoo to remove excess access and suspends or revokes other
systems.

## Gates

All gates fail closed:

```text
PROVISIONING_SERVICE_GATE=
SERVICE_AUTHENTICATION_GATE=
SERVICE_AUTHORIZATION_GATE=
STEP_ENGINE_GATE=
RETRY_GATE=
DEAD_LETTER_GATE=
CALLBACK_GATE=
RECONCILIATION_GATE=
SECRET_STORAGE_GATE=
RESTART_RECOVERY_GATE=
```

The dedicated staging configuration enables them. Provider adapters remain
disabled individually until an approved HTTPS endpoint, CA, and protected
credential file are added to `adapter_config.json`.

## Operations

```bash
systemctl status codestra-provisioning-service
systemctl reload codestra-provisioning-service
journalctl -u codestra-provisioning-service
```

Health, readiness, and Prometheus metrics are available only inside the private
network at `/health`, `/ready`, and `/metrics`.

## Keycloak staging provisioning

The Keycloak adapter is enabled only through the private staging identity
network. Its confidential client is
`codestra-provisioning-service-staging`; the secret is root-owned and
file-mounted.

Users are created disabled with `UPDATE_PASSWORD` and `CONFIGURE_TOTP`. The
service never accepts or sends a user password. Group, realm-role, and
client-role assignments are checked against server-side allowlists. Browser
claims do not replace Odoo or provisioning-service authorization.

See `KEYCLOAK-PROVISIONING.md` and `KEYCLOAK-TEST-RESULTS.md`.
