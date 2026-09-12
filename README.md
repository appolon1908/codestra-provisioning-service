# Codestra Provisioning Service

Private, staging-only identity and access provisioning orchestration for Odoo,
Keycloak, VICIdial, SIP, Agent Desktop, hosted email, protected credential
storage, n8n event notification, verification, and reconciliation.

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
MIDDLEWARE_INVOCATION_REQUIRED_GATE=
```

The dedicated staging configuration enables them. Provider adapters remain
disabled individually until an approved HTTPS endpoint, CA, and protected
credential file are added to `adapter_config.json`.

## Authority boundary: this service is not a second provisioning authority

Per `appolon1908-hue/Infustruction-repo#124` (ADR), `appolon1908-hue/Middleware-`
is the sole canonical public provisioning authority
(`POST /platform/v1/agent-provisioning/requests`). This service is the private
downstream execution layer Middleware's saga invokes -- it must not be
independently triggerable.

A caller presenting a valid, correctly-scoped service JWT is necessary but not
sufficient to reach a mutating route (`execute`, `retry`, `verify`, `cancel`,
the `/v1/identities/{employee_id}/*` lifecycle routes, and the SIP browser
session `create`/`renew`/`revoke` routes). Those routes additionally require an
HMAC attestation proving Middleware orchestrated the call:

```text
X-Middleware-Timestamp: <unix seconds>
X-Middleware-Signature: sha256=<hex hmac-sha256 of "<timestamp>.<raw request body>"
                         using MIDDLEWARE_INVOCATION_HMAC_SECRET_FILE>
```

The signature covers the exact raw request body (same convention as the
existing outbound Odoo callback signing in `callbacks.py`) and is replay-
protected via the same `replay_jti` table used for JWT `jti`s. A missing,
stale, or invalid attestation is rejected (`401`) before the engine is ever
invoked; read-only routes (`GET .../requests/{id}`, `GET .../reconciliation`,
`GET /config`) are unaffected. `MIDDLEWARE_INVOCATION_REQUIRED_GATE` is part of
the same fail-closed `GATES` tuple as every other capability -- the service
cannot report `/ready` while this attestation requirement is disabled, so it
can never become fully live without also requiring proof of Middleware
orchestration. See `app/security.py::require_middleware_invocation` and
`tests/test_api_security.py::test_execute_request_requires_middleware_invocation_even_with_valid_scope`.

**Known limitation, tracked for the actual Middleware-side integration work**:
this service does not yet have a live caller anywhere in the organization --
`Middleware-`'s `connectors/manifests/provisioning-service.connector.json` is
an explicit `UNVERIFIED_TEMPLATE_ONLY` scaffold with
`runtime_activation_authorized: false`. Activating that connector (issuing the
shared HMAC secret to Middleware, wiring its saga to call this service's
routes with the attestation headers above) is separate follow-up work, not
done as part of this change.

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
