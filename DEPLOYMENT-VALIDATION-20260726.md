# Codestra provisioning service — staging deployment validation

Validated 2026-07-26 UTC.

## Deployment

```text
SERVICE=codestra-provisioning-service
ENVIRONMENT=staging
IMAGE=codestra/provisioning-service:identity-integration-20260726-v10
IMAGE_ID=sha256:94824414ceef7986dc63e7e17815229b7bf9626854ce1f7f6f0a4ef405427748
CONTAINER_HEALTH=healthy
HOST_PORTS=none
NETWORKS=private,telephony_private,keycloak_staging
```

The API is exposed only through the private Docker networks. No host port is
published and no public listener was found.

## Gates

```text
PROVISIONING_SERVICE_GATE=PASS
SERVICE_AUTHENTICATION_GATE=PASS
SERVICE_AUTHORIZATION_GATE=PASS
STEP_ENGINE_GATE=PASS
RETRY_GATE=PASS
DEAD_LETTER_GATE=PASS
CALLBACK_GATE=PASS
RECONCILIATION_GATE=PASS
SECRET_STORAGE_GATE=PASS
RESTART_RECOVERY_GATE=PASS
```

All gates are enabled in the protected staging environment file. The service
implements the requested Odoo, Keycloak, VICIdial, SIP, Agent Desktop,
email-provider, secret-storage, verification, and reconciliation adapter
boundaries; unconfigured providers remain individually fail-closed.

## Tests

The Python 3.12 isolated test image passed the full suite:

```text
29 passed, 1 warning
```

The live Keycloak staging acceptance separately passed creation, duplicate
suppression, role/group isolation, required password and MFA actions,
activation, suspension, reactivation, termination, session revocation,
reconciliation, and privilege-drift detection.

## Secret controls

```text
DIRECTORY_MODE=0700
DIRECTORY_OWNER=root:root
SECRET_FILES_MODE=0600
SECRET_FILES_OWNER=root:root
PLAINTEXT_CREDENTIAL_PERSISTENCE=disabled
PUBLIC_API_EXPOSURE=disabled
```
