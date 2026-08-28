# Environment variable inventory

Generated from the captured application, workers, Dockerfiles, Compose files, and scripts. No live values are included. Requirement/default semantics remain defined by the referenced code.

| Variable | Requirement | Secret | Consumers |
|---|---|---|---|
| `ACCEPTANCE_GROUP_PATH` | inspect code/default | no/inspect deployment | application/runtime |
| `ACCEPTANCE_STAMP` | inspect code/default | no/inspect deployment | application/runtime |
| `ADAPTER_CONFIG_FILE` | inspect code/default | no/inspect deployment | application/runtime |
| `CLAIM_TIMEOUT_SECONDS` | inspect code/default | no/inspect deployment | application/runtime |
| `CREDENTIAL_ENCRYPTION_KEY_FILE` | inspect code/default | yes | application/runtime |
| `ENVIRONMENT` | inspect code/default | no/inspect deployment | application/runtime |
| `JWT_ALGORITHMS` | inspect code/default | no/inspect deployment | application/runtime |
| `JWT_ALLOWED_CLIENTS` | inspect code/default | no/inspect deployment | application/runtime |
| `JWT_AUDIENCE` | inspect code/default | no/inspect deployment | application/runtime |
| `JWT_ISSUER` | inspect code/default | no/inspect deployment | application/runtime |
| `JWT_PUBLIC_KEY_FILE` | inspect code/default | no/inspect deployment | application/runtime |
| `ODOO_CALLBACK_CA_FILE` | inspect code/default | no/inspect deployment | application/runtime |
| `ODOO_CALLBACK_HMAC_SECRET_FILE` | inspect code/default | yes | application/runtime |
| `ODOO_CALLBACK_URL` | inspect code/default | no/inspect deployment | application/runtime |
| `RATE_LIMIT_REQUESTS` | inspect code/default | no/inspect deployment | application/runtime |
| `RATE_LIMIT_WINDOW_SECONDS` | inspect code/default | no/inspect deployment | application/runtime |
| `REQUEST_MAX_AGE_SECONDS` | inspect code/default | no/inspect deployment | application/runtime |
| `REQUEST_MAX_BYTES` | inspect code/default | no/inspect deployment | application/runtime |
| `RETRY_BASE_SECONDS` | inspect code/default | no/inspect deployment | application/runtime |
| `STATE_DATABASE_PATH` | inspect code/default | no/inspect deployment | application/runtime |
| `TLS_CERT_FILE` | inspect code/default | no/inspect deployment | application/runtime |
| `TLS_KEY_FILE` | inspect code/default | no/inspect deployment | application/runtime |
| `TURN_SHARED_SECRET_FILE` | inspect code/default | yes | application/runtime |
