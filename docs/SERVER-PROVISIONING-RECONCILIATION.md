# Server Provisioning Reconciliation

## Frozen evidence and provenance

- `NEW_ARCHITECTURE_MAIN_SHA=db970edc54207945b7c0bb1547a84b1bdd8905b9`
- `SERVER_CAPTURE_SHA=3018e3a3862de0be6f1eff26197c60a555091a3d`
- `SERVER_SOURCE_PROVENANCE=UNKNOWN`
- `IMAGE_DIGEST=sha256:db7dfcf1d8547d9daa9f1e1b7f7f834b0138b95e15fce95345e4e2e1211ed578`
- Captured image: `codestra/provisioning-service:identity-integration-20260726-v15`
- Evidence branch: `import/server-provisioning-20260828` (read-only; never merge directly)

The server directory had no Git metadata and the image had no OCI source/revision labels. This document does not invent a historical commit. Future images must carry `org.opencontainers.image.source`, `org.opencontainers.image.revision`, and `org.opencontainers.image.version`.

## Authority boundary

| Authority | Owns | Must not own |
|---|---|---|
| Provisioning service | Resource lifecycle, bootstrap provisioning, extension/resource allocation, status, reconciliation and rollback | Cross-system capability policy or ingress identity policy |
| Middleware | Tenant/capability enforcement and durable command/event orchestration | Provider-local provisioning state |
| Kong | Ingress authentication enforcement and traffic policy | Provisioning lifecycle state |
| Keycloak | Identity, tokens, clients and claims | Cross-system command orchestration |

## Functional reconciliation

| Area | Captured behavior | Canonical decision | Classification | Required tests |
|---|---|---|---|---|
| API and security | JWT validation, request bounds, rate limits, staging-only gates | Preserve main security/readiness controls; port only missing endpoints/contracts | `KEEP_AND_PORT` | invalid tenant, audience/client/scope, body limit, rate limit, disabled capability |
| Operation contracts | Requested operations and target systems | Extend to request ID, tenant, resource type, desired state, idempotency key and operation ID | `KEEP_AND_PORT` | duplicate command, semantic conflict and lifecycle transition tests |
| Execution engine | Multi-step execution, retries and adapter errors | Represent requested→validated→planned→executing→verifying→completed/failed with durable recovery | `KEEP_AND_PORT` | timeout, partial success, restart, retry, rollback and read-back mismatch |
| Repository | SQLite-backed state in capture | Preserve main lifecycle/recovery controls; define migration and locking requirements before schema change | `KEEP_AND_PORT` | restart, locking, backup/restore, migration replay and duplicate operation |
| Adapters | Identity, email and telephony/provider actions | Explicit adapters with normalized errors, idempotency and mandatory read-back | `KEEP_AND_PORT` | provider unavailable, 429/500, duplicate and read-back tests |
| Keycloak | Client/bootstrap provisioning | Keep Keycloak as identity owner and require least-privilege service identity | `KEEP_AND_PORT` | issuer, JWKS, allowed client, rotation and rollback tests |
| SIP/browser | Short-lived browser/telephony resources | Keep separate from Middleware telephony command authority | `KEEP_AND_PORT` | expiry, replay, secret non-disclosure and revocation tests |
| Readiness | Stronger readiness module exists only on main | Preserve current main implementation | `ALREADY_IMPLEMENTED` | missing secret, DB unavailable, dependency unavailable and migration mismatch |
| Mailbox support | Stronger mailbox module exists only on main | Preserve current main implementation and reconcile adapter overlap | `ALREADY_IMPLEMENTED` | duplicate mailbox, provider retry and read-back tests |
| No-effect preflight | Missing from capture; authoritative shell preflight exists on main | Preserve and later evolve to one canonical no-effect command | `ALREADY_IMPLEMENTED` | all effects disabled, digest/migration/dependency checks, zero mutations |
| Build provenance | Capture image lacks OCI provenance | Replace with main build plus mandatory source/revision/version labels | `REPLACE` | image-label and source-to-digest manifest tests |
| Deployment overlays | Capture has root-level historical Compose variants | Extract behavior into owned staging/production definitions; do not copy chain verbatim | `KEEP_AND_PORT` | Compose validation, secret references, isolation and resource limits |

## Complete changed-path classification

All **75** paths differing between main and the frozen capture are classified below.

| Git status | Path | Classification | Decision |
|---|---|---|---|
| `M` | `.dockerignore` | `REPLACE` | Keep the newer reproducible/provenance-aware build controls and selectively add only server-required runtime behavior. |
| `A` | `.env.example` | `KEEP_AND_PORT` | Use the capture to complete a value-free environment contract while retaining main's fail-closed defaults. |
| `D` | `.github/CODEOWNERS` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `.github/workflows/ci.yml` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `.gitignore` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `.gitleaks.toml` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `APP-PROVISIONING-COMPLETION-20260726.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `APP-PROVISIONING-RUNTIME-AUDIT-20260726T0412Z.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `CANONICAL-KEYCLOAK-VERIFIER.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `CONCURRENT-RUNTIME-CHANGE-20260726T0413Z.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `A` | `DEPLOYMENT-VALIDATION-20260726.md` | `KEEP_AND_PORT` | Retain factual validation evidence only where independently reproducible; historical assertions are not release proof. |
| `M` | `Dockerfile` | `REPLACE` | Keep the newer reproducible/provenance-aware build controls and selectively add only server-required runtime behavior. |
| `M` | `Dockerfile.test` | `REPLACE` | Keep the newer reproducible/provenance-aware build controls and selectively add only server-required runtime behavior. |
| `D` | `Dockerfile.test.dockerignore` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `A` | `ENVIRONMENT-VARIABLES.md` | `KEEP_AND_PORT` | Use the capture to complete a value-free environment contract while retaining main's fail-closed defaults. |
| `M` | `README.md` | `KEEP_AND_PORT` | Update canonical documentation with verified live behavior without discarding current governance and recovery guidance. |
| `D` | `RECOVERED-SOURCE-PROVENANCE.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `SECURITY.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `A` | `SERVER-VS-GITHUB-DRIFT.md` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `M` | `app/adapters.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `M` | `app/config.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `M` | `app/contracts.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `M` | `app/engine.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `M` | `app/logging.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `D` | `app/mailbox.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `M` | `app/main.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `D` | `app/readiness.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `M` | `app/repository.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `M` | `app/security.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `M` | `app/sip_browser.py` | `KEEP_AND_PORT` | Compare behavior at contract level and port only missing lifecycle capability behind canonical authority and fail-closed controls. |
| `A` | `compose.live-delivery-safety.yaml` | `KEEP_AND_PORT` | Extract verified service/network/health behavior into canonical deploy files; do not restore the historical overlay chain verbatim. |
| `A` | `compose.protected-0e7d889.yaml` | `KEEP_AND_PORT` | Extract verified service/network/health behavior into canonical deploy files; do not restore the historical overlay chain verbatim. |
| `A` | `compose.webrtc-6101-controlled.yaml` | `KEEP_AND_PORT` | Extract verified service/network/health behavior into canonical deploy files; do not restore the historical overlay chain verbatim. |
| `A` | `compose.webrtc-6101-controlled.yaml.pre-wss-decouple-20260819T0208Z` | `KEEP_AND_PORT` | Extract verified service/network/health behavior into canonical deploy files; do not restore the historical overlay chain verbatim. |
| `A` | `compose.yaml` | `KEEP_AND_PORT` | Extract verified service/network/health behavior into canonical deploy files; do not restore the historical overlay chain verbatim. |
| `D` | `deploy/canonical-verifier.env.example` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/compose.identity-relay.yaml` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/compose.production.yaml` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/production.env.example` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/provisioning-sqlite.rules.yml` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/staging-candidate.override.yaml` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/systemd/codestra-provisioning-sqlite-backup.service` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/systemd/codestra-provisioning-sqlite-backup.timer` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/systemd/codestra-provisioning-sqlite-restore.service` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `deploy/systemd/codestra-provisioning-sqlite-restore.timer` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `docs/CHANGE-APPROVAL-CHECKLIST.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `docs/PRODUCTION-GOVERNANCE.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `docs/PRODUCTION-PREFLIGHT.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `docs/SQLITE-RECOVERY.md` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `M` | `pyproject.toml` | `REPLACE` | Resolve dependencies from current main and revalidate server behavior; do not regress to captured dependency state. |
| `M` | `requirements-dev.txt` | `REPLACE` | Resolve dependencies from current main and revalidate server behavior; do not regress to captured dependency state. |
| `M` | `requirements.txt` | `REPLACE` | Resolve dependencies from current main and revalidate server behavior; do not regress to captured dependency state. |
| `M` | `scripts/keycloak_acceptance.py` | `KEEP_AND_PORT` | Retain the stronger main script and incorporate only verified no-effect checks or acceptance semantics. |
| `D` | `scripts/production_preflight.sh` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `scripts/run_sqlite_restore_rehearsal.sh` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `scripts/sqlite_lifecycle.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `A` | `server-baseline/README.md` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/SERVER-RUNTIME-MANIFEST.md` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/TEST-RESULTS.md` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/deployment/01-compose.yaml` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/deployment/INDEX.json` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/networks.json` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/provenance/gitleaks-report.json` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/provenance/source.json` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/runtime-image.json` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `A` | `server-baseline/runtime-services.json` | `DEPRECATED` | Evidence remains on the frozen import branch; do not copy capture artifacts into canonical runtime source. |
| `M` | `tests/test_adapters.py` | `KEEP_AND_PORT` | Preserve current coverage and add captured regressions that prove required server behavior without live effects. |
| `M` | `tests/test_api_security.py` | `KEEP_AND_PORT` | Preserve current coverage and add captured regressions that prove required server behavior without live effects. |
| `M` | `tests/test_engine.py` | `KEEP_AND_PORT` | Preserve current coverage and add captured regressions that prove required server behavior without live effects. |
| `D` | `tests/test_mailbox.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `tests/test_readiness.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `M` | `tests/test_repository.py` | `KEEP_AND_PORT` | Preserve current coverage and add captured regressions that prove required server behavior without live effects. |
| `D` | `tests/test_security_and_callbacks.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `tests/test_sip_browser_contract.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |
| `D` | `tests/test_sqlite_lifecycle.py` | `ALREADY_IMPLEMENTED` | Present only on current main; preserve the newer governance, security, recovery, preflight or test control. |

## Classification summary

- `ALREADY_IMPLEMENTED`: **35**
- `DEPRECATED`: **11**
- `KEEP_AND_PORT`: **23**
- `REPLACE`: **6**
- `UNKNOWN_PATHS=0`

## Canonical lifecycle requirement

Every command must durably carry request ID, tenant, resource type, desired state, idempotency key, operation ID, status and read-back. The canonical lifecycle is `requested → validated → planned → executing → verifying → completed`, or `failed → reconciliation/rollback`. Repeated equivalent requests return the same operation; conflicting reuse is rejected.

## No-effect preflight decision

Current main already contains `scripts/production_preflight.sh`; the capture deleted it. Preserve main. A later implementation milestone may replace it with a single Python entrypoint only if coverage is at least equivalent. It must verify environment, issuer, required secret-file presence, database reachability, Middleware reachability, Kong contract, disabled capabilities/effects, deployment digest and migration state without provisioning any resource.

## Map exit gate

- Every changed path is classified.
- Server provenance remains explicitly unknown; image digest is recorded.
- Stronger main security, governance, readiness, preflight and recovery controls are retained.
- No provisioning code was ported by this milestone.
