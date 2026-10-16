# Provisioning production governance packet

Change: `CHG-20260826-PROVISIONING-PRODUCTION-01`

Status: **PROPOSED — NOT APPROVED**. This packet becomes authoritative only
when Ralph Appolon records approval and an independent authorized reviewer
records approval on the linked GitHub change issue for the exact commit.

## Accountability

| Responsibility | Owner |
| --- | --- |
| Accountable, security, identity, PKI, release, rollback, database, workflow, capability | Ralph Appolon (`appolon1908-hue`) |
| Independent approver | `kazan555` |

## Release signing

- Model: Sigstore keyless
- OIDC issuer: `https://token.actions.githubusercontent.com`
- Repository: `appolon1908-hue/codestra-provisioning-service`
- Workflow: `.github/workflows/ci.yml`
- Ref: `refs/heads/main`
- Protected environment: `provisioning-production-release`
- Certificate identity: `https://github.com/appolon1908-hue/codestra-provisioning-service/.github/workflows/ci.yml@refs/heads/main`
- Verification: exact digest, Fulcio identity and issuer, Rekor inclusion, SBOM,
  and SLSA provenance must pass before deployment.

The signing job may use only `contents: read`, `packages: write`, and
`id-token: write`. Mutable tags are not deployment authority.

## Production identity

- Client ID/type: `codestra-provisioning-service` / confidential
- Service account: enabled
- Standard, implicit, and direct-access-grant flows: disabled
- Full scope: disabled
- Issuer: `https://auth.codestra.co/realms/codestra`
- Audience and authorized party: `codestra-provisioning-service`
- Required scopes: `identity:rotate`, `provisioning:execute`, `provisioning:read`
- Maximum access-token TTL: 300 seconds; algorithm: RS256
- Realm-management roles: `query-users`, `view-users`, `manage-users`,
  `view-clients`, `view-realm`
- Forbidden roles: `realm-admin`, `manage-realm`, `manage-clients`
- Secret, rotation, and revocation owner: Ralph Appolon
- Proposed rotation interval: 90 days

Server-side allowlists for groups, realm roles, client roles, redirect targets,
and identity attributes remain mandatory.

## Production PKI

- CA: `Codestra Provisioning Production CA`
- CA validity: 5 years
- Leaf validity: 90 days
- Renewal begins: 30 days before expiry
- PKI, rotation, and trust-distribution owner: Ralph Appolon
- Server profile: `serverAuth`, SAN `provisioning-service-production`
- Telephony profile: `clientAuth`, issued only when the adapter is approved
- Callback certificate: issued only for the discovered, approved trust direction

Trust consumers must be derived from production Compose, adapter configuration,
middleware callback configuration, telephony configuration, and monitoring
probes. No unrelated trust store may be modified.

## Capability policy

| Capability | Proposed classification | Readiness effect | Write policy |
| --- | --- | --- | --- |
| verification | REQUIRED | fail when degraded | bounded provisioning operations |
| reconciliation | REQUIRED | fail when degraded | audited and idempotent |
| odoo | REQUIRED for callback only | fail when callback dependency is unusable | no broad Odoo writes |
| agent_desktop | OPTIONAL | no failure while disabled | disabled unless separately approved |
| n8n_event | INTENTIONALLY_DISABLED | none | no writes |
| email_provider | INTENTIONALLY_DISABLED absent approved credentials | none | no sends |
| vicidial | REQUIRED for approved non-dialing provisioning | fail when unavailable | dialing and writes disabled |
| sip | REQUIRED only for `TEST_SYN` endpoint `6101` | fail when enabled and unavailable | certification boundary only |

Capability owner and activation approver: Ralph Appolon.

## Release gate

Production deployment, secret activation, monitoring, timers, canaries, DR,
rollback, and load/soak require an exact maintenance window recorded on the
change issue after signing, identity, PKI, secrets, backup/restore, monitoring,
and rollback prechecks pass. Time zone: `America/Santo_Domingo`; proposed window
is the next available 00:00–04:00.

## Canonical ownership amendment — 2026-10-16

The original `CHG-20260826-PROVISIONING-PRODUCTION-01` proposal, owner identity,
and signing identity above remain historical records; its status remains
**PROPOSED — NOT APPROVED**. Existing exact-commit approval requirements,
independent review, protected release environment, and maintenance-window
controls still apply.

Active repository authority is now `appolon1908/codestra-provisioning-service`.
Future canonical releases must be verified against
`https://github.com/appolon1908/codestra-provisioning-service/.github/workflows/ci.yml@refs/heads/main`
and the existing GitHub Actions OIDC issuer. The historical image
`ghcr.io/appolon1908-hue/codestra-provisioning-service@sha256:83669077e8b0c45a19c13cf688d4093cd639dadbb02f2bb3c3389170821d70f5`
has not been relabeled or adopted as a canonical release. Preflight's protected
canonical image pin is empty, so activation fails closed until a real canonical
release is accepted and its exact digest is reviewed into protected Git through
the existing approval process. An environment candidate or CI parsing fixture
cannot supply that authority. This amendment records source ownership and
verification policy only; it records no release acceptance or live activation.
