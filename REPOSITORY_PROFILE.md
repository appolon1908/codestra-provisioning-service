# Repository Profile — `codestra-provisioning-service`

## Identity

- **Repository:** `appolon1908-hue/codestra-provisioning-service`
- **Category:** Platform service — provisioning
- **Visibility:** `private`
- **Default branch:** `main`
- **Authority:** Controlled provisioning and resource-lifecycle runtime authority
- **Status:** Active platform service repository whose production actions must remain approval-gated and observable.

## Purpose

Coordinates reviewed creation, update, reconciliation, and retirement of campaigns, tenants, integration resources, service configuration, and other platform-owned resources.

## Owns

- Provisioning commands, state, idempotency, audit, and reconciliation
- Approved provider/resource adapters
- Plan/apply/read-back/rollback evidence for provisioned resources

## Does not own

- Unreviewed direct changes to provider systems
- Application business state already owned by product repositories or Odoo
- Keycloak, Kong, Caddy, or Middleware source authority

## Key integrations

- Middleware as the privileged command boundary
- Odoo and n8n through approved contracts
- Keycloak, Kong, provider runtimes, and infrastructure repositories

## Current priorities

1. Define explicit resource types and ownership boundaries
2. Require plan, approval, idempotency, read-back, and rollback for every effectful operation
3. Keep provider credentials external and narrowly scoped
4. Add drift, failure, partial-apply, reconciliation, and disaster-recovery tests

## Governance and safety

- Target promotion model: `feature/docs/fix/security/upgrade -> development -> test -> staging -> production -> main`.
- Use pull requests and exact-head/merge-result validation; merging source never authorizes provisioning.
- Never commit credentials, private keys, customer data, provider payload secrets, or database dumps.
- Production artifacts must be immutable and every live action separately approved.
- This document does not provision resources, apply identity/gateway state, or activate production.

## Account-wide catalog

See `appolon1908-hue/documentaions/REPOSITORY_CATALOG.md`.
