# Codestra Provisioning Fabric v2

The provisioning service is the controlled executor for tenant and agent lifecycle changes. n8n coordinates the lifecycle but never receives destination credentials and never calls Keycloak, Odoo, VICIdial, Klyrow, Telnexa, Postly, Kyqra, or Beyvra directly.

```text
approved request -> Middleware durable command -> provisioning service
provisioning service -> destination adapter -> destination read-back
provisioning service -> Middleware result -> n8n coordination -> final reconciliation
```

## Supported request types

- Tenant bootstrap.
- Agent/user resource provisioning.
- Product entitlement provisioning.
- Resource suspension.
- Resource reactivation.
- Deprovisioning.
- Credential-rotation coordination without exposing credentials.
- Drift detection and operator-approved repair plans.

## Destination ownership

- Keycloak: authentication identity, service clients, groups, roles, sessions.
- Odoo: employee, user, company, campaign and CRM business projection.
- VICIdial/Asterisk: restricted agent/campaign/extension resources through the private adapter.
- Klyrow: workspace, mailbox, sender and email-domain projection.
- Telnexa: SMS account/sender projection.
- Postly: social workspace/account authorization state; provider tokens remain in Postly.
- Kyqra: crawler tenant policy and quotas.
- Beyvra: non-financial support/onboarding projection only.

## Transaction model

Provisioning is a durable saga. Each step records request fingerprint, target, desired state, prior safe state, attempt, provider reference, read-back, result, and compensation eligibility. A timeout is `UNKNOWN`; no retry occurs until read-back. Partial success is visible and recoverable.

Compensation never silently deletes an identity, financial record, audit record, provider account, mailbox, phone extension, or tenant. High-risk repair, suspension, deletion and replay require protected approval.

## Security

- Middleware-derived tenant and actor.
- Client Credentials with exact audience and scope.
- mTLS for private destination adapters.
- no passwords, OTPs, reset tokens, refresh tokens, private keys, API secrets, provider tokens, or SMTP/SMPP credentials in requests or logs.
- all write capabilities disabled by default.

No runtime provisioning is authorized by this source contract.
