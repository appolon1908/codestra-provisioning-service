# Canonical VICIdial provisioning client

VICidial `create_disabled` calls the private adapter route
`POST /v1/agents/provision-disabled`. The client uses the dedicated
`telephony:agent-provision` scope and the canonical version-2 HMAC contract,
which binds the version, method, path, service identity, sorted scopes,
timestamp, nonce, idempotency key, and body digest.

The configured base URL is the reviewed Server B 8443
`/restricted-vicidial` Apache location. Apache removes only that external
location prefix when forwarding to the loopback adapter, so the signed backend
path remains `/v1/agents/provision-disabled`; this is the existing Server B
destination, not a substitute backend.

Legacy `/v1/provisioning/create_user_disabled` is not a supported fallback.
Other VICidial lifecycle operations remain unsupported by this client until a
separately reviewed canonical route exists. SIP routing is unchanged.

Production configuration must keep `vicidial.enabled=false` until an exact,
expiring, single-user policy has been installed on Server B and the deployed
adapter digest and negative tests have been verified. This change does not
require or authorize `PRODUCTION_BUSINESS_WRITES_ENABLED=YES`; unrelated
business writes and dialing gates stay closed.
