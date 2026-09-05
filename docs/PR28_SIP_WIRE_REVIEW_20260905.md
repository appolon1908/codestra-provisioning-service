# PR #28 SIP compatibility repair

Prepared from PR #28 head `2d1210cccb4da2947df8a3de733d8ccc69b36fa9` on a
separate follow-up branch. The coordinated PR branch is not modified by this
session. Integrate through review, refresh its exact head and renew the required
review; the approval on the earlier head does not certify this change.

The shared telephony client must select the wire contract by target system:

| Target | Forwarded adapter path | HMAC contract |
| --- | --- | --- |
| VICIdial | `/v1/agents/provision-disabled` | v2: method, backend path, identity, scope, timestamp, nonce, idempotency key and body digest |
| SIP | `/v1/provisioning/<existing-operation>` | legacy: timestamp, nonce and body digest; no v2 header |

Ingress prefixes remain part of the configured base URL. Server B's readable
Apache include maps `/restricted-vicidial/` to `http://127.0.0.1:8097/`.
VICIdial signs the backend path, not the external prefix. This is config/source
evidence, not an authenticated end-to-end provisioning request.

Validation used an isolated Python 3.12.14 venv with requirements-dev.txt:

- `ruff check app tests scripts`: PASS.
- `python -m pytest -q`: 104 passed, two dependency deprecation warnings.
- Nine SIP lifecycle operations check full prefixed route and legacy HMAC.
- Browser rotation/renewal helper and revocation tests use the real adapter
  with an HTTP test transport and assert payload, signature, credential handling
  and distinct idempotency keys. Existing expiry/identity tests remain passing.
- VICIdial v2 route, dedicated scope and canonical signature remain covered.
- Secret scanning found no leaks in changed source/test files.

All HTTP interactions are synthetic test transports. No browser credentials,
accounts, calls, production services, flags, policy or database grants changed.
This evidence does not establish installed runtime compatibility or a release.
