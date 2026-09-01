# Provisioning runtime-source reconciliation

Date: 2026-09-01

`PROVISIONING_RUNTIME_EQUIVALENCE=UNPROVEN`

The existing recovery record remains authoritative. This record contains only file names and SHA-256 checksums; it does not import or assert equivalence of the running source.

| File | Runtime evidence SHA-256 | Protected source SHA-256 | Result |
|---|---|---|---|
| `app/__init__.py` | `7a222b09824bfda5d5e95c3da0902e73f19e5c37b0190c558c90e926630f0192` | `7a222b09824bfda5d5e95c3da0902e73f19e5c37b0190c558c90e926630f0192` | MATCH |
| `app/adapters.py` | `fb6dba02467fc8d0eba8cb8f4b017b660554c18ea5c4147d8126157adc3c3daa` | `4e705796ba3e7c17efad264566090a3a825566743441354123aaf65b7f871b0e` | DIFFERS |
| `app/callbacks.py` | `726e22bf897ae78afc0f52e4fc2ce99f7ceca019bf37c545919ee584860f17a1` | `726e22bf897ae78afc0f52e4fc2ce99f7ceca019bf37c545919ee584860f17a1` | MATCH |
| `app/config.py` | `e0b82e0e9af11fb840a32fd91f4e0df1b7b974a50f29d5bc46bb1f514a358c47` | `b3cabe1b8a65de2249656521312e8521af723bbaac332d491b88295ca9d2e370` | DIFFERS |
| `app/contracts.py` | `b9aab36e297d01ba512fe2bb92a3627eff398e99a03311cca1977f8909a73bf9` | `e98d6c8d604f013bb2e4cfed6b770f47ac19c9682b5f5f739d7ccd9b6c86e473` | DIFFERS |
| `app/engine.py` | `995235bd227d2b56c457c337d95a4cd20959068ec1825caac6310e98543731a2` | `1ad6c5fb39f1ebc9ebf715340be573ee29a8b9d7abf0bd7d03869e11dd3a330a` | DIFFERS |
| `app/keycloak.py` | `2cdeeb50f9bd1b1b02328007a2ff58ff66e50ba013d39d8e8d64e613bb9209bb` | `2cdeeb50f9bd1b1b02328007a2ff58ff66e50ba013d39d8e8d64e613bb9209bb` | MATCH |
| `app/logging.py` | `80af8924208f181a22c3f291c347348e2f50a596be3d82291f863c852c76ec06` | `c3020bbfbde822a2aca8a3b2e73c822d53a4f3e4fd26ac74c7cec0559cd87292` | DIFFERS |
| `app/mailbox.py` | `a34ea4ae08d17e7d1e8850e7542b5b6c57d85b05376daa28d3d0c6a9aa2f239a` | `a34ea4ae08d17e7d1e8850e7542b5b6c57d85b05376daa28d3d0c6a9aa2f239a` | MATCH |
| `app/main.py` | `880b30dd55c7b65789c7dcd7d483561979dbb6910b300feee39938c4bf8bb1fa` | `759c09b83767ad87a74ea98fc57efd3734ae9bea774fbc977ca75baeea5603ea` | DIFFERS |
| `app/repository.py` | `c4ef40bcdbfad59c68d7296494b06ea9cae3d35cce0331e58920a3dc390cd1db` | `f21b5d98ad9472cbb3fc5047bd8554e1e15303963b67903af0dee44413d60d05` | DIFFERS |
| `app/readiness.py` | `ABSENT` | `a779bff971a65756e14cacc62b0cd2a748b5fb9ece7f82ca0bd81b539fecbde8` | PROTECTED_ONLY |
| `app/secrets.py` | `715c26eb2b1e7173bddbc171c7a572a1199178097a815822648ca52f3eaf6090` | `715c26eb2b1e7173bddbc171c7a572a1199178097a815822648ca52f3eaf6090` | MATCH |
| `app/security.py` | `571452d7d6ea94df36a27e1243b62f9beeb31c0e6d9c2954d0a7c6fc03579c13` | `8e21c7c97302e9d4e2f577bea9afd3f04105b6a6c1eb77adaf7f52e8e2b85d99` | DIFFERS |
| `app/sip_browser.py` | `6751cf18c73449bcd4f126acbae4584aca79330a040dcb42638aade28ca984ca` | `b965b7eb87d02a853dd6a9e136feb01812c20169e8568e22c1d770a130611df6` | DIFFERS |

A future candidate must be built from protected `main`, pass exact-head tests and security gates, and publish an immutable digest, SBOM, provenance, and signature. Only independent behavioral and artifact verification may supersede `UNPROVEN`. This PR does not authorize deployment.
