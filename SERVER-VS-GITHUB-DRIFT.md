# Provisioning service server versus GitHub drift

This import intentionally preserves server reality and does not reconcile it with the prior branch contents. Deleted paths are GitHub-only; added paths are server-only; modified paths differ.

## Diff summary

```text
.dockerignore                                      |   4 -
 .github/CODEOWNERS                                 |   1 -
 .github/workflows/ci.yml                           | 152 -----
 .gitignore                                         |   4 -
 .gitleaks.toml                                     |   9 -
 APP-PROVISIONING-COMPLETION-20260726.md            | 105 ----
 APP-PROVISIONING-RUNTIME-AUDIT-20260726T0412Z.md   | 129 -----
 CANONICAL-KEYCLOAK-VERIFIER.md                     |  26 -
 CONCURRENT-RUNTIME-CHANGE-20260726T0413Z.md        |  48 --
 Dockerfile                                         |  28 +-
 Dockerfile.test                                    |   1 -
 Dockerfile.test.dockerignore                       |   8 -
 README.md                                          |   2 +-
 RECOVERED-SOURCE-PROVENANCE.md                     |  22 -
 SECURITY.md                                        |   9 -
 app/adapters.py                                    |   9 +-
 app/config.py                                      | 102 +---
 app/contracts.py                                   |   2 -
 app/engine.py                                      | 272 ++-------
 app/logging.py                                     |   2 +-
 app/mailbox.py                                     | 365 ------------
 app/main.py                                        | 141 +----
 app/readiness.py                                   | 173 ------
 app/repository.py                                  | 432 ++------------
 app/security.py                                    |  35 +-
 app/sip_browser.py                                 |  11 +-
 deploy/canonical-verifier.env.example              |  11 -
 deploy/compose.identity-relay.yaml                 |  56 --
 deploy/compose.production.yaml                     |  83 ---
 deploy/production.env.example                      |  33 --
 deploy/provisioning-sqlite.rules.yml               |  35 --
 deploy/staging-candidate.override.yaml             |   5 -
 .../codestra-provisioning-sqlite-backup.service    |  15 -
 .../codestra-provisioning-sqlite-backup.timer      |  11 -
 .../codestra-provisioning-sqlite-restore.service   |  16 -
 .../codestra-provisioning-sqlite-restore.timer     |  11 -
 docs/CHANGE-APPROVAL-CHECKLIST.md                  |  19 -
 docs/PRODUCTION-GOVERNANCE.md                      |  86 ---
 docs/PRODUCTION-PREFLIGHT.md                       |  14 -
 docs/SQLITE-RECOVERY.md                            |  38 --
 pyproject.toml                                     |   3 +-
 requirements-dev.txt                               |   1 -
 requirements.txt                                   |   4 +-
 scripts/keycloak_acceptance.py                     |   2 +-
 scripts/production_preflight.sh                    |  97 ----
 scripts/run_sqlite_restore_rehearsal.sh            |  32 --
 scripts/sqlite_lifecycle.py                        | 201 -------
 tests/test_adapters.py                             |   6 +-
 tests/test_api_security.py                         | 239 +-------
 tests/test_engine.py                               | 620 +--------------------
 tests/test_mailbox.py                              | 221 --------
 tests/test_readiness.py                            | 138 -----
 tests/test_repository.py                           | 275 ++-------
 tests/test_security_and_callbacks.py               |  55 --
 tests/test_sip_browser_contract.py                 | 139 -----
 tests/test_sqlite_lifecycle.py                     |  92 ---
 56 files changed, 184 insertions(+), 4466 deletions(-)
```

## Working-tree inventory before capture commit

```text
M .dockerignore
 D .github/CODEOWNERS
 D .github/workflows/ci.yml
 D .gitignore
 D .gitleaks.toml
 D APP-PROVISIONING-COMPLETION-20260726.md
 D APP-PROVISIONING-RUNTIME-AUDIT-20260726T0412Z.md
 D CANONICAL-KEYCLOAK-VERIFIER.md
 D CONCURRENT-RUNTIME-CHANGE-20260726T0413Z.md
 M Dockerfile
 M Dockerfile.test
 D Dockerfile.test.dockerignore
 M README.md
 D RECOVERED-SOURCE-PROVENANCE.md
 D SECURITY.md
 M app/adapters.py
 M app/config.py
 M app/contracts.py
 M app/engine.py
 M app/logging.py
 D app/mailbox.py
 M app/main.py
 D app/readiness.py
 M app/repository.py
 M app/security.py
 M app/sip_browser.py
 D deploy/canonical-verifier.env.example
 D deploy/compose.identity-relay.yaml
 D deploy/compose.production.yaml
 D deploy/production.env.example
 D deploy/provisioning-sqlite.rules.yml
 D deploy/staging-candidate.override.yaml
 D deploy/systemd/codestra-provisioning-sqlite-backup.service
 D deploy/systemd/codestra-provisioning-sqlite-backup.timer
 D deploy/systemd/codestra-provisioning-sqlite-restore.service
 D deploy/systemd/codestra-provisioning-sqlite-restore.timer
 D docs/CHANGE-APPROVAL-CHECKLIST.md
 D docs/PRODUCTION-GOVERNANCE.md
 D docs/PRODUCTION-PREFLIGHT.md
 D docs/SQLITE-RECOVERY.md
 M pyproject.toml
 M requirements-dev.txt
 M requirements.txt
 M scripts/keycloak_acceptance.py
 D scripts/production_preflight.sh
 D scripts/run_sqlite_restore_rehearsal.sh
 D scripts/sqlite_lifecycle.py
 M tests/test_adapters.py
 M tests/test_api_security.py
 M tests/test_engine.py
 D tests/test_mailbox.py
 D tests/test_readiness.py
 M tests/test_repository.py
 D tests/test_security_and_callbacks.py
 D tests/test_sip_browser_contract.py
 D tests/test_sqlite_lifecycle.py
?? .env.example
?? DEPLOYMENT-VALIDATION-20260726.md
?? ENVIRONMENT-VARIABLES.md
?? SERVER-VS-GITHUB-DRIFT.md
?? app/__pycache__/
?? compose.live-delivery-safety.yaml
?? compose.protected-0e7d889.yaml
?? compose.webrtc-6101-controlled.yaml
?? compose.webrtc-6101-controlled.yaml.pre-wss-decouple-20260819T0208Z
?? compose.yaml
?? scripts/__pycache__/
?? server-baseline/
?? tests/__pycache__/
```
