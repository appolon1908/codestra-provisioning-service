# CHG-20260826-PROVISIONING-PRODUCTION-01 approval checklist

All approvals must refer to the exact governance commit and be recorded on the
authoritative GitHub issue. A checkbox without an accountable comment is not an
approval.

- [ ] Accountable owner approves signing, identity, PKI, capability, backlog,
      and release policies.
- [ ] Independent approver approves the exact commit.
- [ ] GitHub environment `provisioning-production-release` exists with required
      independent reviewers and branch restricted to `main`.
- [ ] Signing and independent verification pass for the exact image digest.
- [ ] Production Keycloak client and protected secret are created and tested.
- [ ] Production certificates are issued and trust consumers verified.
- [ ] Complete secret bundle is validated without exposing values.
- [ ] Monitoring platform PR is approved, merged, deployed, and loaded.
- [ ] Backlog disposition table is approved without automatic replay.
- [ ] Exact maintenance window and rollback owner are recorded.
- [ ] Deployment, timers, canaries, DR, rollback, and load/soak pass.

