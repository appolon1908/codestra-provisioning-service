# Provisioning Fabric Branch Map

Parent contract: `integration/codestra-provisioning-fabric-v2`

- `feature/tenant-provisioning-v1`
- `feature/agent-provisioning-v1`
- `feature/deprovisioning-v1`
- `feature/provisioning-reconciliation-v1`
- `test/provisioning-fabric-contracts-v1`

Each branch must remain independent. Destination-specific adapters belong in their owning repository/Middleware branch; do not commit destination credentials or live apply logic to this contract branch.
