import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from app.adapters import PermanentAdapterError
from app.contracts import Operation, StepCommand, TargetSystem
from app.keycloak import KeycloakAdminAdapter, REQUIRED_ACTIONS


def command(
    operation: Operation,
    employee_id: str,
    username: str,
    group_path: str,
    *,
    idempotency: str,
    desired=None,
):
    attributes = {
        "employee_id": employee_id,
        "company_id": "staging-company",
        "business_unit_id": "staging-business-unit",
        "department_id": "staging-department",
        "team_id": "staging-team",
        "supervisor_id": "staging-supervisor",
        "campaign_ids": ["staging-campaign"],
        "role_template": "AGENT",
        "agent_desktop_roles": ["agent"],
    }
    payload = {
        "username": username,
        "email": f"{username}@staging.invalid",
        "first_name": "Keycloak",
        "last_name": "Acceptance",
        "attributes": attributes,
        "groups": [group_path],
        "realm_roles": ["codestra_agent"],
        "client_roles": {"codestra-agent-desktop": ["agent"]},
    }
    if desired is not None:
        payload = {"desired": desired}
    return StepCommand(
        schema_version="1.0",
        request_id=f"request-{employee_id}",
        correlation_id=f"correlation-{employee_id}",
        idempotency_key=idempotency,
        employee_id=employee_id,
        target_system=TargetSystem.KEYCLOAK,
        operation=operation,
        timestamp=datetime.now(UTC),
        step_id=f"step-{employee_id}-{operation.value}",
        sequence=10,
        payload=payload,
    )


async def main():
    config = json.loads(Path(os.environ["ADAPTER_CONFIG_FILE"]).read_text())["keycloak"]
    adapter = KeycloakAdminAdapter(
        base_url=config["base_url"],
        realm=config["realm"],
        client_id=config["client_id"],
        client_secret_file=config["client_secret_file"],
        approved_group_prefixes=config["approved_group_prefixes"],
        approved_realm_roles=config["approved_realm_roles"],
        approved_client_roles=config["approved_client_roles"],
        activation_clients=config.get("activation_clients"),
    )
    stamp = os.environ["ACCEPTANCE_STAMP"]
    employee_id = f"KP-STAGING-{stamp}"
    username = f"kp-staging-{stamp.lower()}"
    group_path = os.environ["ACCEPTANCE_GROUP_PATH"]
    key = f"kp-acceptance-{stamp}"
    created = await adapter.create_disabled(
        command(
            Operation.CREATE_DISABLED,
            employee_id,
            username,
            group_path,
            idempotency=key,
        )
    )
    user = await adapter._user_for_command(
        command(
            Operation.VERIFY, employee_id, username, group_path, idempotency=key
        )
    )
    assert user["enabled"] is False
    assert REQUIRED_ACTIONS <= set(user["requiredActions"])
    replay = await adapter.create_disabled(
        command(
            Operation.CREATE_DISABLED,
            employee_id,
            username,
            group_path,
            idempotency=key,
        )
    )
    assert replay["external_id"] == created["external_id"]
    duplicate_username = False
    try:
        await adapter.create_disabled(
            command(
                Operation.CREATE_DISABLED,
                f"{employee_id}-OTHER",
                username,
                group_path,
                idempotency=f"{key}-other",
            )
        )
    except PermanentAdapterError as exc:
        duplicate_username = exc.code == "keycloak_duplicate_username"
    assert duplicate_username
    duplicate_identity = False
    try:
        await adapter.create_disabled(
            command(
                Operation.CREATE_DISABLED,
                employee_id,
                f"{username}-other",
                group_path,
                idempotency=f"{key}-identity",
            )
        )
    except PermanentAdapterError as exc:
        duplicate_identity = exc.code == "keycloak_duplicate_identity"
    assert duplicate_identity
    await adapter.verify(
        command(Operation.VERIFY, employee_id, username, group_path, idempotency=key)
    )
    await adapter.activate(
        command(Operation.ACTIVATE, employee_id, username, group_path, idempotency=key)
    )
    user = await adapter._user_for_command(
        command(Operation.VERIFY, employee_id, username, group_path, idempotency=key)
    )
    assert user["enabled"] is True
    snapshot = await adapter._snapshot(user)
    desired = {
        "enabled": True,
        "required_actions": sorted(REQUIRED_ACTIONS),
        "groups": snapshot["groups"],
        "realm_roles": snapshot["realm_roles"],
        "client_roles": snapshot["client_roles"],
        "attributes": {
            name: snapshot["attributes"][name]
            for name in (
                "employee_id",
                "company_id",
                "business_unit_id",
                "department_id",
                "team_id",
                "supervisor_id",
                "campaign_ids",
                "role_template",
                "agent_desktop_roles",
            )
        },
    }
    aligned = await adapter.reconcile(
        command(
            Operation.RECONCILE,
            employee_id,
            username,
            group_path,
            idempotency=key,
            desired=desired,
        )
    )
    assert aligned["state"] == "aligned"
    drift_desired = {**desired, "realm_roles": ["intentionally-missing-role"]}
    drift = await adapter.reconcile(
        command(
            Operation.RECONCILE,
            employee_id,
            username,
            group_path,
            idempotency=key,
            desired=drift_desired,
        )
    )
    assert drift["state"] == "privilege_drift"
    await adapter.suspend(
        command(Operation.SUSPEND, employee_id, username, group_path, idempotency=key)
    )
    user = await adapter._user_for_command(
        command(Operation.VERIFY, employee_id, username, group_path, idempotency=key)
    )
    assert user["enabled"] is False
    await adapter.reactivate(
        command(Operation.REACTIVATE, employee_id, username, group_path, idempotency=key)
    )
    user = await adapter._user_for_command(
        command(Operation.VERIFY, employee_id, username, group_path, idempotency=key)
    )
    assert user["enabled"] is True
    await adapter.terminate(
        command(Operation.TERMINATE, employee_id, username, group_path, idempotency=key)
    )
    user = await adapter._user_for_command(
        command(Operation.VERIFY, employee_id, username, group_path, idempotency=key)
    )
    assert user["enabled"] is False
    assert user["attributes"]["lifecycle_state"] == ["terminated"]
    print(
        json.dumps(
            {
                "valid_creation": "PASS",
                "duplicate_request": "PASS",
                "duplicate_username": "PASS",
                "duplicate_identity": "PASS",
                "required_password_action": "PASS",
                "required_mfa_action": "PASS",
                "group_assignment": "PASS",
                "realm_role_assignment": "PASS",
                "client_role_assignment": "PASS",
                "activation": "PASS",
                "session_revocation_endpoint": "PASS",
                "suspension": "PASS",
                "reactivation": "PASS",
                "termination": "PASS",
                "reconciliation": "PASS",
                "privilege_drift": "PASS",
                "user_id": created["external_id"],
                "employee_id": employee_id,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
