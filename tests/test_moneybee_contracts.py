from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.moneybee_contracts import (
    MoneyBeeAccountProvisioningIntent,
    MoneyBeeMiddlewareCommand,
    build_moneybee_provisioning_plan,
)


def intent(**overrides):
    tenant_id = overrides.pop("tenant_id", uuid4())
    values = {
        "event_id": "evt-moneybee-account-0001",
        "tenant_id": tenant_id,
        "user_id": uuid4(),
        "organization_id": tenant_id,
        "correlation_id": "corr-moneybee-0001",
        "email": "borrower@example.com",
        "email_verified": True,
        "membership_type": "BORROWER",
        "display_name": "Borrower Example",
        "marketing_consent": False,
        "tenant_baseline_required": True,
    }
    values.update(overrides)
    return MoneyBeeAccountProvisioningIntent(**values)


def test_plan_uses_only_approved_tenant_provisioning_scope():
    value = intent()
    plan = build_moneybee_provisioning_plan(value)
    assert [item.command for item in plan.commands] == ["tenant.provision.requested.v1"]
    assert [item.required_scope for item in plan.commands] == ["tenant.provision"]
    assert all(item.destination == "middleware-api" for item in plan.commands)
    tenant_id = str(value.tenant_id)
    assert plan.commands[0].idempotency_key == (
        f"{tenant_id}:{value.event_id}:tenant-baseline"
    )
    assert plan.commands[0].payload["tenant_id"] == tenant_id
    assert plan.commands[0].payload["activation_mode"] == "PLAN_ONLY"
    assert plan.base_crm_projection_owner == "middleware"
    assert plan.borrower_onboarding_owner == "n8n"
    assert plan.direct_keycloak_admin_access is False
    assert plan.direct_odoo_access is False
    assert plan.direct_n8n_access is False
    assert plan.direct_klyrow_access is False
    assert plan.contains_identity_secret_material is False
    assert plan.activates_external_delivery is False


def test_same_event_id_in_different_tenants_has_distinct_commands():
    shared_event_id = "evt-moneybee-account-shared"
    first = build_moneybee_provisioning_plan(intent(event_id=shared_event_id))
    second = build_moneybee_provisioning_plan(intent(event_id=shared_event_id))
    assert first.commands[0].payload["tenant_id"] != second.commands[0].payload["tenant_id"]
    assert first.commands[0].idempotency_key != second.commands[0].idempotency_key


def test_normal_account_event_does_not_duplicate_crm_onboarding_or_marketing():
    plan = build_moneybee_provisioning_plan(intent(marketing_consent=True))
    commands = {item.command for item in plan.commands}
    assert "crm.contact.sync.requested.v1" not in commands
    assert "onboarding.started.v1" not in commands
    assert "marketing.contact.enrollment.requested.v1" not in commands


def test_baseline_can_be_explicitly_skipped_without_external_effects():
    plan = build_moneybee_provisioning_plan(intent(tenant_baseline_required=False))
    assert plan.commands == []
    assert plan.activates_external_delivery is False


def test_tenant_must_match_moneybee_organization():
    with pytest.raises(ValidationError):
        intent(organization_id=uuid4())


def test_unverified_or_secret_bearing_input_is_rejected():
    with pytest.raises(ValidationError):
        intent(email_verified=False)
    with pytest.raises(ValidationError):
        MoneyBeeAccountProvisioningIntent(
            **intent().model_dump(),
            password="never-accepted",
        )


def test_nested_secret_bearing_command_payload_is_rejected():
    with pytest.raises(ValidationError):
        MoneyBeeMiddlewareCommand(
            command="tenant.provision.requested.v1",
            required_scope="tenant.provision",
            idempotency_key="tenant:event:provision",
            correlation_id="corr-moneybee-0001",
            payload={
                "tenant_id": str(uuid4()),
                "profile": {"credentials": {"password": "never-accepted"}},
            },
        )
