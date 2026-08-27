from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.moneybee_contracts import (
    MoneyBeeAccountProvisioningIntent,
    MoneyBeeMiddlewareCommand,
    build_moneybee_provisioning_plan,
)


def intent(**overrides):
    values = {
        "event_id": "evt-moneybee-account-0001",
        "tenant_id": uuid4(),
        "user_id": uuid4(),
        "organization_id": uuid4(),
        "correlation_id": "corr-moneybee-0001",
        "email": "borrower@example.com",
        "email_verified": True,
        "membership_type": "BORROWER",
        "display_name": "Borrower Example",
        "marketing_consent": False,
    }
    values.update(overrides)
    return MoneyBeeAccountProvisioningIntent(**values)


def test_plan_uses_middleware_only_and_is_tenant_scoped_idempotent():
    value = intent()
    plan = build_moneybee_provisioning_plan(value)
    assert [item.command for item in plan.commands] == [
        "crm.contact.sync.requested.v1",
        "onboarding.started.v1",
    ]
    assert all(item.destination == "middleware-api" for item in plan.commands)
    tenant_id = str(value.tenant_id)
    assert [item.idempotency_key for item in plan.commands] == [
        f"{tenant_id}:{value.event_id}:crm",
        f"{tenant_id}:{value.event_id}:onboarding",
    ]
    assert all(item.payload["tenant_id"] == tenant_id for item in plan.commands)
    assert plan.direct_keycloak_admin_access is False
    assert plan.direct_odoo_access is False
    assert plan.direct_n8n_access is False
    assert plan.direct_klyrow_access is False
    assert plan.contains_identity_secret_material is False


def test_same_event_id_in_different_tenants_has_distinct_commands():
    shared_event_id = "evt-moneybee-account-shared"
    first = build_moneybee_provisioning_plan(intent(event_id=shared_event_id))
    second = build_moneybee_provisioning_plan(intent(event_id=shared_event_id))
    assert first.commands[0].payload["tenant_id"] != second.commands[0].payload["tenant_id"]
    assert first.commands[0].idempotency_key != second.commands[0].idempotency_key


def test_marketing_command_requires_explicit_consent():
    without = build_moneybee_provisioning_plan(intent(marketing_consent=False))
    with_consent = build_moneybee_provisioning_plan(intent(marketing_consent=True))
    assert all("marketing" not in item.command for item in without.commands)
    assert with_consent.commands[-1].command == "marketing.contact.enrollment.requested.v1"


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
            command="crm.contact.sync.requested.v1",
            idempotency_key="tenant:event:crm",
            correlation_id="corr-moneybee-0001",
            payload={
                "tenant_id": str(uuid4()),
                "profile": {"credentials": {"password": "never-accepted"}},
            },
        )
