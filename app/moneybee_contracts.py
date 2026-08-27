"""MoneyBee account-provisioning intent contracts.

This module intentionally does not call Keycloak, Odoo, n8n, Klyrow or Postal.
It converts a verified MoneyBee account event into a deterministic set of
Middleware commands. Middleware remains the only cross-system mutation boundary.
"""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


PROHIBITED_SECRET_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "verification_code",
        "otp",
        "otp_hash",
        "reset_token",
        "reset_url",
        "access_token",
        "refresh_token",
        "smtp_password",
        "smtp_secret",
        "client_secret",
        "keycloak_admin_credential",
    }
)


def _assert_no_identity_secret_material(value: object, path: str = "payload") -> None:
    """Reject secret-bearing keys anywhere in a command payload."""

    if isinstance(value, dict):
        for raw_key, nested in value.items():
            key = str(raw_key).strip().lower()
            if key in PROHIBITED_SECRET_KEYS:
                raise ValueError(f"identity secret material is prohibited at {path}.{key}")
            _assert_no_identity_secret_material(nested, f"{path}.{key}")
        return
    if isinstance(value, list | tuple | set | frozenset):
        for index, nested in enumerate(value):
            _assert_no_identity_secret_material(nested, f"{path}[{index}]")


class MoneyBeeAccountProvisioningIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(min_length=8, max_length=160)
    tenant_id: UUID
    user_id: UUID
    organization_id: UUID
    correlation_id: str = Field(min_length=8, max_length=160)
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^\s@]+@[^\s@]+$")
    email_verified: Literal[True]
    membership_type: Literal["BORROWER"]
    display_name: str | None = Field(default=None, max_length=255)
    marketing_consent: bool = False

    @model_validator(mode="after")
    def verified_email_is_required(self):
        if not self.email_verified:
            raise ValueError("verified MoneyBee email is required")
        return self


class MoneyBeeMiddlewareCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination: Literal["middleware-api"] = "middleware-api"
    command: str
    idempotency_key: str
    correlation_id: str
    payload: dict[str, object]

    @field_validator("payload", mode="before")
    @classmethod
    def reject_identity_secret_material(cls, value: object) -> object:
        _assert_no_identity_secret_material(value)
        return value


class MoneyBeeProvisioningPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_event_id: str
    commands: list[MoneyBeeMiddlewareCommand]
    direct_keycloak_admin_access: Literal[False] = False
    direct_odoo_access: Literal[False] = False
    direct_n8n_access: Literal[False] = False
    direct_klyrow_access: Literal[False] = False
    contains_identity_secret_material: Literal[False] = False


def build_moneybee_provisioning_plan(
    intent: MoneyBeeAccountProvisioningIntent,
) -> MoneyBeeProvisioningPlan:
    tenant_id = str(intent.tenant_id)
    common = {
        "tenant_id": tenant_id,
        "user_id": str(intent.user_id),
        "organization_id": str(intent.organization_id),
        "email": intent.email.lower(),
        "email_verified": True,
        "membership_type": intent.membership_type,
        "display_name": intent.display_name,
        "marketing_consent": intent.marketing_consent,
    }
    idempotency_prefix = f"{tenant_id}:{intent.event_id}"
    commands = [
        MoneyBeeMiddlewareCommand(
            command="crm.contact.sync.requested.v1",
            idempotency_key=f"{idempotency_prefix}:crm",
            correlation_id=intent.correlation_id,
            payload=common,
        ),
        MoneyBeeMiddlewareCommand(
            command="onboarding.started.v1",
            idempotency_key=f"{idempotency_prefix}:onboarding",
            correlation_id=intent.correlation_id,
            payload=common,
        ),
    ]
    if intent.marketing_consent:
        commands.append(
            MoneyBeeMiddlewareCommand(
                command="marketing.contact.enrollment.requested.v1",
                idempotency_key=f"{idempotency_prefix}:marketing",
                correlation_id=intent.correlation_id,
                payload=common,
            )
        )
    return MoneyBeeProvisioningPlan(
        source_event_id=intent.event_id,
        commands=commands,
    )
