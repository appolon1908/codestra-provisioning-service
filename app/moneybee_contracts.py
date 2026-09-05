# ruff: noqa: I001
"""MoneyBee enterprise provisioning intent contracts.

This service is deliberately *not* an onboarding/CRM orchestrator. Middleware owns
base CRM projection and n8n owns borrower onboarding. The provisioning service
uses only its reviewed tenant/integration provisioning scope and never calls
Keycloak, Odoo, n8n, Klyrow or Postal directly.
"""

import typing
import uuid

import pydantic


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


class MoneyBeeAccountProvisioningIntent(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = pydantic.Field(min_length=8, max_length=160)
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    organization_id: uuid.UUID
    correlation_id: str = pydantic.Field(min_length=8, max_length=160)
    email: str = pydantic.Field(min_length=3, max_length=320, pattern=r"^[^\s@]+@[^\s@]+$")
    email_verified: typing.Literal[True]
    membership_type: typing.Literal["BORROWER"]
    display_name: str | None = pydantic.Field(default=None, max_length=255)
    marketing_consent: bool = False
    tenant_baseline_required: bool = True

    @pydantic.model_validator(mode="after")
    def verified_email_is_required(self):
        if not self.email_verified:
            raise ValueError("verified MoneyBee email is required")
        if self.tenant_id != self.organization_id:
            raise ValueError("MoneyBee tenant_id must equal the borrower organization_id")
        return self


class MoneyBeeMiddlewareCommand(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")

    destination: typing.Literal["middleware-api"] = "middleware-api"
    command: typing.Literal["tenant.provision.requested.v1"]
    required_scope: typing.Literal["tenant.provision"] = "tenant.provision"
    idempotency_key: str
    correlation_id: str
    payload: dict[str, object]

    @pydantic.field_validator("payload", mode="before")
    @classmethod
    def reject_identity_secret_material(cls, value: object) -> object:
        _assert_no_identity_secret_material(value)
        return value


class MoneyBeeProvisioningPlan(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")

    source_event_id: str
    commands: list[MoneyBeeMiddlewareCommand]
    orchestration_owner: typing.Literal["provisioning-service"] = "provisioning-service"
    base_crm_projection_owner: typing.Literal["middleware"] = "middleware"
    borrower_onboarding_owner: typing.Literal["n8n"] = "n8n"
    direct_keycloak_admin_access: typing.Literal[False] = False
    direct_odoo_access: typing.Literal[False] = False
    direct_n8n_access: typing.Literal[False] = False
    direct_klyrow_access: typing.Literal[False] = False
    contains_identity_secret_material: typing.Literal[False] = False
    activates_external_delivery: typing.Literal[False] = False


def build_moneybee_provisioning_plan(
    intent: MoneyBeeAccountProvisioningIntent,
) -> MoneyBeeProvisioningPlan:
    """Build only the approved tenant-provisioning command.

    CRM synchronization is already owned by Middleware and onboarding by n8n, so
    this service must not duplicate either workflow. Marketing consent is kept as
    context for downstream policy but never causes direct marketing enrollment.
    """

    tenant_id = str(intent.tenant_id)
    commands: list[MoneyBeeMiddlewareCommand] = []
    if intent.tenant_baseline_required:
        commands.append(
            MoneyBeeMiddlewareCommand(
                command="tenant.provision.requested.v1",
                idempotency_key=f"{tenant_id}:{intent.event_id}:tenant-baseline",
                correlation_id=intent.correlation_id,
                payload={
                    "tenant_id": tenant_id,
                    "organization_id": str(intent.organization_id),
                    "user_id": str(intent.user_id),
                    "membership_type": intent.membership_type,
                    "email_verified": True,
                    "marketing_consent": intent.marketing_consent,
                    "activation_mode": "PLAN_ONLY",
                },
            )
        )
    return MoneyBeeProvisioningPlan(
        source_event_id=intent.event_id,
        commands=commands,
    )
