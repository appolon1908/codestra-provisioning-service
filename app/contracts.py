import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TargetSystem(StrEnum):
    ODOO = "odoo"
    KEYCLOAK = "keycloak"
    VICIDIAL = "vicidial"
    SIP = "sip"
    AGENT_DESKTOP = "agent_desktop"
    EMAIL_PROVIDER = "email_provider"
    N8N_EVENT = "n8n_event"
    SECRET_STORAGE = "secret_storage"
    VERIFICATION = "verification"
    RECONCILIATION = "reconciliation"


class Operation(StrEnum):
    CREATE_DISABLED = "create_disabled"
    UPDATE = "update"
    VERIFY = "verify"
    ACTIVATE = "activate"
    SUSPEND = "suspend"
    REACTIVATE = "reactivate"
    TERMINATE = "terminate"
    ROTATE_CREDENTIALS = "rotate_credentials"
    RECONCILE = "reconcile"
    CANCEL = "cancel"


class StepState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    RETRY_WAIT = "retry_wait"
    SUCCEEDED = "succeeded"
    VERIFIED = "verified"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"
    COMPENSATED = "compensated"


SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "private_key",
    "client_secret",
    "api_key",
    "authorization",
    "credential",
    "credentials",
}


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key).lower()
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_keys(nested)


class RequestEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: str = Field(pattern=r"^1\.[0-9]+$", max_length=16)
    request_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=8, max_length=128)
    idempotency_key: str = Field(min_length=16, max_length=128)
    employee_id: str = Field(min_length=1, max_length=128)
    target_system: TargetSystem
    operation: Operation
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp timezone is required")
        return value.astimezone(UTC)


class StepCommand(RequestEnvelope):
    payload: dict[str, Any] = Field(default_factory=dict)
    step_id: str = Field(min_length=8, max_length=128)
    sequence: int = Field(ge=0, le=100)
    max_attempts: int = Field(default=3, ge=1, le=8)
    mandatory: bool = True

    @model_validator(mode="after")
    def no_inline_secrets(self):
        found = SENSITIVE_KEYS.intersection(_walk_keys(self.payload))
        reference_keys = {
            key for key in found if key.endswith(("_reference", "_ref"))
        }
        found -= reference_keys
        if found:
            raise ValueError("credential values are forbidden; use protected references")
        return self


class VicidialProvisioningContext(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    correlation_id: str = Field(min_length=8, max_length=128)
    actor: str = Field(min_length=3, max_length=128)
    reason: str = Field(min_length=8, max_length=500)
    requested_at: datetime


class VicidialAgentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    user_id: str = Field(pattern=r"^[A-Z]{3}[0-9]{4,12}$")
    full_name: str = Field(min_length=2, max_length=50)
    user_group: str = Field(pattern=r"^[A-Z0-9_]{2,20}$")
    campaigns: list[str] = Field(min_length=1, max_length=30)
    inbound_groups: list[str] = Field(default_factory=list, max_length=30)
    active: Literal[False] = False
    adopt_existing_sha256: Annotated[
        str, Field(pattern=r"^[a-f0-9]{64}$")
    ] | None = None

    @field_validator("campaigns")
    @classmethod
    def valid_campaigns(cls, values: list[str]) -> list[str]:
        if any(re.fullmatch(r"[A-Z0-9_]{2,8}", value) is None for value in values):
            raise ValueError("invalid VICIdial campaign")
        return values

    @field_validator("inbound_groups")
    @classmethod
    def valid_inbound_groups(cls, values: list[str]) -> list[str]:
        if any(re.fullmatch(r"[A-Z0-9_]{2,20}", value) is None for value in values):
            raise ValueError("invalid VICIdial inbound group")
        return values


class VicidialProvisioningPayload(BaseModel):
    """Client copy of the canonical disabled-agent request boundary."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    context: VicidialProvisioningContext
    agent: VicidialAgentSpec
    user_level: Literal[9]
    authorization_reference: str = Field(pattern=r"^CHG-[A-Z0-9-]{10,80}$")
    plan_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    backup_reference: str = Field(pattern=r"^[A-Za-z0-9._:/-]{8,255}$")

    @model_validator(mode="after")
    def plan_matches_agent(self):
        encoded = json.dumps(
            self.agent.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if hashlib.sha256(encoded).hexdigest() != self.plan_sha256:
            raise ValueError("VICIdial plan hash does not match agent")
        return self


class RequestExecution(RequestEnvelope):
    steps: list[StepCommand] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def consistent_steps(self):
        sequences = [step.sequence for step in self.steps]
        if len(sequences) != len(set(sequences)):
            raise ValueError("step sequences must be unique")
        for step in self.steps:
            for field in (
                "schema_version",
                "request_id",
                "correlation_id",
                "employee_id",
            ):
                if getattr(step, field) != getattr(self, field):
                    raise ValueError(f"step {field} mismatch")
        return self


class ActionRequest(RequestEnvelope):
    payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def no_inline_secrets(self):
        found = SENSITIVE_KEYS.intersection(_walk_keys(self.payload))
        if found:
            raise ValueError("credential values are forbidden; use protected references")
        return self


class StepResult(BaseModel):
    step_id: str
    target_system: TargetSystem
    operation: Operation
    state: StepState
    attempt_count: int
    external_id: str | None = None
    external_reference: str | None = None
    credential_reference: str | None = None
    evidence_hash: str | None = None
    error_code: str | None = None
    retry_at: datetime | None = None
    replayed: bool = False


class ExecutionResult(BaseModel):
    request_id: str
    employee_id: str
    correlation_id: str
    state: str
    step_results: list[StepResult]
    replayed: bool = False
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CallbackEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    schema_version: str = "1.0"
    request_id: str
    employee_id: str
    correlation_id: str
    idempotency_key: str
    target_system: TargetSystem = TargetSystem.ODOO
    operation: Operation = Operation.UPDATE
    state: str
    step_results: list[StepResult]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReconciliationResult(BaseModel):
    employee_id: str
    state: str
    systems: list[StepResult]


class SipBrowserSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    employee_id: str = Field(min_length=1, max_length=128)
    keycloak_subject: str = Field(min_length=16, max_length=128)
    odoo_employee_id: str = Field(min_length=1, max_length=128)
    vicidial_username: str = Field(pattern=r"^[A-Za-z0-9_-]{1,20}$")
    endpoint: int = Field(ge=6100, le=6999)
    campaign: str = Field(pattern=r"^[A-Za-z0-9_-]{1,20}$")
    role: str = Field(pattern=r"^[A-Z_]{1,40}$")
    browser_session_binding: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )


class SipBrowserSessionAction(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    session_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    browser_session_binding: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )


class SipBrowserSessionResponse(BaseModel):
    session_id: str
    temporary_sip_authorization_username: str
    temporary_sip_credential: str
    endpoint: int
    sip_uri: str
    approved_wss_url: str
    temporary_turn_username: str
    temporary_turn_credential: str
    approved_turn_url: str
    expiration: datetime
    campaign: str
    role: str
    employee_identity: str
    browser_session_binding: str
