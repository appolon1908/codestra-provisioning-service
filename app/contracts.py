from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TargetSystem(StrEnum):
    ODOO = "odoo"
    KEYCLOAK = "keycloak"
    VICIDIAL = "vicidial"
    SIP = "sip"
    AGENT_DESKTOP = "agent_desktop"
    EMAIL_PROVIDER = "email_provider"
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
