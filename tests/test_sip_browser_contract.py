import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.adapters import TelephonyProvisioningAdapter
from app.contracts import Operation, SipBrowserSessionRequest, StepState, TargetSystem
from app.repository import StateRepository
from app.sip_browser import (
    CANONICAL_BROWSER_WSS_URL,
    SipBrowserSessionError,
    SipBrowserSessionManager,
)
from tests.helpers import execution


class FakeSipAdapter(TelephonyProvisioningAdapter):
    def __init__(self):
        pass


class FakeRepository:
    def employee_results(self, employee_id):
        del employee_id
        return [
            SimpleNamespace(
                target_system=target,
                external_id=external_id,
                operation=Operation.ACTIVATE,
            )
            for target, external_id in (
                (TargetSystem.KEYCLOAK, "12345678-1234-4234-9234-123456789abc"),
                (TargetSystem.VICIDIAL, "synthetic_agent"),
                (TargetSystem.SIP, "6101"),
            )
        ]

    def employee_commands(self, employee_id):
        del employee_id
        return [
            SimpleNamespace(
                target_system=TargetSystem.KEYCLOAK,
                payload={"attributes": {"role_template": "AGENT"}},
            ),
            SimpleNamespace(
                target_system=TargetSystem.VICIDIAL,
                payload={
                    "agent": {
                        "user_id": "synthetic_agent",
                        "campaigns": ["TEST_SYN"],
                    }
                },
            ),
            SimpleNamespace(
                target_system=TargetSystem.SIP,
                payload={"extension": 6101},
            ),
        ]


def values(**changes):
    result = {
        "employee_id": "APP-DESKTOP-STAGE-001",
        "keycloak_subject": "12345678-1234-4234-9234-123456789abc",
        "odoo_employee_id": "APP-DESKTOP-STAGE-001",
        "vicidial_username": "synthetic_agent",
        "endpoint": 6101,
        "campaign": "TEST_SYN",
        "role": "AGENT",
        "browser_session_binding": str(uuid.uuid4()),
    }
    result.update(changes)
    return result


def manager():
    return SipBrowserSessionManager(
        FakeRepository(),
        {TargetSystem.SIP.value: FakeSipAdapter()},
        "/unused/turn-secret",
        endpoint=6101,
        campaign="TEST_SYN",
    )


def test_only_canonical_subject_test_syn_and_6101_are_authorized():
    service = manager()
    service._validated_command(SipBrowserSessionRequest(**values()))
    for change in (
        {"keycloak_subject": "00000000-0000-4000-8000-000000000000"},
        {"campaign": "OTHER"},
        {"endpoint": 6102},
    ):
        with pytest.raises(SipBrowserSessionError):
            service._validated_command(SipBrowserSessionRequest(**values(**change)))


def test_conflicting_or_malformed_vicidial_identity_is_rejected():
    for payload in (
        {"agent": {"user_id": "synthetic_agent", "campaigns": "TEST_SYN"}},
        {
            "agent": {
                "user_id": "synthetic_agent",
                "campaigns": ["TEST_SYN"],
            },
            "username": "other",
            "campaigns": ["TEST_SYN"],
        },
        {"username": "synthetic_agent"},
    ):
        repository = FakeRepository()
        commands = repository.employee_commands("")
        commands[1].payload = payload
        repository.employee_commands = lambda _, items=commands: items
        service = SipBrowserSessionManager(
            repository, {TargetSystem.SIP.value: FakeSipAdapter()}, "/unused/turn-secret"
        )
        with pytest.raises(SipBrowserSessionError, match="identity_authorization_mismatch"):
            service._validated_command(SipBrowserSessionRequest(**values()))


def test_persisted_canonical_command_authorizes_browser_session(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    employee_id = values()["employee_id"]

    def persist(request_id, target, operation, payload, external_id):
        plan = execution(
            request_id=request_id,
            employee_id=employee_id,
            key=f"idempotency-{request_id}",
            target=target,
            operation=operation,
        )
        command = plan.steps[0].model_copy(update={"payload": payload})
        plan = plan.model_copy(update={"steps": [command]})
        repository.begin_execution(plan, request_id[-1] * 64)
        repository.complete_step(command.step_id, StepState.SUCCEEDED, {"external_id": external_id})

    persist(
        "request-keycloak-1", TargetSystem.KEYCLOAK, Operation.CREATE_DISABLED,
        {"attributes": {"role_template": "AGENT"}}, values()["keycloak_subject"],
    )
    persist(
        "request-keycloak-2", TargetSystem.KEYCLOAK, Operation.ACTIVATE,
        {}, values()["keycloak_subject"],
    )
    persist(
        "request-vicidial-3", TargetSystem.VICIDIAL, Operation.CREATE_DISABLED,
        {"agent": {"user_id": "synthetic_agent", "campaigns": ["TEST_SYN"]}},
        "synthetic_agent",
    )
    persist(
        "request-sip-4", TargetSystem.SIP, Operation.CREATE_DISABLED,
        {"extension": 6101}, "6101",
    )
    service = SipBrowserSessionManager(
        repository, {TargetSystem.SIP.value: FakeSipAdapter()}, "/unused/turn-secret"
    )
    command = service._validated_command(SipBrowserSessionRequest(**values()))
    assert command.target_system == TargetSystem.SIP


def test_machine_request_cannot_assert_tenant_or_production_mode():
    with pytest.raises(ValidationError):
        SipBrowserSessionRequest(**values(tenant_id="OTHER"))
    with pytest.raises(ValidationError):
        SipBrowserSessionRequest(**values(production=True))


def test_browser_signaling_uses_the_canonical_asterisk_wss_origin():
    assert CANONICAL_BROWSER_WSS_URL == "wss://wss.codestra.agency:8089/ws"


def test_renew_after_expiration_is_a_controlled_conflict_not_500():
    class ExpiredRepository(FakeRepository):
        def __init__(self):
            self.expired = False
            self.session = {
                **values(),
                "session_id": str(uuid.uuid4()),
                "state": "active",
                "expires_at": (
                    datetime.now(UTC) - timedelta(seconds=1)
                ).isoformat(),
            }

        def sip_browser_session(self, session_id):
            assert session_id == self.session["session_id"]
            return self.session

        def expire_sip_browser_session(self, session_id):
            assert session_id == self.session["session_id"]
            self.expired = True
            self.session["state"] = "expired"
            return self.session

    repository = ExpiredRepository()
    service = SipBrowserSessionManager(
        repository,
        {TargetSystem.SIP.value: FakeSipAdapter()},
        "/unused/turn-secret",
    )
    action = SimpleNamespace(
        session_id=repository.session["session_id"],
        browser_session_binding=repository.session["browser_session_binding"],
    )
    with pytest.raises(SipBrowserSessionError, match="not_active"):
        service._active(action)
    assert repository.expired
