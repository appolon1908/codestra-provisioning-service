import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from app.adapters import TelephonyProvisioningAdapter
from app.contracts import Operation, SipBrowserSessionRequest, TargetSystem
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
                payload={"username": "synthetic_agent", "campaigns": ["TEST_SYN"]},
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


@pytest.mark.asyncio
@pytest.mark.parametrize("include_temporary", [True, False])
async def test_browser_rotation_and_revocation_keep_sip_wire_contract(
    tmp_path, include_temporary,
):
    key = tmp_path / "synthetic-hmac"
    key.write_text("synthetic-hmac-value")
    key.chmod(0o600)
    binding = "00000000-0000-4000-8000-000000000001"
    requests = []

    async def legacy_server(request):
        requests.append(request)
        assert request.url.path == (
            "/vicidial-provisioning/v1/provisioning/rotate_sip_secret"
        )
        assert "x-signature-version" not in request.headers
        body = json.loads(request.content)
        if include_temporary:
            assert body["browser_session_binding"] == binding
            assert "browser_session_revocation" not in body
        else:
            assert body["browser_session_revocation"] is True
            assert "browser_session_binding" not in body
        message = "\n".join((
            request.headers["x-request-timestamp"],
            request.headers["x-request-nonce"],
            hashlib.sha256(request.content).hexdigest(),
        )).encode()
        assert request.headers["x-request-signature"] == hmac.new(
            b"synthetic-hmac-value", message, hashlib.sha256
        ).hexdigest()
        response = {"extension": 6101, "rotated": True}
        if include_temporary:
            response.update(temporary_sip_credential="x" * 48, expires_in_seconds=300)
        return httpx.Response(200, json=response)

    async with httpx.AsyncClient(transport=httpx.MockTransport(legacy_server)) as client:
        adapter = TelephonyProvisioningAdapter(
            "sip", "https://edge.example.invalid/vicidial-provisioning",
            str(key), str(key), str(key), str(key), "synthetic-provisioning",
            "telephony:provision", client,
        )
        service = SipBrowserSessionManager(FakeRepository(), {"sip": adapter}, str(key))
        command = execution().steps[0].model_copy(update={"target_system": "sip"})
        # create() and renew() both use the temporary path; revoke() uses false.
        first = await service._rotate(command, binding, include_temporary)
        second = await service._rotate(command, binding, include_temporary)
    assert ("temporary_sip_credential" in first) is include_temporary
    assert ("temporary_sip_credential" in second) is include_temporary
    assert len(requests) == 2
    assert requests[0].headers["idempotency-key"] != requests[1].headers["idempotency-key"]
