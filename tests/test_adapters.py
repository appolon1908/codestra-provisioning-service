import hashlib
import hmac

import httpx
import pytest

from app.adapters import (
    CompanyMailboxProvider,
    DeterministicMailboxMockAdapter,
    EmailProviderAdapter,
    HttpAdapter,
    PermanentAdapterError,
    ProvisioningAdapter,
    RetryableAdapterError,
    TelephonyProvisioningAdapter,
)
from app.contracts import Operation, TargetSystem
from app.repository import StateRepository
from app.secrets import SecretReferenceError
from tests.helpers import execution


def test_adapter_contract_has_all_lifecycle_operations():
    required = {
        "create_disabled",
        "update",
        "verify",
        "activate",
        "suspend",
        "reactivate",
        "terminate",
        "rotate_credentials",
        "reconcile",
    }
    assert required <= set(ProvisioningAdapter.__abstractmethods__)
    assert TargetSystem.N8N_EVENT.value == "n8n_event"


def test_mailbox_provider_contract_has_all_required_operations():
    assert set(CompanyMailboxProvider.__abstractmethods__) == {
        "check_availability", "reserve_address", "create_mailbox_disabled",
        "assign_license", "create_alias", "send_activation", "verify_mailbox",
        "activate_mailbox", "suspend_mailbox", "reactivate_mailbox",
        "terminate_mailbox", "reconcile_mailbox",
    }


def test_adapter_rejects_credentials_or_query_in_url(tmp_path):
    secret = tmp_path / "token"
    secret.write_text("value")
    secret.chmod(0o600)
    with pytest.raises(ValueError):
        HttpAdapter("odoo", "https://user:pass@odoo/internal", str(secret), str(secret))
    with pytest.raises(ValueError):
        HttpAdapter("odoo", "https://odoo/internal?token=x", str(secret), str(secret))


@pytest.mark.asyncio
async def test_timeout_is_retryable_and_400_is_permanent(tmp_path):
    secret = tmp_path / "token"
    secret.write_text("value")
    secret.chmod(0o600)

    async def timeout(request):
        raise httpx.ReadTimeout("timeout", request=request)

    adapter = HttpAdapter(
        "odoo",
        "https://odoo.internal",
        str(secret),
        str(secret),
        client=httpx.AsyncClient(transport=httpx.MockTransport(timeout)),
    )
    with pytest.raises(RetryableAdapterError):
        await adapter.execute(execution().steps[0])
    await adapter.client.aclose()

    adapter = HttpAdapter(
        "odoo",
        "https://odoo.internal",
        str(secret),
        str(secret),
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(400, json={}))
        ),
    )
    with pytest.raises(PermanentAdapterError):
        await adapter.execute(execution().steps[0])
    await adapter.client.aclose()


@pytest.mark.asyncio
async def test_mailbox_adapter_lifecycle_and_one_time_activation(tmp_path):
    secret = tmp_path / "token"
    secret.write_text("provider-credential")
    secret.chmod(0o600)
    requests = []

    async def provider(request):
        requests.append(request)
        action = request.url.path.rsplit("/", 1)[-1]
        if action == "check-availability":
            return httpx.Response(200, json={"available": True})
        if action == "create-disabled":
            return httpx.Response(
                201, json={"external_mailbox_id": "synthetic-mailbox-1",
                           "state": "disabled"}
            )
        return httpx.Response(200, json={"state": "succeeded"})

    adapter = EmailProviderAdapter(
        "email_provider", "https://mail.invalid.example",
        str(secret), str(secret),
        client=httpx.AsyncClient(transport=httpx.MockTransport(provider)),
    )
    key = "mailbox-adapter-idempotency-0001"
    assert (await adapter.check_availability(
        "mailbox@invalid.example", key
    ))["available"]
    await adapter.reserve_address("mailbox@invalid.example", key)
    created = await adapter.create_mailbox_disabled(
        "mailbox@invalid.example", key
    )
    mailbox_id = created["external_mailbox_id"]
    await adapter.assign_license(mailbox_id, key)
    await adapter.create_alias(mailbox_id, "alias@invalid.example", key)
    await adapter.send_activation(
        mailbox_id, "activation-sink@invalid.example", key
    )
    await adapter.verify_mailbox(mailbox_id, key)
    await adapter.activate_mailbox(mailbox_id, key)
    await adapter.suspend_mailbox(mailbox_id, key)
    await adapter.reactivate_mailbox(mailbox_id, key)
    await adapter.terminate_mailbox(mailbox_id, key)
    await adapter.reconcile_mailbox(mailbox_id, key)
    activation = next(
        request for request in requests if request.url.path.endswith("send-activation")
    )
    assert activation.read().find(b"provider_one_time_reset") >= 0
    assert b"password" not in activation.read().lower()
    await adapter.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "error_code", "error_type"),
    [
        (409, "email_address_collision", PermanentAdapterError),
        (402, "email_license_exhausted", PermanentAdapterError),
        (503, "email_provider_http_503", RetryableAdapterError),
    ],
)
async def test_mailbox_provider_failures_are_classified(
    tmp_path, status_code, error_code, error_type
):
    secret = tmp_path / "token"
    secret.write_text("provider-credential")
    secret.chmod(0o600)
    adapter = EmailProviderAdapter(
        "email_provider", "https://mail.invalid.example",
        str(secret), str(secret),
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(status_code, json={})
            )
        ),
    )
    with pytest.raises(error_type, match=error_code):
        await adapter.check_availability("mailbox@invalid.example", "request-key")
    await adapter.client.aclose()


@pytest.mark.asyncio
async def test_mailbox_provider_rejects_password_response(tmp_path):
    secret = tmp_path / "token"
    secret.write_text("provider-credential")
    secret.chmod(0o600)
    adapter = EmailProviderAdapter(
        "email_provider", "https://mail.invalid.example",
        str(secret), str(secret),
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json={"temporary_password": "no"})
            )
        ),
    )
    with pytest.raises(
        PermanentAdapterError, match="email_provider_returned_forbidden_secret"
    ):
        await adapter.create_mailbox_disabled(
            "mailbox@invalid.example", "request-key"
        )
    await adapter.client.aclose()


@pytest.mark.asyncio
async def test_telephony_adapter_signs_request_and_maps_targets(tmp_path):
    key = tmp_path / "hmac"
    key.write_text("synthetic-hmac-value")
    key.chmod(0o600)
    observed = []

    async def endpoint(request):
        observed.append(request)
        assert request.headers["x-service-identity"] == (
            "odoo-provisioning@65.109.65.169"
        )
        expected_scope = ("telephony:agent-provision" if
                          "/v1/agents/provision-disabled" in request.url.path else
                          "telephony:provision")
        assert request.headers["x-service-scopes"] == expected_scope
        assert request.headers["x-request-signature"]
        if "/v1/agents/provision-disabled" in request.url.path:
            canonical = "\n".join((
                "v2", "POST", "/v1/agents/provision-disabled",
                request.headers["x-service-identity"],
                request.headers["x-service-scopes"],
                request.headers["x-request-timestamp"],
                request.headers["x-request-nonce"],
                request.headers["idempotency-key"],
                hashlib.sha256(request.content).hexdigest(),
            )).encode()
            assert request.headers["x-request-signature"] == hmac.new(
                b"synthetic-hmac-value", canonical, hashlib.sha256
            ).hexdigest()
        body = {"status": "complete_disabled", "actual": {
            "user_id": "COD1001", "active": "N"}}
        if request.url.path.endswith("/rotate_sip_secret"):
            body = {
                "extension": 6197,
                "rotated": True,
                "temporary_sip_credential": "x" * 48,
                "expires_in_seconds": 300,
            }
        return httpx.Response(200, json=body, request=request)

    adapter = TelephonyProvisioningAdapter(
        "vicidial",
        "https://edge.internal.codestra.agency:8443/restricted-vicidial",
        str(key), str(key), str(key), str(key),
        "odoo-provisioning@65.109.65.169",
        "telephony:agent-provision",
        httpx.AsyncClient(transport=httpx.MockTransport(endpoint)),
    )
    command = execution().steps[0].model_copy(
        update={"target_system": "vicidial"}
    )
    result = await adapter.create_disabled(command)
    assert result["state"] == "complete_disabled"
    assert observed[0].url.path.endswith("/v1/agents/provision-disabled")
    assert observed[0].headers["x-signature-version"] == "v2"
    assert result["external_id"] == "COD1001"
    await adapter.client.aclose()

    sip = TelephonyProvisioningAdapter(
        "sip",
        "https://edge.internal.codestra.agency:8443/vicidial-provisioning",
        str(key), str(key), str(key), str(key),
        "odoo-provisioning@65.109.65.169",
        "telephony:provision",
        httpx.AsyncClient(transport=httpx.MockTransport(endpoint)),
    )
    browser_command = command.model_copy(
        update={
            "target_system": "sip",
            "operation": Operation.ROTATE_CREDENTIALS,
            "payload": {
                "username": "synthetic.agent",
                "browser_session_binding": "00000000-0000-4000-8000-000000000001",
            },
        }
    )
    temporary = await sip.issue_browser_credential(browser_command)
    assert temporary["temporary_sip_credential"] == "x" * 48
    assert observed[-1].url.path.endswith("/rotate_sip_secret")
    await sip.client.aclose()


@pytest.mark.asyncio
async def test_vicidial_provisioning_rejects_empty_hmac_credential(tmp_path):
    key = tmp_path / "empty-hmac"
    key.write_text("")
    key.chmod(0o600)
    adapter = TelephonyProvisioningAdapter(
        "vicidial", "https://edge.internal.codestra.agency:8443",
        str(key), str(key), str(key), str(key), "codestra-provisioning",
        "telephony:agent-provision", httpx.AsyncClient(),
    )
    command = execution().steps[0].model_copy(update={"target_system": "vicidial"})
    with pytest.raises(SecretReferenceError, match="secret_reference_empty"):
        await adapter.create_disabled(command)
    await adapter.client.aclose()


@pytest.mark.asyncio
async def test_deterministic_mailbox_mock_is_durable_and_delivery_free(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    adapter = DeterministicMailboxMockAdapter(repository)
    command = execution(target=TargetSystem.EMAIL_PROVIDER).steps[0].model_copy(
        update={
            "employee_id": "SYNTHETIC-001",
            "payload": {"email_address": "synthetic@staging.invalid"},
        }
    )
    created = await adapter.create_disabled(command)
    replayed = await adapter.create_disabled(command)
    assert created == replayed
    assert created["external_id"].startswith("mock:")
    assert created["credential_reference"] == "mock:no-provider-credential"
    suspended = await adapter.suspend(
        command.model_copy(update={"operation": Operation.SUSPEND})
    )
    assert suspended["state"] == "suspended"
    reconciled = await adapter.reconcile(
        command.model_copy(update={"operation": Operation.RECONCILE})
    )
    assert reconciled["state"] == "aligned"
    assert reconciled["actual_state"] == "suspended"
