import sqlite3

import pytest
from cryptography.fernet import Fernet

from app.adapters import SecretStorageAdapter
from app.callbacks import CallbackDispatcher
from app.config import Settings
from app.contracts import Operation, StepState, TargetSystem
from app.engine import ProvisioningEngine
from app.repository import StateRepository
from tests.helpers import (
    FakeAdapter,
    PermanentAdapterError,
    RetryableAdapterError,
    action,
    execution,
)


def settings(tmp_path) -> Settings:
    placeholder = tmp_path / "placeholder"
    placeholder.write_text("x")
    return Settings(
        environment="staging",
        state_database_path=str(tmp_path / "state.db"),
        jwt_issuer="https://issuer.invalid/realms/codestra",
        jwt_audience="codestra-provisioning-service",
        jwt_public_key_file=str(placeholder),
        jwt_algorithms=("RS256",),
        jwt_allowed_clients=frozenset({"test-service"}),
        request_max_bytes=65536,
        request_max_age_seconds=300,
        rate_limit_requests=100,
        rate_limit_window_seconds=60,
        claim_timeout_seconds=0,
        retry_base_seconds=0,
        callback_url=None,
        callback_hmac_file=str(placeholder),
        encryption_key_file=str(placeholder),
        adapter_config_file=str(placeholder),
        tls_cert_file=str(placeholder),
        tls_key_file=str(placeholder),
    )


def engine(tmp_path, adapter):
    repository = StateRepository(str(tmp_path / "state.db"))
    configured = settings(tmp_path)
    callbacks = CallbackDispatcher(None, configured.callback_hmac_file, repository)
    return ProvisioningEngine(
        {TargetSystem.ODOO.value: adapter}, repository, configured, callbacks
    )


@pytest.mark.asyncio
async def test_bounded_retry_and_step_only_retry(tmp_path):
    adapter = FakeAdapter([RetryableAdapterError("timeout")])
    service = engine(tmp_path, adapter)
    request = execution()
    first = await service.submit(request.request_id, request)
    assert first.state == "retry_wait"
    retried = await service.retry(
        request.request_id, action(request.request_id, Operation.UPDATE)
    )
    assert retried.state == "completed"
    assert retried.step_results[0].attempt_count == 2
    callback_count = service.repository._connection.execute(
        "SELECT count(*) FROM callback_events"
    ).fetchone()[0]
    assert callback_count == 2
    replayed = await service.retry(
        request.request_id, action(request.request_id, Operation.UPDATE)
    )
    assert replayed.replayed
    callback_count = service.repository._connection.execute(
        "SELECT count(*) FROM callback_events"
    ).fetchone()[0]
    assert callback_count == 3


@pytest.mark.asyncio
async def test_permanent_failure_dead_letters_without_delete_compensation(tmp_path):
    adapter = FakeAdapter([PermanentAdapterError("rejected")])
    service = engine(tmp_path, adapter)
    request = execution()
    result = await service.submit(request.request_id, request)
    assert result.state == "dead_letter"
    assert result.step_results[0].state == StepState.DEAD_LETTER
    assert all(call.operation != Operation.TERMINATE for call in adapter.calls)
    assert service.repository.counts()["dead_letters"] == 1


@pytest.mark.asyncio
async def test_partial_failure_uses_suspend_not_delete(tmp_path):
    adapter = FakeAdapter([None, PermanentAdapterError("later_failed")])
    original_call = adapter.call

    async def call(command):
        if adapter.failures and adapter.failures[0] is None:
            adapter.failures.pop(0)
            adapter.calls.append(command)
            return {"state": "succeeded", "external_id": "created-disabled"}
        return await original_call(command)

    adapter.create_disabled = call
    adapter.update = call
    adapter.suspend = call
    service = engine(tmp_path, adapter)
    request = execution(steps=2)
    result = await service.submit(request.request_id, request)
    assert result.state == "dead_letter"
    assert any(
        item.operation == Operation.UPDATE
        and item.payload.get("compensation") == "remove_excess_access"
        for item in adapter.calls
    )
    assert Operation.TERMINATE not in [item.operation for item in adapter.calls]


@pytest.mark.asyncio
async def test_idempotent_execution_replays_result(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    request = execution()
    first = await service.submit(request.request_id, request)
    second = await service.submit(request.request_id, request)
    assert first.state == "completed"
    assert second.replayed
    assert len(adapter.calls) == 1


@pytest.mark.asyncio
async def test_verification_and_reconciliation_preserve_adapter_identifiers(
    tmp_path,
):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    request = execution()
    original = request.steps[0].model_copy(
        update={"payload": {"username": "synthetic-user"}}
    )
    request = request.model_copy(update={"steps": [original]})
    await service.submit(request.request_id, request)
    await service.verify(
        request.request_id, action(request.request_id, Operation.VERIFY)
    )
    await service.reconcile(
        request.employee_id,
        action(request.request_id, Operation.RECONCILE).model_copy(
            update={"employee_id": request.employee_id}
        ),
    )
    verification = next(
        item for item in adapter.calls if item.operation == Operation.VERIFY
    )
    reconciliation = next(
        item for item in adapter.calls if item.operation == Operation.RECONCILE
    )
    assert verification.payload["username"] == "synthetic-user"
    assert reconciliation.payload["username"] == "synthetic-user"


@pytest.mark.asyncio
async def test_lifecycle_carries_forward_provider_identity_payload(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    original = execution()
    original = original.model_copy(
        update={
            "steps": [
                original.steps[0].model_copy(
                    update={
                        "payload": {
                            "username": "synthetic-user",
                            "extension": 6197,
                        }
                    }
                )
            ]
        }
    )
    await service.submit(original.request_id, original)
    lifecycle = execution(
        request_id="lifecycle-suspend-0001",
        employee_id=original.employee_id,
        key="lifecycle-idempotency-0001",
        operation=Operation.SUSPEND,
    )
    await service.lifecycle(
        original.employee_id, Operation.SUSPEND, lifecycle
    )
    suspended = adapter.calls[-1]
    assert suspended.operation == Operation.SUSPEND
    assert suspended.payload == {
        "username": "synthetic-user",
        "extension": 6197,
    }


@pytest.mark.asyncio
async def test_secret_storage_never_persists_plaintext(tmp_path):
    key_file = tmp_path / "fernet"
    key_file.write_bytes(Fernet.generate_key())
    key_file.chmod(0o600)
    repository = StateRepository(str(tmp_path / "state.db"))
    adapter = SecretStorageAdapter(repository, str(key_file))
    command = execution(target=TargetSystem.SECRET_STORAGE).steps[0]
    result = await adapter.create_disabled(command)
    assert result["credential_reference"].startswith("vault:")
    connection = sqlite3.connect(repository.path)
    ciphertext = connection.execute(
        "SELECT ciphertext FROM encrypted_credentials"
    ).fetchone()[0]
    assert b"vault:" not in ciphertext
