from datetime import UTC, datetime, timedelta

import pytest

from app.contracts import Operation, StepState, TargetSystem
from app.repository import IdempotencyConflict, StateRepository
from tests.helpers import execution


def test_duplicate_suppression_and_payload_conflict(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    request = execution()
    assert repository.begin_execution(request, "a" * 64) == (None, False)
    assert repository.begin_execution(request, "a" * 64)[1] is True
    with pytest.raises(IdempotencyConflict):
        repository.begin_execution(request.model_copy(update={"employee_id": "other"}), "b" * 64)


def test_atomic_claim_and_restart_recovery(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    request = execution()
    repository.begin_execution(request, "a" * 64)
    claimed = repository.claim_next(request.request_id)
    assert claimed is not None
    assert repository.claim_next(request.request_id) is None
    assert repository.recover_stale(0) == 1
    assert repository.claim_next(request.request_id) is not None


def test_replay_and_rate_state_are_durable(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    expiration = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    assert repository.accept_jti("once", expiration)
    assert not repository.accept_jti("once", expiration)
    assert repository.check_rate("service", 2, 60)
    assert repository.check_rate("service", 2, 60)
    assert not repository.check_rate("service", 2, 60)


def test_callback_retries_are_bounded(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    repository.enqueue_callback("event-1", {"state": "completed"})
    for _ in range(8):
        repository.mark_callback(
            "event-1",
            False,
            "transport_error",
            datetime.now(UTC),
        )
    assert repository.due_callbacks() == []
    assert repository.counts()["failed_callbacks"] == 1


def test_employee_commands_preserves_canonical_binding_payload(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    original = execution(target=TargetSystem.VICIDIAL).model_copy(
        update={
            "steps": [
                execution(target=TargetSystem.VICIDIAL).steps[0].model_copy(
                    update={
                        "payload": {
                            "username": "synthetic-agent",
                            "campaigns": ["TRANSFER_TEST"],
                            "role": "AGENT",
                        }
                    }
                )
            ]
        }
    )
    repository.begin_execution(original, "a" * 64)
    repository.complete_step(
        original.steps[0].step_id,
        StepState.SUCCEEDED,
        {"external_id": "synthetic-agent"},
    )
    later = execution(
        request_id="request-later",
        key="idempotency-later",
        target=TargetSystem.VICIDIAL,
        operation=Operation.SUSPEND,
    )
    repository.begin_execution(later, "b" * 64)
    repository.complete_step(
        later.steps[0].step_id,
        StepState.SUCCEEDED,
        {"external_id": "synthetic-agent"},
    )
    command = repository.employee_commands("employee-0001")[0]
    assert command.operation == Operation.CREATE_DISABLED
    assert command.payload["campaigns"] == ["TRANSFER_TEST"]


def test_expired_browser_session_is_not_active(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    session = repository.create_sip_browser_session(
        {
            "session_id": "00000000-0000-4000-8000-000000000010",
            "employee_id": "employee-expired",
            "keycloak_subject": "subject-expired-0001",
            "odoo_employee_id": "odoo-expired",
            "vicidial_username": "expired-agent",
            "endpoint": 6198,
            "campaign": "TEST_EXP",
            "role": "AGENT",
            "browser_session_binding": "00000000-0000-4000-8000-000000000011",
            "credential_fingerprint": "fingerprint",
            "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        }
    )
    assert session["state"] == "active"
    assert repository.active_sip_browser_session("employee-expired") is None
    assert repository.sip_browser_session(session["session_id"])["state"] == "expired"
