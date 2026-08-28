import asyncio
import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

from .adapters import AdapterError, ProvisioningAdapter, RetryableAdapterError
from .callbacks import CallbackDispatcher
from .config import Settings, enabled
from .contracts import (
    ActionRequest,
    CallbackEvent,
    ExecutionResult,
    Operation,
    ReconciliationResult,
    RequestEnvelope,
    RequestExecution,
    StepResult,
    StepState,
    TargetSystem,
)
from .repository import IdempotencyConflict, StateRepository

logger = logging.getLogger(__name__)


class EngineError(RuntimeError):
    def __init__(self, status_code: int, code: str):
        super().__init__(code)
        self.status_code = status_code
        self.code = code


def canonical_hash(execution: RequestExecution) -> str:
    return hashlib.sha256(
        json.dumps(
            execution.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()


def hashed_key(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


class ProvisioningEngine:
    def __init__(
        self,
        adapters: dict[str, ProvisioningAdapter],
        repository: StateRepository,
        settings: Settings,
        callback_dispatcher: CallbackDispatcher,
    ):
        self.adapters = adapters
        self.repository = repository
        self.settings = settings
        self.callback_dispatcher = callback_dispatcher
        self._locks: dict[str, asyncio.Lock] = {}
        self._recovery_task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    def _validate_freshness(self, execution: RequestExecution):
        age = abs((datetime.now(UTC) - execution.timestamp).total_seconds())
        if age > self.settings.request_max_age_seconds:
            raise EngineError(422, "request_timestamp_outside_window")

    @staticmethod
    def _normalize_keys(execution: RequestExecution) -> RequestExecution:
        document = execution.model_dump()
        document["idempotency_key"] = hashed_key(execution.idempotency_key)
        for index, step in enumerate(execution.steps):
            document["steps"][index]["idempotency_key"] = hashed_key(step.idempotency_key)
        return RequestExecution.model_validate(document)

    async def submit(
        self, request_id: str, execution: RequestExecution
    ) -> ExecutionResult:
        if not enabled("PROVISIONING_SERVICE_GATE") or not enabled("STEP_ENGINE_GATE"):
            raise EngineError(503, "provisioning_engine_gate_closed")
        if execution.request_id != request_id:
            raise EngineError(422, "request_id_mismatch")
        self._validate_freshness(execution)
        normalized = self._normalize_keys(execution)
        lock = self._locks.setdefault(request_id, asyncio.Lock())
        async with lock:
            try:
                existing, replayed = self.repository.begin_execution(
                    normalized, canonical_hash(normalized)
                )
            except IdempotencyConflict as exc:
                raise EngineError(409, str(exc)) from exc
            if replayed:
                current = existing or self.repository.request_result(
                    request_id, replayed=True
                )
                if current:
                    return current.model_copy(update={"replayed": True})
            await self._run_request(request_id)
            result = self.repository.request_result(request_id)
            if not result:
                raise EngineError(500, "execution_state_missing")
            await self._callback(normalized, result)
            return result

    async def retry(self, request_id: str, action: ActionRequest) -> ExecutionResult:
        if not enabled("RETRY_GATE"):
            raise EngineError(503, "retry_gate_closed")
        if action.request_id != request_id or action.operation != Operation.UPDATE:
            raise EngineError(422, "retry_envelope_mismatch")
        self._validate_action_freshness(action)
        lock = self._locks.setdefault(request_id, asyncio.Lock())
        async with lock:
            if not self.repository.schedule_step_retry(request_id):
                current = self.repository.request_result(request_id, replayed=True)
                if current:
                    await self._callback(action, current)
                    return current
                raise EngineError(404, "request_not_found")
            await self._run_request(request_id)
            result = self.repository.request_result(request_id)
            if not result:
                raise EngineError(404, "request_not_found")
            await self._callback(action, result)
            return result

    async def _run_request(self, request_id: str):
        while command := self.repository.claim_next(request_id):
            adapter = self.adapters.get(command.target_system.value)
            if not adapter:
                state = self.repository.fail_step(
                    command.step_id, "adapter_not_registered", "permanent", None
                )
                if state == StepState.DEAD_LETTER:
                    await self._compensate(request_id)
                return
            try:
                raw_result = await adapter.execute(command)
                evidence = hashlib.sha256(
                    json.dumps(
                        raw_result, sort_keys=True, separators=(",", ":"), default=str
                    ).encode()
                ).hexdigest()
                state = (
                    StepState.VERIFIED
                    if command.operation in {Operation.VERIFY, Operation.RECONCILE}
                    else StepState.SUCCEEDED
                )
                self.repository.complete_step(
                    command.step_id,
                    state,
                    {
                        "target_system": command.target_system,
                        "operation": command.operation,
                        "external_id": raw_result.get("external_id"),
                        "external_reference": raw_result.get("external_reference"),
                        "credential_reference": raw_result.get("credential_reference"),
                        "evidence_hash": evidence,
                    },
                )
            except AdapterError as exc:
                retry_at = None
                if isinstance(exc, RetryableAdapterError):
                    current = self.repository.request_result(request_id)
                    attempt = next(
                        (
                            step.attempt_count
                            for step in current.step_results
                            if step.step_id == command.step_id
                        ),
                        1,
                    )
                    retry_at = datetime.now(UTC) + timedelta(
                        seconds=min(
                            self.settings.retry_base_seconds * (2 ** max(attempt - 1, 0)),
                            300,
                        )
                    )
                state = self.repository.fail_step(
                    command.step_id, exc.code, exc.retry_class, retry_at
                )
                logger.warning(
                    "adapter step failed",
                    extra={
                        "fields": {
                            "request_id": request_id,
                            "step_id": command.step_id,
                            "target_system": command.target_system,
                            "error_code": exc.code,
                            "state": state,
                        }
                    },
                )
                if state == StepState.DEAD_LETTER:
                    if not enabled("DEAD_LETTER_GATE"):
                        raise EngineError(503, "dead_letter_gate_closed") from exc
                    await self._compensate(request_id)
                return
            except Exception:
                self.repository.fail_step(
                    command.step_id,
                    "adapter_unclassified_failure",
                    "permanent",
                    None,
                )
                await self._compensate(request_id)
                logger.exception(
                    "unclassified adapter failure",
                    extra={"fields": {"request_id": request_id, "step_id": command.step_id}},
                )
                return

    async def _compensate(self, request_id: str):
        """Reduce access after partial failure; never deletes a created identity."""
        for original in self.repository.successful_commands(request_id):
            if original.operation not in {
                Operation.CREATE_DISABLED,
                Operation.UPDATE,
                Operation.ACTIVATE,
            }:
                continue
            operation = (
                Operation.UPDATE
                if original.target_system == TargetSystem.ODOO
                else Operation.SUSPEND
            )
            payload = {
                "compensation": (
                    "remove_excess_access"
                    if operation == Operation.UPDATE
                    else (
                        "revoke_sessions"
                        if original.target_system == TargetSystem.AGENT_DESKTOP
                        else "suspend"
                    )
                )
            }
            command = original.model_copy(
                update={
                    "operation": operation,
                    "idempotency_key": hashed_key(
                        f"compensate:{request_id}:{original.step_id}:{operation}"
                    ),
                    "payload": payload,
                }
            )
            try:
                result = await self.adapters[original.target_system.value].execute(command)
                evidence = hashlib.sha256(
                    json.dumps(result, sort_keys=True, default=str).encode()
                ).hexdigest()
                self.repository.record_compensation(
                    request_id, original.step_id, operation.value, "succeeded", evidence
                )
            except AdapterError as exc:
                self.repository.record_compensation(
                    request_id,
                    original.step_id,
                    operation.value,
                    "failed",
                    error_code=exc.code,
                )

    def _validate_action_freshness(self, action: ActionRequest):
        age = abs((datetime.now(UTC) - action.timestamp).total_seconds())
        if age > self.settings.request_max_age_seconds:
            raise EngineError(422, "request_timestamp_outside_window")

    async def cancel(self, request_id: str, action: ActionRequest) -> ExecutionResult:
        if action.request_id != request_id or action.operation != Operation.CANCEL:
            raise EngineError(422, "cancel_operation_required")
        self._validate_action_freshness(action)
        if not self.repository.request_result(request_id):
            raise EngineError(404, "request_not_found")
        self.repository.cancel_pending(request_id)
        await self._compensate(request_id)
        result = self.repository.request_result(request_id)
        if not result:
            raise EngineError(500, "execution_state_missing")
        return result

    async def verify(self, request_id: str, action: ActionRequest) -> ExecutionResult:
        if action.request_id != request_id or action.operation != Operation.VERIFY:
            raise EngineError(422, "verify_operation_required")
        self._validate_action_freshness(action)
        current = self.repository.request_result(request_id)
        if not current:
            raise EngineError(404, "request_not_found")
        results = []
        for original in self.repository.successful_commands(request_id):
            command = original.model_copy(
                update={
                    "operation": Operation.VERIFY,
                    "idempotency_key": hashed_key(
                        f"verify:{action.idempotency_key}:{original.step_id}"
                    ),
                    "payload": {
                        **original.payload,
                        "external_verification": True,
                    },
                }
            )
            try:
                raw = await self.adapters[command.target_system.value].verify(command)
                evidence = hashlib.sha256(
                    json.dumps(raw, sort_keys=True, default=str).encode()
                ).hexdigest()
                results.append(
                    current.step_results[0].model_copy(
                        update={
                            "step_id": command.step_id,
                            "target_system": command.target_system,
                            "operation": Operation.VERIFY,
                            "state": StepState.VERIFIED,
                            "evidence_hash": evidence,
                            "error_code": None,
                        }
                    )
                )
            except AdapterError as exc:
                results.append(
                    current.step_results[0].model_copy(
                        update={
                            "step_id": command.step_id,
                            "target_system": command.target_system,
                            "operation": Operation.VERIFY,
                            "state": StepState.FAILED,
                            "error_code": exc.code,
                        }
                    )
                )
        return current.model_copy(
            update={
                "state": (
                    "verified"
                    if results and all(item.state == StepState.VERIFIED for item in results)
                    else "verification_failed"
                ),
                "step_results": results,
            }
        )

    async def lifecycle(
        self, employee_id: str, operation: Operation, execution: RequestExecution
    ) -> ExecutionResult:
        if execution.employee_id != employee_id:
            raise EngineError(422, "employee_id_mismatch")
        if execution.operation != operation or any(
            step.operation != operation for step in execution.steps
        ):
            raise EngineError(422, "operation_mismatch")
        # Provider identifiers stay bound to the last successful target
        # command. Lifecycle callers may add fields, but must not have to
        # reconstruct or guess the VICIdial/SIP identity mapping.
        prior = {
            command.target_system.value: command
            for command in self.repository.employee_commands(employee_id)
        }
        document = execution.model_dump()
        for step in document["steps"]:
            previous = prior.get(step["target_system"])
            if previous:
                step["payload"] = {**previous.payload, **step["payload"]}
        enriched = RequestExecution.model_validate(document)
        return await self.submit(enriched.request_id, enriched)

    async def reconcile(
        self, employee_id: str, action: ActionRequest
    ) -> ReconciliationResult:
        if not enabled("RECONCILIATION_GATE"):
            raise EngineError(503, "reconciliation_gate_closed")
        if (
            action.employee_id != employee_id
            or action.operation != Operation.RECONCILE
        ):
            raise EngineError(422, "reconciliation_envelope_mismatch")
        self._validate_action_freshness(action)
        results: list[StepResult] = []
        for original in self.repository.employee_commands(employee_id):
            command = original.model_copy(
                update={
                    "operation": Operation.RECONCILE,
                    "idempotency_key": hashed_key(
                        f"reconcile:{action.idempotency_key}:{original.step_id}"
                    ),
                    "payload": {
                        **original.payload,
                        "expected_state_check": True,
                    },
                }
            )
            try:
                raw = await self.adapters[command.target_system.value].reconcile(command)
                evidence = hashlib.sha256(
                    json.dumps(raw, sort_keys=True, default=str).encode()
                ).hexdigest()
                results.append(
                    StepResult(
                        step_id=command.step_id,
                        target_system=command.target_system,
                        operation=Operation.RECONCILE,
                        state=StepState.VERIFIED,
                        attempt_count=1,
                        external_id=raw.get("external_id"),
                        external_reference=raw.get("external_reference"),
                        evidence_hash=evidence,
                    )
                )
            except AdapterError as exc:
                results.append(
                    StepResult(
                        step_id=command.step_id,
                        target_system=command.target_system,
                        operation=Operation.RECONCILE,
                        state=StepState.FAILED,
                        attempt_count=1,
                        error_code=exc.code,
                    )
                )
        return ReconciliationResult(
            employee_id=employee_id,
            state=(
                "aligned"
                if results and all(item.state == StepState.VERIFIED for item in results)
                else "drift_or_unavailable"
            ),
            systems=results,
        )

    async def _callback(
        self, execution: RequestEnvelope, result: ExecutionResult
    ):
        if not enabled("CALLBACK_GATE"):
            return
        event = CallbackEvent(
            event_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"{result.request_id}:{result.state}:{result.updated_at.isoformat()}",
                )
            ),
            request_id=result.request_id,
            employee_id=result.employee_id,
            correlation_id=result.correlation_id,
            idempotency_key=hashed_key(execution.idempotency_key),
            state=result.state,
            step_results=result.step_results,
        )
        await self.callback_dispatcher.enqueue_and_dispatch(event)

    async def recover(self):
        if not enabled("RESTART_RECOVERY_GATE"):
            raise EngineError(503, "restart_recovery_gate_closed")
        recovered = self.repository.recover_stale(self.settings.claim_timeout_seconds)
        logger.info("restart recovery complete", extra={"fields": {"recovered_steps": recovered}})
        for request_id in self.repository.pending_request_ids():
            await self._run_request(request_id)

    async def worker(self):
        while not self._stopping.is_set():
            for request_id in self.repository.pending_request_ids():
                lock = self._locks.setdefault(request_id, asyncio.Lock())
                if not lock.locked():
                    async with lock:
                        await self._run_request(request_id)
            await self.callback_dispatcher.dispatch_due()
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=1)
            except TimeoutError:
                pass

    async def start(self):
        await self.recover()
        self._recovery_task = asyncio.create_task(self.worker())

    async def stop(self):
        self._stopping.set()
        if self._recovery_task:
            await self._recovery_task
