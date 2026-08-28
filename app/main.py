import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .adapters import DisabledAdapter, load_adapters
from .callbacks import CallbackDispatcher
from .config import Settings
from .contracts import (
    ActionRequest,
    ExecutionResult,
    Operation,
    ReconciliationResult,
    RequestEnvelope,
    RequestExecution,
    SipBrowserSessionAction,
    SipBrowserSessionRequest,
    SipBrowserSessionResponse,
)
from .engine import EngineError, ProvisioningEngine
from .logging import configure_logging
from .repository import StateRepository
from .security import JWTAuthorizer, Principal, require_scope
from .sip_browser import SipBrowserSessionError, SipBrowserSessionManager

configure_logging()
logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    repository: StateRepository | None = None,
    adapters=None,
) -> FastAPI:
    configured = settings or Settings.load()
    state = repository or StateRepository(configured.state_database_path)
    loaded_adapters = adapters or load_adapters(
        configured.adapter_config_file,
        state,
        configured.encryption_key_file,
    )
    callbacks = CallbackDispatcher(
        configured.callback_url,
        configured.callback_hmac_file,
        state,
        configured.callback_ca_file,
    )
    engine = ProvisioningEngine(loaded_adapters, state, configured, callbacks)
    try:
        sip_browser = SipBrowserSessionManager(
            state, loaded_adapters, configured.turn_shared_secret_file
        )
    except RuntimeError:
        sip_browser = None
    authorizer = JWTAuthorizer(configured, state)
    disabled_adapters = sorted(
        name for name, adapter in loaded_adapters.items() if isinstance(adapter, DisabledAdapter)
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await engine.start()
        yield
        await engine.stop()

    api = FastAPI(
        title="Codestra Provisioning Service",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    api.state.settings = configured
    api.state.repository = state
    api.state.engine = engine

    @api.middleware("http")
    async def security_boundary(request: Request, call_next):
        started = time.monotonic()
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > configured.request_max_bytes:
                    return JSONResponse(
                        {"detail": "request_too_large"},
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    )
            except ValueError:
                return JSONResponse({"detail": "invalid_content_length"}, status_code=400)
        body = await request.body()
        if len(body) > configured.request_max_bytes:
            return JSONResponse(
                {"detail": "request_too_large"},
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            )
        if (
            request.url.path.startswith("/v1/")
            or request.url.path in {"/session", "/renew", "/config", "/revoke"}
        ) and request.url.scheme != "https":
            return JSONResponse({"detail": "tls_required"}, status_code=400)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        logger.info(
            "request completed",
            extra={
                "fields": {
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round((time.monotonic() - started) * 1000, 2),
                }
            },
        )
        return response

    @api.exception_handler(EngineError)
    async def engine_error(_: Request, exc: EngineError):
        return JSONResponse({"detail": exc.code}, status_code=exc.status_code)

    @api.exception_handler(SipBrowserSessionError)
    async def sip_browser_error(_: Request, exc: SipBrowserSessionError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @api.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError):
        del exc
        return JSONResponse({"detail": "request_validation_failed"}, status_code=422)

    @api.get("/health")
    async def health():
        return {"status": "ok", "environment": "staging"}

    @api.get("/ready")
    async def ready(response: Response):
        errors = configured.readiness_errors()
        if errors:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "not_ready", "conditions": sorted(errors)}
        state.counts()
        return {
            "status": "ready",
            "environment": "staging",
            "degraded_capabilities": disabled_adapters,
            "callback_configured": bool(configured.callback_url),
        }

    @api.get("/metrics", include_in_schema=False)
    async def metrics():
        counts = state.counts()
        lines = [
            "# HELP codestra_provisioning_pending_steps Durable runnable or claimed steps.",
            "# TYPE codestra_provisioning_pending_steps gauge",
            f"codestra_provisioning_pending_steps {counts['pending_steps']}",
            "# HELP codestra_provisioning_dead_letters Unresolved dead-letter steps.",
            "# TYPE codestra_provisioning_dead_letters gauge",
            f"codestra_provisioning_dead_letters {counts['dead_letters']}",
            "# HELP codestra_provisioning_pending_callbacks Undelivered Odoo callbacks.",
            "# TYPE codestra_provisioning_pending_callbacks gauge",
            f"codestra_provisioning_pending_callbacks {counts['pending_callbacks']}",
            "# HELP codestra_provisioning_failed_callbacks Exhausted callback deliveries.",
            "# TYPE codestra_provisioning_failed_callbacks gauge",
            f"codestra_provisioning_failed_callbacks {counts['failed_callbacks']}",
            "# HELP codestra_provisioning_failed_compensations Failed access reductions.",
            "# TYPE codestra_provisioning_failed_compensations gauge",
            f"codestra_provisioning_failed_compensations {counts['failed_compensations']}",
            (
                f'codestra_provisioning_alert{{condition="dead_letter"}} '
                f"{int(counts['dead_letters'] > 0)}"
            ),
            (
                f'codestra_provisioning_alert{{condition="callback_backlog"}} '
                f"{int(counts['pending_callbacks'] > 20)}"
            ),
            (
                f'codestra_provisioning_alert{{condition="callback_failed"}} '
                f"{int(counts['failed_callbacks'] > 0)}"
            ),
            (
            f'codestra_provisioning_alert{{condition="compensation_failed"}} '
                f"{int(counts['failed_compensations'] > 0)}"
            ),
            (
                f'codestra_provisioning_alert{{condition="adapter_unconfigured"}} '
                f"{int(bool(disabled_adapters))}"
            ),
            (
                f'codestra_provisioning_alert{{condition="callback_unconfigured"}} '
                f"{int(not configured.callback_url)}"
            ),
        ]
        return Response("\n".join(lines) + "\n", media_type="text/plain")

    execute_auth = require_scope(authorizer, "provisioning:execute")
    retry_auth = require_scope(authorizer, "provisioning:retry")
    verify_auth = require_scope(authorizer, "provisioning:verify")
    cancel_auth = require_scope(authorizer, "provisioning:cancel")
    read_auth = require_scope(authorizer, "provisioning:read")
    lifecycle_scopes = {
        Operation.SUSPEND: "identity:suspend",
        Operation.REACTIVATE: "identity:reactivate",
        Operation.TERMINATE: "identity:terminate",
        Operation.ROTATE_CREDENTIALS: "identity:rotate",
    }

    @api.post(
        "/v1/provisioning/requests/{request_id}/execute",
        response_model=ExecutionResult,
    )
    async def execute_request(
        request_id: str,
        execution: RequestExecution,
        principal: Principal = Depends(execute_auth),  # noqa: B008
    ):
        del principal
        return await engine.submit(request_id, execution)

    @api.post(
        "/v1/provisioning/requests/{request_id}/retry",
        response_model=ExecutionResult,
    )
    async def retry_request(
        request_id: str,
        action: ActionRequest,
        principal: Principal = Depends(retry_auth),  # noqa: B008
    ):
        del principal
        return await engine.retry(request_id, action)

    @api.post(
        "/v1/provisioning/requests/{request_id}/verify",
        response_model=ExecutionResult,
    )
    async def verify_request(
        request_id: str,
        action: ActionRequest,
        principal: Principal = Depends(verify_auth),  # noqa: B008
    ):
        del principal
        return await engine.verify(request_id, action)

    @api.post(
        "/v1/provisioning/requests/{request_id}/cancel",
        response_model=ExecutionResult,
    )
    async def cancel_request(
        request_id: str,
        action: ActionRequest,
        principal: Principal = Depends(cancel_auth),  # noqa: B008
    ):
        del principal
        return await engine.cancel(request_id, action)

    @api.get(
        "/v1/provisioning/requests/{request_id}",
        response_model=ExecutionResult,
    )
    async def get_request(
        request_id: str,
        envelope: RequestEnvelope,
        principal: Principal = Depends(read_auth),  # noqa: B008
    ):
        del principal
        if envelope.request_id != request_id:
            raise HTTPException(422, "request_id_mismatch")
        result = state.request_result(request_id)
        if not result:
            raise HTTPException(404, "request_not_found")
        return result

    def lifecycle_route(operation: Operation):
        scope_dependency = require_scope(authorizer, lifecycle_scopes[operation])

        async def route(
            employee_id: str,
            execution: RequestExecution,
            principal: Principal = Depends(scope_dependency),  # noqa: B008
        ):
            del principal
            return await engine.lifecycle(employee_id, operation, execution)

        return route

    for operation in (
        Operation.SUSPEND,
        Operation.REACTIVATE,
        Operation.TERMINATE,
        Operation.ROTATE_CREDENTIALS,
    ):
        path_operation = (
            "rotate" if operation == Operation.ROTATE_CREDENTIALS else operation.value
        )
        api.add_api_route(
            f"/v1/identities/{{employee_id}}/{path_operation}",
            lifecycle_route(operation),
            methods=["POST"],
            response_model=ExecutionResult,
        )

    reconcile_auth = require_scope(authorizer, "identity:reconcile")

    @api.get(
        "/v1/identities/{employee_id}/reconciliation",
        response_model=ReconciliationResult,
    )
    async def reconciliation(
        employee_id: str,
        action: ActionRequest,
        principal: Principal = Depends(reconcile_auth),  # noqa: B008
    ):
        del principal
        return await engine.reconcile(employee_id, action)

    @api.post(
        "/session",
        response_model=SipBrowserSessionResponse,
    )
    async def create_sip_browser_session(
        session_request: SipBrowserSessionRequest,
        principal: Principal = Depends(execute_auth),  # noqa: B008
    ):
        del principal
        if sip_browser is None:
            raise HTTPException(503, "sip_browser_adapter_unavailable")
        return await sip_browser.create(session_request)

    @api.post(
        "/renew",
        response_model=SipBrowserSessionResponse,
    )
    async def renew_sip_browser_session(
        action: SipBrowserSessionAction,
        principal: Principal = Depends(
            require_scope(authorizer, "identity:rotate")
        ),  # noqa: B008
    ):
        del principal
        if sip_browser is None:
            raise HTTPException(503, "sip_browser_adapter_unavailable")
        return await sip_browser.renew(action)

    @api.get("/config")
    async def sip_browser_config(
        session_id: str,
        browser_session_binding: str,
        principal: Principal = Depends(read_auth),  # noqa: B008
    ):
        del principal
        if sip_browser is None:
            raise HTTPException(503, "sip_browser_adapter_unavailable")
        action = SipBrowserSessionAction(
            session_id=session_id,
            browser_session_binding=browser_session_binding,
        )
        return sip_browser.config(action)

    @api.post("/revoke")
    async def revoke_sip_browser_session(
        action: SipBrowserSessionAction,
        principal: Principal = Depends(
            require_scope(authorizer, "identity:rotate")
        ),  # noqa: B008
    ):
        del principal
        if sip_browser is None:
            raise HTTPException(503, "sip_browser_adapter_unavailable")
        return await sip_browser.revoke(action)

    return api
