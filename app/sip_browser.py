import base64
import hashlib
import hmac
import uuid
from datetime import UTC, datetime, timedelta

from .adapters import PermanentAdapterError, TelephonyProvisioningAdapter
from .contracts import (
    Operation,
    SipBrowserSessionAction,
    SipBrowserSessionRequest,
    SipBrowserSessionResponse,
    TargetSystem,
)
from .repository import StateRepository
from .secrets import read_secret_file


class SipBrowserSessionError(RuntimeError):
    pass


class SipBrowserSessionManager:
    """Issues memory-only browser credentials bound to real staging identities."""

    def __init__(
        self,
        repository: StateRepository,
        adapters: dict,
        turn_secret_file: str,
    ):
        self.repository = repository
        adapter = adapters.get(TargetSystem.SIP.value)
        if not isinstance(adapter, TelephonyProvisioningAdapter):
            raise RuntimeError("sip_runtime_adapter_required")
        self.sip_adapter = adapter
        self.turn_secret_file = turn_secret_file

    def _validated_command(self, request: SipBrowserSessionRequest):
        results = {
            item.target_system.value: item
            for item in self.repository.employee_results(request.employee_id)
        }
        commands = {
            item.target_system.value: item
            for item in self.repository.employee_commands(request.employee_id)
        }
        required = {"keycloak", "vicidial", "sip"}
        if not required <= set(results) or not required <= set(commands):
            raise SipBrowserSessionError("identity_binding_incomplete")
        keycloak_result = results["keycloak"]
        if keycloak_result.external_id != request.keycloak_subject:
            raise SipBrowserSessionError("keycloak_subject_mismatch")
        if keycloak_result.operation not in {Operation.ACTIVATE, Operation.REACTIVATE}:
            raise SipBrowserSessionError("identity_not_active")
        vicidial = commands["vicidial"].payload
        sip = commands["sip"].payload
        keycloak = commands["keycloak"].payload
        if (
            vicidial.get("username") != request.vicidial_username
            or int(sip.get("extension", 0)) != request.endpoint
            or keycloak.get("attributes", {}).get("role_template") != request.role
            or request.campaign
            not in set(vicidial.get("campaigns", []))
        ):
            raise SipBrowserSessionError("identity_authorization_mismatch")
        return commands["sip"]

    async def _rotate(self, original, binding: str, include_temporary: bool):
        command = original.model_copy(
            update={
                "operation": Operation.ROTATE_CREDENTIALS,
                "idempotency_key": (
                    f"sip-browser:{uuid.uuid4()}:{original.employee_id}"
                ),
                "payload": {
                    **original.payload,
                    **(
                        {"browser_session_binding": binding}
                        if include_temporary
                        else {"browser_session_revocation": True}
                    ),
                },
            }
        )
        if include_temporary:
            return await self.sip_adapter.issue_browser_credential(command)
        return await self.sip_adapter.rotate_credentials(command)

    def _response(self, session: dict, temporary: dict):
        expires_at = datetime.fromisoformat(session["expires_at"])
        turn_username = f"{int(expires_at.timestamp())}:{session['session_id']}"
        turn_secret = read_secret_file(self.turn_secret_file).encode()
        turn_credential = base64.b64encode(
            hmac.new(turn_secret, turn_username.encode(), hashlib.sha1).digest()
        ).decode()
        return SipBrowserSessionResponse(
            session_id=session["session_id"],
            temporary_sip_authorization_username=str(session["endpoint"]),
            temporary_sip_credential=temporary["temporary_sip_credential"],
            endpoint=session["endpoint"],
            sip_uri=(
                f"sip:{session['endpoint']}@vicidial-staging.codestra.agency"
            ),
            approved_wss_url="wss://vicidial-staging.codestra.agency:8089/ws",
            temporary_turn_username=turn_username,
            temporary_turn_credential=turn_credential,
            approved_turn_url=(
                "turns:vicidial-staging.codestra.agency:5349?transport=tcp"
            ),
            expiration=expires_at,
            campaign=session["campaign"],
            role=session["role"],
            employee_identity=session["employee_id"],
            browser_session_binding=session["browser_session_binding"],
        )

    async def create(
        self, request: SipBrowserSessionRequest
    ) -> SipBrowserSessionResponse:
        if self.repository.active_sip_browser_session(request.employee_id):
            raise SipBrowserSessionError("active_browser_session_exists")
        original = self._validated_command(request)
        temporary = await self._rotate(
            original, request.browser_session_binding, True
        )
        expires_at = datetime.now(UTC) + timedelta(
            seconds=temporary["expires_in_seconds"]
        )
        session = self.repository.create_sip_browser_session(
            {
                **request.model_dump(),
                "session_id": str(uuid.uuid4()),
                "credential_fingerprint": hashlib.sha256(
                    temporary["temporary_sip_credential"].encode()
                ).hexdigest(),
                "expires_at": expires_at.isoformat(),
            }
        )
        return self._response(session, temporary)

    async def renew(
        self, action: SipBrowserSessionAction
    ) -> SipBrowserSessionResponse:
        session = self._active(action)
        request = SipBrowserSessionRequest(
            **{
                key: session[key]
                for key in SipBrowserSessionRequest.model_fields
            }
        )
        original = self._validated_command(request)
        temporary = await self._rotate(
            original, action.browser_session_binding, True
        )
        expires_at = datetime.now(UTC) + timedelta(
            seconds=temporary["expires_in_seconds"]
        )
        session = self.repository.renew_sip_browser_session(
            action.session_id,
            hashlib.sha256(
                temporary["temporary_sip_credential"].encode()
            ).hexdigest(),
            expires_at.isoformat(),
        )
        return self._response(session, temporary)

    def _active(self, action: SipBrowserSessionAction) -> dict:
        session = self.repository.sip_browser_session(action.session_id)
        if session and session["state"] == "active":
            expires_at = datetime.fromisoformat(session["expires_at"])
            if expires_at <= datetime.now(UTC):
                self.repository.expire_sip_browser_session(action.session_id)
                session = self.repository.sip_browser_session(action.session_id)
        if (
            not session
            or session["state"] != "active"
            or session["browser_session_binding"]
            != action.browser_session_binding
        ):
            raise SipBrowserSessionError("sip_browser_session_not_active")
        return session

    def config(self, action: SipBrowserSessionAction) -> dict:
        session = self._active(action)
        return {
            key: session[key]
            for key in (
                "session_id",
                "employee_id",
                "endpoint",
                "campaign",
                "role",
                "browser_session_binding",
                "expires_at",
                "state",
            )
        }

    async def revoke(self, action: SipBrowserSessionAction) -> dict:
        session = self._active(action)
        commands = {
            item.target_system.value: item
            for item in self.repository.employee_commands(session["employee_id"])
        }
        try:
            await self._rotate(
                commands[TargetSystem.SIP.value],
                action.browser_session_binding,
                False,
            )
        except PermanentAdapterError as exc:
            raise SipBrowserSessionError("sip_credential_revocation_failed") from exc
        self.repository.revoke_sip_browser_session(action.session_id)
        return {"session_id": action.session_id, "state": "revoked"}
