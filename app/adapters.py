import hashlib
import hmac
import json
import secrets
import ssl
import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet

from .config import enabled
from .contracts import Operation, StepCommand, TargetSystem
from .repository import IdempotencyConflict, StateRepository
from .secrets import read_secret_file


class AdapterError(RuntimeError):
    retry_class = "permanent"

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class RetryableAdapterError(AdapterError):
    retry_class = "transient"


class PermanentAdapterError(AdapterError):
    retry_class = "permanent"


class ProvisioningAdapter(ABC):
    @abstractmethod
    async def create_disabled(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def update(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def verify(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def activate(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def suspend(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def reactivate(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def terminate(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def rotate_credentials(self, command: StepCommand) -> dict[str, Any]: ...

    @abstractmethod
    async def reconcile(self, command: StepCommand) -> dict[str, Any]: ...

    async def execute(self, command: StepCommand) -> dict[str, Any]:
        method = getattr(self, command.operation.value, None)
        if not method:
            raise PermanentAdapterError("unsupported_adapter_operation")
        return await method(command)


class CompanyMailboxProvider(ABC):
    """Mailbox provider contract using provider-native one-time activation."""

    @abstractmethod
    async def check_availability(
        self, email_address: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def reserve_address(
        self, email_address: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def create_mailbox_disabled(
        self, email_address: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def assign_license(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def create_alias(
        self, external_mailbox_id: str, alias: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def send_activation(
        self, external_mailbox_id: str, activation_recipient: str,
        idempotency_key: str,
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def verify_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def activate_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def suspend_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def reactivate_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def terminate_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def reconcile_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict[str, Any]: ...


class DisabledAdapter(ProvisioningAdapter):
    def __init__(self, system: str):
        self.system = system

    async def _disabled(self, command: StepCommand) -> dict[str, Any]:
        del command
        raise PermanentAdapterError(f"{self.system}_adapter_not_configured")

    create_disabled = update = verify = activate = suspend = reactivate = _disabled
    terminate = rotate_credentials = reconcile = _disabled


class HttpAdapter(ProvisioningAdapter):
    """Private TLS adapter. Credentials are loaded only from protected files."""

    default_routes: ClassVar[dict[Operation, str]] = {
        operation: operation.value for operation in Operation
    }

    def __init__(
        self,
        system: str,
        base_url: str,
        credential_file: str,
        ca_file: str,
        routes: dict[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("adapter URL must be credential-free HTTPS")
        self.system = system
        self.base_url = base_url.rstrip("/")
        self.credential_file = credential_file
        self.ca_file = ca_file
        self.routes = {**self.default_routes, **(routes or {})}
        self.client = client

    async def _call(self, command: StepCommand) -> dict[str, Any]:
        credential = read_secret_file(self.credential_file)
        route = self.routes.get(command.operation, command.operation.value)
        envelope = command.model_dump(mode="json")
        headers = {
            "Authorization": f"Bearer {credential}",
            "Idempotency-Key": command.idempotency_key,
            "X-Correlation-ID": command.correlation_id,
            "X-Codestra-Schema-Version": command.schema_version,
        }
        owned = self.client is None
        client = self.client or httpx.AsyncClient(
            timeout=httpx.Timeout(15, connect=3),
            verify=self.ca_file,
            follow_redirects=False,
        )
        try:
            response = await client.post(
                f"{self.base_url}/{route.lstrip('/')}", json=envelope, headers=headers
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise RetryableAdapterError(f"{self.system}_transport_unavailable") from exc
        except httpx.HTTPError as exc:
            raise PermanentAdapterError(f"{self.system}_transport_rejected") from exc
        finally:
            if owned:
                await client.aclose()
        if response.status_code in {408, 425, 429} or response.status_code >= 500:
            raise RetryableAdapterError(f"{self.system}_http_{response.status_code}")
        if response.status_code >= 400:
            raise PermanentAdapterError(f"{self.system}_http_{response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise PermanentAdapterError(f"{self.system}_invalid_response") from exc
        if not isinstance(body, dict):
            raise PermanentAdapterError(f"{self.system}_invalid_response")
        return {
            "state": body.get(
                "state", "verified" if command.operation == Operation.VERIFY else "succeeded"
            ),
            "external_id": body.get("external_id"),
            "external_reference": body.get("external_reference"),
            "credential_reference": body.get("credential_reference"),
            "response_hash": hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }

    create_disabled = update = verify = activate = suspend = reactivate = _call
    terminate = rotate_credentials = reconcile = _call


class OdooAdapter(HttpAdapter):
    pass


class VicidialAdapter(HttpAdapter):
    pass


class SipAdapter(HttpAdapter):
    pass


class AgentDesktopAdapter(HttpAdapter):
    pass


class EmailProviderAdapter(HttpAdapter, CompanyMailboxProvider):
    """Approved hosted-mail boundary; never accepts or returns passwords."""

    mailbox_routes: ClassVar[dict[str, str]] = {
        "check_availability": "mailboxes/check-availability",
        "reserve_address": "mailboxes/reserve",
        "create_mailbox_disabled": "mailboxes/create-disabled",
        "assign_license": "mailboxes/assign-license",
        "create_alias": "mailboxes/create-alias",
        "send_activation": "mailboxes/send-activation",
        "verify_mailbox": "mailboxes/verify",
        "activate_mailbox": "mailboxes/activate",
        "suspend_mailbox": "mailboxes/suspend",
        "reactivate_mailbox": "mailboxes/reactivate",
        "terminate_mailbox": "mailboxes/terminate",
        "reconcile_mailbox": "mailboxes/reconcile",
    }

    @staticmethod
    def _assert_secret_free(value: Any) -> None:
        forbidden = {
            "password", "password_hash", "temporary_password", "token",
            "secret", "private_key", "recovery_code",
        }

        def keys(item):
            if isinstance(item, dict):
                for key, nested in item.items():
                    yield str(key).lower()
                    yield from keys(nested)
            elif isinstance(item, list):
                for nested in item:
                    yield from keys(nested)

        if forbidden.intersection(keys(value)):
            raise PermanentAdapterError("email_provider_returned_forbidden_secret")

    async def _mailbox_call(
        self, operation: str, payload: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        self._assert_secret_free(payload)
        credential = read_secret_file(self.credential_file)
        headers = {
            "Authorization": f"Bearer {credential}",
            "Idempotency-Key": idempotency_key,
            "X-Correlation-ID": idempotency_key,
        }
        owned = self.client is None
        client = self.client or httpx.AsyncClient(
            timeout=httpx.Timeout(15, connect=3),
            verify=self.ca_file,
            follow_redirects=False,
        )
        try:
            response = await client.post(
                f"{self.base_url}/{self.mailbox_routes[operation]}",
                json=payload,
                headers=headers,
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise RetryableAdapterError("email_provider_transport_unavailable") from exc
        except httpx.HTTPError as exc:
            raise PermanentAdapterError("email_provider_transport_rejected") from exc
        finally:
            if owned:
                await client.aclose()
        if response.status_code in {408, 425, 429} or response.status_code >= 500:
            raise RetryableAdapterError(
                f"email_provider_http_{response.status_code}"
            )
        if response.status_code == 409:
            raise PermanentAdapterError("email_address_collision")
        if response.status_code == 402:
            raise PermanentAdapterError("email_license_exhausted")
        if response.status_code >= 400:
            raise PermanentAdapterError(
                f"email_provider_http_{response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise PermanentAdapterError("email_provider_invalid_response") from exc
        if not isinstance(body, dict):
            raise PermanentAdapterError("email_provider_invalid_response")
        self._assert_secret_free(body)
        return body

    async def check_availability(self, email_address, idempotency_key):
        return await self._mailbox_call(
            "check_availability", {"email_address": email_address}, idempotency_key
        )

    async def reserve_address(self, email_address, idempotency_key):
        return await self._mailbox_call(
            "reserve_address", {"email_address": email_address}, idempotency_key
        )

    async def create_mailbox_disabled(self, email_address, idempotency_key):
        return await self._mailbox_call(
            "create_mailbox_disabled", {"email_address": email_address},
            idempotency_key,
        )

    async def assign_license(self, external_mailbox_id, idempotency_key):
        return await self._mailbox_call(
            "assign_license", {"external_mailbox_id": external_mailbox_id},
            idempotency_key,
        )

    async def create_alias(self, external_mailbox_id, alias, idempotency_key):
        return await self._mailbox_call(
            "create_alias",
            {"external_mailbox_id": external_mailbox_id, "alias": alias},
            idempotency_key,
        )

    async def send_activation(
        self, external_mailbox_id, activation_recipient, idempotency_key
    ):
        return await self._mailbox_call(
            "send_activation",
            {
                "external_mailbox_id": external_mailbox_id,
                "activation_recipient": activation_recipient,
                "activation_method": "provider_one_time_reset",
            },
            idempotency_key,
        )

    async def verify_mailbox(self, external_mailbox_id, idempotency_key):
        return await self._mailbox_call(
            "verify_mailbox", {"external_mailbox_id": external_mailbox_id},
            idempotency_key,
        )

    async def activate_mailbox(self, external_mailbox_id, idempotency_key):
        return await self._mailbox_call(
            "activate_mailbox", {"external_mailbox_id": external_mailbox_id},
            idempotency_key,
        )

    async def suspend_mailbox(self, external_mailbox_id, idempotency_key):
        return await self._mailbox_call(
            "suspend_mailbox", {"external_mailbox_id": external_mailbox_id},
            idempotency_key,
        )

    async def reactivate_mailbox(self, external_mailbox_id, idempotency_key):
        return await self._mailbox_call(
            "reactivate_mailbox", {"external_mailbox_id": external_mailbox_id},
            idempotency_key,
        )

    async def terminate_mailbox(self, external_mailbox_id, idempotency_key):
        return await self._mailbox_call(
            "terminate_mailbox", {"external_mailbox_id": external_mailbox_id},
            idempotency_key,
        )

    async def reconcile_mailbox(self, external_mailbox_id, idempotency_key):
        return await self._mailbox_call(
            "reconcile_mailbox", {"external_mailbox_id": external_mailbox_id},
            idempotency_key,
        )


class DeterministicMailboxMockAdapter(ProvisioningAdapter):
    """Delivery-free durable mock; never represents a hosted mailbox."""

    def __init__(self, repository: StateRepository):
        self.repository = repository

    async def _transition(self, command: StepCommand) -> dict[str, Any]:
        try:
            row = self.repository.transition_mock_mailbox(
                command.employee_id,
                command.operation.value,
                command.payload.get("email_address"),
            )
        except (IdempotencyConflict, ValueError, LookupError) as exc:
            raise PermanentAdapterError(str(exc)) from exc
        return {
            "state": row["provisioning_state"],
            "external_id": row["external_mailbox_id"],
            "external_reference": "deterministic_internal_mock",
            "credential_reference": row["credential_reference"],
        }

    create_disabled = verify = activate = suspend = reactivate = terminate = _transition
    reconcile = _transition

    async def update(self, command: StepCommand) -> dict[str, Any]:
        del command
        raise PermanentAdapterError("mock_mailbox_update_unsupported")

    async def rotate_credentials(self, command: StepCommand) -> dict[str, Any]:
        del command
        raise PermanentAdapterError("mock_mailbox_has_no_credentials")


class TelephonyProvisioningAdapter(ProvisioningAdapter):
    """Private Server B mTLS + HMAC provisioning boundary."""

    operation_map: ClassVar[dict[str, dict[Operation, str]]] = {
        TargetSystem.VICIDIAL.value: {
            Operation.CREATE_DISABLED: "create_user_disabled",
            Operation.UPDATE: "update_user",
            Operation.VERIFY: "verify_user",
            Operation.ACTIVATE: "activate_user",
            Operation.SUSPEND: "disable_user",
            Operation.REACTIVATE: "activate_user",
            Operation.TERMINATE: "disable_user",
            Operation.RECONCILE: "reconcile",
        },
        TargetSystem.SIP.value: {
            Operation.CREATE_DISABLED: "create_phone_disabled",
            Operation.UPDATE: "update_phone",
            Operation.VERIFY: "verify_phone",
            Operation.ACTIVATE: "activate_phone",
            Operation.SUSPEND: "disable_phone",
            Operation.REACTIVATE: "activate_phone",
            Operation.TERMINATE: "revoke_sip_secret",
            Operation.ROTATE_CREDENTIALS: "rotate_sip_secret",
            Operation.RECONCILE: "reconcile",
        },
    }

    def __init__(
        self,
        system: str,
        base_url: str,
        hmac_key_file: str,
        ca_file: str,
        client_cert_file: str,
        client_key_file: str,
        service_identity: str,
        required_scope: str,
        client: httpx.AsyncClient | None = None,
    ):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("telephony adapter URL must be credential-free HTTPS")
        if system not in self.operation_map:
            raise ValueError("unsupported telephony target")
        self.system = system
        self.base_url = base_url.rstrip("/")
        self.hmac_key_file = hmac_key_file
        self.ca_file = ca_file
        self.client_cert_file = client_cert_file
        self.client_key_file = client_key_file
        self.service_identity = service_identity
        self.required_scope = required_scope
        self.client = client

    async def _call(
        self, command: StepCommand, include_temporary: bool = False
    ) -> dict[str, Any]:
        operation = self.operation_map[self.system].get(command.operation)
        if not operation:
            raise PermanentAdapterError("unsupported_telephony_operation")
        raw = json.dumps(
            command.payload, sort_keys=True, separators=(",", ":")
        ).encode()
        timestamp = int(time.time())
        nonce = uuid4().hex
        message = (
            f"{timestamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
        )
        signature = hmac.new(
            read_secret_file(self.hmac_key_file).encode(), message, hashlib.sha256
        ).hexdigest()
        headers = {
            "X-Service-Identity": self.service_identity,
            "X-Service-Scopes": self.required_scope,
            "X-Request-Timestamp": str(timestamp),
            "X-Request-Nonce": nonce,
            "X-Request-Signature": signature,
            "Idempotency-Key": command.idempotency_key,
            "Content-Type": "application/json",
        }
        owned = self.client is None
        if self.client is None:
            tls_context = ssl.create_default_context(cafile=self.ca_file)
            tls_context.load_cert_chain(
                self.client_cert_file, self.client_key_file
            )
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(15, connect=3),
                verify=tls_context,
                follow_redirects=False,
            )
        else:
            client = self.client
        try:
            response = await client.post(
                f"{self.base_url}/v1/provisioning/{operation}",
                content=raw,
                headers=headers,
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise RetryableAdapterError(
                f"{self.system}_provisioning_transport_unavailable"
            ) from exc
        except httpx.HTTPError as exc:
            raise PermanentAdapterError(
                f"{self.system}_provisioning_transport_rejected"
            ) from exc
        finally:
            if owned:
                await client.aclose()
        if response.status_code in {408, 425, 429} or response.status_code >= 500:
            raise RetryableAdapterError(
                f"{self.system}_provisioning_http_{response.status_code}"
            )
        if response.status_code == 403:
            raise PermanentAdapterError(
                f"{self.system}_provisioning_authorization_rejected"
            )
        if response.status_code >= 400:
            raise PermanentAdapterError(
                f"{self.system}_provisioning_http_{response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise PermanentAdapterError(
                f"{self.system}_provisioning_invalid_response"
            ) from exc
        if not isinstance(body, dict):
            raise PermanentAdapterError(
                f"{self.system}_provisioning_invalid_response"
            )
        external_id = body.get("username") or body.get("extension")
        state = body.get("state")
        if operation == "reconcile":
            state = "aligned" if body.get("count") == 0 else "drift_detected"
        elif operation.startswith("verify_"):
            state = "verified" if body.get("present") else "failed"
        result = {
            "state": state or "succeeded",
            "external_id": str(external_id) if external_id is not None else None,
            "external_reference": operation,
            "response_hash": hashlib.sha256(raw + response.content).hexdigest(),
        }
        if include_temporary:
            credential = body.get("temporary_sip_credential")
            expires_in = body.get("expires_in_seconds")
            if (
                self.system != TargetSystem.SIP.value
                or not isinstance(credential, str)
                or len(credential) < 32
                or not isinstance(expires_in, int)
                or not 60 <= expires_in <= 900
            ):
                raise PermanentAdapterError(
                    "sip_browser_credential_response_invalid"
                )
            result["temporary_sip_credential"] = credential
            result["expires_in_seconds"] = expires_in
        return result

    async def issue_browser_credential(
        self, command: StepCommand
    ) -> dict[str, Any]:
        if (
            self.system != TargetSystem.SIP.value
            or command.operation != Operation.ROTATE_CREDENTIALS
            or not command.payload.get("browser_session_binding")
        ):
            raise PermanentAdapterError("sip_browser_credential_request_invalid")
        return await self._call(command, include_temporary=True)

    create_disabled = update = verify = activate = suspend = reactivate = _call
    terminate = rotate_credentials = reconcile = _call


class SecretStorageAdapter(ProvisioningAdapter):
    """Creates one-time credentials and persists only authenticated ciphertext."""

    def __init__(self, repository: StateRepository, encryption_key_file: str):
        if not enabled("SECRET_STORAGE_GATE"):
            raise RuntimeError("secret_storage_gate_closed")
        self.repository = repository
        self.cipher = Fernet(read_secret_file(encryption_key_file).encode())

    async def create_disabled(self, command: StepCommand) -> dict[str, Any]:
        plaintext = secrets.token_urlsafe(32)
        reference = f"vault:provisioning/{command.employee_id}/{command.step_id}"
        fingerprint = hashlib.sha256(plaintext.encode()).hexdigest()
        self.repository.store_encrypted_credential(
            reference, self.cipher.encrypt(plaintext.encode()), fingerprint
        )
        return {
            "state": "succeeded",
            "credential_reference": reference,
            "external_reference": fingerprint,
        }

    async def rotate_credentials(self, command: StepCommand) -> dict[str, Any]:
        return await self.create_disabled(command)

    async def terminate(self, command: StepCommand) -> dict[str, Any]:
        reference = command.payload.get("credential_reference")
        if isinstance(reference, str):
            self.repository.revoke_credential(reference)
        return {"state": "succeeded", "credential_reference": reference}

    async def verify(self, command: StepCommand) -> dict[str, Any]:
        del command
        return {"state": "verified"}

    async def reconcile(self, command: StepCommand) -> dict[str, Any]:
        del command
        return {"state": "verified"}

    async def _unsupported(self, command: StepCommand) -> dict[str, Any]:
        del command
        raise PermanentAdapterError("secret_storage_operation_unsupported")

    update = activate = suspend = reactivate = _unsupported


def load_adapters(
    config_file: str,
    repository: StateRepository,
    encryption_key_file: str,
    client: httpx.AsyncClient | None = None,
) -> dict[str, ProvisioningAdapter]:
    raw = read_secret_file(config_file)
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise TypeError("adapter configuration must be an object")
    from .keycloak import KeycloakAdminAdapter

    classes = {
        TargetSystem.ODOO: OdooAdapter,
        TargetSystem.AGENT_DESKTOP: AgentDesktopAdapter,
        TargetSystem.EMAIL_PROVIDER: EmailProviderAdapter,
    }
    adapters: dict[str, ProvisioningAdapter] = {}
    keycloak = document.get(TargetSystem.KEYCLOAK.value, {})
    if isinstance(keycloak, dict) and keycloak.get("enabled"):
        adapters[TargetSystem.KEYCLOAK.value] = KeycloakAdminAdapter(
            base_url=keycloak["base_url"],
            realm=keycloak["realm"],
            client_id=keycloak["client_id"],
            client_secret_file=keycloak["client_secret_file"],
            approved_group_prefixes=keycloak["approved_group_prefixes"],
            approved_realm_roles=keycloak["approved_realm_roles"],
            approved_client_roles=keycloak["approved_client_roles"],
            activation_clients=keycloak.get("activation_clients"),
            client=client,
        )
    else:
        adapters[TargetSystem.KEYCLOAK.value] = DisabledAdapter(
            TargetSystem.KEYCLOAK.value
        )
    for system in (TargetSystem.VICIDIAL, TargetSystem.SIP):
        config = document.get(system.value, {})
        if not isinstance(config, dict) or not config.get("enabled"):
            adapters[system.value] = DisabledAdapter(system.value)
            continue
        adapters[system.value] = TelephonyProvisioningAdapter(
            system.value,
            config["base_url"],
            config["hmac_key_file"],
            config["ca_file"],
            config["client_cert_file"],
            config["client_key_file"],
            config["service_identity"],
            config["required_scope"],
            client,
        )
    for system, adapter_class in classes.items():
        config = document.get(system.value, {})
        if not isinstance(config, dict) or not config.get("enabled"):
            adapters[system.value] = DisabledAdapter(system.value)
            continue
        if (
            system == TargetSystem.EMAIL_PROVIDER
            and config.get("provider") == "deterministic_internal_mock"
        ):
            adapters[system.value] = DeterministicMailboxMockAdapter(repository)
            continue
        adapters[system.value] = adapter_class(
            system.value,
            config["base_url"],
            config["credential_file"],
            config["ca_file"],
            config.get("routes"),
            client,
        )
    adapters[TargetSystem.SECRET_STORAGE.value] = SecretStorageAdapter(
        repository, encryption_key_file
    )
    adapters[TargetSystem.VERIFICATION.value] = DisabledAdapter("verification")
    adapters[TargetSystem.RECONCILIATION.value] = DisabledAdapter("reconciliation")
    return adapters
