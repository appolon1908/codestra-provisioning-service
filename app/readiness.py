import asyncio
import json
import ssl
import time
from typing import Any

import httpx

from .config import Settings
from .secrets import read_secret_file


class DependencyReadiness:
    """Bounded, cached probes for dependencies required by the active release."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._checked_at = 0.0
        self._cached: list[str] = []
        self._lock = asyncio.Lock()

    async def errors(self) -> list[str]:
        now = time.monotonic()
        if now - self._checked_at < self.settings.readiness_cache_seconds:
            return list(self._cached)
        async with self._lock:
            now = time.monotonic()
            if now - self._checked_at < self.settings.readiness_cache_seconds:
                return list(self._cached)
            errors = await self._probe()
            self._cached = sorted(set(errors))
            self._checked_at = time.monotonic()
            return list(self._cached)

    async def _probe(self) -> list[str]:
        try:
            document = json.loads(read_secret_file(self.settings.adapter_config_file))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return ["adapter_config_unusable"]
        checks = []
        keycloak = document.get("keycloak", {})
        if isinstance(keycloak, dict) and keycloak.get("enabled"):
            checks.append(self._check_keycloak(keycloak))
        if self.settings.callback_url:
            checks.append(self._check_callback())
        seen: set[tuple[Any, ...]] = set()
        for name in ("vicidial", "sip"):
            config = document.get(name, {})
            if not isinstance(config, dict) or not config.get("enabled"):
                continue
            identity = (
                config.get("base_url"),
                config.get("ca_file"),
                config.get("client_cert_file"),
                config.get("client_key_file"),
            )
            if identity not in seen:
                seen.add(identity)
                checks.append(self._check_telephony(config))
        for name in ("odoo", "agent_desktop", "email_provider", "n8n_event"):
            config = document.get(name, {})
            if not isinstance(config, dict) or not config.get("enabled"):
                continue
            if (
                name == "email_provider"
                and config.get("provider") == "deterministic_internal_mock"
            ):
                continue
            checks.append(self._check_http_adapter(name, config))
        if not checks:
            return []
        results = await asyncio.gather(*checks, return_exceptions=True)
        errors = []
        for result in results:
            if isinstance(result, BaseException):
                errors.append("dependency_probe_failed")
            elif result:
                errors.append(result)
        return errors

    def _timeout(self) -> httpx.Timeout:
        value = self.settings.readiness_timeout_seconds
        return httpx.Timeout(value, connect=value)

    async def _check_keycloak(self, config: dict[str, Any]) -> str | None:
        realm_url = (
            f"{config['base_url'].rstrip('/')}/realms/{config['realm']}"
        )
        discovery_url = f"{realm_url}/.well-known/openid-configuration"
        token_endpoint = f"{realm_url}/protocol/openid-connect/token"
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout(), follow_redirects=False
            ) as client:
                discovery_response = await client.get(discovery_url)
                discovery_response.raise_for_status()
                discovery = discovery_response.json()
                if discovery.get("issuer") != self.settings.jwt_issuer:
                    return "keycloak_issuer_mismatch"
                if discovery.get("jwks_uri") != self.settings.jwt_jwks_url:
                    return "keycloak_jwks_mismatch"
                jwks_response = await client.get(self.settings.jwt_jwks_url)
                jwks_response.raise_for_status()
                if not jwks_response.json().get("keys"):
                    return "keycloak_jwks_unusable"
                if not isinstance(discovery.get("token_endpoint"), str):
                    return "keycloak_token_endpoint_missing"
                secret = read_secret_file(config["client_secret_file"])
                token_response = await client.post(
                    token_endpoint,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": config["client_id"],
                        "client_secret": secret,
                    },
                )
                if token_response.status_code != 200:
                    return "keycloak_client_auth_failed"
                token = token_response.json().get("access_token")
                if not isinstance(token, str) or not token:
                    return "keycloak_token_invalid"
        except (OSError, KeyError, ValueError, httpx.HTTPError):
            return "keycloak_unavailable"
        return None

    async def _check_http_adapter(
        self, name: str, config: dict[str, Any]
    ) -> str | None:
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout(),
                verify=config["ca_file"],
                follow_redirects=False,
            ) as client:
                response = await client.get(config["base_url"])
                if response.status_code >= 500:
                    return f"{name}_unavailable"
        except (OSError, KeyError, httpx.HTTPError):
            return f"{name}_unavailable"
        return None

    async def _check_callback(self) -> str | None:
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout(),
                verify=self.settings.callback_ca_file,
                follow_redirects=False,
            ) as client:
                response = await client.get(self.settings.callback_url)
                if response.status_code >= 500:
                    return "callback_unavailable"
        except (OSError, httpx.HTTPError):
            return "callback_unavailable"
        return None

    async def _check_telephony(self, config: dict[str, Any]) -> str | None:
        try:
            context = ssl.create_default_context(cafile=config["ca_file"])
            context.load_cert_chain(
                config["client_cert_file"], config["client_key_file"]
            )
            async with httpx.AsyncClient(
                timeout=self._timeout(), verify=context, follow_redirects=False
            ) as client:
                response = await client.get(config["base_url"])
                if response.status_code >= 500:
                    return "telephony_unavailable"
        except (OSError, KeyError, ssl.SSLError, httpx.HTTPError):
            return "telephony_unavailable"
        return None
