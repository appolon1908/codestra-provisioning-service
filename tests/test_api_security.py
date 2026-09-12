import hashlib
import hmac
import json
import time
import uuid
from dataclasses import replace
from inspect import getclosurevars
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.config import (
    CANONICAL_ISSUER,
    CANONICAL_JWKS_URL,
    MACHINE_AUDIENCE,
    MACHINE_CLIENT_ID,
    MACHINE_SCOPES,
    MAX_TOKEN_TTL_SECONDS,
    Settings,
)
from app.contracts import TargetSystem
from app.main import create_app
from app.repository import StateRepository
from app.security import JWTAuthorizer, Principal
from tests.helpers import FakeAdapter, execution


def material(tmp_path):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_file = tmp_path / "jwt.pem"
    public_file.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_file.chmod(0o600)
    placeholder = tmp_path / "placeholder"
    placeholder.write_text("configured")
    placeholder.chmod(0o600)
    middleware_invocation_secret_file = tmp_path / "middleware_invocation_hmac_secret"
    middleware_invocation_secret_file.write_text("test-middleware-invocation-secret")
    middleware_invocation_secret_file.chmod(0o600)
    configured = Settings(
        environment="staging",
        state_database_path=str(tmp_path / "state.db"),
        jwt_issuer="https://auth.test/realms/codestra",
        jwt_audience="codestra-provisioning-service",
        jwt_public_key_file=str(public_file),
        jwt_algorithms=("RS256",),
        jwt_allowed_clients=frozenset({"test-service"}),
        request_max_bytes=4096,
        request_max_age_seconds=300,
        rate_limit_requests=20,
        rate_limit_window_seconds=60,
        claim_timeout_seconds=0,
        retry_base_seconds=0,
        callback_url=None,
        callback_hmac_file=str(placeholder),
        encryption_key_file=str(placeholder),
        adapter_config_file=str(placeholder),
        tls_cert_file=str(placeholder),
        tls_key_file=str(placeholder),
        jwt_expected_azp="test-service",
        jwt_required_scopes=frozenset(
            {"identity:rotate", "provisioning:execute", "provisioning:read"}
        ),
        jwt_max_token_ttl_seconds=300,
        middleware_invocation_hmac_file=str(middleware_invocation_secret_file),
    )
    repository = StateRepository(configured.state_database_path)
    adapter = FakeAdapter()
    app = create_app(
        configured,
        repository,
        {TargetSystem.ODOO.value: adapter},
    )
    return private, configured, app, adapter


def middleware_invocation_headers(settings: Settings, body: bytes) -> dict[str, str]:
    secret = Path(settings.middleware_invocation_hmac_file).read_text().strip()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    return {
        "X-Middleware-Timestamp": timestamp,
        "X-Middleware-Signature": f"sha256={signature}",
    }


def token(private, settings, **changes):
    now = int(time.time())
    claims = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": "service-account-test",
        "azp": "test-service",
        "codestra_scopes": "identity:rotate provisioning:execute provisioning:read",
        "typ": "Bearer",
        "iat": now,
        "nbf": now - 1,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    claims.update(changes)
    claims = {key: value for key, value in claims.items() if value is not None}
    return jwt.encode(claims, private, algorithm="RS256")


def test_strict_jwt_scope_replay_and_private_tls(tmp_path):
    private, settings, app, adapter = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    with TestClient(app, base_url="https://provisioning-service") as client:
        assert client.post(url, json=request.model_dump(mode="json")).status_code == 401
        wrong_scope = token(private, settings, codestra_scopes="provisioning:read")
        assert (
            client.post(
                url,
                json=request.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {wrong_scope}"},
            ).status_code
            == 401
        )
        valid = token(
            private,
            settings,
            nbf=None,
        )
        body_bytes = json.dumps(request.model_dump(mode="json")).encode()
        response = client.post(
            url,
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {valid}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
        assert response.status_code == 200
        assert response.json()["state"] == "completed"
        assert len(adapter.calls) == 1
        replay = client.post(
            url,
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {valid}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
        assert replay.status_code == 409


def test_strict_issuer_audience_and_size_limit(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    with TestClient(app, base_url="https://provisioning-service") as client:
        wrong_issuer = token(private, settings, iss="https://evil.invalid")
        response = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {wrong_issuer}"},
        )
        assert response.status_code == 401
        oversized = client.post(
            "/missing",
            content=b"x" * 5000,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert oversized.status_code == 413


def test_canonical_token_contract_negative_matrix(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    second_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    cases = (
        token(private, settings, iss="https://auth.codestra.agency/realms/codestra"),
        token(private, settings, aud="wrong-audience"),
        token(private, settings, azp="codestra-client-provisioner"),
        token(private, settings, azp="codestra-middleware-production"),
        token(private, settings, azp="codestra-n8n"),
        token(private, settings, azp=None),
        token(private, settings, iat=None),
        token(private, settings, exp=None),
        token(private, settings, iat=now, exp=now),
        token(private, settings, iat=now, exp=now + 301),
        token(private, settings, iat=now - 600, exp=now - 300),
        token(private, settings, jti=None),
        token(private, settings, codestra_scopes=None, scope="provisioning:execute"),
        token(private, settings, codestra_scopes="identity:rotate provisioning:read"),
        token(private, settings, codestra_scopes="identity:rotate provisioning:execute"),
        token(private, settings, codestra_scopes="provisioning:execute provisioning:read"),
        token(
            private,
            settings,
            codestra_scopes=(
                "identity:rotate provisioning:execute provisioning:read realm-admin"
            ),
        ),
        token(second_private, settings),
    )
    with TestClient(app, base_url="https://provisioning-service") as client:
        for candidate in cases:
            response = client.post(
                url,
                json=request.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {candidate}"},
            )
            assert response.status_code == 401


def test_maximum_300_second_token_and_replay(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    now = int(time.time())
    candidate = token(private, settings, iat=now, exp=now + 300)
    body_bytes = json.dumps(request.model_dump(mode="json")).encode()
    with TestClient(app, base_url="https://provisioning-service") as client:
        first = client.post(
            url,
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {candidate}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
        assert first.status_code == 200
        replay = client.post(
            url,
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {candidate}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
        assert replay.status_code == 409


def test_runtime_defaults_are_the_canonical_machine_contract(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "staging")
    for name in (
        "JWT_ISSUER",
        "JWT_JWKS_URL",
        "JWT_AUDIENCE",
        "JWT_EXPECTED_AZP",
        "JWT_ALLOWED_CLIENTS",
        "JWT_REQUIRED_SCOPES",
        "JWT_MAX_TOKEN_TTL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.load()
    assert settings.jwt_issuer == CANONICAL_ISSUER
    assert settings.jwt_jwks_url == CANONICAL_JWKS_URL
    assert settings.jwt_audience == MACHINE_AUDIENCE
    assert settings.jwt_expected_azp == MACHINE_CLIENT_ID
    assert settings.jwt_allowed_clients == frozenset({MACHINE_CLIENT_ID})
    assert settings.jwt_required_scopes == MACHINE_SCOPES
    assert settings.jwt_max_token_ttl_seconds == MAX_TOKEN_TTL_SECONDS


def test_readiness_rejects_sip_boundary_overrides_and_not_jwks_local_key(tmp_path):
    _, settings, _, _ = material(tmp_path)
    jwks = replace(
        settings,
        jwt_jwks_url="https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs",
        jwt_public_key_file=str(tmp_path / "absent.pem"),
        sip_browser_endpoint=6102,
        sip_browser_campaign="OTHER",
    )
    errors = jwks.readiness_errors()
    assert "sip_browser_endpoint_invalid" in errors
    assert "sip_browser_campaign_invalid" in errors
    assert "jwt_public_key_missing" not in errors


def test_local_key_mode_requires_existing_public_key(tmp_path):
    _, settings, _, _ = material(tmp_path)
    missing = replace(
        settings,
        jwt_jwks_url="",
        jwt_public_key_file=str(tmp_path / "absent.pem"),
    )
    assert "jwt_public_key_missing" in missing.readiness_errors()
    present = replace(settings, jwt_jwks_url="")
    assert "jwt_public_key_missing" not in present.readiness_errors()


@pytest.mark.parametrize(
    ("name", "value"),
    (("SIP_BROWSER_ENDPOINT", "6102"), ("SIP_BROWSER_CAMPAIGN", "OTHER")),
)
def test_runtime_refuses_noncanonical_sip_boundary(monkeypatch, name, value):
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match="certification boundary invalid"):
        Settings.load()


@pytest.mark.asyncio
async def test_jwks_lookup_runs_in_worker_thread(tmp_path, monkeypatch):
    private, settings, _, _ = material(tmp_path)
    settings = replace(settings, jwt_jwks_url="https://auth.test/jwks")
    authorizer = JWTAuthorizer(settings, StateRepository(settings.state_database_path))
    authorizer.jwks_client = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key=private.public_key())
    )
    calls = []

    async def fake_to_thread(function, *args):
        calls.append(function)
        return function(*args)

    monkeypatch.setattr("app.security.asyncio.to_thread", fake_to_thread)
    request = Request({"type": "http", "query_string": b"", "headers": []})
    principal = await authorizer.authenticate(
        request, f"Bearer {token(private, settings)}"
    )
    assert principal.client_id == "test-service"
    assert calls == [authorizer.jwks_client.get_signing_key_from_jwt]


def test_required_route_set_is_exact(tmp_path):
    _, _, app, _ = material(tmp_path)
    routes = {(method, route.path) for route in app.routes for method in route.methods or []}
    required = {
        ("POST", "/v1/provisioning/requests/{request_id}/execute"),
        ("POST", "/v1/provisioning/requests/{request_id}/retry"),
        ("POST", "/v1/provisioning/requests/{request_id}/verify"),
        ("POST", "/v1/provisioning/requests/{request_id}/cancel"),
        ("POST", "/v1/identities/{employee_id}/suspend"),
        ("POST", "/v1/identities/{employee_id}/reactivate"),
        ("POST", "/v1/identities/{employee_id}/terminate"),
        ("POST", "/v1/identities/{employee_id}/rotate"),
        ("GET", "/v1/provisioning/requests/{request_id}"),
        ("GET", "/v1/identities/{employee_id}/reconciliation"),
        ("GET", "/health"),
        ("GET", "/ready"),
        ("GET", "/metrics"),
    }
    assert required <= routes


@pytest.mark.asyncio
async def test_every_protected_route_enforces_its_contract_scope(
    tmp_path, monkeypatch
):
    _, _, app, _ = material(tmp_path)
    expected = {
        ("POST", "/v1/provisioning/requests/{request_id}/execute"): "provisioning:execute",
        ("POST", "/v1/provisioning/requests/{request_id}/retry"): "provisioning:execute",
        ("POST", "/v1/provisioning/requests/{request_id}/verify"): "provisioning:execute",
        ("POST", "/v1/provisioning/requests/{request_id}/cancel"): "provisioning:execute",
        ("GET", "/v1/provisioning/requests/{request_id}"): "provisioning:read",
        ("POST", "/v1/identities/{employee_id}/suspend"): "provisioning:execute",
        ("POST", "/v1/identities/{employee_id}/reactivate"): "provisioning:execute",
        ("POST", "/v1/identities/{employee_id}/terminate"): "provisioning:execute",
        ("POST", "/v1/identities/{employee_id}/rotate"): "identity:rotate",
        ("GET", "/v1/identities/{employee_id}/reconciliation"): "provisioning:read",
        ("POST", "/session"): "provisioning:execute",
        ("POST", "/renew"): "identity:rotate",
        ("GET", "/config"): "provisioning:read",
        ("POST", "/revoke"): "identity:rotate",
    }
    actual = {}
    dependencies = {}
    for route in app.routes:
        for method in route.methods or []:
            key = (method, route.path)
            if key not in expected:
                continue
            scopes = [
                getclosurevars(item.call).nonlocals.get("required")
                for item in route.dependant.dependencies
                if item.call.__name__ == "dependency"
            ]
            assert len(scopes) == 1
            actual[key] = scopes[0]
            dependencies[key] = next(
                item.call
                for item in route.dependant.dependencies
                if item.call.__name__ == "dependency"
            )
    assert actual == expected
    request = Request({"type": "http", "query_string": b"", "headers": []})
    for key, required in expected.items():
        dependency = dependencies[key]
        authorizer = getclosurevars(dependency).nonlocals["authorizer"]

        async def authorized(*_, granted=required):
            return Principal("subject", "test-service", frozenset({granted}))

        monkeypatch.setattr(authorizer, "authenticate", authorized)
        assert (await dependency(request, None)).scopes == frozenset({required})

        async def unauthorized(*_):
            return Principal("subject", "test-service", frozenset())

        monkeypatch.setattr(authorizer, "authenticate", unauthorized)
        with pytest.raises(HTTPException) as denied:
            await dependency(request, None)
        assert denied.value.status_code == 403


def test_authoritative_numeric_odoo_request_id_is_accepted(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution().model_copy(
        update={
            "request_id": "87",
            "steps": [
                item.model_copy(update={"request_id": "87"})
                for item in execution().steps
            ],
        }
    )
    body_bytes = json.dumps(request.model_dump(mode="json")).encode()
    with TestClient(app, base_url="https://provisioning-service") as client:
        response = client.post(
            "/v1/provisioning/requests/87/execute",
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {token(private, settings)}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
    assert response.status_code == 200


def test_execute_request_requires_middleware_invocation_even_with_valid_scope(tmp_path):
    """A caller holding a perfectly valid, correctly-scoped service JWT must
    still be rejected on mutating provisioning routes unless it also proves
    the request was orchestrated by Middleware's saga (see
    app.security.require_middleware_invocation). This is the mechanism that
    keeps this service from being a second, independently-triggerable
    provisioning authority."""
    private, settings, app, adapter = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    body_bytes = json.dumps(request.model_dump(mode="json")).encode()
    with TestClient(app, base_url="https://provisioning-service") as client:
        no_attestation = client.post(
            url,
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {token(private, settings)}",
                "Content-Type": "application/json",
            },
        )
        assert no_attestation.status_code == 401
        assert no_attestation.json()["detail"] == "middleware_invocation_missing"
        assert adapter.calls == []

        tampered_body = json.dumps(
            {**request.model_dump(mode="json"), "employee_id": "someone-else"}
        ).encode()
        forged_signature = client.post(
            url,
            content=tampered_body,
            headers={
                "Authorization": f"Bearer {token(private, settings)}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
        assert forged_signature.status_code == 401
        assert forged_signature.json()["detail"] == "middleware_invocation_signature_invalid"
        assert adapter.calls == []

        legitimate = client.post(
            url,
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {token(private, settings)}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
        assert legitimate.status_code == 200
        assert len(adapter.calls) == 1


def test_middleware_invocation_gate_closed_fails_closed(tmp_path, monkeypatch):
    private, settings, app, adapter = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    valid_scope_token = token(private, settings)
    body_bytes = json.dumps(request.model_dump(mode="json")).encode()
    monkeypatch.delenv("MIDDLEWARE_INVOCATION_REQUIRED_GATE", raising=False)
    with TestClient(app, base_url="https://provisioning-service") as client:
        response = client.post(
            url,
            content=body_bytes,
            headers={
                "Authorization": f"Bearer {valid_scope_token}",
                "Content-Type": "application/json",
                **middleware_invocation_headers(settings, body_bytes),
            },
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "middleware_invocation_gate_closed"
        assert adapter.calls == []


def test_lifecycle_and_sip_browser_mutating_routes_require_middleware_invocation(tmp_path):
    """Every mutating route -- not just /execute -- must require the same
    attestation. Lifecycle (suspend/reactivate/terminate/rotate) and SIP
    browser session create/renew/revoke all mutate provisioning-adjacent
    state and must not be independently callable."""
    private, settings, app, _ = material(tmp_path)
    with TestClient(app, base_url="https://provisioning-service") as client:
        for method, path, payload in (
            (
                "post",
                "/v1/identities/employee-1/suspend",
                {
                    "schema_version": "1.0",
                    "request_id": "req-1",
                    "correlation_id": "corr-00000001",
                    "idempotency_key": "idem-0000000000000001",
                    "employee_id": "employee-1",
                    "target_system": "keycloak",
                    "operation": "suspend",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "payload": {},
                },
            ),
            (
                "post",
                "/session",
                {"employee_id": "employee-1", "extension": "6101", "campaign": "TEST_SYN"},
            ),
        ):
            body_bytes = json.dumps(payload).encode()
            response = getattr(client, method)(
                path,
                content=body_bytes,
                headers={
                    "Authorization": f"Bearer {token(private, settings)}",
                    "Content-Type": "application/json",
                },
            )
            assert response.status_code in (401, 422), (path, response.status_code, response.text)
            if response.status_code == 401:
                assert response.json()["detail"] == "middleware_invocation_missing"
