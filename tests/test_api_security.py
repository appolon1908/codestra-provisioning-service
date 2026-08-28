import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import Settings
from app.contracts import TargetSystem
from app.main import create_app
from app.repository import StateRepository
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
    )
    repository = StateRepository(configured.state_database_path)
    adapter = FakeAdapter()
    app = create_app(
        configured,
        repository,
        {TargetSystem.ODOO.value: adapter},
    )
    return private, configured, app, adapter


def token(private, settings, scope="provisioning:execute", **changes):
    now = int(time.time())
    claims = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": "service-account-test",
        "azp": "test-service",
        "scope": scope,
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
        wrong_scope = token(private, settings, "provisioning:read")
        assert (
            client.post(
                url,
                json=request.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {wrong_scope}"},
            ).status_code
            == 403
        )
        valid = token(
            private,
            settings,
            scope="",
            codestra_scopes="provisioning:execute",
            nbf=None,
        )
        response = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {valid}"},
        )
        assert response.status_code == 200
        assert response.json()["state"] == "completed"
        assert len(adapter.calls) == 1
        replay = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {valid}"},
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
    with TestClient(app, base_url="https://provisioning-service") as client:
        response = client.post(
            "/v1/provisioning/requests/87/execute",
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {token(private, settings)}"},
        )
    assert response.status_code == 200
