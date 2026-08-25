import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.readiness import DependencyReadiness
from tests.test_api_security import material


class FixedReadiness:
    def __init__(self, errors):
        self._errors = errors

    async def errors(self):
        return list(self._errors)


@pytest.mark.parametrize(
    "condition",
    (
        "keycloak_unavailable",
        "callback_unavailable",
        "telephony_unavailable",
    ),
)
def test_required_dependency_failure_makes_readiness_fail(tmp_path, condition):
    _, settings, _, adapter = material(tmp_path)
    from app.main import create_app

    app = create_app(
        settings,
        adapters={"odoo": adapter},
        readiness_checker=FixedReadiness([condition]),
    )
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 503
    assert condition in response.json()["conditions"]


def test_sqlite_failure_makes_readiness_fail(tmp_path, monkeypatch):
    _, settings, app, _ = material(tmp_path)
    app.state.settings = settings

    def unavailable():
        raise OSError("synthetic SQLite failure")

    monkeypatch.setattr(app.state.repository, "counts", unavailable)
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 503
    assert "sqlite_unavailable" in response.json()["conditions"]


@pytest.mark.asyncio
async def test_intentionally_disabled_optional_adapters_are_ignored(tmp_path):
    _, settings, _, _ = material(tmp_path)
    config = tmp_path / "adapters.json"
    config.write_text(
        json.dumps(
            {
                "keycloak": {"enabled": False},
                "odoo": {"enabled": False},
                "agent_desktop": {"enabled": False},
                "vicidial": {"enabled": False},
                "sip": {"enabled": False},
            }
        )
    )
    config.chmod(0o600)
    checker = DependencyReadiness(
        replace(settings, adapter_config_file=str(config), callback_url=None)
    )
    assert await checker.errors() == []


def test_production_rejects_staging_machine_client(tmp_path):
    _, settings, _, _ = material(tmp_path)
    production = replace(
        settings,
        environment="production",
        jwt_issuer="https://auth.codestra.co/realms/codestra",
        jwt_jwks_url=(
            "https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs"
        ),
        jwt_expected_azp="codestra-provisioning-service-staging",
        jwt_allowed_clients=frozenset({"codestra-provisioning-service-staging"}),
    )
    assert "production_client_is_staging" in production.readiness_errors()
