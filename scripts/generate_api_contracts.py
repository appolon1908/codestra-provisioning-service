from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from app.adapters import DisabledAdapter
from app.config import (
    CANONICAL_ISSUER,
    MACHINE_AUDIENCE,
    MACHINE_CLIENT_ID,
    Settings,
)
from app.main import create_app
from app.repository import StateRepository

ROOT = Path(__file__).resolve().parents[1]
OPENAPI_PATH = ROOT / "contracts" / "provisioning-openapi.generated.json"
SECURITY_MATRIX_PATH = ROOT / "contracts" / "provisioning-security-matrix.v1.json"
POSTMAN_PATH = ROOT / "postman" / "Codestra-Provisioning-Service.postman_collection.json"

METHODS = {"get", "post", "put", "patch", "delete"}

SECURITY = {
    ("GET", "/health"): {"scope": None, "middleware_invocation": False, "classification": "operational"},
    ("GET", "/ready"): {"scope": None, "middleware_invocation": False, "classification": "operational"},
    ("GET", "/config"): {"scope": "provisioning:read", "middleware_invocation": False, "classification": "read"},
    ("POST", "/session"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/renew"): {"scope": "identity:rotate", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/revoke"): {"scope": "identity:rotate", "middleware_invocation": True, "classification": "effect"},
    ("GET", "/v1/provisioning/requests/{request_id}"): {"scope": "provisioning:read", "middleware_invocation": False, "classification": "read"},
    ("POST", "/v1/provisioning/requests/{request_id}/execute"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/v1/provisioning/requests/{request_id}/retry"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/v1/provisioning/requests/{request_id}/verify"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/v1/provisioning/requests/{request_id}/cancel"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/v1/identities/{employee_id}/suspend"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/v1/identities/{employee_id}/reactivate"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/v1/identities/{employee_id}/terminate"): {"scope": "provisioning:execute", "middleware_invocation": True, "classification": "effect"},
    ("POST", "/v1/identities/{employee_id}/rotate"): {"scope": "identity:rotate", "middleware_invocation": True, "classification": "effect"},
    ("GET", "/v1/identities/{employee_id}/reconciliation"): {"scope": "provisioning:read", "middleware_invocation": False, "classification": "read"},
}


def _settings(root: Path) -> Settings:
    return Settings(
        environment="staging",
        state_database_path=str(root / "state.db"),
        jwt_issuer=CANONICAL_ISSUER,
        jwt_audience=MACHINE_AUDIENCE,
        jwt_public_key_file=str(root / "jwt.pem"),
        jwt_algorithms=("RS256",),
        jwt_allowed_clients=frozenset({MACHINE_CLIENT_ID}),
        request_max_bytes=262144,
        request_max_age_seconds=300,
        rate_limit_requests=120,
        rate_limit_window_seconds=60,
        claim_timeout_seconds=120,
        retry_base_seconds=5,
        callback_url=None,
        callback_hmac_file=str(root / "callback"),
        encryption_key_file=str(root / "encryption"),
        adapter_config_file=str(root / "adapters.json"),
        tls_cert_file=str(root / "tls.crt"),
        tls_key_file=str(root / "tls.key"),
        jwt_jwks_url="",
    )


def build_openapi() -> dict[str, Any]:
    with TemporaryDirectory(prefix="codestra-provisioning-openapi-") as td:
        root = Path(td)
        settings = _settings(root)
        repository = StateRepository(settings.state_database_path)
        app = create_app(settings, repository, {"odoo": DisabledAdapter("odoo")})
        document = app.openapi()
    document["x-codestra-integration"] = {
        "canonical_command_authority": "Middleware /platform/v1",
        "middleware_runtime": "middleware-integration-api:8095",
        "service_role": "provider/provisioning execution service",
        "metrics_public": False,
        "production_effects_default": False,
    }
    return document


def operations(openapi: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, item in sorted(openapi.get("paths", {}).items()):
        for method, operation in sorted(item.items()):
            if method.lower() not in METHODS:
                continue
            key = (method.upper(), path)
            security = SECURITY.get(key)
            if security is None:
                raise RuntimeError(f"unclassified API operation: {key}")
            rows.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "operation_id": operation.get("operationId"),
                    **security,
                }
            )
    return rows


def build_security_matrix(openapi: dict[str, Any]) -> dict[str, Any]:
    rows = operations(openapi)
    return {
        "schema": "codestra.provisioning.security-matrix.v1",
        "repository": "ingtrader21-spec/codestra-provisioning-service",
        "identity_authority": "Keycloak",
        "middleware_command_authority": "Middleware /platform/v1",
        "tenant_model": "service-internal provisioning; authenticated service identity and request ownership",
        "metrics": {"path": "/metrics", "included_in_openapi": False, "public": False},
        "operations": rows,
        "summary": {
            "operations": len(rows),
            "effects": sum(1 for row in rows if row["classification"] == "effect"),
            "reads": sum(1 for row in rows if row["classification"] == "read"),
            "operational": sum(1 for row in rows if row["classification"] == "operational"),
            "middleware_invocation_required": sum(
                1 for row in rows if row["middleware_invocation"]
            ),
        },
    }


def _postman_url(path: str) -> str:
    rendered = path
    for token in ("request_id", "employee_id"):
        rendered = rendered.replace("{" + token + "}", "{{" + token + "}}")
    return "{{base_url}}" + rendered


def build_postman(openapi: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    by_key = {(row["method"], row["path"]): row for row in matrix["operations"]}
    items = []
    for path, methods in sorted(openapi["paths"].items()):
        for method, operation in sorted(methods.items()):
            if method.lower() not in METHODS:
                continue
            key = (method.upper(), path)
            row = by_key[key]
            headers = []
            if row["scope"]:
                headers.append(
                    {"key": "Authorization", "value": "Bearer {{access_token}}", "type": "text"}
                )
            if row["middleware_invocation"]:
                headers.extend(
                    [
                        {"key": "X-Middleware-Timestamp", "value": "{{middleware_timestamp}}", "type": "text"},
                        {"key": "X-Middleware-Signature", "value": "{{middleware_signature}}", "type": "text"},
                    ]
                )
            request: dict[str, Any] = {
                "method": method.upper(),
                "header": headers,
                "url": {"raw": _postman_url(path), "host": ["{{base_url}}"], "path": []},
                "description": (
                    f"operationId={operation.get('operationId')} | "
                    f"scope={row['scope'] or 'none'} | "
                    f"middleware_invocation={str(row['middleware_invocation']).lower()}"
                ),
            }
            if method.lower() in {"post", "put", "patch"}:
                request["header"].append({"key": "Content-Type", "value": "application/json", "type": "text"})
                request["body"] = {"mode": "raw", "raw": "{}"}
            items.append({"name": f"{method.upper()} {path}", "request": request})
    return {
        "info": {
            "name": "Codestra Provisioning Service",
            "_postman_id": "codestra-provisioning-service-v1",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": "Generated from the committed FastAPI/OpenAPI contract. Effectful requests require a valid Keycloak token and Middleware invocation signature.",
        },
        "variable": [
            {"key": "base_url", "value": "https://provisioning.internal"},
            {"key": "access_token", "value": ""},
            {"key": "middleware_timestamp", "value": ""},
            {"key": "middleware_signature", "value": ""},
            {"key": "request_id", "value": ""},
            {"key": "employee_id", "value": ""},
        ],
        "item": items,
    }


def _write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    openapi = build_openapi()
    matrix = build_security_matrix(openapi)
    postman = build_postman(openapi, matrix)
    _write(OPENAPI_PATH, openapi)
    _write(SECURITY_MATRIX_PATH, matrix)
    _write(POSTMAN_PATH, postman)
    print(f"OPENAPI_PATHS={len(openapi['paths'])}")
    print(f"CONTRACT_OPERATIONS={matrix['summary']['operations']}")
    print(f"EFFECT_OPERATIONS={matrix['summary']['effects']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
