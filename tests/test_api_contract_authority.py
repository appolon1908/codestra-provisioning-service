from __future__ import annotations

import json
from pathlib import Path

from scripts.generate_api_contracts import (
    OPENAPI_PATH,
    POSTMAN_PATH,
    SECURITY_MATRIX_PATH,
    build_openapi,
    build_postman,
    build_security_matrix,
)

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_generated_openapi_is_committed_authority():
    assert build_openapi() == _load(OPENAPI_PATH)


def test_security_matrix_is_committed_authority():
    openapi = build_openapi()
    matrix = build_security_matrix(openapi)
    assert matrix == _load(SECURITY_MATRIX_PATH)
    assert matrix["summary"] == {
        "operations": 16,
        "effects": 11,
        "reads": 3,
        "operational": 2,
        "middleware_invocation_required": 11,
    }


def test_effectful_operations_require_middleware_invocation():
    matrix = _load(SECURITY_MATRIX_PATH)
    effects = [row for row in matrix["operations"] if row["classification"] == "effect"]
    assert effects
    assert all(row["middleware_invocation"] is True for row in effects)
    assert all(row["scope"] in {"provisioning:execute", "identity:rotate"} for row in effects)


def test_metrics_remains_outside_public_openapi():
    openapi = _load(OPENAPI_PATH)
    matrix = _load(SECURITY_MATRIX_PATH)
    assert "/metrics" not in openapi["paths"]
    assert matrix["metrics"] == {
        "path": "/metrics",
        "included_in_openapi": False,
        "public": False,
    }


def test_postman_is_generated_from_same_authority():
    openapi = build_openapi()
    matrix = build_security_matrix(openapi)
    assert build_postman(openapi, matrix) == _load(POSTMAN_PATH)
    assert len(_load(POSTMAN_PATH)["item"]) == matrix["summary"]["operations"]
