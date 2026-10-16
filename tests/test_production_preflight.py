import re
import subprocess
from pathlib import Path

import pytest

PREFLIGHT = Path(__file__).resolve().parents[1] / "scripts" / "production_preflight.sh"
IMAGE_PREFIX = "ghcr.io/appolon1908/codestra-provisioning-service@sha256:"
SYNTHETIC_IMAGE = IMAGE_PREFIX + "1" * 64


def run_preflight(tmp_path, candidate, *, protected_pin=None):
    """Exercise source guards with every host command replaced by a failing stub."""
    tools = tmp_path / "bin"
    tools.mkdir()
    calls = tmp_path / "tool-calls"
    for name in ("docker", "cosign", "systemctl", "stat", "openssl", "sort", "grep"):
        stub = tools / name
        stub.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$PREFLIGHT_TOOL_LOG"\nexit 99\n'
        )
        stub.chmod(0o755)
    script = PREFLIGHT
    if protected_pin is not None:
        script = tmp_path / "preflight.sh"
        script.write_text(
            re.sub(
                r"(?m)^canonical_image=.*$",
                f"canonical_image='{protected_pin}'",
                PREFLIGHT.read_text(),
                count=1,
            )
        )
    environment = {
        "PATH": str(tools),
        "PREFLIGHT_TOOL_LOG": str(calls),
        "PROVISIONING_SECRET_DIR": str(tmp_path / "absent-secrets"),
        "PROVISIONING_COMPOSE_FILE": str(tmp_path / "synthetic-compose.yaml"),
    }
    if candidate is not None:
        environment["PROVISIONING_IMAGE"] = candidate
    result = subprocess.run(
        ["/bin/bash"],
        input=script.read_text(),
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return result, calls.read_text() if calls.exists() else ""


def test_checked_in_release_is_unadopted_before_any_host_probe(tmp_path):
    result, calls = run_preflight(tmp_path, SYNTHETIC_IMAGE)
    assert result.returncode == 1
    assert "FAIL|canonical_release_adopted" in result.stdout
    assert calls == ""


@pytest.mark.parametrize(
    "pin",
    [
        "",
        "ghcr.io/appolon1908-hue/codestra-provisioning-service@sha256:" + "1" * 64,
        "ghcr.io/appolon1908/codestra-provisioning-service:latest",
        IMAGE_PREFIX + "0" * 64,
        IMAGE_PREFIX + "A" * 64,
        IMAGE_PREFIX + "1" * 63,
    ],
)
def test_invalid_protected_release_cannot_reach_host_probes(tmp_path, pin):
    result, calls = run_preflight(tmp_path, SYNTHETIC_IMAGE, protected_pin=pin)
    assert result.returncode == 1
    assert calls == ""


@pytest.mark.parametrize(
    "candidate",
    [
        None,
        "",
        "ghcr.io/appolon1908/codestra-provisioning-service:latest",
        "ghcr.io/appolon1908-hue/codestra-provisioning-service@sha256:" + "1" * 64,
        IMAGE_PREFIX + "0" * 64,
        IMAGE_PREFIX + "A" * 64,
        IMAGE_PREFIX + "g" * 64,
        IMAGE_PREFIX + "1" * 63,
        IMAGE_PREFIX + "1" * 65,
        SYNTHETIC_IMAGE + "\n",
        IMAGE_PREFIX + "2" * 64,
    ],
)
def test_invalid_or_mismatched_candidate_stops_before_host_probes(tmp_path, candidate):
    result, calls = run_preflight(tmp_path, candidate, protected_pin=SYNTHETIC_IMAGE)
    assert result.returncode == 1
    assert calls == ""


def test_exact_synthetic_pin_reaches_only_stubbed_host_checks(tmp_path):
    result, calls = run_preflight(
        tmp_path, SYNTHETIC_IMAGE, protected_pin=SYNTHETIC_IMAGE
    )
    assert result.returncode == 1  # Failing stubs never establish production readiness.
    assert "PASS|image_digest_pinned" in result.stdout
    assert "PASS|image_authority_match" in result.stdout
    assert "FAIL|compose_validation" in result.stdout
    assert calls
    assert all(line.startswith(str(tmp_path / "bin") + "/") for line in calls.splitlines())
    assert (
        "--certificate-identity https://github.com/appolon1908/"
        "codestra-provisioning-service/.github/workflows/ci.yml@refs/heads/main"
    ) in calls
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in calls
