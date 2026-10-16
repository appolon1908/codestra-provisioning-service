import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PASS = "CODESTRA_PROVISIONING_FABRIC_V2=PASS"
REQUIRED_FORBIDDEN_KEYS = (
    "password",
    "otp",
    "reset_token",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "provider_token",
)


def run_validator(tmp_path, optimized, violation=None):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "validate_integration_fabric.py"
    script.write_text((ROOT / "scripts" / script.name).read_text())
    targets = json.loads((ROOT / "config/provisioning-targets.v2.json").read_text())
    capabilities = json.loads(
        (ROOT / "config/integration-fabric-capabilities.v2.json").read_text()
    )
    if violation == "duplicate_target":
        targets["targets"][1]["id"] = targets["targets"][0]["id"]
    elif violation and violation[0] == "direct_n8n_access":
        targets["targets"][0]["direct_n8n_access"] = violation[1]
    elif violation and violation[0] == "capability":
        capabilities["PROVISIONING_WRITE"] = violation[1]
    elif violation and violation[0] == "forbidden_key":
        targets["forbidden_payload_keys"].remove(violation[1])
    config = tmp_path / "config"
    config.mkdir()
    (config / "provisioning-targets.v2.json").write_text(json.dumps(targets))
    (config / "integration-fabric-capabilities.v2.json").write_text(json.dumps(capabilities))
    command = [sys.executable, "-I", "-B"]
    if optimized:
        command.append("-O")
    command.append(str(script))
    # The interpreter and copied repository script are trusted; only JSON fixtures vary.
    return subprocess.run(  # noqa: S603
        command, capture_output=True, text=True, check=False, timeout=10
    )


@pytest.mark.parametrize("optimized", [False, True], ids=["normal", "optimized"])
def test_valid_integration_fabric_passes(tmp_path, optimized):
    result = run_validator(tmp_path, optimized)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == PASS


@pytest.mark.parametrize("optimized", [False, True], ids=["normal", "optimized"])
@pytest.mark.parametrize(
    "violation",
    [
        pytest.param("duplicate_target", id="duplicate-target"),
        *[
            pytest.param(("direct_n8n_access", value), id=f"direct-n8n-{value}")
            for value in (True, 0, None)
        ],
        *[
            pytest.param(("capability", value), id=f"capability-{value}")
            for value in (True, 0, None)
        ],
        *[
            pytest.param(("forbidden_key", key), id=f"missing-{key}")
            for key in REQUIRED_FORBIDDEN_KEYS
        ],
    ],
)
def test_invalid_integration_fabric_fails_closed(tmp_path, optimized, violation):
    result = run_validator(tmp_path, optimized, violation)
    assert result.returncode != 0
    assert PASS not in result.stdout
