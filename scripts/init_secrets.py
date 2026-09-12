import os
import shutil
import stat
from pathlib import Path

SOURCE = Path("/source-secrets")
TARGET = Path("/run/provisioning-secrets")
STATE = Path("/var/lib/codestra")
EXPECTED = {
    "jwt_public_key.pem",
    "odoo_callback_hmac",
    "credential_encryption_key",
    "adapter_config.json",
    "server.crt",
    "server.key",
    "ca.crt",
    "keycloak_client_secret",
    "telephony_hmac_key",
    "telephony_client.crt",
    "telephony_client.key",
    "telephony_ca.crt",
    "turn_shared_secret",
    "middleware_invocation_hmac_secret",
}


def main():
    source_mode = stat.S_IMODE(SOURCE.stat().st_mode)
    if source_mode != 0o700:
        raise SystemExit("source secret directory must be mode 0700")
    TARGET.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(STATE, 10001, 10001)
    os.chmod(STATE, 0o700)
    os.chmod(TARGET, 0o700)
    for name in EXPECTED:
        source = SOURCE / name
        if source.is_symlink() or not source.is_file():
            raise SystemExit(f"required secret file missing: {name}")
        if stat.S_IMODE(source.stat().st_mode) != 0o600:
            raise SystemExit(f"secret file must be mode 0600: {name}")
        destination = TARGET / name
        shutil.copyfile(source, destination)
        os.chown(destination, 10001, 10001)
        os.chmod(destination, 0o400)
    os.chown(TARGET, 10001, 10001)


if __name__ == "__main__":
    main()
