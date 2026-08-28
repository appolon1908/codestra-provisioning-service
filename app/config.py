import os
from dataclasses import dataclass
from pathlib import Path

GATES = (
    "PROVISIONING_SERVICE_GATE",
    "SERVICE_AUTHENTICATION_GATE",
    "SERVICE_AUTHORIZATION_GATE",
    "STEP_ENGINE_GATE",
    "RETRY_GATE",
    "DEAD_LETTER_GATE",
    "CALLBACK_GATE",
    "RECONCILIATION_GATE",
    "SECRET_STORAGE_GATE",
    "RESTART_RECOVERY_GATE",
)


def enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "enabled"}


@dataclass(frozen=True)
class Settings:
    environment: str
    state_database_path: str
    jwt_issuer: str
    jwt_audience: str
    jwt_public_key_file: str
    jwt_algorithms: tuple[str, ...]
    jwt_allowed_clients: frozenset[str]
    request_max_bytes: int
    request_max_age_seconds: int
    rate_limit_requests: int
    rate_limit_window_seconds: int
    claim_timeout_seconds: int
    retry_base_seconds: int
    callback_url: str | None
    callback_hmac_file: str
    encryption_key_file: str
    adapter_config_file: str
    tls_cert_file: str
    tls_key_file: str
    callback_ca_file: str = "/run/provisioning-secrets/ca.crt"
    turn_shared_secret_file: str = (
        "/run/provisioning-secrets/turn_shared_secret"
    )

    @classmethod
    def load(cls) -> "Settings":
        environment = os.getenv("ENVIRONMENT", "").strip().lower()
        if environment != "staging":
            raise RuntimeError("service is staging-only")
        return cls(
            environment=environment,
            state_database_path=os.getenv(
                "STATE_DATABASE_PATH", "/var/lib/codestra/provisioning.db"
            ),
            jwt_issuer=os.getenv("JWT_ISSUER", "").strip(),
            jwt_audience=os.getenv("JWT_AUDIENCE", "").strip(),
            jwt_public_key_file=os.getenv(
                "JWT_PUBLIC_KEY_FILE", "/run/secrets/jwt_public_key.pem"
            ),
            jwt_algorithms=tuple(
                item.strip()
                for item in os.getenv("JWT_ALGORITHMS", "RS256").split(",")
                if item.strip()
            ),
            jwt_allowed_clients=frozenset(
                item.strip()
                for item in os.getenv(
                    "JWT_ALLOWED_CLIENTS", "codestra-middleware,codestra-n8n"
                ).split(",")
                if item.strip()
            ),
            request_max_bytes=int(os.getenv("REQUEST_MAX_BYTES", "262144")),
            request_max_age_seconds=int(os.getenv("REQUEST_MAX_AGE_SECONDS", "300")),
            rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "120")),
            rate_limit_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
            claim_timeout_seconds=int(os.getenv("CLAIM_TIMEOUT_SECONDS", "120")),
            retry_base_seconds=int(os.getenv("RETRY_BASE_SECONDS", "5")),
            callback_url=os.getenv("ODOO_CALLBACK_URL") or None,
            callback_hmac_file=os.getenv(
                "ODOO_CALLBACK_HMAC_SECRET_FILE",
                "/run/secrets/odoo_callback_hmac",
            ),
            callback_ca_file=os.getenv(
                "ODOO_CALLBACK_CA_FILE", "/run/provisioning-secrets/ca.crt"
            ),
            turn_shared_secret_file=os.getenv(
                "TURN_SHARED_SECRET_FILE",
                "/run/provisioning-secrets/turn_shared_secret",
            ),
            encryption_key_file=os.getenv(
                "CREDENTIAL_ENCRYPTION_KEY_FILE",
                "/run/secrets/credential_encryption_key",
            ),
            adapter_config_file=os.getenv(
                "ADAPTER_CONFIG_FILE", "/run/secrets/adapter_config.json"
            ),
            tls_cert_file=os.getenv("TLS_CERT_FILE", "/run/tls/server.crt"),
            tls_key_file=os.getenv("TLS_KEY_FILE", "/run/tls/server.key"),
        )

    def readiness_errors(self) -> list[str]:
        errors = [f"{gate.lower()}_closed" for gate in GATES if not enabled(gate)]
        if not self.jwt_issuer:
            errors.append("jwt_issuer_missing")
        if not self.jwt_audience:
            errors.append("jwt_audience_missing")
        for name, path in (
            ("jwt_public_key", self.jwt_public_key_file),
            ("callback_hmac", self.callback_hmac_file),
            ("encryption_key", self.encryption_key_file),
            ("adapter_config", self.adapter_config_file),
            ("tls_cert", self.tls_cert_file),
            ("tls_key", self.tls_key_file),
            ("turn_shared_secret", self.turn_shared_secret_file),
        ):
            candidate = Path(path)
            if not candidate.is_file():
                errors.append(f"{name}_missing")
        return errors
