import os
from dataclasses import dataclass
from pathlib import Path

CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
CANONICAL_JWKS_URL = f"{CANONICAL_ISSUER}/protocol/openid-connect/certs"
MACHINE_AUDIENCE = "codestra-provisioning-service"
MACHINE_CLIENT_ID = "codestra-provisioning-service-staging"
MACHINE_SCOPES = frozenset(
    {"identity:rotate", "provisioning:execute", "provisioning:read"}
)
MAX_TOKEN_TTL_SECONDS = 300
SIP_BROWSER_ENDPOINT = 6101
SIP_BROWSER_CAMPAIGN = "TEST_SYN"

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
        "/run/provisioning-secrets/turn_shared_secret"  # noqa: S105
    )
    jwt_jwks_url: str = ""
    jwt_expected_azp: str = MACHINE_CLIENT_ID
    jwt_required_scopes: frozenset[str] = MACHINE_SCOPES
    jwt_max_token_ttl_seconds: int = MAX_TOKEN_TTL_SECONDS
    sip_browser_endpoint: int = SIP_BROWSER_ENDPOINT
    sip_browser_campaign: str = SIP_BROWSER_CAMPAIGN
    readiness_timeout_seconds: float = 3.0
    readiness_cache_seconds: float = 15.0
    sqlite_backup_metadata_file: str = "/run/provisioning-backup-status/latest.json"

    @classmethod
    def load(cls) -> "Settings":
        environment = os.getenv("ENVIRONMENT", "").strip().lower()
        if environment not in {"staging", "production"}:
            raise RuntimeError("environment must be staging or production")
        sip_browser_endpoint = int(
            os.getenv("SIP_BROWSER_ENDPOINT", str(SIP_BROWSER_ENDPOINT))
        )
        sip_browser_campaign = os.getenv(
            "SIP_BROWSER_CAMPAIGN", SIP_BROWSER_CAMPAIGN
        ).strip()
        if (
            sip_browser_endpoint != SIP_BROWSER_ENDPOINT
            or sip_browser_campaign != SIP_BROWSER_CAMPAIGN
        ):
            raise RuntimeError("sip browser certification boundary invalid")
        return cls(
            environment=environment,
            state_database_path=os.getenv(
                "STATE_DATABASE_PATH", "/var/lib/codestra/provisioning.db"
            ),
            jwt_issuer=os.getenv("JWT_ISSUER", CANONICAL_ISSUER).strip(),
            jwt_audience=os.getenv("JWT_AUDIENCE", MACHINE_AUDIENCE).strip(),
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
                    "JWT_ALLOWED_CLIENTS", MACHINE_CLIENT_ID
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
            jwt_jwks_url=os.getenv("JWT_JWKS_URL", CANONICAL_JWKS_URL).strip(),
            jwt_expected_azp=os.getenv("JWT_EXPECTED_AZP", MACHINE_CLIENT_ID).strip(),
            jwt_required_scopes=frozenset(
                value.strip()
                for value in os.getenv(
                    "JWT_REQUIRED_SCOPES", " ".join(sorted(MACHINE_SCOPES))
                ).split()
                if value.strip()
            ),
            jwt_max_token_ttl_seconds=int(
                os.getenv("JWT_MAX_TOKEN_TTL_SECONDS", str(MAX_TOKEN_TTL_SECONDS))
            ),
            sip_browser_endpoint=sip_browser_endpoint,
            sip_browser_campaign=sip_browser_campaign,
            readiness_timeout_seconds=float(
                os.getenv("READINESS_TIMEOUT_SECONDS", "3")
            ),
            readiness_cache_seconds=float(
                os.getenv("READINESS_CACHE_SECONDS", "15")
            ),
            sqlite_backup_metadata_file=os.getenv(
                "SQLITE_BACKUP_METADATA_FILE",
                "/run/provisioning-backup-status/latest.json",
            ),
        )

    def readiness_errors(self) -> list[str]:
        errors = [f"{gate.lower()}_closed" for gate in GATES if not enabled(gate)]
        if not self.jwt_issuer:
            errors.append("jwt_issuer_missing")
        if not self.jwt_audience:
            errors.append("jwt_audience_missing")
        if self.jwt_issuer != CANONICAL_ISSUER:
            errors.append("jwt_issuer_not_canonical")
        if self.jwt_audience != MACHINE_AUDIENCE:
            errors.append("jwt_audience_invalid")
        if self.jwt_jwks_url != CANONICAL_JWKS_URL:
            errors.append("jwt_jwks_not_canonical")
        if not self.jwt_expected_azp:
            errors.append("jwt_expected_azp_missing")
        if self.jwt_expected_azp == "REQUIRED_PRODUCTION_CLIENT_ID":
            errors.append("production_client_placeholder")
        if self.jwt_allowed_clients != frozenset({self.jwt_expected_azp}):
            errors.append("jwt_allowed_clients_invalid")
        if self.environment == "staging" and self.jwt_expected_azp != MACHINE_CLIENT_ID:
            errors.append("jwt_expected_azp_invalid")
        if self.environment == "production" and self.jwt_expected_azp.endswith("-staging"):
            errors.append("production_client_is_staging")
        if enabled("CALLBACK_GATE") and not self.callback_url:
            errors.append("callback_url_missing")
        if self.callback_url and self.callback_url.startswith("REQUIRED_"):
            errors.append("callback_url_placeholder")
        if self.jwt_required_scopes != MACHINE_SCOPES:
            errors.append("jwt_required_scopes_invalid")
        if self.jwt_max_token_ttl_seconds != MAX_TOKEN_TTL_SECONDS:
            errors.append("jwt_max_token_ttl_invalid")
        if self.sip_browser_endpoint != SIP_BROWSER_ENDPOINT:
            errors.append("sip_browser_endpoint_invalid")
        if self.sip_browser_campaign != SIP_BROWSER_CAMPAIGN:
            errors.append("sip_browser_campaign_invalid")
        if not 0.25 <= self.readiness_timeout_seconds <= 10:
            errors.append("readiness_timeout_invalid")
        if not 1 <= self.readiness_cache_seconds <= 60:
            errors.append("readiness_cache_invalid")
        for name, path in (
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
        if not self.jwt_jwks_url and not Path(self.jwt_public_key_file).is_file():
            errors.append("jwt_public_key_missing")
        return errors
