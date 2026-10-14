import asyncio
import hashlib
import hmac
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from fastapi import Header, HTTPException, Request, status
from jwt import InvalidTokenError, PyJWKClient, PyJWKClientError

from .config import Settings, enabled
from .repository import StateRepository


@dataclass(frozen=True)
class Principal:
    subject: str
    client_id: str
    scopes: frozenset[str]


class JWTAuthorizer:
    def __init__(self, settings: Settings, repository: StateRepository):
        self.settings = settings
        self.repository = repository
        self.jwks_client = (
            PyJWKClient(settings.jwt_jwks_url, cache_keys=True)
            if settings.jwt_jwks_url
            else None
        )

    async def authenticate(
        self,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> Principal:
        if not enabled("SERVICE_AUTHENTICATION_GATE"):
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "authentication_gate_closed")
        if any(
            key.lower() != "idempotency_key"
            and any(
                word in key.lower()
                for word in ("token", "secret", "password", "credential", "key")
            )
            for key in request.query_params
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "credentials_in_url_forbidden")
        if not authorization:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication_required")
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token or " " in token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_authorization")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in self.settings.jwt_algorithms:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_algorithm")
            if self.jwks_client is not None:
                signing_key = await asyncio.to_thread(
                    self.jwks_client.get_signing_key_from_jwt, token
                )
                public_key = signing_key.key
            else:
                public_key = Path(self.settings.jwt_public_key_file).read_text()
            claims = jwt.decode(
                token,
                public_key,
                algorithms=list(self.settings.jwt_algorithms),
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                options={
                    "require": ["iss", "aud", "sub", "exp", "iat", "jti", "azp"]
                },
                leeway=10,
            )
        except HTTPException:
            raise
        except (OSError, InvalidTokenError, PyJWKClientError, ValueError, TypeError) as exc:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "token_validation_failed"
            ) from exc
        subject = claims.get("sub")
        client_id = claims.get("azp")
        jti = claims.get("jti")
        scopes = claims.get("codestra_scopes")
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        parsed_scopes = frozenset(scopes.split()) if isinstance(scopes, str) else frozenset()
        if (
            not isinstance(subject, str)
            or client_id != self.settings.jwt_expected_azp
            or not isinstance(jti, str)
            or not jti
            or type(issued_at) is not int
            or type(expires_at) is not int
            or expires_at <= issued_at
            or expires_at - issued_at > self.settings.jwt_max_token_ttl_seconds
            or parsed_scopes != self.settings.jwt_required_scopes
            or claims.get("typ") not in {"Bearer", "at+jwt"}
        ):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_service_identity")
        if not self.repository.accept_jti(jti, int(claims["exp"])):
            raise HTTPException(status.HTTP_409_CONFLICT, "token_replay_detected")
        if not self.repository.check_rate(
            hashlib.sha256(subject.encode()).hexdigest(),
            self.settings.rate_limit_requests,
            self.settings.rate_limit_window_seconds,
        ):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate_limit_exceeded")
        return Principal(subject, client_id, parsed_scopes)


def require_scope(authorizer: JWTAuthorizer, required: str):
    async def dependency(
        request: Request, authorization: str | None = Header(default=None)
    ) -> Principal:
        if not enabled("SERVICE_AUTHORIZATION_GATE"):
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "authorization_gate_closed")
        principal = await authorizer.authenticate(request, authorization)
        if required not in principal.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "required_scope_missing")
        return principal

    return dependency


class MiddlewareInvocationError(HTTPException):
    def __init__(self, status_code: int, code: str):
        super().__init__(status_code=status_code, detail=code)


def require_middleware_invocation(settings: Settings, repository: StateRepository):
    """Attests that a mutating request was orchestrated by Middleware's
    agent-provisioning saga, not issued directly against this service.

    This service executes provisioning steps; it must not be an
    independently-triggerable second authority. A caller presenting a
    correctly-scoped JWT (see JWTAuthorizer) is necessary but not
    sufficient for mutating routes -- it must also present an
    HMAC-signed attestation over the exact request body, using a secret
    shared only with Middleware, following the same
    timestamp-then-signature convention already used for outbound Odoo
    callbacks (see callbacks.py).
    """

    async def verify_middleware_invocation(request: Request) -> None:
        if not enabled("MIDDLEWARE_INVOCATION_REQUIRED_GATE"):
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "middleware_invocation_gate_closed",
            )
        timestamp = request.headers.get("x-middleware-timestamp")
        signature = request.headers.get("x-middleware-signature")
        if not timestamp or not signature:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "middleware_invocation_missing"
            )
        try:
            timestamp_value = int(timestamp)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "middleware_invocation_timestamp_invalid"
            ) from exc
        skew = abs(int(time.time()) - timestamp_value)
        if skew > settings.middleware_invocation_max_skew_seconds:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "middleware_invocation_stale"
            )
        from .secrets import SecretReferenceError, read_secret_file

        try:
            secret = read_secret_file(settings.middleware_invocation_hmac_file)
        except SecretReferenceError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "middleware_invocation_secret_unavailable",
            ) from exc
        body = await request.body()
        expected = hmac.new(
            secret.encode(),
            timestamp.encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        prefix = "sha256="
        if not signature.startswith(prefix) or not hmac.compare_digest(
            signature[len(prefix):], expected
        ):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "middleware_invocation_signature_invalid"
            )
        replay_expiry = timestamp_value + settings.middleware_invocation_max_skew_seconds
        if not repository.accept_jti(f"mw-invocation:{signature}", replay_expiry):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "middleware_invocation_replayed"
            )

    return verify_middleware_invocation
