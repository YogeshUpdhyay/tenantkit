"""JWT issue and verification with independently pinned keys per identity type."""

from datetime import datetime, timezone
from typing import Any
import logging
from uuid import uuid4
import jwt
from pydantic import ValidationError
from tenantkit.config.models import TenantKitConfig, TokenTypeConfig
from tenantkit.domain.claims import (
    AdminClaims,
    ImpersonationClaims,
    RefreshClaims,
    TenantClaims,
    TokenPair,
    TokenType,
)
from tenantkit.domain.errors import (
    ExpiredTokenError,
    InvalidTokenError,
    KeyLoadError,
    WrongTokenTypeError,
)
from tenantkit.domain.models import Admin, Tenant, TenantUser


class TokenService:
    def __init__(self, config: TenantKitConfig) -> None:
        self.config = config
        self._keys: dict[str, tuple[TokenType, TokenTypeConfig]] = {}
        for typ in ("admin", "tenant", "impersonation"):
            cfg: TokenTypeConfig = getattr(config.tokens, typ)
            if cfg.algorithm != "HS256":
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_private_key,
                    load_pem_public_key,
                )
                from cryptography.hazmat.primitives.asymmetric import rsa, ec

                try:
                    private = load_pem_private_key(
                        cfg.private_key.get_secret_value().encode(), password=None
                    )
                    public = load_pem_public_key(
                        (cfg.public_key or cfg.private_key).get_secret_value().encode()
                    )
                    if cfg.algorithm == "RS256" and not isinstance(private, rsa.RSAPrivateKey):
                        raise ValueError()
                    if cfg.algorithm == "ES256" and (
                        not isinstance(private, ec.EllipticCurvePrivateKey)
                        or private.curve.name != "secp256r1"
                    ):
                        raise ValueError()
                    if private.public_key().public_numbers() != public.public_numbers():
                        raise ValueError()  # type: ignore[union-attr]
                except (ValueError, TypeError, AttributeError):
                    raise KeyLoadError(f"tokens.{typ}: invalid or mismatched key") from None
            self._keys[cfg.kid] = (typ, cfg)  # type: ignore[assignment]

    def issue_pair(
        self,
        *,
        typ: TokenType,
        subject: Admin | TenantUser,
        tenant: Tenant | None = None,
        roles: list[str] | tuple[str, ...] | None = None,
        admin_refresh_exp: int | None = None,
        reason: str | None = None,
    ) -> TokenPair:
        if typ == "tenant" and (
            tenant is None or not isinstance(subject, TenantUser) or subject.tenant_id != tenant.id
        ):
            raise InvalidTokenError("Tenant subject and matching tenant required")
        if typ in ("admin", "impersonation") and not isinstance(subject, Admin):
            raise InvalidTokenError("Admin subject required")
        if typ == "impersonation" and tenant is None:
            raise InvalidTokenError("Target tenant required")
        cfg: TokenTypeConfig = getattr(self.config.tokens, typ)
        current = int(datetime.now(timezone.utc).timestamp())
        registry = getattr(self.config.roles, typ)
        requested = roles if roles is not None else subject.roles
        for role in requested:
            if role not in registry:
                logging.getLogger(__name__).warning(
                    "Stored role missing from configuration: %s", role
                )
        assigned = [r for r in requested if r in registry]
        permissions = sorted({p for r in assigned for p in registry[r].permissions})
        common: dict[str, Any] = dict(
            iss=self.config.issuer,
            aud=self.config.audience,
            sub=str(subject.id),
            typ=typ,
            iat=current,
            nbf=current,
        )
        if tenant:
            common["tid"] = str(tenant.id)
        refresh_exp = current + int(cfg.refresh_ttl.total_seconds())
        access_exp = current + int(cfg.access_ttl.total_seconds())
        if typ == "impersonation":
            if admin_refresh_exp is None:
                raise InvalidTokenError("Admin session expiry required")
            refresh_exp = min(refresh_exp, admin_refresh_exp)
            access_exp = min(access_exp, admin_refresh_exp)
        if refresh_exp <= current:
            raise ExpiredTokenError("Session expired")
        access = dict(
            common,
            use="access",
            exp=access_exp,
            jti=str(uuid4()),
            email=subject.email,
            roles=assigned,
            perms=permissions,
        )
        if tenant:
            access["tslug"] = tenant.slug
        if typ == "impersonation":
            access["act"] = {"sub": str(subject.id), "email": subject.email}
            if reason is not None:
                access["reason"] = reason
        refresh = dict(common, use="refresh", exp=refresh_exp, jti=str(uuid4()))
        # Stateless impersonation refresh must retain the chosen privilege and cap.
        if typ == "impersonation":
            refresh["impersonation_role"] = assigned[0] if assigned else ""
            refresh["admin_refresh_exp"] = admin_refresh_exp
            if reason is not None:
                refresh["reason"] = reason
        key = cfg.private_key.get_secret_value()
        headers = {"kid": cfg.kid}
        model = {
            "admin": AdminClaims,
            "tenant": TenantClaims,
            "impersonation": ImpersonationClaims,
        }[typ]
        return TokenPair(
            claims=model.model_validate(access),
            access_token=jwt.encode(access, key, algorithm=cfg.algorithm, headers=headers),
            refresh_token=jwt.encode(refresh, key, algorithm=cfg.algorithm, headers=headers),
            expires_in=access_exp - current,
        )

    def _decode(self, token: str, use: str, expected: str | set[str] | None) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            typ, cfg = self._keys[header["kid"]]
            if header.get("alg") != cfg.algorithm:
                raise InvalidTokenError("Invalid algorithm")
            key = (cfg.public_key or cfg.private_key).get_secret_value()
            payload: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[cfg.algorithm],
                issuer=self.config.issuer,
                audience=self.config.audience,
                leeway=self.config.clock.skew_seconds,
                options={
                    "require": ["iss", "aud", "sub", "typ", "use", "iat", "nbf", "exp", "jti"]
                },
            )
            if payload["typ"] != typ or payload["use"] != use:
                raise WrongTokenTypeError("Wrong token type or use")
            if expected is not None and typ not in (
                {expected} if isinstance(expected, str) else expected
            ):
                raise WrongTokenTypeError("Wrong token type")
            return payload
        except jwt.ExpiredSignatureError:
            raise ExpiredTokenError("Token expired") from None
        except (jwt.PyJWTError, KeyError, TypeError, ValueError):
            raise InvalidTokenError("Invalid token") from None

    def verify(
        self, token: str, expected: str | set[str] | None = None
    ) -> AdminClaims | TenantClaims | ImpersonationClaims:
        payload = self._decode(token, "access", expected)
        try:
            for key in ("email", "roles", "perms"):
                if key not in payload:
                    raise InvalidTokenError("Missing claims")
            model = {
                "admin": AdminClaims,
                "tenant": TenantClaims,
                "impersonation": ImpersonationClaims,
            }[payload["typ"]]
            return model.model_validate(payload)
        except (ValidationError, KeyError):
            raise InvalidTokenError("Malformed claims") from None

    def verify_refresh(self, token: str, expected: str | set[str] | None = None) -> RefreshClaims:
        try:
            return RefreshClaims.model_validate(self._decode(token, "refresh", expected))
        except ValidationError:
            raise InvalidTokenError("Malformed refresh claims") from None
