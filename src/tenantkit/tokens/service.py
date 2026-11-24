"""JWT issue and verification with independently pinned keys per identity type."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast
import logging
from uuid import UUID, uuid4
import jwt
from pydantic import ValidationError
from tenantkit.config.models import TenantKitConfig, TokenTypeConfig
from tenantkit.domain.claims import (
    AdminClaims,
    BaseClaims,
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
    RevokedTokenError,
    WrongTokenTypeError,
)
from tenantkit.domain.models import Admin, Tenant, TenantUser

if TYPE_CHECKING:
    from tenantkit.storage.interfaces import Storage

AnyClaims = AdminClaims | TenantClaims | ImpersonationClaims
_CLAIM_MODELS: dict[str, type[BaseClaims]] = {
    "admin": AdminClaims,
    "tenant": TenantClaims,
    "impersonation": ImpersonationClaims,
}


class TokenService:
    def __init__(self, config: TenantKitConfig, storage: Storage | None = None) -> None:
        self.config = config
        self.storage = storage
        self._keys: dict[str, tuple[TokenType, TokenTypeConfig]] = {}
        for typ in ("admin", "tenant", "impersonation"):
            cfg: TokenTypeConfig = getattr(config.tokens, typ)
            if cfg.algorithm != "HS256":
                from cryptography.hazmat.primitives.serialization import (
                    Encoding,
                    PublicFormat,
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
                    spki = (Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                    if private.public_key().public_bytes(*spki) != public.public_bytes(*spki):
                        raise ValueError()
                except (ValueError, TypeError, AttributeError):
                    raise KeyLoadError(f"tokens.{typ}: invalid or mismatched key") from None
            self._keys[cfg.kid] = (typ, cfg)

    def issue_pair(
        self,
        *,
        typ: TokenType,
        subject: Admin | TenantUser,
        session_id: UUID,
        tenant: Tenant | None = None,
        roles: list[str] | tuple[str, ...] | None = None,
        refresh_cap: datetime | None = None,
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
            sid=str(session_id),
            iat=current,
            nbf=current,
        )
        if tenant:
            common["tid"] = str(tenant.id)
        refresh_exp = current + int(cfg.refresh_ttl.total_seconds())
        access_exp = current + int(cfg.access_ttl.total_seconds())
        if typ == "impersonation":
            if refresh_cap is None:
                raise InvalidTokenError("Admin session expiry required")
            cap = int(refresh_cap.timestamp())
            refresh_exp = min(refresh_exp, cap)
            access_exp = min(access_exp, cap)
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
        refresh_jti = uuid4()
        refresh = dict(common, use="refresh", exp=refresh_exp, jti=str(refresh_jti))
        # Impersonation refresh retains the chosen role; the cap comes from the parent session.
        if typ == "impersonation":
            refresh["impersonation_role"] = assigned[0] if assigned else ""
            if reason is not None:
                refresh["reason"] = reason
        key = cfg.private_key.get_secret_value()
        headers = {"kid": cfg.kid}
        return TokenPair(
            claims=cast(AnyClaims, _CLAIM_MODELS[typ].model_validate(access)),
            access_token=jwt.encode(access, key, algorithm=cfg.algorithm, headers=headers),
            refresh_token=jwt.encode(refresh, key, algorithm=cfg.algorithm, headers=headers),
            expires_in=access_exp - current,
            refresh_jti=refresh_jti,
            refresh_expires_at=datetime.fromtimestamp(refresh_exp, timezone.utc),
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

    def verify(self, token: str, expected: str | set[str] | None = None) -> AnyClaims:
        payload = self._decode(token, "access", expected)
        try:
            for key in ("email", "roles", "perms"):
                if key not in payload:
                    raise InvalidTokenError("Missing claims")
            return cast(AnyClaims, _CLAIM_MODELS[payload["typ"]].model_validate(payload))
        except (ValidationError, KeyError):
            raise InvalidTokenError("Malformed claims") from None

    def verify_refresh(self, token: str, expected: str | set[str] | None = None) -> RefreshClaims:
        try:
            return RefreshClaims.model_validate(self._decode(token, "refresh", expected))
        except ValidationError:
            raise InvalidTokenError("Malformed refresh claims") from None

    async def verify_active(self, token: str, expected: str | set[str] | None = None) -> AnyClaims:
        """Like ``verify`` but also requires the token's session (and parent) to be live."""
        if self.storage is None:
            raise RuntimeError("verify_active requires a TokenService created with storage")
        claims = self.verify(token, expected)
        session = await self.storage.sessions.get(claims.sid)
        if session is None:
            raise InvalidTokenError("Unknown session")
        if not session.is_active:
            raise RevokedTokenError("Session revoked or expired")
        if claims.typ == "impersonation":
            parent = (
                await self.storage.sessions.get(session.parent_id) if session.parent_id else None
            )
            if parent is None or not parent.is_active:
                raise RevokedTokenError("Session revoked or expired")
        return claims
