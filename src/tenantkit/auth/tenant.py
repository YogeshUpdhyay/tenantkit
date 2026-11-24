from dataclasses import asdict
from typing import Any
from uuid import UUID, uuid4
from tenantkit.audit.service import AuditService, actor_fields
from tenantkit.auth.providers.base import AuthProvider, AuthRequest, AuthResult
from tenantkit.config.models import TenantKitConfig
from tenantkit.storage.interfaces import Storage
from tenantkit.tokens.service import TokenService
from tenantkit.auth.hashing import Hashing
from tenantkit.domain.claims import TokenPair
from tenantkit.domain.models import AuditEvent, RevokeReason, Tenant, TenantUser
from tenantkit.sessions.service import SessionService
from tenantkit.domain.errors import (
    AccountLockedError,
    ExpiredTokenError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
)


class TenantAuthService:
    def __init__(
        self,
        config: TenantKitConfig,
        storage: Storage,
        tokens: TokenService,
        hashing: Hashing,
        providers: dict[str, AuthProvider],
        audit: AuditService,
        sessions: SessionService,
    ) -> None:
        self.config = config
        self.storage = storage
        self.tokens = tokens
        self.hashing = hashing
        self.providers = providers
        self.audit = audit
        self.sessions = sessions

    async def _tenant(self, slug: str) -> Tenant:
        tenant = await self.storage.tenants.get_by_slug(slug)
        if tenant is None or not tenant.is_active:
            raise InvalidCredentialsError()
        return tenant

    async def login_methods(self, *, tenant_slug: str) -> list[str]:
        tenant = await self._tenant(tenant_slug)
        policy = tenant.login_policy or self.config.tenant_auth.default_policy
        return list(policy.providers)

    async def _fail(
        self,
        tenant_slug: str,
        tenant: Tenant | None,
        credentials: dict[str, Any],
        result: AuthResult | None,
    ) -> None:
        """Persist failure events before the caller raises; must run outside a transaction."""
        metadata: dict[str, Any] = {"subject_type": "tenant", "tenant_slug": tenant_slug}
        if self.config.audit.include_failed_login_email:
            metadata["email"] = str(credentials.get("email", ""))
        tenant_id = tenant.id if tenant is not None else None
        async with self.audit.recorder() as rec:
            await rec.emit(
                AuditEvent(
                    action="auth.login.failed",
                    outcome="failure",
                    actor_type="anonymous",
                    tenant_id=tenant_id,
                    metadata=metadata,
                )
            )
            if result is not None and result.newly_locked and result.subject_id is not None:
                await rec.emit(
                    AuditEvent(
                        action="auth.account.locked",
                        outcome="failure",
                        actor_type="anonymous",
                        tenant_id=tenant_id,
                        target_type="account",
                        target_id=result.subject_id,
                        metadata={"subject_type": "tenant", "tenant_slug": tenant_slug},
                    )
                )

    async def _authenticate(
        self, tenant_slug: str, method: str, credentials: dict[str, Any]
    ) -> tuple[TenantUser, Tenant]:
        tenant: Tenant | None = None
        result: AuthResult | None = None
        try:
            tenant = await self._tenant(tenant_slug)
            policy = tenant.login_policy or self.config.tenant_auth.default_policy
            if method not in policy.providers:
                raise InvalidCredentialsError()
            result = await self.providers[method].authenticate(
                AuthRequest("tenant_user", credentials, tenant.id), policy
            )
            user = None
            if result.status == "success" and result.subject_id is not None:
                user = await self.storage.tenant_users.get(result.subject_id)
            if user is None or not user.is_active or user.tenant_id != tenant.id:
                raise InvalidCredentialsError()
        except InvalidCredentialsError:
            locked = result is not None and result.reason == "locked"
            await self._fail(tenant_slug, tenant, credentials, result)
            if locked:
                raise AccountLockedError() from None
            raise
        return user, tenant

    async def login(
        self, *, tenant_slug: str, method: str, credentials: dict[str, Any]
    ) -> TokenPair:
        user, tenant = await self._authenticate(tenant_slug, method, credentials)
        session_id = uuid4()
        async with self.audit.recorder() as rec:
            pair = self.tokens.issue_pair(
                typ="tenant", subject=user, tenant=tenant, session_id=session_id
            )
            await self.sessions.create(
                pair=pair, kind="tenant", subject_id=user.id, tenant_id=tenant.id
            )
            await rec.emit(
                AuditEvent(
                    **{
                        **actor_fields(pair.claims),
                        "action": "auth.login.succeeded",
                        "outcome": "success",
                        "target_type": "session",
                        "target_id": session_id,
                    }
                )
            )
        return pair

    async def refresh(self, *, refresh_token: str) -> TokenPair:
        claims = self.tokens.verify_refresh(refresh_token, expected="tenant")
        session = await self.sessions.load(claims)
        if claims.tenant_id is None:
            raise InvalidTokenError("Missing tenant")
        user = await self.storage.tenant_users.get(UUID(claims.sub))
        tenant = await self.storage.tenants.get(claims.tenant_id)
        if tenant is not None and not tenant.is_active:
            await self.sessions.revoke_standalone(
                session_id=session.id, reason=RevokeReason.TENANT_DEACTIVATED
            )
            raise InvalidTokenError("Inactive account")
        if user is None or not user.is_active:
            await self.sessions.revoke_standalone(
                session_id=session.id, reason=RevokeReason.SUBJECT_DEACTIVATED
            )
            raise InvalidTokenError("Inactive account")
        if tenant is None or user.tenant_id != tenant.id:
            raise InvalidTokenError("Inactive account")
        pair = self.tokens.issue_pair(
            typ="tenant", subject=user, tenant=tenant, session_id=session.id
        )
        await self.sessions.rotate(claims=claims, pair=pair, action="auth.token.refreshed")
        return pair

    async def logout(self, *, refresh_token: str) -> None:
        """Revoke the session behind a refresh token. Idempotent; expired tokens are a no-op."""
        try:
            claims = self.tokens.verify_refresh(refresh_token, expected="tenant")
        except ExpiredTokenError:
            return
        async with self.audit.recorder() as rec:
            count = await self.sessions.revoke(
                session_id=claims.sid, reason=RevokeReason.LOGOUT, cascade_children=True
            )
            if count:
                await rec.emit(
                    AuditEvent(
                        **{
                            **actor_fields(claims),
                            "action": "auth.logout",
                            "outcome": "success",
                            "target_type": "session",
                            "target_id": claims.sid,
                        }
                    )
                )

    async def logout_all(self, *, actor: Any) -> int:
        user, _ = await self._subject(actor)
        async with self.audit.recorder() as rec:
            count = await self.sessions.revoke(
                kind="tenant", subject_id=user.id, reason=RevokeReason.LOGOUT_ALL
            )
            await rec.emit(
                AuditEvent(
                    **{
                        **actor_fields(actor),
                        "action": "auth.logout_all",
                        "outcome": "success",
                        "target_type": "tenant_user",
                        "target_id": user.id,
                        "metadata": {"count": count},
                    }
                )
            )
        return count

    async def _subject(self, actor: Any) -> tuple[TenantUser, Tenant]:
        if actor.typ != "tenant" or actor.use != "access":
            raise PermissionDeniedError("Tenant access required")
        user = await self.storage.tenant_users.get(UUID(actor.sub))
        tenant = await self.storage.tenants.get(actor.tenant_id)
        if (
            user is None
            or tenant is None
            or not user.is_active
            or not tenant.is_active
            or user.tenant_id != tenant.id
        ):
            raise InvalidCredentialsError()
        return user, tenant

    async def me(self, *, actor: Any) -> dict[str, Any]:
        user, _ = await self._subject(actor)
        data = asdict(user)
        data.pop("password_hash")
        return data

    async def change_password(self, *, actor: Any, current: str, new: str) -> None:
        user, tenant = await self._subject(actor)
        if not self.hashing.verify(user.password_hash, current):
            raise InvalidCredentialsError()
        policy = tenant.login_policy or self.config.tenant_auth.default_policy
        self.hashing.validate(new, user.email, self.config.tenant_auth.password)
        self.hashing.validate(new, user.email, policy.password)
        user.password_hash = self.hashing.hash(new)
        async with self.audit.recorder() as rec:
            await self.storage.tenant_users.update(user)
            await self.sessions.revoke(
                kind="tenant", subject_id=user.id, reason=RevokeReason.PASSWORD_CHANGED
            )
            await rec.emit(
                AuditEvent(
                    **{
                        **actor_fields(actor),
                        "action": "auth.password.changed",
                        "outcome": "success",
                        "target_type": "tenant_user",
                        "target_id": user.id,
                    }
                )
            )
