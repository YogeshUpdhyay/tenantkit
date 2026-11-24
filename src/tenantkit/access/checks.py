from collections.abc import Iterable
from uuid import UUID, uuid4
from tenantkit.config.models import TenantKitConfig
from tenantkit.storage.interfaces import Storage
from tenantkit.audit.service import AuditService, actor_fields
from tenantkit.domain.models import Admin, AuditEvent, RevokeReason, Tenant
from tenantkit.domain.permissions import has_permission
from tenantkit.sessions.service import SessionService
from tenantkit.domain.claims import BaseClaims, TokenPair
from tenantkit.domain.errors import (
    ExpiredTokenError,
    ImpersonationDisabledError,
    NotFoundError,
    PermissionDeniedError,
    RevokedTokenError,
    WrongTokenTypeError,
)
from tenantkit.tokens.service import TokenService


class AccessService:
    def __init__(
        self,
        config: TenantKitConfig,
        storage: Storage,
        tokens: TokenService,
        audit: AuditService,
        sessions: SessionService,
    ) -> None:
        self.config, self.storage, self.tokens = config, storage, tokens
        self.audit, self.sessions = audit, sessions

    @staticmethod
    def is_type(claims: BaseClaims, *types: str) -> bool:
        return claims.typ in types

    @staticmethod
    def has_role(claims: BaseClaims, role: str) -> bool:
        return role in claims.roles

    @staticmethod
    def has_permission(claims: BaseClaims, permission: str) -> bool:
        return has_permission(claims, permission)

    @classmethod
    def has_all(cls, claims: BaseClaims, permissions: Iterable[str]) -> bool:
        return all(cls.has_permission(claims, p) for p in permissions)

    @classmethod
    def has_any(cls, claims: BaseClaims, permissions: Iterable[str]) -> bool:
        return any(cls.has_permission(claims, p) for p in permissions)

    @classmethod
    def require_permission(cls, claims: BaseClaims, permission: str) -> None:
        if not cls.has_permission(claims, permission):
            raise PermissionDeniedError("Permission denied")

    @classmethod
    def require_type(cls, claims: BaseClaims, *types: str) -> None:
        if not cls.is_type(claims, *types):
            raise WrongTokenTypeError("Wrong token type")

    async def _check_impersonation(
        self, admin_id: UUID, tenant_id: UUID, role: str
    ) -> tuple[Admin, Tenant]:
        if not self.config.impersonation.enabled:
            raise ImpersonationDisabledError("Impersonation disabled")
        admin = await self.storage.admins.get(admin_id)
        if admin is None or not admin.is_active:
            raise PermissionDeniedError("Admin inactive")
        scope = admin.impersonation_scope
        if scope.mode != "all" and (scope.mode != "list" or tenant_id not in scope.tenant_ids):
            raise PermissionDeniedError("Tenant outside scope")
        tenant = await self.storage.tenants.get(tenant_id)
        if tenant is None:
            raise NotFoundError("Tenant not found")
        if not tenant.is_active:
            raise PermissionDeniedError("Tenant inactive")
        if role not in self.config.roles.impersonation or not any(
            role in self.config.impersonation.allowed_roles.get(r, ()) for r in admin.roles
        ):
            raise PermissionDeniedError("Role not allowed")
        return admin, tenant

    async def impersonate(
        self,
        *,
        actor: BaseClaims,
        tenant_id: UUID,
        role: str,
        admin_refresh_token: str,
        reason: str | None = None,
    ) -> TokenPair:
        self.require_type(actor, "admin")
        try:
            self.require_permission(actor, "impersonate")
            admin, tenant = await self._check_impersonation(UUID(actor.sub), tenant_id, role)
        except PermissionDeniedError as exc:
            await self.audit.emit_standalone(
                AuditEvent(
                    **{
                        **actor_fields(actor),
                        "action": "impersonation.denied",
                        "outcome": "failure",
                        "tenant_id": tenant_id,
                        "target_type": "tenant",
                        "target_id": tenant_id,
                        "metadata": {"role": role, "cause": str(exc)},
                    }
                )
            )
            raise
        refresh = self.tokens.verify_refresh(admin_refresh_token, expected="admin")
        if refresh.sub != actor.sub or refresh.sid != actor.sid:
            raise PermissionDeniedError("Admin session mismatch")
        parent = await self.sessions.load(refresh)
        session_id = uuid4()
        pair = self.tokens.issue_pair(
            typ="impersonation",
            subject=admin,
            session_id=session_id,
            tenant=tenant,
            roles=[role],
            refresh_cap=parent.expires_at,
            reason=reason,
        )
        async with self.audit.recorder() as rec:
            await self.sessions.create(
                pair=pair,
                kind="impersonation",
                subject_id=admin.id,
                tenant_id=tenant.id,
                parent_id=parent.id,
            )
            await rec.emit(
                AuditEvent(
                    **{
                        **actor_fields(actor),
                        "action": "impersonation.started",
                        "outcome": "success",
                        "tenant_id": tenant.id,
                        "target_type": "session",
                        "target_id": session_id,
                        "reason": reason,
                        "metadata": {"role": role},
                    }
                )
            )
        return pair

    async def refresh_impersonation(self, refresh_token: str) -> TokenPair:
        claims = self.tokens.verify_refresh(refresh_token, expected="impersonation")
        if claims.tenant_id is None:
            raise PermissionDeniedError("Missing tenant")
        session = await self.sessions.load(claims)
        parent = await self.storage.sessions.get(session.parent_id) if session.parent_id else None
        if parent is None or not parent.is_active:
            await self.sessions.revoke_standalone(
                session_id=session.id, reason=RevokeReason.PARENT_REVOKED
            )
            raise RevokedTokenError("Parent session revoked or expired")
        admin = await self.storage.admins.get(UUID(claims.sub))
        if admin is None or not admin.is_active:
            await self.sessions.revoke_standalone(
                session_id=session.id, reason=RevokeReason.SUBJECT_DEACTIVATED
            )
            raise PermissionDeniedError("Admin inactive")
        target = await self.storage.tenants.get(claims.tenant_id)
        if target is not None and not target.is_active:
            await self.sessions.revoke_standalone(
                session_id=session.id, reason=RevokeReason.TENANT_DEACTIVATED
            )
        admin, tenant = await self._check_impersonation(
            UUID(claims.sub), claims.tenant_id, claims.impersonation_role or ""
        )
        role = claims.impersonation_role or ""
        pair = self.tokens.issue_pair(
            typ="impersonation",
            subject=admin,
            session_id=session.id,
            tenant=tenant,
            roles=[role],
            refresh_cap=parent.expires_at,
            reason=claims.reason,
        )
        await self.sessions.rotate(
            claims=claims, pair=pair, action="impersonation.refreshed", metadata={"role": role}
        )
        return pair

    async def end_impersonation(self, *, refresh_token: str) -> None:
        """Revoke an impersonation session early. Idempotent; expired tokens are a no-op."""
        try:
            claims = self.tokens.verify_refresh(refresh_token, expected="impersonation")
        except ExpiredTokenError:
            return
        async with self.audit.recorder() as rec:
            count = await self.sessions.revoke(
                session_id=claims.sid, reason=RevokeReason.IMPERSONATION_ENDED
            )
            if count:
                await rec.emit(
                    AuditEvent(
                        **{
                            **actor_fields(claims),
                            "action": "impersonation.ended",
                            "outcome": "success",
                            "target_type": "session",
                            "target_id": claims.sid,
                        }
                    )
                )
