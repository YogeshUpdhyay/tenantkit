from collections.abc import Iterable
from uuid import UUID
from tenantkit.config.models import TenantKitConfig
from tenantkit.storage.interfaces import Storage
from tenantkit.domain.models import Admin, Tenant
from tenantkit.domain.claims import BaseClaims, TokenPair
from tenantkit.domain.errors import (
    ImpersonationDisabledError,
    NotFoundError,
    PermissionDeniedError,
    WrongTokenTypeError,
)
from tenantkit.tokens.service import TokenService


class AccessService:
    def __init__(self, config: TenantKitConfig, storage: Storage, tokens: TokenService) -> None:
        self.config, self.storage, self.tokens = config, storage, tokens

    @staticmethod
    def is_type(claims: BaseClaims, *types: str) -> bool:
        return claims.typ in types

    @staticmethod
    def has_role(claims: BaseClaims, role: str) -> bool:
        return role in claims.roles

    @staticmethod
    def has_permission(claims: BaseClaims, permission: str) -> bool:
        if "*" in permission:
            raise ValueError("Permission checks require concrete permissions")
        return any(
            p == "*" or p == permission or (p.endswith(":*") and permission.startswith(p[:-1]))
            for p in claims.perms
        )

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
        self.require_permission(actor, "impersonate")
        admin, tenant = await self._check_impersonation(UUID(actor.sub), tenant_id, role)
        refresh = self.tokens.verify_refresh(admin_refresh_token, expected="admin")
        if refresh.sub != actor.sub:
            raise PermissionDeniedError("Admin session mismatch")
        return self.tokens.issue_pair(
            typ="impersonation",
            subject=admin,
            tenant=tenant,
            roles=[role],
            admin_refresh_exp=refresh.exp,
            reason=reason,
        )

    async def refresh_impersonation(self, refresh_token: str) -> TokenPair:
        claims = self.tokens.verify_refresh(refresh_token, expected="impersonation")
        if claims.tenant_id is None:
            raise PermissionDeniedError("Missing tenant")
        admin, tenant = await self._check_impersonation(
            UUID(claims.sub), claims.tenant_id, claims.impersonation_role or ""
        )
        return self.tokens.issue_pair(
            typ="impersonation",
            subject=admin,
            tenant=tenant,
            roles=[claims.impersonation_role or ""],
            admin_refresh_exp=claims.exp,
            reason=claims.reason,
        )
