from dataclasses import asdict
from typing import Any
from uuid import UUID
from tenantkit.auth.providers.base import AuthRequest, AuthProvider
from tenantkit.config.models import TenantKitConfig
from tenantkit.storage.interfaces import Storage
from tenantkit.tokens.service import TokenService
from tenantkit.auth.hashing import Hashing
from tenantkit.domain.claims import TokenPair
from tenantkit.domain.models import Tenant, TenantUser
from tenantkit.domain.errors import (
    AccountLockedError,
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
    ) -> None:
        self.config = config
        self.storage = storage
        self.tokens = tokens
        self.hashing = hashing
        self.providers = providers

    async def _tenant(self, slug: str) -> Tenant:
        tenant = await self.storage.tenants.get_by_slug(slug)
        if tenant is None or not tenant.is_active:
            raise InvalidCredentialsError()
        return tenant

    async def login_methods(self, *, tenant_slug: str) -> list[str]:
        tenant = await self._tenant(tenant_slug)
        policy = tenant.login_policy or self.config.tenant_auth.default_policy
        return list(policy.providers)

    async def login(
        self, *, tenant_slug: str, method: str, credentials: dict[str, Any]
    ) -> TokenPair:
        tenant = await self._tenant(tenant_slug)
        policy = tenant.login_policy or self.config.tenant_auth.default_policy
        if method not in policy.providers:
            raise InvalidCredentialsError()
        result = await self.providers[method].authenticate(
            AuthRequest("tenant_user", credentials, tenant.id), policy
        )
        if result.status != "success":
            if result.reason == "locked":
                raise AccountLockedError()
            raise InvalidCredentialsError()
        if result.subject_id is None:
            raise InvalidCredentialsError()
        user = await self.storage.tenant_users.get(result.subject_id)
        if user is None or not user.is_active or user.tenant_id != tenant.id:
            raise InvalidCredentialsError()
        return self.tokens.issue_pair(typ="tenant", subject=user, tenant=tenant)

    async def refresh(self, *, refresh_token: str) -> TokenPair:
        claims = self.tokens.verify_refresh(refresh_token, expected="tenant")
        user = await self.storage.tenant_users.get(UUID(claims.sub))
        if claims.tenant_id is None:
            raise InvalidTokenError("Missing tenant")
        tenant = await self.storage.tenants.get(claims.tenant_id)
        if (
            user is None
            or tenant is None
            or not user.is_active
            or not tenant.is_active
            or user.tenant_id != tenant.id
        ):
            raise InvalidTokenError("Inactive account")
        return self.tokens.issue_pair(typ="tenant", subject=user, tenant=tenant)

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
        await self.storage.tenant_users.update(user)
