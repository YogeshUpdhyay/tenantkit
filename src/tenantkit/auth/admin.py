from dataclasses import asdict
from typing import Any
from uuid import UUID
from tenantkit.auth.providers.base import AuthRequest, AuthProvider
from tenantkit.config.models import TenantKitConfig
from tenantkit.storage.interfaces import Storage
from tenantkit.tokens.service import TokenService
from tenantkit.auth.hashing import Hashing
from tenantkit.domain.claims import TokenPair
from tenantkit.domain.models import Admin
from tenantkit.domain.errors import (
    AccountLockedError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
)


class AdminAuthService:
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

    async def login(self, *, email: str, password: str) -> TokenPair:
        policy = self.config.admin_auth.policy
        result = await self.providers[policy.providers[0]].authenticate(
            AuthRequest("admin", {"email": email, "password": password}), policy
        )
        if result.status != "success":
            if result.reason == "locked":
                raise AccountLockedError()
            raise InvalidCredentialsError()
        if result.subject_id is None:
            raise InvalidCredentialsError()
        admin = await self.storage.admins.get(result.subject_id)
        if admin is None or not admin.is_active:
            raise InvalidCredentialsError()
        return self.tokens.issue_pair(typ="admin", subject=admin)

    async def refresh(self, *, refresh_token: str) -> TokenPair:
        claims = self.tokens.verify_refresh(refresh_token, expected="admin")
        admin = await self.storage.admins.get(UUID(claims.sub))
        if admin is None or not admin.is_active:
            raise InvalidTokenError("Inactive account")
        return self.tokens.issue_pair(typ="admin", subject=admin)

    async def me(self, *, actor: Any) -> dict[str, Any]:
        admin = await self._subject(actor)
        data = asdict(admin)
        data.pop("password_hash")
        return data

    async def _subject(self, actor: Any) -> Admin:
        if actor.typ != "admin" or actor.use != "access":
            raise PermissionDeniedError("Admin access required")
        admin = await self.storage.admins.get(UUID(actor.sub))
        if admin is None or not admin.is_active:
            raise InvalidCredentialsError()
        return admin

    async def change_password(self, *, actor: Any, current: str, new: str) -> None:
        admin = await self._subject(actor)
        if not self.hashing.verify(admin.password_hash, current):
            raise InvalidCredentialsError()
        self.hashing.validate(new, admin.email, self.config.admin_auth.password)
        admin.password_hash = self.hashing.hash(new)
        await self.storage.admins.update(admin)
