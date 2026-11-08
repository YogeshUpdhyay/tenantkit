"""Explicitly configured service facade."""

from typing import Sequence
from tenantkit.config.models import TenantKitConfig
from tenantkit.storage.interfaces import Storage
from tenantkit.auth.hashing import Hashing
from tenantkit.auth.providers.base import AuthProvider
from tenantkit.auth.providers.password import PasswordProvider
from tenantkit.auth.admin import AdminAuthService
from tenantkit.auth.tenant import TenantAuthService
from tenantkit.tokens.service import TokenService
from tenantkit.access.checks import AccessService
from tenantkit.control_plane.service import ControlPlaneService
from tenantkit.domain.errors import ConfigError, StorageUnavailableError


class TenantKit:
    def __init__(
        self,
        *,
        config: TenantKitConfig,
        storage: Storage,
        providers: Sequence[AuthProvider] | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        hashing = Hashing(config.hashing.argon2)
        registered: dict[str, AuthProvider] = {
            "password": PasswordProvider(storage, hashing, config)
        }
        for provider in providers or ():
            if provider.name in registered:
                raise ConfigError("Duplicate provider name")
            registered[provider.name] = provider
        for policy in (config.admin_auth.policy, config.tenant_auth.default_policy):
            if not policy.providers or any(name not in registered for name in policy.providers):
                raise ConfigError("Unknown provider")
        self.tokens = TokenService(config)
        self.access = AccessService(config, storage, self.tokens)
        self.control_plane = ControlPlaneService(config, storage, self.access, hashing, registered)
        self.admin_auth = AdminAuthService(config, storage, self.tokens, hashing, registered)
        self.tenant_auth = TenantAuthService(config, storage, self.tokens, hashing, registered)

    async def health_check(self) -> None:
        try:
            await self.storage.health_check()
        except Exception:
            raise StorageUnavailableError("Storage health check failed") from None

    @classmethod
    async def create(
        cls,
        *,
        config: TenantKitConfig,
        storage: Storage,
        providers: Sequence[AuthProvider] | None = None,
    ) -> "TenantKit":
        kit = cls(config=config, storage=storage, providers=providers)
        await kit.health_check()
        return kit
