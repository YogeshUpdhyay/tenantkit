import importlib.util
import pytest
from tenantkit import TenantKit, TenantKitConfig
from tenantkit.domain.errors import (
    AlreadyBootstrappedError,
    InvalidCredentialsError,
    LastAdminError,
    TenantValidationError,
)
from tenantkit.storage.memory import InMemoryStorage

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None,
    reason="argon2-cffi unavailable in offline environment",
)


@pytest.fixture
def config():
    return TenantKitConfig.from_dict(
        {
            "issuer": "tests",
            "audience": "tests",
            "tokens": {
                kind: {"private_key": kind * 32, "kid": kind}
                for kind in ["admin", "tenant", "impersonation"]
            },
            "roles": {
                "admin": {"super_admin": {"permissions": ["*"]}},
                "tenant": {"reader": {"permissions": ["data:read"]}},
            },
            "tenant_schema": {"fields": [{"name": "name", "type": "string", "required": True}]},
        }
    )


@pytest.mark.asyncio
async def test_bootstrap_is_one_time(config):
    kit = TenantKit(config=config, storage=InMemoryStorage())
    await kit.control_plane.bootstrap_super_admin(
        email="root@example.com", password="strong-passphrase-123"
    )
    with pytest.raises(AlreadyBootstrappedError):
        await kit.control_plane.bootstrap_super_admin(
            email="other@example.com", password="strong-passphrase-123"
        )


@pytest.mark.asyncio
async def test_tenant_login_requires_matching_slug_and_active_tenant(config):
    kit = TenantKit(config=config, storage=InMemoryStorage())
    await kit.control_plane.bootstrap_super_admin("root@example.com", "strong-passphrase-123")
    admin = (
        await kit.admin_auth.login(email=" ROOT@example.com ", password="strong-passphrase-123")
    ).claims
    tenant = await kit.control_plane.create_tenant(admin, "acme", {"name": "Acme"})
    await kit.control_plane.create_tenant(admin, "other", {"name": "Other"})
    await kit.control_plane.create_tenant_user(
        admin, tenant.id, "user@example.com", "strong-passphrase-123", ["reader"]
    )
    pair = await kit.tenant_auth.login(
        tenant_slug="acme",
        method="password",
        credentials={"email": "user@example.com", "password": "strong-passphrase-123"},
    )
    assert pair.claims.tenant_id == tenant.id
    assert "data:read" in pair.claims.perms
    with pytest.raises(InvalidCredentialsError):
        await kit.tenant_auth.login(
            tenant_slug="other",
            method="password",
            credentials={"email": "user@example.com", "password": "strong-passphrase-123"},
        )
    await kit.control_plane.deactivate_tenant(admin, tenant.id)
    from tenantkit.domain.errors import InvalidTokenError

    with pytest.raises(InvalidTokenError):
        await kit.tenant_auth.refresh(refresh_token=pair.refresh_token)


@pytest.mark.asyncio
async def test_last_manager_and_dynamic_schema_are_protected(config):
    kit = TenantKit(config=config, storage=InMemoryStorage())
    root = await kit.control_plane.bootstrap_super_admin(
        "root@example.com", "strong-passphrase-123"
    )
    claims = (await kit.admin_auth.login(email=root.email, password="strong-passphrase-123")).claims
    with pytest.raises(LastAdminError):
        await kit.control_plane.deactivate_admin(claims, root.id)
    with pytest.raises(TenantValidationError):
        await kit.control_plane.create_tenant(claims, "acme", {"typo": "value"})


@pytest.mark.asyncio
async def test_admin_cannot_grant_role_with_broader_impersonation_privileges(config):
    from tenantkit.domain.errors import PermissionDeniedError
    from tenantkit.domain.models import ImpersonationScope
    from tenantkit.config.models import RolesConfig, ImpersonationConfig

    config = config.model_copy(
        update={
            "roles": RolesConfig(
                admin={
                    "manager": {"permissions": ["admins:manage"]},
                    "power_manager": {"permissions": ["admins:manage"]},
                },
                impersonation={"full": {"permissions": ["data:write"]}},
            ),
            "impersonation": ImpersonationConfig(allowed_roles={"power_manager": ("full",)}),
        }
    )
    kit = TenantKit(config=config, storage=InMemoryStorage())
    root = await kit.control_plane.bootstrap_super_admin(
        "root@example.com", "strong-passphrase-123"
    )
    root.roles = ["manager"]
    await kit.storage.admins.update(root)
    claims = (await kit.admin_auth.login(email=root.email, password="strong-passphrase-123")).claims
    with pytest.raises(PermissionDeniedError):
        await kit.control_plane.create_admin(
            claims,
            "new@example.com",
            "strong-passphrase-123",
            ["power_manager"],
            ImpersonationScope("none"),
        )
