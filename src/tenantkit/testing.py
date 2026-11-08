"""Reusable adapter contract: subclass and implement ``make_storage``."""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import replace
import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from tenantkit.domain.errors import AlreadyExistsError
from tenantkit.domain.models import Admin, Tenant, TenantUser
from tenantkit.storage.interfaces import Storage


class StorageContract:
    async def make_storage(self) -> Storage:
        raise NotImplementedError

    async def close_storage(self, storage: Storage) -> None:
        """Override to release adapter resources after each contract test."""

    @asynccontextmanager
    async def storage(self) -> AsyncIterator[Storage]:
        storage = await self.make_storage()
        try:
            yield storage
        finally:
            await self.close_storage(storage)

    @pytest.mark.asyncio
    async def test_tenant_lifecycle(self) -> None:
        async with self.storage() as storage:
            tenant = await storage.tenants.create(
                Tenant(slug="acme", attributes={"nested": {"count": 3}})
            )
            loaded = await storage.tenants.get_by_slug("acme")
            assert loaded == tenant
            assert loaded is not None
            loaded.attributes["nested"]["count"] = 9
            persisted = await storage.tenants.get(tenant.id)
            assert persisted is not None and persisted.attributes == {"nested": {"count": 3}}
            await storage.tenants.update(replace(tenant, is_active=False))
            assert await storage.tenants.list(active=True) == []
            assert len(await storage.tenants.list(active=False)) == 1
            with pytest.raises(AlreadyExistsError):
                await storage.tenants.create(Tenant(slug="acme"))

    @pytest.mark.asyncio
    async def test_admin_and_user_lifecycle(self) -> None:
        async with self.storage() as storage:
            tenant = await storage.tenants.create(Tenant(slug="acme"))
            admin = await storage.admins.create(
                Admin(email="admin@example.com", password_hash="hash")
            )
            assert await storage.admins.get_by_email(admin.email) == admin
            await storage.admins.update(replace(admin, is_active=False))
            assert await storage.admins.list(active=True) == []
            with pytest.raises(AlreadyExistsError):
                await storage.admins.create(Admin(email=admin.email, password_hash="hash"))
            user = await storage.tenant_users.create(
                TenantUser(tenant_id=tenant.id, email="user@example.com", password_hash="hash")
            )
            assert await storage.tenant_users.get_by_email(user.email) == user
            await storage.tenant_users.update(replace(user, is_active=False))
            assert await storage.tenant_users.list(tenant.id, active=True) == []

    @pytest.mark.asyncio
    async def test_transaction_rollback(self) -> None:
        async with self.storage() as storage:
            with pytest.raises(RuntimeError):
                async with storage.transaction():
                    await storage.tenants.create(Tenant(slug="rollback"))
                    raise RuntimeError("abort")
            assert await storage.tenants.get_by_slug("rollback") is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("subject_type", ["admin", "tenant_user"])
    @pytest.mark.parametrize("max_attempts", [1, 5])
    async def test_concurrent_failures_lock_atomically(
        self, subject_type: str, max_attempts: int
    ) -> None:
        async with self.storage() as storage:
            identity = uuid4()
            until = datetime.now(timezone.utc) + timedelta(minutes=15)
            rows = await asyncio.gather(
                *[
                    storage.login_attempts.record_failure(
                        subject_type, identity, max_attempts=max_attempts, locked_until=until
                    )
                    for _ in range(12)
                ]
            )
            attempt = await storage.login_attempts.get(subject_type, identity)
            assert attempt is not None
            assert attempt.failed_count == 12
            assert attempt.locked_until == until
            assert sum(row.locked_until is not None for row in rows) == 13 - max_attempts
            # A stale caller with a higher threshold cannot clear an existing lock.
            later = await storage.login_attempts.record_failure(
                subject_type, identity, max_attempts=100, locked_until=until
            )
            assert later.failed_count == 13
            assert later.locked_until == until
