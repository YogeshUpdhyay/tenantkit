import asyncio
import os
from uuid import uuid4

import pytest

from tenantkit.domain.errors import AlreadyExistsError
from tenantkit.domain.models import Tenant, TenantUser
from tenantkit.storage.memory import InMemoryStorage
from tenantkit.testing import StorageContract


class TestMemoryStorage(StorageContract):
    async def make_storage(self):
        return InMemoryStorage()


@pytest.mark.asyncio
async def test_global_user_email_unique():
    storage = InMemoryStorage()
    first = await storage.tenants.create(Tenant(slug="one"))
    second = await storage.tenants.create(Tenant(slug="two"))
    await storage.tenant_users.create(
        TenantUser(tenant_id=first.id, email="one@example.com", password_hash="hash")
    )
    with pytest.raises(AlreadyExistsError):
        await storage.tenant_users.create(
            TenantUser(tenant_id=second.id, email="one@example.com", password_hash="hash")
        )


@pytest.mark.asyncio
async def test_attempt_increment_and_reset():
    storage = InMemoryStorage()
    identity = uuid4()
    await storage.login_attempts.record_failure("admin", identity)
    attempt = await storage.login_attempts.record_failure("admin", identity)
    assert attempt.failed_count == 2
    await storage.login_attempts.reset("admin", identity)
    assert await storage.login_attempts.get("admin", identity) is None


class TestSqlAlchemyStorage(StorageContract):
    database_url = "sqlite+aiosqlite://"

    async def make_storage(self):
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from tenantkit.storage.sqlalchemy import SqlAlchemyStorage

        if self.database_url.startswith("sqlite") and os.getenv("TENANTKIT_SKIP_SQLITE") == "1":
            pytest.skip("SQLite unavailable in this environment")
        self.engine = create_async_engine(self.database_url)
        storage = SqlAlchemyStorage(
            session_factory=async_sessionmaker(self.engine),
            table_prefix="test_" + uuid4().hex + "_",
        )
        self.metadata = storage.metadata
        async with asyncio.timeout(10):
            async with self.engine.begin() as connection:
                await connection.run_sync(storage.metadata.create_all)
            await storage.health_check()
        return storage

    async def close_storage(self, storage):
        try:
            async with self.engine.begin() as connection:
                await connection.run_sync(self.metadata.drop_all)
        finally:
            await self.engine.dispose()


@pytest.mark.skipif(
    not os.getenv("TENANTKIT_TEST_DATABASE_URL"), reason="PostgreSQL test URL not configured"
)
class TestPostgresStorage(TestSqlAlchemyStorage):
    database_url = os.getenv("TENANTKIT_TEST_DATABASE_URL", "postgresql+asyncpg://")
