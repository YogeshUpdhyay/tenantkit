"""Shared scaffolding: storage backends and a seeded TenantKit for service-level tests."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import pytest

from tenantkit import AuditEvent, TenantKit, TenantKitConfig
from tenantkit.domain.models import Admin, Tenant, TenantUser
from tenantkit.storage.interfaces import Storage
from tenantkit.storage.memory import InMemoryStorage

PASSWORD = "strong-passphrase-123"


def make_config(**overrides: Any) -> TenantKitConfig:
    data: dict[str, Any] = {
        "issuer": "tests",
        "audience": "tests",
        "tokens": {
            kind: {"private_key": kind * 32, "kid": kind}
            for kind in ["admin", "tenant", "impersonation"]
        },
        "roles": {
            "admin": {
                "super_admin": {"permissions": ["*"]},
                "auditor": {"permissions": ["audit:read"]},
                "purger": {"permissions": ["audit:purge"]},
                "session_admin": {"permissions": ["sessions:read", "sessions:revoke"]},
            },
            "tenant": {"reader": {"permissions": ["data:read"]}},
            "impersonation": {"support": {"permissions": ["data:read"]}},
        },
        "impersonation": {"allowed_roles": {"super_admin": ["support"]}},
        "tenant_schema": {"fields": [{"name": "name", "type": "string"}]},
    }
    data.update(overrides)
    return TenantKitConfig.from_dict(data)


MONGO_URL = os.getenv("TENANTKIT_TEST_MONGO_URL")
BACKENDS = [
    "memory",
    "sqlite",
    pytest.param(
        "postgres",
        marks=pytest.mark.skipif(
            not os.getenv("TENANTKIT_TEST_DATABASE_URL"), reason="PostgreSQL test URL not set"
        ),
    ),
    pytest.param(
        "mongo",
        marks=pytest.mark.skipif(not MONGO_URL, reason="TENANTKIT_TEST_MONGO_URL not set"),
    ),
]


@asynccontextmanager
async def open_mongo_storage(**options: Any) -> AsyncIterator[Storage]:
    """A BeanieStorage on a clean test database; one prefix is used for the whole suite."""
    from beanie import init_beanie
    from pymongo import AsyncMongoClient

    from tenantkit.storage.beanie import BeanieStorage, document_models

    assert MONGO_URL
    client: AsyncMongoClient[Any] = AsyncMongoClient(
        MONGO_URL, uuidRepresentation="standard", tz_aware=True, serverSelectionTimeoutMS=5000
    )
    try:
        database = client["tenantkit_test"]
        models = document_models("mt_")
        await init_beanie(database=database, document_models=list(models.all))
        for model in models.all:
            await model.get_pymongo_collection().delete_many({})
        storage = BeanieStorage(database=database, models=models, **options)
        await storage.health_check()
        yield storage
    finally:
        await client.close()


@asynccontextmanager
async def open_storage(kind: str) -> AsyncIterator[Storage]:
    if kind == "memory":
        yield InMemoryStorage()
        return
    if kind == "mongo":
        async with open_mongo_storage() as storage:
            yield storage
        return
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from tenantkit.storage.sqlalchemy import SqlAlchemyStorage

    if kind == "postgres":
        engine = create_async_engine(os.environ["TENANTKIT_TEST_DATABASE_URL"])
        storage = SqlAlchemyStorage(
            session_factory=async_sessionmaker(engine), table_prefix="t_" + uuid4().hex + "_"
        )
        try:
            async with engine.begin() as connection:
                await connection.run_sync(storage.metadata.create_all)
            yield storage
        finally:
            async with engine.begin() as connection:
                await connection.run_sync(storage.metadata.drop_all)
            await engine.dispose()
        return

    with tempfile.TemporaryDirectory(prefix="tenantkit-sqlite-") as directory:
        engine = create_async_engine("sqlite+aiosqlite:///" + directory + "/test.db")
        storage = SqlAlchemyStorage(
            session_factory=async_sessionmaker(engine), table_prefix="t_" + uuid4().hex + "_"
        )
        try:
            async with engine.begin() as connection:
                await connection.run_sync(storage.metadata.create_all)
            yield storage
        finally:
            await engine.dispose()


@dataclass
class Env:
    kit: TenantKit
    storage: Storage
    root: Admin
    hook_events: list[AuditEvent] = field(default_factory=list)

    async def admin_login(self, email: str = "root@example.com") -> Any:
        return await self.kit.admin_auth.login(email=email, password=PASSWORD)

    async def tenant_login(self, slug: str, email: str) -> Any:
        return await self.kit.tenant_auth.login(
            tenant_slug=slug, method="password", credentials={"email": email, "password": PASSWORD}
        )

    async def make_tenant(
        self, actor: Any, slug: str, *users: str
    ) -> tuple[Tenant, list[TenantUser]]:
        tenant = await self.kit.control_plane.create_tenant(actor, slug, {"name": slug})
        created = [
            await self.kit.control_plane.create_tenant_user(
                actor, tenant.id, email, PASSWORD, ["reader"]
            )
            for email in users
        ]
        return tenant, created


@asynccontextmanager
async def open_env(kind: str, **config: Any) -> AsyncIterator[Env]:
    async with open_storage(kind) as storage:
        events: list[AuditEvent] = []

        async def hook(event: AuditEvent) -> None:
            events.append(event)

        kit = TenantKit(config=make_config(**config), storage=storage, audit_hooks=[hook])
        root = await kit.control_plane.bootstrap_super_admin("root@example.com", PASSWORD)
        yield Env(kit, storage, root, events)
