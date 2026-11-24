"""Deterministically put every request past the initial lock check."""

import asyncio
from typing import cast

import pytest

from tenantkit.audit import AuditService
from tenantkit.auth.admin import AdminAuthService
from tenantkit.auth.tenant import TenantAuthService
from tenantkit.auth.hashing import Hashing
from tenantkit.auth.providers.password import PasswordProvider
from tenantkit.domain.errors import AccountLockedError
from tenantkit.domain.models import Admin, Tenant, TenantUser
from tenantkit.storage.memory import InMemoryStorage
from tenantkit.sessions import SessionService
from tenantkit.tokens.service import TokenService
from test_core import config


class TestHashing:
    __test__ = False
    dummy = "dummy"

    def verify(self, hashed, password):
        return hashed == password


class SimultaneousReads:
    def __init__(self, repository, size):
        self.repository = repository
        self.remaining = size
        self.ready = asyncio.Event()

    async def get(self, *args):
        row = await self.repository.get(*args)
        if self.remaining:
            self.remaining -= 1
            if self.remaining == 0:
                self.ready.set()
            await self.ready.wait()
        return row

    def __getattr__(self, name):
        return getattr(self.repository, name)


@pytest.mark.parametrize("subject_type", ["admin", "tenant_user"])
async def test_parallel_password_failures_lock_account(subject_type):
    cfg = config()
    storage = InMemoryStorage()
    hashing = cast(Hashing, TestHashing())
    tokens = TokenService(cfg, storage)
    audit = AuditService(cfg, storage)
    sessions = SessionService(cfg, storage, audit, tokens)
    provider = PasswordProvider(storage, hashing, cfg)
    tenant = await storage.tenants.create(
        Tenant(slug="beta", login_policy=cfg.tenant_auth.default_policy)
    )
    if subject_type == "admin":
        subject = await storage.admins.create(
            Admin(email="beta@example.com", password_hash="correct")
        )
        auth = AdminAuthService(
            cfg, storage, tokens, hashing, {"password": provider}, audit, sessions
        )

        async def login(password):
            return await auth.login(email=subject.email, password=password)
    else:
        subject = await storage.tenant_users.create(
            TenantUser(tenant_id=tenant.id, email="beta@example.com", password_hash="correct")
        )
        auth = TenantAuthService(
            cfg, storage, tokens, hashing, {"password": provider}, audit, sessions
        )

        async def login(password):
            return await auth.login(
                tenant_slug="beta",
                method="password",
                credentials={"email": subject.email, "password": password},
            )

    storage.login_attempts = SimultaneousReads(storage.login_attempts, 12)
    results = await asyncio.gather(
        *[login(f"wrong-{i}") for i in range(12)], return_exceptions=True
    )
    attempt = await storage.login_attempts.get(subject_type, subject.id)
    assert attempt.failed_count == 12
    assert attempt.locked_until is not None
    assert sum(isinstance(result, AccountLockedError) for result in results) == 8
    # Exactly one of the parallel failures sets the lock, so exactly one lock event exists.
    locked = await storage.audit_events.list(action="auth.account.locked")
    assert len(locked) == 1 and locked[0].target_id == subject.id
    assert len(await storage.audit_events.list(action="auth.login.failed")) == 12
    with pytest.raises(AccountLockedError):
        await login("correct")
