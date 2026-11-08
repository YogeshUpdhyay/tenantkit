"""Isolated in-memory repositories with rollback and uniqueness enforcement."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime
from typing import AsyncIterator, Generic, TypeVar
from uuid import UUID

from tenantkit.domain.errors import AlreadyExistsError, NotFoundError, StorageError
from tenantkit.domain.models import Admin, LoginAttempt, Tenant, TenantUser
from tenantkit.storage.interfaces import (
    AdminRepository,
    LoginAttemptRepository,
    TenantRepository,
    TenantUserRepository,
)

T = TypeVar("T", Admin, Tenant, TenantUser)


class _Repository(Generic[T]):
    def __init__(self, storage: InMemoryStorage, unique: str) -> None:
        self.storage = storage
        self.unique = unique
        self.rows: dict[UUID, T] = {}

    async def create(self, value: T) -> T:
        async with self.storage.transaction():
            if value.id in self.rows:
                raise AlreadyExistsError("ID already exists")
            self._validate(value)
            self.rows[value.id] = deepcopy(value)
            return deepcopy(value)

    def _validate(self, value: T) -> None:
        key = getattr(value, self.unique)
        for row in self.rows.values():
            if row.id != value.id and getattr(row, self.unique) == key:
                raise AlreadyExistsError(f"{self.unique} already exists")
        if isinstance(value, TenantUser) and value.tenant_id not in self.storage._tenants.rows:
            raise StorageError("Tenant does not exist")

    async def get(self, record_id: UUID) -> T | None:
        return deepcopy(self.rows.get(record_id))

    async def _find(self, key: str, value: str) -> T | None:
        return next(
            (deepcopy(row) for row in self.rows.values() if getattr(row, key) == value), None
        )

    async def get_by_slug(self, slug: str) -> T | None:
        return await self._find("slug", slug)

    async def get_by_email(self, email: str) -> T | None:
        return await self._find("email", email)

    async def list(
        self,
        tenant_id: UUID | None = None,
        *,
        active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[T]:
        if limit < 0 or offset < 0:
            raise ValueError("Pagination values cannot be negative")
        rows = [
            row
            for row in self.rows.values()
            if (active is None or row.is_active == active)
            and (tenant_id is None or isinstance(row, TenantUser) and row.tenant_id == tenant_id)
        ]
        return deepcopy(rows[offset : offset + limit])

    async def update(self, value: T) -> T:
        async with self.storage.transaction():
            if value.id not in self.rows:
                raise NotFoundError("Record does not exist")
            self._validate(value)
            self.rows[value.id] = deepcopy(value)
            return deepcopy(value)


class _LoginAttempts:
    def __init__(self, storage: InMemoryStorage) -> None:
        self.storage = storage
        self.rows: dict[tuple[str, UUID], LoginAttempt] = {}

    async def get(self, subject_type: str, subject_id: UUID) -> LoginAttempt | None:
        return deepcopy(self.rows.get((subject_type, subject_id)))

    async def record_failure(
        self, subject_type: str, subject_id: UUID, *, locked_until: datetime | None = None
    ) -> LoginAttempt:
        async with self.storage.transaction():
            key = (subject_type, subject_id)
            old = self.rows.get(key)
            value = LoginAttempt(
                subject_type=subject_type,
                subject_id=subject_id,
                failed_count=(old.failed_count if old else 0) + 1,
                locked_until=locked_until,
            )
            self.rows[key] = value
            return deepcopy(value)

    async def reset(self, subject_type: str, subject_id: UUID) -> None:
        async with self.storage.transaction():
            self.rows.pop((subject_type, subject_id), None)


class InMemoryStorage:
    def __init__(self) -> None:
        self._tenants = _Repository[Tenant](self, "slug")
        self._admins = _Repository[Admin](self, "email")
        self._users = _Repository[TenantUser](self, "email")
        self._attempts = _LoginAttempts(self)
        self.tenants: TenantRepository = self._tenants
        self.admins: AdminRepository = self._admins
        self.tenant_users: TenantUserRepository = self._users
        self.login_attempts: LoginAttemptRepository = self._attempts
        self._lock = asyncio.Lock()
        self._owner: ContextVar[asyncio.Task[object] | None] = ContextVar(
            "tenantkit_memory_transaction", default=None
        )

    async def health_check(self) -> None:
        return None

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        task = asyncio.current_task()
        if self._owner.get() is task and task is not None:
            yield
            return
        async with self._lock:
            token = self._owner.set(task)
            snapshots = (
                deepcopy(self._tenants.rows),
                deepcopy(self._admins.rows),
                deepcopy(self._users.rows),
                deepcopy(self._attempts.rows),
            )
            try:
                yield
            except BaseException:
                self._tenants.rows, self._admins.rows, self._users.rows, self._attempts.rows = (
                    snapshots
                )
                raise
            finally:
                self._owner.reset(token)
