"""Isolated in-memory repositories with rollback and uniqueness enforcement."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from copy import deepcopy
from collections.abc import Sequence
from datetime import datetime
from typing import AsyncIterator, Generic, TypeVar
from uuid import UUID

from tenantkit.domain.errors import AlreadyExistsError, NotFoundError, StorageError
from tenantkit.domain.models import (
    Admin,
    AuditEvent,
    LoginAttempt,
    RevokeReason,
    Session,
    SessionKind,
    Tenant,
    TenantUser,
)
from tenantkit.storage.interfaces import (
    AdminRepository,
    AuditEventRepository,
    LoginAttemptRepository,
    SessionRepository,
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
        self, subject_type: str, subject_id: UUID, *, max_attempts: int, locked_until: datetime
    ) -> LoginAttempt:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        async with self.storage.transaction():
            key = (subject_type, subject_id)
            old = self.rows.get(key)
            count = (old.failed_count if old else 0) + 1
            until = old.locked_until if old else None
            if until is None and count >= max_attempts:
                until = locked_until
            value = LoginAttempt(
                subject_type=subject_type,
                subject_id=subject_id,
                failed_count=count,
                locked_until=until,
            )
            self.rows[key] = value
            return deepcopy(value)

    async def reset(self, subject_type: str, subject_id: UUID) -> None:
        async with self.storage.transaction():
            self.rows.pop((subject_type, subject_id), None)


class _Sessions:
    def __init__(self, storage: InMemoryStorage) -> None:
        self.storage = storage
        self.rows: dict[UUID, Session] = {}

    async def create(self, session: Session, /) -> Session:
        async with self.storage.transaction():
            if session.id in self.rows:
                raise AlreadyExistsError("ID already exists")
            self.rows[session.id] = deepcopy(session)
            return deepcopy(session)

    async def get(self, session_id: UUID, /) -> Session | None:
        return deepcopy(self.rows.get(session_id))

    async def rotate(
        self,
        session_id: UUID,
        *,
        expected_jti: UUID,
        new_jti: UUID,
        expires_at: datetime,
        used_at: datetime,
    ) -> Session | None:
        async with self.storage.transaction():
            row = self.rows.get(session_id)
            if row is None or row.revoked_at is not None or row.current_jti != expected_jti:
                return None
            row.current_jti = new_jti
            row.expires_at = expires_at
            row.last_used_at = used_at
            return deepcopy(row)

    async def revoke(
        self,
        *,
        reason: str,
        at: datetime,
        session_id: UUID | None = None,
        kind: SessionKind | None = None,
        subject_id: UUID | None = None,
        tenant_id: UUID | None = None,
        cascade_children: bool = False,
    ) -> int:
        if session_id is None and kind is None and subject_id is None and tenant_id is None:
            raise ValueError("At least one revoke filter is required")
        async with self.storage.transaction():
            matched = [
                row
                for row in self.rows.values()
                if (session_id is None or row.id == session_id)
                and (kind is None or row.kind == kind)
                and (subject_id is None or row.subject_id == subject_id)
                and (tenant_id is None or row.tenant_id == tenant_id)
            ]
            count = 0
            for row in matched:
                if row.revoked_at is None:
                    row.revoked_at, row.revoked_reason = at, reason
                    count += 1
            if cascade_children:
                parents = {row.id for row in matched}
                for row in self.rows.values():
                    if row.parent_id in parents and row.revoked_at is None:
                        row.revoked_at, row.revoked_reason = at, RevokeReason.PARENT_REVOKED
                        count += 1
            return count

    async def list(
        self,
        *,
        kind: SessionKind,
        subject_id: UUID,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Session]:
        if limit < 0 or offset < 0:
            raise ValueError("Pagination values cannot be negative")
        rows = [
            row
            for row in self.rows.values()
            if row.kind == kind
            and row.subject_id == subject_id
            and (not active_only or row.is_active)
        ]
        rows.sort(key=lambda row: (row.created_at, row.id), reverse=True)
        return deepcopy(rows[offset : offset + limit])

    async def purge_expired(self, *, before: datetime) -> int:
        async with self.storage.transaction():
            doomed = [
                key
                for key, row in self.rows.items()
                if row.expires_at < before
                or (row.revoked_at is not None and row.revoked_at < before)
            ]
            for key in doomed:
                del self.rows[key]
            return len(doomed)


class _AuditEvents:
    def __init__(self, storage: InMemoryStorage) -> None:
        self.storage = storage
        self.rows: list[AuditEvent] = []

    async def append(self, event: AuditEvent, /) -> None:
        async with self.storage.transaction():
            self.rows.append(deepcopy(event))

    async def list(
        self,
        *,
        tenant_ids: Sequence[UUID] | None = None,
        actor_id: UUID | None = None,
        target_id: UUID | None = None,
        action: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]:
        if limit < 0 or offset < 0:
            raise ValueError("Pagination values cannot be negative")
        if tenant_ids is not None and not tenant_ids:
            return []
        prefix = action[:-1] if action is not None and action.endswith(".*") else None

        def matches(event: AuditEvent) -> bool:
            if tenant_ids is not None and event.tenant_id not in tenant_ids:
                return False
            if actor_id is not None and event.actor_id != actor_id:
                return False
            if target_id is not None and event.target_id != target_id:
                return False
            if action is not None and not (
                event.action.startswith(prefix) if prefix is not None else event.action == action
            ):
                return False
            if since is not None and event.occurred_at < since:
                return False
            return until is None or event.occurred_at <= until

        rows = sorted(
            (e for e in self.rows if matches(e)), key=lambda e: (e.occurred_at, e.id), reverse=True
        )
        return deepcopy(rows[offset : offset + limit])

    async def purge(self, *, before: datetime) -> int:
        async with self.storage.transaction():
            kept = [e for e in self.rows if e.occurred_at >= before]
            removed = len(self.rows) - len(kept)
            self.rows = kept
            return removed


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
        self._sessions = _Sessions(self)
        self._audit = _AuditEvents(self)
        self.sessions: SessionRepository = self._sessions
        self.audit_events: AuditEventRepository = self._audit
        self._lock = asyncio.Lock()
        self._owner: ContextVar[asyncio.Task[object] | None] = ContextVar(
            "tenantkit_memory_transaction", default=None
        )

    async def health_check(self) -> None:
        return None

    def in_transaction(self) -> bool:
        task = asyncio.current_task()
        return task is not None and self._owner.get() is task

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
                deepcopy(self._sessions.rows),
                list(self._audit.rows),
            )
            try:
                yield
            except BaseException:
                (
                    self._tenants.rows,
                    self._admins.rows,
                    self._users.rows,
                    self._attempts.rows,
                    self._sessions.rows,
                    self._audit.rows,
                ) = snapshots
                raise
            finally:
                self._owner.reset(token)
