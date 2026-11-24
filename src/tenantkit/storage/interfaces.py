from contextlib import AbstractAsyncContextManager
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from tenantkit.domain.models import (
    Admin,
    AuditEvent,
    LoginAttempt,
    Session,
    SessionKind,
    Tenant,
    TenantUser,
)


class TenantRepository(Protocol):
    async def create(self, tenant: Tenant, /) -> Tenant: ...
    async def get(self, tenant_id: UUID, /) -> Tenant | None: ...
    async def get_by_slug(self, slug: str) -> Tenant | None: ...
    async def list(
        self, *, active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[Tenant]: ...
    async def update(self, tenant: Tenant, /) -> Tenant: ...


class AdminRepository(Protocol):
    async def create(self, admin: Admin, /) -> Admin: ...
    async def get(self, admin_id: UUID, /) -> Admin | None: ...
    async def get_by_email(self, email: str) -> Admin | None: ...
    async def list(
        self, *, active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[Admin]: ...
    async def update(self, admin: Admin, /) -> Admin: ...


class TenantUserRepository(Protocol):
    async def create(self, user: TenantUser, /) -> TenantUser: ...
    async def get(self, user_id: UUID, /) -> TenantUser | None: ...
    async def get_by_email(self, email: str) -> TenantUser | None: ...
    async def list(
        self, tenant_id: UUID, *, active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[TenantUser]: ...
    async def update(self, user: TenantUser, /) -> TenantUser: ...


class LoginAttemptRepository(Protocol):
    async def get(self, subject_type: str, subject_id: UUID) -> LoginAttempt | None: ...
    async def record_failure(
        self, subject_type: str, subject_id: UUID, *, max_attempts: int, locked_until: datetime
    ) -> LoginAttempt: ...
    async def reset(self, subject_type: str, subject_id: UUID) -> None: ...


class SessionRepository(Protocol):
    async def create(self, session: Session, /) -> Session: ...
    async def get(self, session_id: UUID, /) -> Session | None: ...
    async def rotate(
        self,
        session_id: UUID,
        *,
        expected_jti: UUID,
        new_jti: UUID,
        expires_at: datetime,
        used_at: datetime,
    ) -> Session | None: ...
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
    ) -> int: ...
    async def list(
        self,
        *,
        kind: SessionKind,
        subject_id: UUID,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Session]: ...
    async def purge_expired(self, *, before: datetime) -> int: ...


class AuditEventRepository(Protocol):
    async def append(self, event: AuditEvent, /) -> None: ...
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
    ) -> list[AuditEvent]: ...
    async def purge(self, *, before: datetime) -> int: ...


class Storage(Protocol):
    tenants: TenantRepository
    admins: AdminRepository
    tenant_users: TenantUserRepository
    login_attempts: LoginAttemptRepository
    sessions: SessionRepository
    audit_events: AuditEventRepository

    def transaction(self) -> AbstractAsyncContextManager[None]: ...
    def in_transaction(self) -> bool: ...
    async def health_check(self) -> None: ...
