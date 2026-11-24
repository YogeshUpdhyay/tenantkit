"""SQLAlchemy 2 async adapter using host-owned sessions and metadata."""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import asdict
from datetime import datetime, timezone
from collections.abc import Sequence
from typing import Any, AsyncIterator, Generic, Literal, TypeVar, cast
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    delete,
    case,
    or_,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tenantkit.domain.errors import (
    AlreadyExistsError,
    NotFoundError,
    StorageError,
    StorageUnavailableError,
)
from tenantkit.domain.models import (
    Admin,
    AuditEvent,
    ImpersonationScope,
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


def _tables(meta: MetaData, prefix: str) -> dict[str, Table]:
    json_type = JSON().with_variant(JSONB(), "postgresql")

    def common() -> list[Column[Any]]:
        return [
            Column("id", String(36), primary_key=True),
            Column("is_active", Boolean, nullable=False),
            Column("created_at", DateTime(timezone=True), nullable=False),
            Column("updated_at", DateTime(timezone=True), nullable=False),
        ]

    tenants = Table(
        prefix + "tenants",
        meta,
        *common(),
        Column("slug", String(63), unique=True, nullable=False),
        Column("attributes", json_type, nullable=False),
        Column("login_policy", json_type),
    )
    admins = Table(
        prefix + "admins",
        meta,
        *common(),
        Column("email", String(320), unique=True, nullable=False),
        Column("password_hash", String, nullable=False),
        Column("roles", json_type, nullable=False),
        Column("impersonation_mode", String, nullable=False),
        Column("impersonation_tenants", json_type, nullable=False),
    )
    users = Table(
        prefix + "tenant_users",
        meta,
        *common(),
        Column("tenant_id", String(36), ForeignKey(tenants.c.id), index=True, nullable=False),
        Column("email", String(320), unique=True, nullable=False),
        Column("password_hash", String, nullable=False),
        Column("roles", json_type, nullable=False),
    )
    attempts = Table(
        prefix + "login_attempts",
        meta,
        Column("subject_type", String, primary_key=True),
        Column("subject_id", String(36), primary_key=True),
        Column("failed_count", Integer, nullable=False),
        Column("locked_until", DateTime(timezone=True)),
    )
    sessions = Table(
        prefix + "sessions",
        meta,
        Column("id", String(36), primary_key=True),
        Column("kind", String(16), nullable=False),
        Column("subject_id", String(36), nullable=False),
        Column("tenant_id", String(36), index=True),
        Column("parent_id", String(36), index=True),
        Column("current_jti", String(36), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False, index=True),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("last_used_at", DateTime(timezone=True), nullable=False),
        Column("revoked_at", DateTime(timezone=True)),
        Column("revoked_reason", String),
    )
    Index(
        prefix + "ix_sessions_subject",
        sessions.c.kind,
        sessions.c.subject_id,
        sessions.c.created_at.desc(),
    )
    audit = Table(
        prefix + "audit_events",
        meta,
        Column("id", String(36), primary_key=True),
        Column("action", String(64), nullable=False, index=True),
        Column("outcome", String(16), nullable=False),
        Column("actor_type", String(16), nullable=False),
        Column("actor_id", String(36), index=True),
        Column("impersonator_id", String(36)),
        Column("tenant_id", String(36)),
        Column("target_type", String(32)),
        Column("target_id", String(36), index=True),
        Column("session_id", String(36)),
        Column("token_jti", String(36)),
        Column("reason", String),
        Column("metadata", json_type, nullable=False),
        Column("occurred_at", DateTime(timezone=True), nullable=False),
    )
    Index(prefix + "ix_audit_occurred", audit.c.occurred_at.desc(), audit.c.id.desc())
    Index(prefix + "ix_audit_tenant", audit.c.tenant_id, audit.c.occurred_at.desc())
    return {
        "tenants": tenants,
        "admins": admins,
        "tenant_users": users,
        "login_attempts": attempts,
        "sessions": sessions,
        "audit_events": audit,
    }


metadata = MetaData()
_default_tables = _tables(metadata, "mt_")
T = TypeVar("T", Admin, Tenant, TenantUser)


def _values(value: Admin | Tenant | TenantUser) -> dict[str, Any]:
    data = asdict(value)
    data["id"] = str(value.id)
    if isinstance(value, TenantUser):
        data["tenant_id"] = str(value.tenant_id)
    if isinstance(value, Admin):
        data.pop("impersonation_scope")
        data["impersonation_mode"] = value.impersonation_scope.mode
        data["impersonation_tenants"] = [str(i) for i in value.impersonation_scope.tenant_ids]
    if isinstance(value, Tenant) and hasattr(value.login_policy, "model_dump"):
        data["login_policy"] = value.login_policy.model_dump(mode="json")
    return data


def _model(cls: type[T], data: dict[str, Any]) -> T:
    data["id"] = UUID(data["id"])
    for key in ("created_at", "updated_at"):
        if data[key].tzinfo is None:
            data[key] = data[key].replace(tzinfo=timezone.utc)
    if cls is TenantUser:
        data["tenant_id"] = UUID(data["tenant_id"])
    if cls is Admin:
        data["impersonation_scope"] = ImpersonationScope(
            mode=cast(Literal["all", "list", "none"], data.pop("impersonation_mode")),
            tenant_ids=[UUID(v) for v in data.pop("impersonation_tenants")],
        )
    if cls is Tenant and data.get("login_policy") is not None:
        from tenantkit.config.models import LoginPolicy

        data["login_policy"] = LoginPolicy.model_validate(data["login_policy"])
    return cls(**data)


class _Repository(Generic[T]):
    def __init__(self, storage: SqlAlchemyStorage, table: Table, cls: type[T]) -> None:
        self.storage: SqlAlchemyStorage = storage
        self.table: Table = table
        self.cls: type[T] = cls

    async def create(self, value: T) -> T:
        async with self.storage._session() as session:
            await session.execute(insert(self.table).values(**_values(value)))
        return value

    async def get(self, record_id: UUID) -> T | None:
        return await self._find(self.table.c.id == str(record_id))

    async def _find(self, condition: Any) -> T | None:
        async with self.storage._session() as session:
            row = (await session.execute(select(self.table).where(condition))).mappings().first()
            return _model(self.cls, dict(row)) if row else None

    async def get_by_slug(self, slug: str) -> T | None:
        return await self._find(self.table.c.slug == slug)

    async def get_by_email(self, email: str) -> T | None:
        return await self._find(self.table.c.email == email)

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
        stmt = (
            select(self.table)
            .order_by(self.table.c.created_at, self.table.c.id)
            .limit(limit)
            .offset(offset)
        )
        if tenant_id is not None:
            stmt = stmt.where(self.table.c.tenant_id == str(tenant_id))
        if active is not None:
            stmt = stmt.where(self.table.c.is_active == active)
        async with self.storage._session() as session:
            rows = (await session.execute(stmt)).mappings().all()
            return [_model(self.cls, dict(row)) for row in rows]

    async def update(self, value: T) -> T:
        async with self.storage._session() as session:
            result = await session.execute(
                update(self.table).where(self.table.c.id == str(value.id)).values(**_values(value))
            )
            if cast("CursorResult[Any]", result).rowcount == 0:
                raise NotFoundError("Record does not exist")
        return value


class _Attempts:
    def __init__(self, storage: SqlAlchemyStorage, table: Table) -> None:
        self.storage, self.table = storage, table

    def _where(self, subject_type: str, subject_id: UUID) -> Any:
        return (self.table.c.subject_type == subject_type) & (
            self.table.c.subject_id == str(subject_id)
        )

    async def get(self, subject_type: str, subject_id: UUID) -> LoginAttempt | None:
        async with self.storage._session() as session:
            row = (
                (
                    await session.execute(
                        select(self.table).where(self._where(subject_type, subject_id))
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                return None
            until = row["locked_until"]
            if until is not None and until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            return LoginAttempt(
                subject_type=subject_type,
                subject_id=subject_id,
                failed_count=row["failed_count"],
                locked_until=until,
            )

    async def record_failure(
        self, subject_type: str, subject_id: UUID, *, max_attempts: int, locked_until: datetime
    ) -> LoginAttempt:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        initial_lock = locked_until if max_attempts == 1 else None
        async with self.storage._session() as session:
            condition = self._where(subject_type, subject_id)
            dialect = session.get_bind().dialect.name
            if dialect in {"sqlite", "postgresql"}:
                upsert: Any
                if dialect == "sqlite":
                    from sqlalchemy.dialects.sqlite import insert as upsert
                else:
                    from sqlalchemy.dialects.postgresql import insert as upsert
                stmt: Any = upsert(self.table).values(
                    subject_type=subject_type,
                    subject_id=str(subject_id),
                    failed_count=1,
                    locked_until=initial_lock,
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["subject_type", "subject_id"],
                    set_={
                        "failed_count": self.table.c.failed_count + 1,
                        "locked_until": case(
                            (self.table.c.locked_until.is_not(None), self.table.c.locked_until),
                            (self.table.c.failed_count + 1 >= max_attempts, locked_until),
                            else_=self.table.c.locked_until,
                        ),
                    },
                ).returning(self.table.c.failed_count, self.table.c.locked_until)
                row = (await session.execute(stmt)).mappings().one()
                count, until = row["failed_count"], row["locked_until"]
            else:
                # A savepoint lets a losing first-insert race continue safely.
                query = select(self.table).where(condition).with_for_update()
                previous = (await session.execute(query)).mappings().first()
                if previous is None:
                    try:
                        async with session.begin_nested():
                            await session.execute(
                                insert(self.table).values(
                                    subject_type=subject_type,
                                    subject_id=str(subject_id),
                                    failed_count=1,
                                    locked_until=initial_lock,
                                )
                            )
                    except IntegrityError:
                        previous = (await session.execute(query)).mappings().one()
                if previous is not None:
                    count = previous["failed_count"] + 1
                    until = previous["locked_until"]
                    if until is None and count >= max_attempts:
                        until = locked_until
                    await session.execute(
                        update(self.table)
                        .where(condition)
                        .values(
                            failed_count=count,
                            locked_until=until,
                        )
                    )
                else:
                    count, until = 1, initial_lock
            if until is not None and until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            return LoginAttempt(
                subject_type=subject_type,
                subject_id=subject_id,
                failed_count=count,
                locked_until=until,
            )

    async def reset(self, subject_type: str, subject_id: UUID) -> None:
        async with self.storage._session() as session:
            await session.execute(delete(self.table).where(self._where(subject_type, subject_id)))


def _utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _opt_uuid(value: str | None) -> UUID | None:
    return UUID(value) if value is not None else None


def _session_model(row: Any) -> Session:
    return Session(
        id=UUID(row["id"]),
        kind=row["kind"],
        subject_id=UUID(row["subject_id"]),
        tenant_id=_opt_uuid(row["tenant_id"]),
        parent_id=_opt_uuid(row["parent_id"]),
        current_jti=UUID(row["current_jti"]),
        expires_at=cast(datetime, _utc(row["expires_at"])),
        created_at=cast(datetime, _utc(row["created_at"])),
        last_used_at=cast(datetime, _utc(row["last_used_at"])),
        revoked_at=_utc(row["revoked_at"]),
        revoked_reason=row["revoked_reason"],
    )


def _opt_str(value: UUID | None) -> str | None:
    return str(value) if value is not None else None


class _Sessions:
    def __init__(self, storage: SqlAlchemyStorage, table: Table) -> None:
        self.storage: SqlAlchemyStorage = storage
        self.table: Table = table

    async def create(self, session: Session, /) -> Session:
        async with self.storage._session() as db:
            await db.execute(
                insert(self.table).values(
                    id=str(session.id),
                    kind=session.kind,
                    subject_id=str(session.subject_id),
                    tenant_id=_opt_str(session.tenant_id),
                    parent_id=_opt_str(session.parent_id),
                    current_jti=str(session.current_jti),
                    expires_at=session.expires_at,
                    created_at=session.created_at,
                    last_used_at=session.last_used_at,
                    revoked_at=session.revoked_at,
                    revoked_reason=session.revoked_reason,
                )
            )
        return session

    async def get(self, session_id: UUID, /) -> Session | None:
        async with self.storage._session() as db:
            row = (
                (await db.execute(select(self.table).where(self.table.c.id == str(session_id))))
                .mappings()
                .first()
            )
            return _session_model(row) if row else None

    async def rotate(
        self,
        session_id: UUID,
        *,
        expected_jti: UUID,
        new_jti: UUID,
        expires_at: datetime,
        used_at: datetime,
    ) -> Session | None:
        t = self.table
        async with self.storage._session() as db:
            row = (
                (
                    await db.execute(
                        update(t)
                        .where(
                            t.c.id == str(session_id),
                            t.c.revoked_at.is_(None),
                            t.c.current_jti == str(expected_jti),
                        )
                        .values(
                            current_jti=str(new_jti), expires_at=expires_at, last_used_at=used_at
                        )
                        .returning(*t.c)
                    )
                )
                .mappings()
                .first()
            )
            return _session_model(row) if row else None

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
        t = self.table
        filters: list[Any] = []
        if session_id is not None:
            filters.append(t.c.id == str(session_id))
        if kind is not None:
            filters.append(t.c.kind == kind)
        if subject_id is not None:
            filters.append(t.c.subject_id == str(subject_id))
        if tenant_id is not None:
            filters.append(t.c.tenant_id == str(tenant_id))
        if not filters:
            raise ValueError("At least one revoke filter is required")
        async with self.storage._session() as db:
            result = await db.execute(
                update(t)
                .where(*filters, t.c.revoked_at.is_(None))
                .values(revoked_at=at, revoked_reason=reason)
            )
            count = cast("CursorResult[Any]", result).rowcount
            if cascade_children:
                matched = select(t.c.id).where(*filters)
                result = await db.execute(
                    update(t)
                    .where(t.c.parent_id.in_(matched), t.c.revoked_at.is_(None))
                    .values(revoked_at=at, revoked_reason=RevokeReason.PARENT_REVOKED)
                )
                count += cast("CursorResult[Any]", result).rowcount
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
        t = self.table
        stmt = (
            select(t)
            .where(t.c.kind == kind, t.c.subject_id == str(subject_id))
            .order_by(t.c.created_at.desc(), t.c.id.desc())
        )
        if active_only:
            stmt = stmt.where(t.c.revoked_at.is_(None))
        async with self.storage._session() as db:
            rows = (await db.execute(stmt)).mappings().all()
        # Expiry is compared in Python so naive SQLite datetimes behave like aware ones.
        sessions = [_session_model(row) for row in rows]
        if active_only:
            sessions = [s for s in sessions if s.is_active]
        return sessions[offset : offset + limit]

    async def purge_expired(self, *, before: datetime) -> int:
        t = self.table
        async with self.storage._session() as db:
            result = await db.execute(
                delete(t).where(or_(t.c.expires_at < before, t.c.revoked_at < before))
            )
            return cast("CursorResult[Any]", result).rowcount


def _audit_model(row: Any) -> AuditEvent:
    return AuditEvent(
        id=UUID(row["id"]),
        action=row["action"],
        outcome=row["outcome"],
        actor_type=row["actor_type"],
        actor_id=_opt_uuid(row["actor_id"]),
        impersonator_id=_opt_uuid(row["impersonator_id"]),
        tenant_id=_opt_uuid(row["tenant_id"]),
        target_type=row["target_type"],
        target_id=_opt_uuid(row["target_id"]),
        session_id=_opt_uuid(row["session_id"]),
        token_jti=_opt_uuid(row["token_jti"]),
        reason=row["reason"],
        metadata=dict(row["metadata"]),
        occurred_at=cast(datetime, _utc(row["occurred_at"])),
    )


class _AuditEvents:
    def __init__(self, storage: SqlAlchemyStorage, table: Table) -> None:
        self.storage: SqlAlchemyStorage = storage
        self.table: Table = table

    async def append(self, event: AuditEvent, /) -> None:
        async with self.storage._session() as db:
            await db.execute(
                insert(self.table).values(
                    id=str(event.id),
                    action=event.action,
                    outcome=event.outcome,
                    actor_type=event.actor_type,
                    actor_id=_opt_str(event.actor_id),
                    impersonator_id=_opt_str(event.impersonator_id),
                    tenant_id=_opt_str(event.tenant_id),
                    target_type=event.target_type,
                    target_id=_opt_str(event.target_id),
                    session_id=_opt_str(event.session_id),
                    token_jti=_opt_str(event.token_jti),
                    reason=event.reason,
                    metadata=dict(event.metadata),
                    occurred_at=event.occurred_at,
                )
            )

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
        t = self.table
        conditions: list[Any] = []
        if tenant_ids is not None:
            conditions.append(t.c.tenant_id.in_([str(i) for i in tenant_ids]))
        if actor_id is not None:
            conditions.append(t.c.actor_id == str(actor_id))
        if target_id is not None:
            conditions.append(t.c.target_id == str(target_id))
        if action is not None:
            if action.endswith(".*"):
                conditions.append(t.c.action.startswith(action[:-1], autoescape=True))
            else:
                conditions.append(t.c.action == action)
        if since is not None:
            conditions.append(t.c.occurred_at >= since)
        if until is not None:
            conditions.append(t.c.occurred_at <= until)
        stmt = (
            select(t)
            .where(*conditions)
            .order_by(t.c.occurred_at.desc(), t.c.id.desc())
            .limit(limit)
            .offset(offset)
        )
        async with self.storage._session() as db:
            rows = (await db.execute(stmt)).mappings().all()
            return [_audit_model(row) for row in rows]

    async def purge(self, *, before: datetime) -> int:
        async with self.storage._session() as db:
            result = await db.execute(delete(self.table).where(self.table.c.occurred_at < before))
            return cast("CursorResult[Any]", result).rowcount


class SqlAlchemyStorage:
    def __init__(
        self, *, session_factory: async_sessionmaker[AsyncSession], table_prefix: str = "mt_"
    ) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table_prefix):
            raise ValueError("Invalid table prefix")
        self.session_factory = session_factory
        self._admin_table_name = table_prefix + "admins"
        self.metadata = metadata if table_prefix == "mt_" else MetaData()
        tables = _default_tables if table_prefix == "mt_" else _tables(self.metadata, table_prefix)
        self.tenants: TenantRepository = _Repository(self, tables["tenants"], Tenant)
        self.admins: AdminRepository = _Repository(self, tables["admins"], Admin)
        self.tenant_users: TenantUserRepository = _Repository(
            self, tables["tenant_users"], TenantUser
        )
        self.login_attempts: LoginAttemptRepository = _Attempts(self, tables["login_attempts"])
        self.sessions: SessionRepository = _Sessions(self, tables["sessions"])
        self.audit_events: AuditEventRepository = _AuditEvents(self, tables["audit_events"])
        self._current: ContextVar[tuple[asyncio.Task[Any] | None, AsyncSession] | None] = (
            ContextVar("tenantkit_sql_transaction", default=None)
        )

    def _active(self) -> AsyncSession | None:
        current = self._current.get()
        return current[1] if current is not None and current[0] is asyncio.current_task() else None

    def in_transaction(self) -> bool:
        return self._active() is not None

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        try:
            active = self._active()
            if active is not None:
                yield active
            else:
                async with self.session_factory() as session, session.begin():
                    yield session
        except IntegrityError:
            raise AlreadyExistsError("A storage constraint was violated") from None
        except SQLAlchemyError:
            raise StorageError("Database operation failed") from None

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        if self._active() is not None:
            yield
            return
        try:
            async with self.session_factory() as session, session.begin():
                dialect = session.get_bind().dialect
                # Serialize read/check/write invariants, including an empty admin
                # table at bootstrap, across adapter instances and processes.
                if dialect.name == "postgresql":
                    table_name = dialect.identifier_preparer.quote(self._admin_table_name)
                    await session.execute(text(f"LOCK TABLE {table_name} IN EXCLUSIVE MODE"))
                elif dialect.name == "sqlite":
                    await session.execute(text("BEGIN IMMEDIATE"))
                token = self._current.set((asyncio.current_task(), session))
                try:
                    yield
                finally:
                    self._current.reset(token)
        except IntegrityError:
            raise AlreadyExistsError("A storage constraint was violated") from None
        except SQLAlchemyError:
            raise StorageError("Database operation failed") from None

    async def health_check(self) -> None:
        try:
            async with self._session() as session:
                await session.execute(text("SELECT 1"))
        except StorageError:
            raise StorageUnavailableError("Storage unavailable") from None
