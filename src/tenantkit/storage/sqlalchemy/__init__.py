"""SQLAlchemy 2 async adapter using host-owned sessions and metadata."""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Generic, Literal, TypeVar, cast
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    delete,
    case,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tenantkit.domain.errors import (
    AlreadyExistsError,
    NotFoundError,
    StorageError,
    StorageUnavailableError,
)
from tenantkit.domain.models import Admin, ImpersonationScope, LoginAttempt, Tenant, TenantUser
from tenantkit.storage.interfaces import (
    AdminRepository,
    LoginAttemptRepository,
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
    return {"tenants": tenants, "admins": admins, "tenant_users": users, "login_attempts": attempts}


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
        self.storage, self.table, self.cls = storage, table, cls

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
            if result.rowcount == 0:
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
                if dialect == "sqlite":
                    from sqlalchemy.dialects.sqlite import insert as upsert
                else:
                    from sqlalchemy.dialects.postgresql import insert as upsert
                stmt = upsert(self.table).values(
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
        self._current: ContextVar[tuple[asyncio.Task[Any] | None, AsyncSession] | None] = (
            ContextVar("tenantkit_sql_transaction", default=None)
        )

    def _active(self) -> AsyncSession | None:
        current = self._current.get()
        return current[1] if current is not None and current[0] is asyncio.current_task() else None

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
