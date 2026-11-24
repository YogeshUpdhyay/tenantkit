"""MongoDB adapter built on Beanie 2.x (PyMongo async). The host owns ``init_beanie``."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any

from bson.binary import UuidRepresentation
from pymongo.asynchronous.client_session import AsyncClientSession
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError, PyMongoError

from tenantkit.domain.errors import (
    AlreadyExistsError,
    ConfigError,
    StorageError,
    StorageUnavailableError,
)
from tenantkit.storage.beanie.documents import BeanieModels, document_models
from tenantkit.storage.beanie.repositories import (
    _Admins,
    _AuditEvents,
    _LoginAttempts,
    _Sessions,
    _Tenants,
    _TenantUsers,
)
from tenantkit.storage.interfaces import (
    AdminRepository,
    AuditEventRepository,
    LoginAttemptRepository,
    SessionRepository,
    TenantRepository,
    TenantUserRepository,
)

__all__ = ["BeanieModels", "BeanieStorage", "document_models"]

log = logging.getLogger("tenantkit.storage.beanie")


class BeanieStorage:
    def __init__(
        self,
        *,
        database: AsyncDatabase[Any],
        models: BeanieModels,
        transactions: bool = True,
    ) -> None:
        self.database = database
        self.models = models
        self.transactions = transactions
        if not transactions:
            log.warning(
                "BeanieStorage transactions are disabled: multi-step operations are not atomic "
                "and audit writes are no longer fail-closed (a change can persist without its "
                "audit event)."
            )
        self._current: ContextVar[tuple[asyncio.Task[Any] | None, AsyncClientSession | None] | None]
        self._current = ContextVar("tenantkit_beanie_transaction", default=None)
        self.admins: AdminRepository = _Admins(self, "admins")
        self.tenants: TenantRepository = _Tenants(self, "tenants")
        self.tenant_users: TenantUserRepository = _TenantUsers(self, "tenant_users")
        self.login_attempts: LoginAttemptRepository = _LoginAttempts(self, "login_attempts")
        self.sessions: SessionRepository = _Sessions(self, "sessions")
        self.audit_events: AuditEventRepository = _AuditEvents(self, "audit_events")

    def _entry(self) -> tuple[asyncio.Task[Any] | None, AsyncClientSession | None] | None:
        current = self._current.get()
        return current if current is not None and current[0] is asyncio.current_task() else None

    def _session(self) -> AsyncClientSession | None:
        entry = self._entry()
        return entry[1] if entry is not None else None

    def in_transaction(self) -> bool:
        return self._entry() is not None

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        if self._entry() is not None:
            yield
            return
        task = asyncio.current_task()
        try:
            if not self.transactions:
                token = self._current.set((task, None))
                try:
                    yield
                finally:
                    self._current.reset(token)
                return
            async with self.database.client.start_session() as session:
                async with await session.start_transaction():
                    token = self._current.set((task, session))
                    try:
                        yield
                    finally:
                        self._current.reset(token)
        except DuplicateKeyError as exc:
            raise AlreadyExistsError("A storage constraint was violated") from exc
        except PyMongoError as exc:
            raise StorageError("Database operation failed") from exc

    async def health_check(self) -> None:
        if self.database.codec_options.uuid_representation != UuidRepresentation.STANDARD:
            raise ConfigError(
                'The MongoDB client must be created with uuidRepresentation="standard"'
            )
        for model in self.models.all:
            try:
                collection = model.get_pymongo_collection()
            except Exception:
                raise ConfigError(
                    "Beanie models are not initialised: pass document_models(...).all to "
                    "init_beanie"
                ) from None
            if collection.database != self.database:
                raise ConfigError("Beanie models were initialised against a different database")
        try:
            await self.database.command("ping")
            if self.transactions:
                hello = await self.database.command("hello")
                if not (hello.get("setName") or hello.get("msg") == "isdbgrid"):
                    raise StorageUnavailableError(
                        "MongoDB transactions require a replica set or mongos; "
                        "see docs/12-mongo-storage.md"
                    )
        except PyMongoError:
            raise StorageUnavailableError("Storage unavailable") from None
