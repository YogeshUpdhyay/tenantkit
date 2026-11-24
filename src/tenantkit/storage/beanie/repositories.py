"""Repositories over Beanie-initialised collections; documents never leave this package."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.asynchronous.client_session import AsyncClientSession
from pymongo.errors import DuplicateKeyError, PyMongoError

from tenantkit.domain.errors import AlreadyExistsError, NotFoundError, StorageError
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

if TYPE_CHECKING:
    from pymongo.asynchronous.collection import AsyncCollection

    from tenantkit.storage.beanie import BeanieStorage

_ATTEMPT_NAMESPACE = uuid5(NAMESPACE_URL, "tenantkit/login_attempts")


def _ms(value: datetime | None) -> datetime | None:
    """BSON stores milliseconds; normalise to aware UTC at that precision."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.replace(microsecond=value.microsecond // 1000 * 1000)


def _req(value: datetime | None) -> datetime:
    result = _ms(value)
    assert result is not None
    return result


def _opt_uuid(value: Any) -> UUID | None:
    return None if value is None else cast(UUID, value)


@asynccontextmanager
async def _guard() -> AsyncIterator[None]:
    try:
        yield
    except DuplicateKeyError as exc:
        raise AlreadyExistsError("A storage constraint was violated") from exc
    except PyMongoError as exc:
        raise StorageError("Database operation failed") from exc


class _Base:
    def __init__(self, storage: BeanieStorage, collection: str) -> None:
        self.storage = storage
        self._collection = collection

    @property
    def coll(self) -> AsyncCollection[dict[str, Any]]:
        return cast(
            "AsyncCollection[dict[str, Any]]",
            getattr(self.storage.models, self._collection).get_pymongo_collection(),
        )

    @property
    def sess(self) -> AsyncClientSession | None:
        return self.storage._session()

    async def _page(
        self,
        query: dict[str, Any],
        sort: list[tuple[str, int]],
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        if limit < 0 or offset < 0:
            raise ValueError("Pagination values cannot be negative")
        if limit == 0:
            return []
        async with _guard():
            cursor = self.coll.find(query, session=self.sess).sort(sort).skip(offset).limit(limit)
            return [row async for row in cursor]


# -- row mappers --------------------------------------------------------------------------


def _admin_raw(admin: Admin) -> dict[str, Any]:
    return {
        "_id": admin.id,
        "email": admin.email,
        "password_hash": admin.password_hash,
        "roles": list(admin.roles),
        "impersonation_mode": admin.impersonation_scope.mode,
        "impersonation_tenants": list(admin.impersonation_scope.tenant_ids),
        "is_active": admin.is_active,
        "created_at": _req(admin.created_at),
        "updated_at": _req(admin.updated_at),
    }


def _admin(raw: dict[str, Any]) -> Admin:
    return Admin(
        id=raw["_id"],
        email=raw["email"],
        password_hash=raw["password_hash"],
        roles=list(raw["roles"]),
        impersonation_scope=ImpersonationScope(
            mode=raw["impersonation_mode"], tenant_ids=list(raw["impersonation_tenants"])
        ),
        is_active=raw["is_active"],
        created_at=_req(raw["created_at"]),
        updated_at=_req(raw["updated_at"]),
    )


def _tenant_raw(tenant: Tenant) -> dict[str, Any]:
    policy = tenant.login_policy
    if hasattr(policy, "model_dump"):
        policy = policy.model_dump(mode="json")
    return {
        "_id": tenant.id,
        "slug": tenant.slug,
        "attributes": tenant.attributes,
        "login_policy": policy,
        "is_active": tenant.is_active,
        "created_at": _req(tenant.created_at),
        "updated_at": _req(tenant.updated_at),
    }


def _tenant(raw: dict[str, Any]) -> Tenant:
    policy = raw.get("login_policy")
    if policy is not None:
        from tenantkit.config.models import LoginPolicy

        policy = LoginPolicy.model_validate(policy)
    return Tenant(
        id=raw["_id"],
        slug=raw["slug"],
        attributes=dict(raw["attributes"]),
        login_policy=policy,
        is_active=raw["is_active"],
        created_at=_req(raw["created_at"]),
        updated_at=_req(raw["updated_at"]),
    )


def _user_raw(user: TenantUser) -> dict[str, Any]:
    return {
        "_id": user.id,
        "tenant_id": user.tenant_id,
        "email": user.email,
        "password_hash": user.password_hash,
        "roles": list(user.roles),
        "is_active": user.is_active,
        "created_at": _req(user.created_at),
        "updated_at": _req(user.updated_at),
    }


def _user(raw: dict[str, Any]) -> TenantUser:
    return TenantUser(
        id=raw["_id"],
        tenant_id=raw["tenant_id"],
        email=raw["email"],
        password_hash=raw["password_hash"],
        roles=list(raw["roles"]),
        is_active=raw["is_active"],
        created_at=_req(raw["created_at"]),
        updated_at=_req(raw["updated_at"]),
    )


def _session_raw(session: Session) -> dict[str, Any]:
    return {
        "_id": session.id,
        "kind": session.kind,
        "subject_id": session.subject_id,
        "tenant_id": session.tenant_id,
        "parent_id": session.parent_id,
        "current_jti": session.current_jti,
        "expires_at": _req(session.expires_at),
        "created_at": _req(session.created_at),
        "last_used_at": _req(session.last_used_at),
        "revoked_at": _ms(session.revoked_at),
        "revoked_reason": session.revoked_reason,
    }


def _session(raw: dict[str, Any]) -> Session:
    return Session(
        id=raw["_id"],
        kind=raw["kind"],
        subject_id=raw["subject_id"],
        tenant_id=_opt_uuid(raw.get("tenant_id")),
        parent_id=_opt_uuid(raw.get("parent_id")),
        current_jti=raw["current_jti"],
        expires_at=_req(raw["expires_at"]),
        created_at=_req(raw["created_at"]),
        last_used_at=_req(raw["last_used_at"]),
        revoked_at=_ms(raw.get("revoked_at")),
        revoked_reason=raw.get("revoked_reason"),
    )


def _event_raw(event: AuditEvent) -> dict[str, Any]:
    return {
        "_id": event.id,
        "action": event.action,
        "outcome": event.outcome,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "impersonator_id": event.impersonator_id,
        "tenant_id": event.tenant_id,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "session_id": event.session_id,
        "token_jti": event.token_jti,
        "reason": event.reason,
        "metadata": dict(event.metadata),
        "occurred_at": _req(event.occurred_at),
    }


def _event(raw: dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        id=raw["_id"],
        action=raw["action"],
        outcome=raw["outcome"],
        actor_type=raw["actor_type"],
        actor_id=_opt_uuid(raw.get("actor_id")),
        impersonator_id=_opt_uuid(raw.get("impersonator_id")),
        tenant_id=_opt_uuid(raw.get("tenant_id")),
        target_type=raw.get("target_type"),
        target_id=_opt_uuid(raw.get("target_id")),
        session_id=_opt_uuid(raw.get("session_id")),
        token_jti=_opt_uuid(raw.get("token_jti")),
        reason=raw.get("reason"),
        metadata=dict(raw.get("metadata") or {}),
        occurred_at=_req(raw["occurred_at"]),
    )


# -- entity repositories ------------------------------------------------------------------


class _Entities(_Base):
    """Shared create/get/update for admins, tenants and tenant users."""

    def _raw(self, value: Any) -> dict[str, Any]:
        raise NotImplementedError

    def _from(self, raw: dict[str, Any]) -> Any:
        raise NotImplementedError

    async def _create(self, value: Any) -> Any:
        raw = self._raw(value)
        async with _guard():
            await self.coll.insert_one(dict(raw), session=self.sess)
        return self._from(raw)

    async def _get(self, query: dict[str, Any]) -> Any:
        async with _guard():
            raw = await self.coll.find_one(query, session=self.sess)
        return self._from(raw) if raw is not None else None

    async def _update(self, value: Any) -> Any:
        raw = self._raw(value)
        async with _guard():
            result = await self.coll.replace_one({"_id": raw["_id"]}, dict(raw), session=self.sess)
        if result.matched_count == 0:
            raise NotFoundError("Record does not exist")
        return self._from(raw)

    async def _list(
        self, query: dict[str, Any], active: bool | None, limit: int, offset: int
    ) -> list[Any]:
        if active is not None:
            query = {**query, "is_active": active}
        rows = await self._page(
            query, [("created_at", ASCENDING), ("_id", ASCENDING)], limit, offset
        )
        return [self._from(row) for row in rows]


class _Admins(_Entities):
    def _raw(self, value: Any) -> dict[str, Any]:
        return _admin_raw(value)

    def _from(self, raw: dict[str, Any]) -> Admin:
        return _admin(raw)

    async def create(self, admin: Admin, /) -> Admin:
        return cast(Admin, await self._create(admin))

    async def get(self, admin_id: UUID, /) -> Admin | None:
        return cast("Admin | None", await self._get({"_id": admin_id}))

    async def get_by_email(self, email: str) -> Admin | None:
        return cast("Admin | None", await self._get({"email": email}))

    async def list(
        self, *, active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[Admin]:
        return cast("list[Admin]", await self._list({}, active, limit, offset))

    async def update(self, admin: Admin, /) -> Admin:
        return cast(Admin, await self._update(admin))


class _Tenants(_Entities):
    def _raw(self, value: Any) -> dict[str, Any]:
        return _tenant_raw(value)

    def _from(self, raw: dict[str, Any]) -> Tenant:
        return _tenant(raw)

    async def create(self, tenant: Tenant, /) -> Tenant:
        return cast(Tenant, await self._create(tenant))

    async def get(self, tenant_id: UUID, /) -> Tenant | None:
        return cast("Tenant | None", await self._get({"_id": tenant_id}))

    async def get_by_slug(self, slug: str) -> Tenant | None:
        return cast("Tenant | None", await self._get({"slug": slug}))

    async def list(
        self, *, active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[Tenant]:
        return cast("list[Tenant]", await self._list({}, active, limit, offset))

    async def update(self, tenant: Tenant, /) -> Tenant:
        return cast(Tenant, await self._update(tenant))


class _TenantUsers(_Entities):
    def _raw(self, value: Any) -> dict[str, Any]:
        return _user_raw(value)

    def _from(self, raw: dict[str, Any]) -> TenantUser:
        return _user(raw)

    async def create(self, user: TenantUser, /) -> TenantUser:
        # MongoDB has no foreign keys: check inside the caller's transaction.
        async with _guard():
            tenant = await self.storage.models.tenants.get_pymongo_collection().find_one(
                {"_id": user.tenant_id}, {"_id": 1}, session=self.sess
            )
        if tenant is None:
            raise StorageError("Tenant does not exist")
        return cast(TenantUser, await self._create(user))

    async def get(self, user_id: UUID, /) -> TenantUser | None:
        return cast("TenantUser | None", await self._get({"_id": user_id}))

    async def get_by_email(self, email: str) -> TenantUser | None:
        return cast("TenantUser | None", await self._get({"email": email}))

    async def list(
        self, tenant_id: UUID, *, active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[TenantUser]:
        return cast(
            "list[TenantUser]", await self._list({"tenant_id": tenant_id}, active, limit, offset)
        )

    async def update(self, user: TenantUser, /) -> TenantUser:
        return cast(TenantUser, await self._update(user))


def _attempt_id(subject_type: str, subject_id: UUID) -> UUID:
    return uuid5(_ATTEMPT_NAMESPACE, f"{subject_type}:{subject_id}")


def _attempt(raw: dict[str, Any]) -> LoginAttempt:
    return LoginAttempt(
        subject_type=raw["subject_type"],
        subject_id=raw["subject_id"],
        failed_count=raw["failed_count"],
        locked_until=_ms(raw.get("locked_until")),
    )


class _LoginAttempts(_Base):
    async def get(self, subject_type: str, subject_id: UUID) -> LoginAttempt | None:
        async with _guard():
            raw = await self.coll.find_one(
                {"_id": _attempt_id(subject_type, subject_id)}, session=self.sess
            )
        return _attempt(raw) if raw is not None else None

    async def record_failure(
        self, subject_type: str, subject_id: UUID, *, max_attempts: int, locked_until: datetime
    ) -> LoginAttempt:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        until = _req(locked_until)
        # One server-side pipeline update: increment, keep an existing lock, lock on threshold.
        pipeline: list[dict[str, Any]] = [
            {
                "$set": {
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "failed_count": {"$add": [{"$ifNull": ["$failed_count", 0]}, 1]},
                }
            },
            {
                "$set": {
                    "locked_until": {
                        "$cond": [
                            {"$ne": [{"$ifNull": ["$locked_until", None]}, None]},
                            "$locked_until",
                            {"$cond": [{"$gte": ["$failed_count", max_attempts]}, until, None]},
                        ]
                    }
                }
            },
        ]
        async with _guard():
            raw = await self.coll.find_one_and_update(
                {"_id": _attempt_id(subject_type, subject_id)},
                pipeline,
                upsert=True,
                return_document=ReturnDocument.AFTER,
                session=self.sess,
            )
        assert raw is not None
        return _attempt(raw)

    async def reset(self, subject_type: str, subject_id: UUID) -> None:
        async with _guard():
            await self.coll.delete_one(
                {"_id": _attempt_id(subject_type, subject_id)}, session=self.sess
            )


class _Sessions(_Base):
    async def create(self, session: Session, /) -> Session:
        raw = _session_raw(session)
        async with _guard():
            await self.coll.insert_one(dict(raw), session=self.sess)
        return _session(raw)

    async def get(self, session_id: UUID, /) -> Session | None:
        async with _guard():
            raw = await self.coll.find_one({"_id": session_id}, session=self.sess)
        return _session(raw) if raw is not None else None

    async def rotate(
        self,
        session_id: UUID,
        *,
        expected_jti: UUID,
        new_jti: UUID,
        expires_at: datetime,
        used_at: datetime,
    ) -> Session | None:
        async with _guard():
            raw = await self.coll.find_one_and_update(
                {"_id": session_id, "revoked_at": None, "current_jti": expected_jti},
                {
                    "$set": {
                        "current_jti": new_jti,
                        "expires_at": _req(expires_at),
                        "last_used_at": _req(used_at),
                    }
                },
                return_document=ReturnDocument.AFTER,
                session=self.sess,
            )
        return _session(raw) if raw is not None else None

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
        match: dict[str, Any] = {}
        if session_id is not None:
            match["_id"] = session_id
        if kind is not None:
            match["kind"] = kind
        if subject_id is not None:
            match["subject_id"] = subject_id
        if tenant_id is not None:
            match["tenant_id"] = tenant_id
        if not match:
            raise ValueError("At least one revoke filter is required")
        revoked_at = _req(at)
        async with _guard():
            parents: list[UUID] = []
            if cascade_children:
                cursor = self.coll.find(match, {"_id": 1}, session=self.sess)
                parents = [row["_id"] async for row in cursor]
            result = await self.coll.update_many(
                {**match, "revoked_at": None},
                {"$set": {"revoked_at": revoked_at, "revoked_reason": reason}},
                session=self.sess,
            )
            count = result.modified_count
            if parents:
                children = await self.coll.update_many(
                    {"parent_id": {"$in": parents}, "revoked_at": None},
                    {
                        "$set": {
                            "revoked_at": revoked_at,
                            "revoked_reason": RevokeReason.PARENT_REVOKED,
                        }
                    },
                    session=self.sess,
                )
                count += children.modified_count
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
        query: dict[str, Any] = {"kind": kind, "subject_id": subject_id}
        if active_only:
            query["revoked_at"] = None
            query["expires_at"] = {"$gt": _req(datetime.now(timezone.utc))}
        rows = await self._page(
            query, [("created_at", DESCENDING), ("_id", DESCENDING)], limit, offset
        )
        return [_session(row) for row in rows]

    async def purge_expired(self, *, before: datetime) -> int:
        cutoff = _req(before)
        async with _guard():
            result = await self.coll.delete_many(
                {"$or": [{"expires_at": {"$lt": cutoff}}, {"revoked_at": {"$lt": cutoff}}]},
                session=self.sess,
            )
        return result.deleted_count


class _AuditEvents(_Base):
    async def append(self, event: AuditEvent, /) -> None:
        async with _guard():
            await self.coll.insert_one(_event_raw(event), session=self.sess)

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
        if tenant_ids is not None and not tenant_ids:
            if limit < 0 or offset < 0:
                raise ValueError("Pagination values cannot be negative")
            return []
        query: dict[str, Any] = {}
        if tenant_ids is not None:
            query["tenant_id"] = {"$in": list(tenant_ids)}
        if actor_id is not None:
            query["actor_id"] = actor_id
        if target_id is not None:
            query["target_id"] = target_id
        if action is not None:
            if action.endswith(".*"):
                query["action"] = {"$regex": "^" + re.escape(action[:-1])}
            else:
                query["action"] = action
        window: dict[str, Any] = {}
        if since is not None:
            window["$gte"] = _req(since)
        if until is not None:
            window["$lte"] = _req(until)
        if window:
            query["occurred_at"] = window
        rows = await self._page(
            query, [("occurred_at", DESCENDING), ("_id", DESCENDING)], limit, offset
        )
        return [_event(row) for row in rows]

    async def purge(self, *, before: datetime) -> int:
        async with _guard():
            result = await self.coll.delete_many(
                {"occurred_at": {"$lt": _req(before)}}, session=self.sess
            )
        return result.deleted_count
