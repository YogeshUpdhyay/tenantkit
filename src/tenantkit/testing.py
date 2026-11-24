"""Reusable adapter contract: subclass and implement ``make_storage``."""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import replace
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest

from tenantkit.domain.errors import AlreadyExistsError
from tenantkit.domain.models import Admin, AuditEvent, RevokeReason, Session, Tenant, TenantUser
from tenantkit.storage.interfaces import Storage


def _make_session(**overrides: Any) -> Session:
    values: dict[str, Any] = {
        "kind": "admin",
        "subject_id": uuid4(),
        "current_jti": uuid4(),
        "expires_at": _T0 + timedelta(days=1),
        "created_at": _T0,
        "last_used_at": _T0,
    }
    values.update(overrides)
    return Session(**values)


def _make_event(**overrides: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "action": "tenant.created",
        "outcome": "success",
        "actor_type": "admin",
        "occurred_at": _T0,
    }
    values.update(overrides)
    return AuditEvent(**values)


_T0 = datetime(2030, 1, 1, tzinfo=timezone.utc)


class StorageContract:
    async def make_storage(self) -> Storage:
        raise NotImplementedError

    async def close_storage(self, storage: Storage) -> None:
        """Override to release adapter resources after each contract test."""

    @asynccontextmanager
    async def storage(self) -> AsyncIterator[Storage]:
        storage = await self.make_storage()
        try:
            yield storage
        finally:
            await self.close_storage(storage)

    @pytest.mark.asyncio
    async def test_tenant_lifecycle(self) -> None:
        async with self.storage() as storage:
            tenant = await storage.tenants.create(
                Tenant(slug="acme", attributes={"nested": {"count": 3}})
            )
            loaded = await storage.tenants.get_by_slug("acme")
            assert loaded == tenant
            assert loaded is not None
            loaded.attributes["nested"]["count"] = 9
            persisted = await storage.tenants.get(tenant.id)
            assert persisted is not None and persisted.attributes == {"nested": {"count": 3}}
            await storage.tenants.update(replace(tenant, is_active=False))
            assert await storage.tenants.list(active=True) == []
            assert len(await storage.tenants.list(active=False)) == 1
            with pytest.raises(AlreadyExistsError):
                await storage.tenants.create(Tenant(slug="acme"))

    @pytest.mark.asyncio
    async def test_admin_and_user_lifecycle(self) -> None:
        async with self.storage() as storage:
            tenant = await storage.tenants.create(Tenant(slug="acme"))
            admin = await storage.admins.create(
                Admin(email="admin@example.com", password_hash="hash")
            )
            assert await storage.admins.get_by_email(admin.email) == admin
            await storage.admins.update(replace(admin, is_active=False))
            assert await storage.admins.list(active=True) == []
            with pytest.raises(AlreadyExistsError):
                await storage.admins.create(Admin(email=admin.email, password_hash="hash"))
            user = await storage.tenant_users.create(
                TenantUser(tenant_id=tenant.id, email="user@example.com", password_hash="hash")
            )
            assert await storage.tenant_users.get_by_email(user.email) == user
            await storage.tenant_users.update(replace(user, is_active=False))
            assert await storage.tenant_users.list(tenant.id, active=True) == []

    @pytest.mark.asyncio
    async def test_transaction_rollback(self) -> None:
        async with self.storage() as storage:
            with pytest.raises(RuntimeError):
                async with storage.transaction():
                    await storage.tenants.create(Tenant(slug="rollback"))
                    raise RuntimeError("abort")
            assert await storage.tenants.get_by_slug("rollback") is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("subject_type", ["admin", "tenant_user"])
    @pytest.mark.parametrize("max_attempts", [1, 5])
    async def test_concurrent_failures_lock_atomically(
        self, subject_type: str, max_attempts: int
    ) -> None:
        async with self.storage() as storage:
            identity = uuid4()
            # Millisecond precision: BSON-backed adapters cannot store microseconds.
            until = (datetime.now(timezone.utc) + timedelta(minutes=15)).replace(microsecond=0)
            rows = await asyncio.gather(
                *[
                    storage.login_attempts.record_failure(
                        subject_type, identity, max_attempts=max_attempts, locked_until=until
                    )
                    for _ in range(12)
                ]
            )
            attempt = await storage.login_attempts.get(subject_type, identity)
            assert attempt is not None
            assert attempt.failed_count == 12
            assert attempt.locked_until == until
            assert sum(row.locked_until is not None for row in rows) == 13 - max_attempts
            # A stale caller with a higher threshold cannot clear an existing lock.
            later = await storage.login_attempts.record_failure(
                subject_type, identity, max_attempts=100, locked_until=until
            )
            assert later.failed_count == 13
            assert later.locked_until == until

    # -- sessions -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_session_create_get_list_ordering(self) -> None:
        async with self.storage() as storage:
            subject = uuid4()
            tenant_id = uuid4()
            first = await storage.sessions.create(
                _make_session(subject_id=subject, created_at=_T0, tenant_id=tenant_id)
            )
            second = await storage.sessions.create(
                _make_session(subject_id=subject, created_at=_T0 + timedelta(seconds=5))
            )
            await storage.sessions.create(_make_session(kind="tenant", subject_id=subject))
            await storage.sessions.create(_make_session())
            loaded = await storage.sessions.get(first.id)
            assert loaded == first
            assert loaded is not None and loaded.tenant_id == tenant_id
            assert loaded.expires_at.tzinfo is not None
            assert await storage.sessions.get(uuid4()) is None
            listed = await storage.sessions.list(kind="admin", subject_id=subject)
            assert [s.id for s in listed] == [second.id, first.id]
            page = await storage.sessions.list(kind="admin", subject_id=subject, limit=1, offset=1)
            assert [s.id for s in page] == [first.id]
            with pytest.raises(AlreadyExistsError):
                await storage.sessions.create(first)

    @pytest.mark.asyncio
    async def test_session_list_active_only(self) -> None:
        async with self.storage() as storage:
            subject = uuid4()
            live = await storage.sessions.create(_make_session(subject_id=subject))
            revoked = await storage.sessions.create(_make_session(subject_id=subject))
            expired = await storage.sessions.create(
                _make_session(
                    subject_id=subject, expires_at=datetime(2001, 1, 1, tzinfo=timezone.utc)
                )
            )
            await storage.sessions.revoke(reason="logout", at=_T0, session_id=revoked.id)
            active = await storage.sessions.list(kind="admin", subject_id=subject)
            assert [s.id for s in active] == [live.id]
            everything = await storage.sessions.list(
                kind="admin", subject_id=subject, active_only=False
            )
            assert {s.id for s in everything} == {live.id, revoked.id, expired.id}

    @pytest.mark.asyncio
    async def test_session_rotate_compare_and_set(self) -> None:
        async with self.storage() as storage:
            session = await storage.sessions.create(_make_session())
            new_jti, expiry, used = uuid4(), _T0 + timedelta(days=2), _T0 + timedelta(hours=1)
            assert (
                await storage.sessions.rotate(
                    session.id,
                    expected_jti=uuid4(),
                    new_jti=new_jti,
                    expires_at=expiry,
                    used_at=used,
                )
                is None
            )
            rotated = await storage.sessions.rotate(
                session.id,
                expected_jti=session.current_jti,
                new_jti=new_jti,
                expires_at=expiry,
                used_at=used,
            )
            assert rotated is not None
            assert (rotated.current_jti, rotated.expires_at, rotated.last_used_at) == (
                new_jti,
                expiry,
                used,
            )
            assert rotated.id == session.id and rotated.created_at == session.created_at
            # The old jti is now stale.
            assert (
                await storage.sessions.rotate(
                    session.id,
                    expected_jti=session.current_jti,
                    new_jti=uuid4(),
                    expires_at=expiry,
                    used_at=used,
                )
                is None
            )
            assert (
                await storage.sessions.rotate(
                    uuid4(), expected_jti=new_jti, new_jti=uuid4(), expires_at=expiry, used_at=used
                )
                is None
            )
            await storage.sessions.revoke(reason="logout", at=_T0, session_id=session.id)
            assert (
                await storage.sessions.rotate(
                    session.id,
                    expected_jti=new_jti,
                    new_jti=uuid4(),
                    expires_at=expiry,
                    used_at=used,
                )
                is None
            )

    @pytest.mark.asyncio
    async def test_session_rotate_concurrent_has_one_winner(self) -> None:
        async with self.storage() as storage:
            session = await storage.sessions.create(_make_session())
            results = await asyncio.gather(
                *[
                    storage.sessions.rotate(
                        session.id,
                        expected_jti=session.current_jti,
                        new_jti=uuid4(),
                        expires_at=_T0 + timedelta(days=2),
                        used_at=_T0,
                    )
                    for _ in range(12)
                ]
            )
            assert sum(result is not None for result in results) == 1

    @pytest.mark.asyncio
    async def test_session_revoke_filters_and_idempotency(self) -> None:
        async with self.storage() as storage:
            subject, tenant_a, tenant_b = uuid4(), uuid4(), uuid4()
            a1 = await storage.sessions.create(
                _make_session(kind="tenant", subject_id=subject, tenant_id=tenant_a)
            )
            a2 = await storage.sessions.create(
                _make_session(kind="tenant", subject_id=uuid4(), tenant_id=tenant_a)
            )
            b1 = await storage.sessions.create(
                _make_session(kind="tenant", subject_id=uuid4(), tenant_id=tenant_b)
            )
            admin = await storage.sessions.create(_make_session(subject_id=subject))
            with pytest.raises(ValueError):
                await storage.sessions.revoke(reason="x", at=_T0)
            # Filters combine with AND.
            assert (
                await storage.sessions.revoke(
                    reason="logout", at=_T0, kind="tenant", subject_id=subject
                )
                == 1
            )
            assert (
                await storage.sessions.revoke(
                    reason="admin_revoked", at=_T0, kind="admin", tenant_id=tenant_a
                )
                == 0
            )
            # Already-revoked rows are skipped and keep their reason.
            assert (
                await storage.sessions.revoke(reason="admin_revoked", at=_T0, tenant_id=tenant_a)
                == 1
            )
            first = await storage.sessions.get(a1.id)
            assert first is not None and first.revoked_reason == "logout"
            assert first.revoked_at == _T0
            second = await storage.sessions.get(a2.id)
            assert second is not None and second.revoked_reason == "admin_revoked"
            other = await storage.sessions.get(b1.id)
            assert other is not None and other.revoked_at is None
            assert await storage.sessions.revoke(reason="logout", at=_T0, session_id=admin.id) == 1
            assert await storage.sessions.revoke(reason="logout", at=_T0, session_id=admin.id) == 0
            assert await storage.sessions.revoke(reason="logout", at=_T0, session_id=uuid4()) == 0

    @pytest.mark.asyncio
    async def test_session_revoke_cascades_to_children(self) -> None:
        async with self.storage() as storage:
            admin_id, tenant_id = uuid4(), uuid4()
            parent = await storage.sessions.create(_make_session(subject_id=admin_id))
            child_a = await storage.sessions.create(
                _make_session(
                    kind="impersonation",
                    subject_id=admin_id,
                    tenant_id=tenant_id,
                    parent_id=parent.id,
                )
            )
            child_b = await storage.sessions.create(
                _make_session(
                    kind="impersonation",
                    subject_id=admin_id,
                    tenant_id=uuid4(),
                    parent_id=parent.id,
                )
            )
            unrelated = await storage.sessions.create(_make_session())
            # Without cascade only the matched session changes.
            assert (
                await storage.sessions.revoke(reason="logout", at=_T0, session_id=child_b.id) == 1
            )
            assert (
                await storage.sessions.revoke(
                    reason="logout_all", at=_T0, session_id=parent.id, cascade_children=True
                )
                == 2
            )
            for child, reason in ((child_a, "parent_revoked"), (child_b, "logout")):
                loaded = await storage.sessions.get(child.id)
                assert loaded is not None and loaded.revoked_reason == reason
            loaded_parent = await storage.sessions.get(parent.id)
            assert loaded_parent is not None and loaded_parent.revoked_reason == "logout_all"
            untouched = await storage.sessions.get(unrelated.id)
            assert untouched is not None and untouched.revoked_at is None
            # Cascading from an already revoked parent still catches live children.
            late = await storage.sessions.create(
                _make_session(kind="impersonation", subject_id=admin_id, parent_id=parent.id)
            )
            assert (
                await storage.sessions.revoke(
                    reason="logout", at=_T0, session_id=parent.id, cascade_children=True
                )
                == 1
            )
            loaded_late = await storage.sessions.get(late.id)
            assert loaded_late is not None
            assert loaded_late.revoked_reason == RevokeReason.PARENT_REVOKED

    @pytest.mark.asyncio
    async def test_session_purge_expired(self) -> None:
        async with self.storage() as storage:
            live = await storage.sessions.create(_make_session())
            expired = await storage.sessions.create(
                _make_session(expires_at=_T0 - timedelta(days=1))
            )
            revoked = await storage.sessions.create(_make_session())
            await storage.sessions.revoke(
                reason="logout", at=_T0 - timedelta(hours=1), session_id=revoked.id
            )
            recent = await storage.sessions.create(_make_session())
            await storage.sessions.revoke(
                reason="logout", at=_T0 + timedelta(hours=1), session_id=recent.id
            )
            assert await storage.sessions.purge_expired(before=_T0) == 2
            assert await storage.sessions.get(expired.id) is None
            assert await storage.sessions.get(revoked.id) is None
            assert await storage.sessions.get(live.id) is not None
            assert await storage.sessions.get(recent.id) is not None

    # -- audit ----------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_audit_append_and_filters(self) -> None:
        async with self.storage() as storage:
            tenant_a, tenant_b, actor, target = uuid4(), uuid4(), uuid4(), uuid4()
            events = [
                _make_event(
                    action="tenant.created",
                    tenant_id=tenant_a,
                    actor_id=actor,
                    occurred_at=_T0,
                    metadata={"nested": {"k": [1, 2]}},
                    reason="why",
                    session_id=uuid4(),
                    token_jti=uuid4(),
                    impersonator_id=uuid4(),
                    target_type="tenant",
                    target_id=target,
                ),
                _make_event(
                    action="tenant.updated",
                    tenant_id=tenant_b,
                    occurred_at=_T0 + timedelta(seconds=1),
                ),
                _make_event(
                    action="tenant_user.created",
                    tenant_id=tenant_a,
                    occurred_at=_T0 + timedelta(seconds=2),
                ),
                _make_event(
                    action="auth.login.failed",
                    outcome="failure",
                    actor_type="anonymous",
                    occurred_at=_T0 + timedelta(seconds=3),
                ),
                _make_event(action="admin_x.created", occurred_at=_T0 + timedelta(seconds=4)),
            ]
            for event in events:
                await storage.audit_events.append(event)
            everything = await storage.audit_events.list()
            assert [e.id for e in everything] == [e.id for e in reversed(events)]
            assert events[0] in everything
            assert await storage.audit_events.list(tenant_ids=[]) == []
            by_tenant = await storage.audit_events.list(tenant_ids=[tenant_a])
            assert {e.action for e in by_tenant} == {"tenant.created", "tenant_user.created"}
            both = await storage.audit_events.list(tenant_ids=[tenant_a, tenant_b])
            assert len(both) == 3
            assert [e.id for e in await storage.audit_events.list(actor_id=actor)] == [events[0].id]
            assert [e.id for e in await storage.audit_events.list(target_id=target)] == [
                events[0].id
            ]
            exact = await storage.audit_events.list(action="tenant.updated")
            assert [e.id for e in exact] == [events[1].id]
            prefix = await storage.audit_events.list(action="tenant.*")
            assert {e.action for e in prefix} == {"tenant.created", "tenant.updated"}
            # "_" is not a wildcard in prefix matches.
            assert await storage.audit_events.list(action="tenant_.*") == []
            failures = await storage.audit_events.list(action="auth.*")
            assert [e.outcome for e in failures] == ["failure"]
            window = await storage.audit_events.list(
                since=_T0 + timedelta(seconds=1), until=_T0 + timedelta(seconds=3)
            )
            assert [e.id for e in window] == [events[3].id, events[2].id, events[1].id]
            page = await storage.audit_events.list(limit=2, offset=1)
            assert [e.id for e in page] == [events[3].id, events[2].id]

    @pytest.mark.asyncio
    async def test_audit_ties_order_by_id_descending(self) -> None:
        async with self.storage() as storage:
            events = [_make_event() for _ in range(5)]
            for event in events:
                await storage.audit_events.append(event)
            listed = await storage.audit_events.list()
            assert [e.id for e in listed] == sorted((e.id for e in events), reverse=True)

    @pytest.mark.asyncio
    async def test_audit_purge(self) -> None:
        async with self.storage() as storage:
            old = _make_event(occurred_at=_T0 - timedelta(days=2))
            new = _make_event(occurred_at=_T0 + timedelta(days=2))
            await storage.audit_events.append(old)
            await storage.audit_events.append(new)
            assert await storage.audit_events.purge(before=_T0) == 1
            assert [e.id for e in await storage.audit_events.list()] == [new.id]

    # -- transactions ---------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_in_transaction_flag(self) -> None:
        async with self.storage() as storage:
            assert storage.in_transaction() is False
            async with storage.transaction():
                assert storage.in_transaction() is True
                async with storage.transaction():
                    assert storage.in_transaction() is True
                assert storage.in_transaction() is True
            assert storage.in_transaction() is False
            with pytest.raises(RuntimeError):
                async with storage.transaction():
                    raise RuntimeError("abort")
            assert storage.in_transaction() is False

    @pytest.mark.asyncio
    async def test_sessions_and_audit_honour_rollback(self) -> None:
        async with self.storage() as storage:
            existing = await storage.sessions.create(_make_session())
            kept_event = _make_event()
            await storage.audit_events.append(kept_event)
            doomed = _make_session()
            with pytest.raises(RuntimeError):
                async with storage.transaction():
                    await storage.sessions.create(doomed)
                    await storage.sessions.revoke(reason="logout", at=_T0, session_id=existing.id)
                    await storage.audit_events.append(_make_event())
                    await storage.audit_events.purge(before=_T0 + timedelta(days=1))
                    raise RuntimeError("abort")
            assert await storage.sessions.get(doomed.id) is None
            reloaded = await storage.sessions.get(existing.id)
            assert reloaded is not None and reloaded.revoked_at is None
            assert [e.id for e in await storage.audit_events.list()] == [kept_event.id]

    @pytest.mark.asyncio
    async def test_session_identifiers_round_trip_as_uuid(self) -> None:
        async with self.storage() as storage:
            session = await storage.sessions.create(
                _make_session(parent_id=uuid4(), tenant_id=uuid4())
            )
            loaded = await storage.sessions.get(session.id)
            assert loaded is not None
            assert isinstance(loaded.id, UUID) and isinstance(loaded.current_jti, UUID)
            assert isinstance(loaded.parent_id, UUID) and isinstance(loaded.tenant_id, UUID)
