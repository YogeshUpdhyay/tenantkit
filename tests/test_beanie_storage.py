"""Beanie adapter specifics. Server-free tests run everywhere; the rest need MongoDB."""

from __future__ import annotations

import logging
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("beanie")

from bson.binary import UuidRepresentation  # noqa: E402

from support import MONGO_URL, open_mongo_storage  # noqa: E402
from tenantkit.domain.errors import (  # noqa: E402
    AlreadyExistsError,
    ConfigError,
    StorageError,
    StorageUnavailableError,
)
from tenantkit.domain.models import Admin, Session, Tenant, TenantUser, now  # noqa: E402
from tenantkit.storage.beanie import BeanieStorage, document_models  # noqa: E402
from tenantkit.storage.beanie import documents as documents_module  # noqa: E402

needs_mongo = pytest.mark.skipif(not MONGO_URL, reason="TENANTKIT_TEST_MONGO_URL not set")


@pytest.fixture
def isolated_models():
    saved = documents_module._cached
    documents_module._reset_for_tests()
    yield
    documents_module._cached = saved


def test_document_models_are_cached_per_process(isolated_models):
    first = document_models("zz_")
    assert document_models("zz_") is first
    assert first.all == (
        first.admins,
        first.tenants,
        first.tenant_users,
        first.login_attempts,
        first.sessions,
        first.audit_events,
    )
    assert first.sessions.Settings.name == "zz_sessions"
    with pytest.raises(ConfigError):
        document_models("other_")


@pytest.mark.parametrize("prefix", ["", "1abc", "a-b", "a b", "mt$"])
def test_document_models_validate_prefix(isolated_models, prefix):
    with pytest.raises(ConfigError):
        document_models(prefix)


class FakeDatabase:
    def __init__(self, *, uuid=UuidRepresentation.STANDARD, hello=None, fail_ping=False):
        self.codec_options = SimpleNamespace(uuid_representation=uuid)
        self._hello = hello if hello is not None else {"setName": "rs0"}
        self._fail_ping = fail_ping
        self.commands: list[str] = []

    async def command(self, name):
        from pymongo.errors import ConnectionFailure

        self.commands.append(name)
        if self._fail_ping:
            raise ConnectionFailure("mongodb://user:secret@host is down")
        return {"ok": 1} if name == "ping" else self._hello


def fake_models(database, *, initialised=True, other=None):
    class Model:
        @staticmethod
        def get_pymongo_collection():
            if not initialised:
                raise RuntimeError("not initialised")
            return SimpleNamespace(database=other or database)

    return SimpleNamespace(all=(Model,))


async def test_health_check_requires_standard_uuid_representation():
    db = FakeDatabase(uuid=UuidRepresentation.UNSPECIFIED)
    with pytest.raises(ConfigError):
        await BeanieStorage(database=db, models=fake_models(db)).health_check()


async def test_health_check_requires_initialised_models_on_this_database():
    db = FakeDatabase()
    with pytest.raises(ConfigError):
        await BeanieStorage(database=db, models=fake_models(db, initialised=False)).health_check()
    with pytest.raises(ConfigError):
        await BeanieStorage(
            database=db, models=fake_models(db, other=FakeDatabase())
        ).health_check()


async def test_health_check_requires_replica_set_or_mongos_for_transactions():
    standalone = FakeDatabase(hello={"isWritablePrimary": True})
    with pytest.raises(StorageUnavailableError):
        await BeanieStorage(database=standalone, models=fake_models(standalone)).health_check()
    for hello in ({"setName": "rs0"}, {"msg": "isdbgrid"}):
        db = FakeDatabase(hello=hello)
        await BeanieStorage(database=db, models=fake_models(db)).health_check()


async def test_health_check_without_transactions_skips_topology_and_warns(caplog):
    db = FakeDatabase(hello={"isWritablePrimary": True})
    with caplog.at_level(logging.WARNING, logger="tenantkit.storage.beanie"):
        storage = BeanieStorage(database=db, models=fake_models(db), transactions=False)
    assert "not atomic" in caplog.text and "fail-closed" in caplog.text
    await storage.health_check()
    assert db.commands == ["ping"]
    caplog.clear()
    BeanieStorage(database=db, models=fake_models(db))
    assert caplog.text == ""


async def test_health_check_unreachable_server_hides_connection_details():
    db = FakeDatabase(fail_ping=True)
    with pytest.raises(StorageUnavailableError) as info:
        await BeanieStorage(database=db, models=fake_models(db)).health_check()
    assert "secret" not in str(info.value)


@needs_mongo
async def test_datetimes_are_aware_utc_even_when_client_is_naive():
    from beanie import init_beanie
    from pymongo import AsyncMongoClient

    client: AsyncMongoClient[Any] = AsyncMongoClient(
        MONGO_URL, uuidRepresentation="standard", tz_aware=False
    )
    try:
        models = document_models("mt_")
        database = client["tenantkit_test"]
        await init_beanie(database=database, document_models=list(models.all))
        await models.sessions.get_pymongo_collection().delete_many({})
        storage = BeanieStorage(database=database, models=models)
        admin = Admin(email="tz@example.com", password_hash="x")
        session = await storage.sessions.create(
            Session(
                kind="admin",
                subject_id=admin.id,
                current_jti=admin.id,
                expires_at=now() + timedelta(days=1),
            )
        )
        loaded = await storage.sessions.get(session.id)
        assert loaded is not None and loaded == session
        for value in (loaded.expires_at, loaded.created_at, loaded.last_used_at):
            assert value.tzinfo is not None and value.utcoffset() == timedelta(0)
    finally:
        await client.close()


@needs_mongo
async def test_error_mapping_and_integrity_checks():
    async with open_mongo_storage() as storage:
        tenant = await storage.tenants.create(Tenant(slug="acme"))
        with pytest.raises(AlreadyExistsError):
            await storage.tenants.create(Tenant(slug="acme"))
        with pytest.raises(StorageError):
            await storage.tenant_users.create(
                TenantUser(tenant_id=Tenant(slug="ghost").id, email="g@y.z", password_hash="h")
            )
        with pytest.raises(Exception) as info:
            await storage.tenants.update(Tenant(slug="missing"))
        assert type(info.value).__name__ == "NotFoundError"
        with pytest.raises(ValueError):
            await storage.tenants.list(limit=-1)
        with pytest.raises(ValueError):
            await storage.login_attempts.record_failure(
                "admin", tenant.id, max_attempts=0, locked_until=now()
            )
        with pytest.raises(ValueError):
            await storage.sessions.list(kind="admin", subject_id=tenant.id, offset=-1)
        assert await storage.sessions.list(kind="admin", subject_id=tenant.id, limit=0) == []
        assert await storage.audit_events.list(tenant_ids=[]) == []


@needs_mongo
async def test_login_policy_round_trips_validated():
    from tenantkit.config.models import LoginPolicy

    async with open_mongo_storage() as storage:
        policy = LoginPolicy(providers=("password",))
        tenant = await storage.tenants.create(Tenant(slug="acme", login_policy=policy))
        loaded = await storage.tenants.get(tenant.id)
        assert loaded is not None and loaded.login_policy == policy


@needs_mongo
async def test_driver_failures_become_storage_errors(monkeypatch):
    from pymongo.asynchronous.collection import AsyncCollection
    from pymongo.errors import ServerSelectionTimeoutError

    async def boom(*args, **kwargs):
        raise ServerSelectionTimeoutError("mongodb://user:secret@host:27017 unreachable")

    async with open_mongo_storage() as storage:
        monkeypatch.setattr(AsyncCollection, "find_one", boom)
        with pytest.raises(StorageError) as info:
            await storage.tenants.get(Tenant(slug="x").id)
        assert "secret" not in str(info.value)
        assert isinstance(info.value.__cause__, ServerSelectionTimeoutError)
        monkeypatch.undo()
        from pymongo.asynchronous.client_session import AsyncClientSession

        async def bad_start(*args, **kwargs):
            raise ServerSelectionTimeoutError("down")

        monkeypatch.setattr(AsyncClientSession, "start_transaction", bad_start)
        with pytest.raises(StorageError):
            async with storage.transaction():
                pass


@needs_mongo
async def test_transactions_disabled_is_not_atomic_but_still_tracks_nesting():
    async with open_mongo_storage(transactions=False) as storage:
        assert not storage.in_transaction()
        with pytest.raises(RuntimeError):
            async with storage.transaction():
                assert storage.in_transaction()
                async with storage.transaction():
                    await storage.tenants.create(Tenant(slug="leaks"))
                raise RuntimeError("abort")
        # Documented-as-unsafe: without transactions the write survives the abort.
        assert await storage.tenants.get_by_slug("leaks") is not None
        assert not storage.in_transaction()


@needs_mongo
async def test_atomic_lockout_pipeline_keeps_first_lock():
    async with open_mongo_storage() as storage:
        who = Tenant(slug="subject").id
        first = now() + timedelta(minutes=15)
        second = now() + timedelta(minutes=30)
        a = await storage.login_attempts.record_failure(
            "admin", who, max_attempts=2, locked_until=first
        )
        assert a.failed_count == 1 and a.locked_until is None
        b = await storage.login_attempts.record_failure(
            "admin", who, max_attempts=2, locked_until=first
        )
        c = await storage.login_attempts.record_failure(
            "admin", who, max_attempts=2, locked_until=second
        )
        assert b.locked_until == c.locked_until and c.failed_count == 3
        assert c.locked_until is not None and c.locked_until < second.replace(microsecond=0)


def test_row_mappers_round_trip_and_normalise_datetimes():
    from datetime import datetime, timezone
    from uuid import uuid4

    from tenantkit.config.models import LoginPolicy
    from tenantkit.domain.models import AuditEvent, ImpersonationScope
    from tenantkit.storage.beanie import repositories as r

    stamp = datetime(2030, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc)
    ms = stamp.replace(microsecond=678000)
    assert r._ms(stamp) == ms and r._ms(None) is None
    assert r._ms(stamp.replace(tzinfo=None)) == ms
    admin = Admin(
        email="a@b.c",
        password_hash="h",
        roles=["x"],
        impersonation_scope=ImpersonationScope("list", [uuid4()]),
        created_at=stamp,
        updated_at=stamp,
    )
    loaded = r._admin(r._admin_raw(admin))
    assert loaded.created_at == ms and loaded.impersonation_scope == admin.impersonation_scope
    tenant = Tenant(slug="t", attributes={"k": 1}, login_policy=LoginPolicy())
    assert r._tenant(r._tenant_raw(tenant)).login_policy == LoginPolicy()
    bare = Tenant(slug="t")
    assert r._tenant(r._tenant_raw(bare)).login_policy is None
    user = TenantUser(tenant_id=tenant.id, email="u@b.c", password_hash="h", created_at=stamp)
    assert r._user(r._user_raw(user)).created_at == ms
    session = Session(
        kind="tenant", subject_id=uuid4(), current_jti=uuid4(), expires_at=stamp, revoked_at=stamp
    )
    again = r._session(r._session_raw(session))
    assert again.revoked_at == ms and again.parent_id is None and again.tenant_id is None
    event = AuditEvent(
        action="a.b", outcome="success", actor_type="system", metadata={"n": 1}, occurred_at=stamp
    )
    assert r._event(r._event_raw(event)) == AuditEvent(**{**event.__dict__, "occurred_at": ms})
    assert r._attempt_id("admin", tenant.id) == r._attempt_id("admin", tenant.id)
    assert r._attempt_id("admin", tenant.id) != r._attempt_id("tenant_user", tenant.id)


async def test_transaction_flag_without_server_when_transactions_disabled():
    db = FakeDatabase()
    storage = BeanieStorage(database=db, models=fake_models(db), transactions=False)
    assert not storage.in_transaction() and storage._session() is None
    async with storage.transaction():
        assert storage.in_transaction()
        async with storage.transaction():
            assert storage.in_transaction()
    assert not storage.in_transaction()


async def test_kit_health_check_surfaces_config_errors():
    from support import make_config
    from tenantkit import TenantKit

    db = FakeDatabase(uuid=UuidRepresentation.UNSPECIFIED)
    kit = TenantKit(
        config=make_config(), storage=BeanieStorage(database=db, models=fake_models(db))
    )
    with pytest.raises(ConfigError):
        await kit.health_check()
    down = FakeDatabase(fail_ping=True)
    kit = TenantKit(
        config=make_config(), storage=BeanieStorage(database=down, models=fake_models(down))
    )
    with pytest.raises(StorageUnavailableError):
        await kit.health_check()
