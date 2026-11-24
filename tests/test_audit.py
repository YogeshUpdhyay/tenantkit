"""Audit trail: catalogue, atomicity, failure events, hooks, visibility and secrecy."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from support import BACKENDS, PASSWORD, Env, open_env
from tenantkit import AuditEvent
from tenantkit.domain.errors import (
    AccountLockedError,
    InvalidCredentialsError,
    PermissionDeniedError,
    RevokedTokenError,
    StorageError,
)
from tenantkit.domain.models import ImpersonationScope


@pytest.fixture(params=BACKENDS)
async def env(request: pytest.FixtureRequest) -> AsyncIterator[Env]:
    async with open_env(request.param) as e:
        yield e


# action -> (outcome, actor_type, target_type)
CATALOGUE: dict[str, tuple[str, str, str | None]] = {
    "admin.bootstrapped": ("success", "system", "admin"),
    "auth.login.succeeded": ("success", "admin", "session"),
    "auth.login.failed": ("failure", "anonymous", None),
    "auth.account.locked": ("failure", "anonymous", "account"),
    "auth.account.unlocked": ("success", "admin", "account"),
    "auth.token.refreshed": ("success", "admin", "session"),
    "auth.logout": ("success", "admin", "session"),
    "auth.logout_all": ("success", "admin", "admin"),
    "auth.password.changed": ("success", "admin", "admin"),
    "token.reuse_detected": ("failure", "admin", "session"),
    "session.revoked": ("success", "admin", "admin"),
    "impersonation.started": ("success", "admin", "session"),
    "impersonation.refreshed": ("success", "admin", "session"),
    "impersonation.ended": ("success", "admin", "session"),
    "impersonation.denied": ("failure", "admin", "tenant"),
    "tenant.created": ("success", "admin", "tenant"),
    "tenant.updated": ("success", "admin", "tenant"),
    "tenant.login_policy_changed": ("success", "admin", "tenant"),
    "tenant.deactivated": ("success", "admin", "tenant"),
    "tenant.reactivated": ("success", "admin", "tenant"),
    "tenant_user.created": ("success", "admin", "tenant_user"),
    "tenant_user.updated": ("success", "admin", "tenant_user"),
    "tenant_user.deactivated": ("success", "admin", "tenant_user"),
    "admin.created": ("success", "admin", "admin"),
    "admin.updated": ("success", "admin", "admin"),
    "admin.deactivated": ("success", "admin", "admin"),
    "audit.purged": ("success", "admin", None),
}


async def _scenario(env: Env) -> list[str]:
    """Exercise every catalogued action; returns every secret that must never be logged."""
    kit, cp = env.kit, env.kit.control_plane
    secrets = [
        PASSWORD,
        "another-passphrase-456",
        "admin" * 32,
        "tenant" * 32,
        "impersonation" * 32,
    ]
    root = await env.admin_login()
    tenant = await cp.create_tenant(root.claims, "acme", {"name": "Acme"})
    await cp.update_tenant(root.claims, tenant.id, {"name": "Acme 2"})
    await cp.set_login_policy(root.claims, tenant.id, {"providers": ["password"]})
    user = await cp.create_tenant_user(
        root.claims, tenant.id, "u@example.com", PASSWORD, ["reader"]
    )
    await cp.update_tenant_user(root.claims, user.id, password="another-passphrase-456")
    pair = await env.kit.tenant_auth.login(
        tenant_slug="acme",
        method="password",
        credentials={"email": user.email, "password": "another-passphrase-456"},
    )
    refreshed = await kit.tenant_auth.refresh(refresh_token=pair.refresh_token)
    await kit.tenant_auth.logout(refresh_token=refreshed.refresh_token)
    await cp.deactivate_tenant_user(root.claims, user.id)
    await cp.deactivate_tenant(root.claims, tenant.id)
    await cp.reactivate_tenant(root.claims, tenant.id)
    second = await cp.create_admin(
        root.claims, "second@example.com", PASSWORD, ["super_admin"], ImpersonationScope("all")
    )
    await cp.update_admin(root.claims, second.id, roles=["super_admin"])
    limited = await cp.create_admin(
        root.claims, "limited@example.com", PASSWORD, ["super_admin"], ImpersonationScope("none")
    )
    await cp.deactivate_admin(root.claims, limited.id)
    with pytest.raises(InvalidCredentialsError):
        await kit.admin_auth.login(email="root@example.com", password="wrong-password-1")
    for _ in range(4):
        with pytest.raises((InvalidCredentialsError, AccountLockedError)):
            await kit.admin_auth.login(email="second@example.com", password="wrong-password-2")
    with pytest.raises(AccountLockedError):
        await kit.admin_auth.login(email="second@example.com", password="wrong-password-3")
    await cp.unlock_account(root.claims, "admin", second.id)
    # impersonation: denied (scope none), started, refreshed, ended
    third = await cp.create_admin(
        root.claims, "third@example.com", PASSWORD, ["super_admin"], ImpersonationScope("none")
    )
    third_pair = await env.admin_login("third@example.com")
    with pytest.raises(PermissionDeniedError):
        await kit.access.impersonate(
            actor=third_pair.claims,
            tenant_id=tenant.id,
            role="support",
            admin_refresh_token=third_pair.refresh_token,
        )
    imp = await kit.access.impersonate(
        actor=root.claims,
        tenant_id=tenant.id,
        role="support",
        admin_refresh_token=root.refresh_token,
        reason="ticket 1",
    )
    imp2 = await kit.access.refresh_impersonation(imp.refresh_token)
    await kit.access.end_impersonation(refresh_token=imp2.refresh_token)
    await cp.revoke_sessions(root.claims, "admin", third.id)
    await kit.admin_auth.change_password(
        actor=(await env.admin_login("second@example.com")).claims,
        current=PASSWORD,
        new="another-passphrase-456",
    )
    fresh = await env.admin_login()
    await kit.admin_auth.logout_all(actor=fresh.claims)
    reuse = await env.admin_login()
    await kit.admin_auth.refresh(refresh_token=reuse.refresh_token)
    with pytest.raises(RevokedTokenError):
        await kit.admin_auth.refresh(refresh_token=reuse.refresh_token)
    await kit.audit.purge(root.claims, before=datetime(2000, 1, 1, tzinfo=timezone.utc))
    secrets += [
        t
        for p in (root, pair, refreshed, imp, imp2, third_pair, fresh, reuse)
        for t in (p.access_token, p.refresh_token)
    ]
    return secrets


async def test_every_action_is_emitted_with_documented_fields(env: Env) -> None:
    secrets = await _scenario(env)
    stored = await env.storage.audit_events.list(limit=10_000)
    assert {e.action for e in stored} == set(CATALOGUE)
    for event in stored:
        outcome, actor_type, target_type = CATALOGUE[event.action]
        assert event.outcome == outcome and event.target_type == target_type, event.action
        assert event.actor_type in {actor_type, "tenant_user"}, event.action
        if event.action not in ("auth.login.succeeded", "auth.token.refreshed", "auth.logout"):
            assert event.actor_type == actor_type, event.action
        assert event.occurred_at.tzinfo is not None
    by_action = {e.action: e for e in reversed(stored)}
    assert by_action["admin.bootstrapped"].actor_id is None
    assert by_action["impersonation.started"].reason == "ticket 1"
    assert by_action["impersonation.started"].metadata == {"role": "support"}
    assert by_action["impersonation.started"].impersonator_id is None
    assert by_action["impersonation.denied"].target_id == by_action["tenant.created"].target_id
    assert by_action["tenant.updated"].metadata == {"changed": ["name"]}
    assert by_action["tenant_user.updated"].metadata == {"changed": ["password"]}
    assert by_action["auth.login.failed"].metadata["subject_type"] == "admin"
    assert by_action["tenant_user.created"].tenant_id == by_action["tenant.created"].tenant_id
    # Hooks saw exactly the committed events, in commit order.
    assert [e.id for e in env.hook_events] == [e.id for e in reversed(stored)]
    # No secret material anywhere in any event.
    blob = json.dumps([repr(e) for e in stored])
    for secret in secrets:
        assert secret not in blob
    assert "$argon2" not in blob and "password_hash" not in blob
    assert "root@example.com" not in blob and "second@example.com" not in blob


async def test_one_change_emits_exactly_one_event(env: Env) -> None:
    root = await env.admin_login()
    baseline = len(await env.storage.audit_events.list(limit=1000))
    await env.kit.control_plane.create_tenant(root.claims, "acme", {"name": "Acme"})
    events = await env.storage.audit_events.list(limit=1000)
    assert len(events) == baseline + 1 and events[0].action == "tenant.created"
    assert events[0].actor_id == env.root.id and events[0].session_id == root.claims.sid
    assert events[0].token_jti == root.claims.jti


async def test_failing_audit_append_rolls_back_the_change(env: Env) -> None:
    root = await env.admin_login()

    class Failing:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        async def append(self, event: AuditEvent) -> None:
            raise StorageError("disk full")

        def __getattr__(self, name: str) -> Any:
            return getattr(self.inner, name)

    real = env.storage.audit_events
    before = len(env.hook_events)
    env.storage.audit_events = Failing(real)  # type: ignore[assignment]
    try:
        with pytest.raises(StorageError):
            await env.kit.control_plane.create_tenant(root.claims, "acme", {"name": "Acme"})
        with pytest.raises(StorageError):
            await env.kit.admin_auth.login(email="root@example.com", password=PASSWORD)
    finally:
        env.storage.audit_events = real
    assert await env.storage.tenants.get_by_slug("acme") is None
    # The failed login must not have left a session behind either.
    assert len(await env.storage.sessions.list(kind="admin", subject_id=env.root.id)) == 1
    assert len(env.hook_events) == before


async def test_failure_events_persist_when_operation_raises(env: Env) -> None:
    with pytest.raises(InvalidCredentialsError):
        await env.kit.admin_auth.login(email="nobody@example.com", password="wrong")
    for _ in range(5):
        with pytest.raises((InvalidCredentialsError, AccountLockedError)):
            await env.kit.admin_auth.login(email="root@example.com", password="wrong")
    events = await env.storage.audit_events.list(action="auth.login.failed", limit=100)
    assert len(events) == 6
    locked = await env.storage.audit_events.list(action="auth.account.locked")
    assert len(locked) == 1 and locked[0].target_id == env.root.id
    assert [e.action for e in env.hook_events].count("auth.account.locked") == 1


async def test_failed_login_email_is_opt_in() -> None:
    async with open_env("memory") as env:
        with pytest.raises(InvalidCredentialsError):
            await env.kit.admin_auth.login(email="Probe@Example.com", password="wrong")
        event = (await env.storage.audit_events.list(action="auth.login.failed"))[0]
        assert "probe" not in repr(event).lower() and "email" not in event.metadata
    async with open_env("memory", audit={"include_failed_login_email": True}) as env:
        with pytest.raises(InvalidCredentialsError):
            await env.kit.admin_auth.login(email="Probe@Example.com", password="wrong")
        event = (await env.storage.audit_events.list(action="auth.login.failed"))[0]
        assert event.metadata["email"] == "Probe@Example.com"
        tenant_root = await env.admin_login()
        await env.make_tenant(tenant_root.claims, "acme")
        with pytest.raises(InvalidCredentialsError):
            await env.kit.tenant_auth.login(
                tenant_slug="acme",
                method="password",
                credentials={"email": "x@y.z", "password": "p"},
            )
        events = await env.storage.audit_events.list(action="auth.login.failed")
        assert events[0].metadata["email"] == "x@y.z"
        assert events[0].metadata["tenant_slug"] == "acme"


async def test_hooks_are_isolated_and_post_commit(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[str] = []

    async def reads_storage(event: AuditEvent) -> None:
        # Must be able to use storage (the transaction is already closed).
        assert await env.storage.tenants.get_by_slug("acme") is not None
        async with env.storage.transaction():
            calls.append(event.action)

    async def boom(event: AuditEvent) -> None:
        raise RuntimeError("secret-looking " + str(event.metadata))

    env.kit.audit.hooks = (boom, reads_storage)
    root = await env.admin_login()
    with caplog.at_level(logging.ERROR, logger="tenantkit.audit"):
        await env.kit.control_plane.create_tenant(root.claims, "acme", {"name": "Acme"})
    assert calls[-1] == "tenant.created"
    record = next(r for r in caplog.records if "tenant.created" in r.getMessage())
    assert record.name == "tenantkit.audit" and "Acme" not in record.getMessage()
    # No hook invocation for a rolled-back change.
    calls.clear()
    with pytest.raises(Exception):
        await env.kit.control_plane.create_tenant(root.claims, "acme", {"name": "dup"})
    assert calls == []


async def test_nested_recorder_defers_hooks_until_outer_commit(env: Env) -> None:
    root = await env.admin_login()
    seen = len(env.hook_events)
    async with env.kit.audit.recorder():
        await env.kit.control_plane.create_tenant(root.claims, "acme", {"name": "Acme"})
        assert len(env.hook_events) == seen
    assert [e.action for e in env.hook_events[seen:]] == ["tenant.created"]
    seen = len(env.hook_events)
    with pytest.raises(RuntimeError):
        async with env.kit.audit.recorder():
            await env.kit.control_plane.create_tenant(root.claims, "beta", {"name": "Beta"})
            raise RuntimeError("abort")
    assert len(env.hook_events) == seen
    assert await env.storage.tenants.get_by_slug("beta") is None


async def test_transaction_discipline_guards(env: Env) -> None:
    root = await env.admin_login()
    event = AuditEvent(action="x.y", outcome="failure", actor_type="anonymous")
    async with env.storage.transaction():
        with pytest.raises(RuntimeError):
            await env.kit.audit.emit_standalone(event)
        with pytest.raises(RuntimeError):
            await env.kit.sessions.revoke_standalone(session_id=root.claims.sid, reason="logout")
        with pytest.raises(RuntimeError):
            await env.kit.control_plane.create_tenant(root.claims, "acme", {"name": "A"})
    await env.kit.audit.emit_standalone(event)
    assert (await env.storage.audit_events.list(action="x.y"))[0].id == event.id


async def test_audit_list_visibility(env: Env) -> None:
    root = await env.admin_login()
    cp = env.kit.control_plane
    acme, (acme_user,) = await env.make_tenant(root.claims, "acme", "a@example.com")
    beta, _ = await env.make_tenant(root.claims, "beta", "b@example.com")

    async def login_as(email: str, roles: list[str], scope: ImpersonationScope) -> Any:
        await cp.create_admin(root.claims, email, PASSWORD, roles, scope)
        return (await env.admin_login(email)).claims

    everything = await env.kit.audit.list(root.claims, limit=500)
    assert any(e.tenant_id is None for e in everything)
    only_acme = await env.kit.audit.list(root.claims, tenant_id=acme.id)
    assert only_acme and {e.tenant_id for e in only_acme} == {acme.id}
    assert [
        e.action for e in await env.kit.audit.list(root.claims, action="tenant.*", limit=1)
    ] == ["tenant.created"]

    scoped = await login_as("s@example.com", ["auditor"], ImpersonationScope("list", [acme.id]))
    seen = await env.kit.audit.list(scoped, limit=500)
    assert seen and {e.tenant_id for e in seen} == {acme.id}
    with pytest.raises(PermissionDeniedError):
        await env.kit.audit.list(scoped, tenant_id=beta.id)
    wide = await login_as("w@example.com", ["auditor"], ImpersonationScope("all"))
    assert any(e.tenant_id is None for e in await env.kit.audit.list(wide, limit=500))
    blind = await login_as("n@example.com", ["auditor"], ImpersonationScope("none"))
    with pytest.raises(PermissionDeniedError):
        await env.kit.audit.list(blind)
    no_perm = await login_as("p@example.com", ["session_admin"], ImpersonationScope("all"))
    with pytest.raises(PermissionDeniedError):
        await env.kit.audit.list(no_perm)
    tenant_pair = await env.tenant_login("acme", acme_user.email)
    with pytest.raises(PermissionDeniedError):
        await env.kit.audit.list(tenant_pair.claims)
    imp = await env.kit.access.impersonate(
        actor=root.claims, tenant_id=acme.id, role="support", admin_refresh_token=root.refresh_token
    )
    with pytest.raises(PermissionDeniedError):
        await env.kit.audit.list(imp.claims)
    assert len(await env.kit.audit.list(root.claims, limit=0)) == 1
    assert len(await env.kit.audit.list(root.claims, limit=10_000)) <= 500


async def test_audit_purge_keeps_its_own_event(env: Env) -> None:
    root = await env.admin_login()
    cp = env.kit.control_plane
    await cp.create_admin(
        root.claims, "p@example.com", PASSWORD, ["purger"], ImpersonationScope("none")
    )
    await cp.create_admin(
        root.claims, "r@example.com", PASSWORD, ["auditor"], ImpersonationScope("all")
    )
    purger = (await env.admin_login("p@example.com")).claims
    reader = (await env.admin_login("r@example.com")).claims
    with pytest.raises(PermissionDeniedError):
        await env.kit.audit.purge(reader, before=datetime.now(timezone.utc))
    total = len(await env.storage.audit_events.list(limit=1000))
    cutoff = datetime.now(timezone.utc) + timedelta(seconds=1)
    assert await env.kit.audit.purge(purger, before=cutoff) == total
    remaining = await env.storage.audit_events.list(limit=1000)
    assert [e.action for e in remaining] == ["audit.purged"]
    assert remaining[0].metadata["count"] == total
    assert remaining[0].metadata["before"] == cutoff.isoformat()
