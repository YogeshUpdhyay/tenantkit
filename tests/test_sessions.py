"""Sessions, refresh rotation, reuse detection and revocation, on memory and SQLite."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import asyncio

import jwt
import pytest

from support import BACKENDS, PASSWORD, Env, make_config, open_env
from tenantkit.domain.errors import (
    AccountLockedError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
    RevokedTokenError,
    WrongTokenTypeError,
)
from tenantkit.domain.models import ImpersonationScope
from tenantkit.tokens.service import TokenService


@pytest.fixture(params=BACKENDS)
async def env(request: pytest.FixtureRequest) -> AsyncIterator[Env]:
    async with open_env(request.param) as e:
        yield e


async def _impersonate(env: Env, admin_pair: Any, tenant_id: Any) -> Any:
    return await env.kit.access.impersonate(
        actor=admin_pair.claims,
        tenant_id=tenant_id,
        role="support",
        admin_refresh_token=admin_pair.refresh_token,
        reason="ticket 42",
    )


async def _audit_actions(env: Env, **filters: Any) -> list[str]:
    return [e.action for e in await env.storage.audit_events.list(limit=500, **filters)]


async def test_login_creates_one_active_session_with_sid_and_jti(env: Env) -> None:
    pair = await env.admin_login()
    sessions = await env.storage.sessions.list(kind="admin", subject_id=env.root.id)
    assert len(sessions) == 1
    session = sessions[0]
    assert session.is_active and session.id == pair.claims.sid
    assert env.kit.tokens.verify_refresh(pair.refresh_token).sid == session.id
    assert env.kit.tokens.verify_refresh(pair.refresh_token).jti == session.current_jti
    assert pair.refresh_jti == session.current_jti and pair.refresh_expires_at == session.expires_at

    tenant, (user,) = await env.make_tenant(pair.claims, "acme", "u@example.com")
    tpair = await env.tenant_login("acme", user.email)
    tsessions = await env.storage.sessions.list(kind="tenant", subject_id=user.id)
    assert [s.id for s in tsessions] == [tpair.claims.sid]
    assert tsessions[0].tenant_id == tenant.id


async def test_refresh_rotates_jti_extends_expiry_keeps_sid(env: Env) -> None:
    pair = await env.admin_login()
    before = await env.storage.sessions.get(pair.claims.sid)
    assert before is not None
    new = await env.kit.admin_auth.refresh(refresh_token=pair.refresh_token)
    after = await env.storage.sessions.get(pair.claims.sid)
    assert after is not None
    assert new.claims.sid == pair.claims.sid
    assert after.current_jti == new.refresh_jti != before.current_jti
    assert after.expires_at >= before.expires_at
    assert after.last_used_at >= before.last_used_at
    assert "auth.token.refreshed" in await _audit_actions(env)


async def test_reuse_revokes_session_and_children_and_persists_after_error(env: Env) -> None:
    admin = await env.admin_login()
    tenant, _ = await env.make_tenant(admin.claims, "acme")
    imp = await _impersonate(env, admin, tenant.id)
    rotated = await env.kit.admin_auth.refresh(refresh_token=admin.refresh_token)
    # Presenting the old token again is reuse.
    with pytest.raises(RevokedTokenError):
        await env.kit.admin_auth.refresh(refresh_token=admin.refresh_token)
    # The error propagated, yet the revoke and the audit event persisted.
    session = await env.storage.sessions.get(admin.claims.sid)
    assert session is not None and session.revoked_reason == "reuse_detected"
    child = await env.storage.sessions.get(imp.claims.sid)
    assert child is not None and child.revoked_reason == "parent_revoked"
    events = await env.storage.audit_events.list(action="token.reuse_detected")
    assert len(events) == 1
    assert events[0].outcome == "failure" and events[0].session_id == admin.claims.sid
    assert any(e.action == "token.reuse_detected" for e in env.hook_events)
    # The legitimately rotated token now fails too, as does the impersonation refresh.
    with pytest.raises(RevokedTokenError):
        await env.kit.admin_auth.refresh(refresh_token=rotated.refresh_token)
    with pytest.raises(RevokedTokenError):
        await env.kit.access.refresh_impersonation(imp.refresh_token)


async def test_logout_revokes_is_idempotent_and_noop_when_expired(env: Env) -> None:
    pair = await env.admin_login()
    await env.kit.admin_auth.logout(refresh_token=pair.refresh_token)
    with pytest.raises(RevokedTokenError):
        await env.kit.admin_auth.refresh(refresh_token=pair.refresh_token)
    await env.kit.admin_auth.logout(refresh_token=pair.refresh_token)
    assert (await _audit_actions(env)).count("auth.logout") == 1
    payload = jwt.decode(pair.refresh_token, options={"verify_signature": False})
    payload["exp"] = int(datetime.now(timezone.utc).timestamp()) - 3600
    expired = jwt.encode(payload, "admin" * 32, algorithm="HS256", headers={"kid": "admin"})
    await env.kit.admin_auth.logout(refresh_token=expired)
    with pytest.raises(InvalidTokenError):
        await env.kit.admin_auth.logout(refresh_token=pair.refresh_token[:-3] + "abc")


async def test_tenant_logout_and_logout_all(env: Env) -> None:
    admin = await env.admin_login()
    _, (user,) = await env.make_tenant(admin.claims, "acme", "u@example.com")
    first = await env.tenant_login("acme", user.email)
    second = await env.tenant_login("acme", user.email)
    await env.kit.tenant_auth.logout(refresh_token=first.refresh_token)
    with pytest.raises(RevokedTokenError):
        await env.kit.tenant_auth.refresh(refresh_token=first.refresh_token)
    assert await env.kit.tenant_auth.logout_all(actor=second.claims) == 1
    with pytest.raises(RevokedTokenError):
        await env.kit.tenant_auth.refresh(refresh_token=second.refresh_token)
    with pytest.raises(PermissionDeniedError):
        await env.kit.tenant_auth.logout_all(actor=admin.claims)


async def test_admin_logout_all_kills_impersonation_and_refuses_impersonation_actor(
    env: Env,
) -> None:
    admin = await env.admin_login()
    other = await env.admin_login()
    tenant, _ = await env.make_tenant(admin.claims, "acme")
    imp = await _impersonate(env, admin, tenant.id)
    with pytest.raises(PermissionDeniedError):
        await env.kit.admin_auth.logout_all(actor=imp.claims)
    assert await env.kit.admin_auth.logout_all(actor=admin.claims) == 3
    for token in (admin.refresh_token, other.refresh_token):
        with pytest.raises(RevokedTokenError):
            await env.kit.admin_auth.refresh(refresh_token=token)
    with pytest.raises(RevokedTokenError):
        await env.kit.access.refresh_impersonation(imp.refresh_token)


async def test_revoke_and_list_sessions_require_permissions(env: Env) -> None:
    root = await env.admin_login()
    cp = env.kit.control_plane
    reader = await cp.create_admin(root.claims, "a@example.com", PASSWORD, ["auditor"])
    manager = await cp.create_admin(root.claims, "b@example.com", PASSWORD, ["session_admin"])
    victim_pair = await env.admin_login()
    weak = (await env.admin_login("a@example.com")).claims
    strong = (await env.admin_login("b@example.com")).claims
    for call in (
        cp.revoke_sessions(weak, "admin", env.root.id),
        cp.list_sessions(weak, "admin", env.root.id),
    ):
        with pytest.raises(PermissionDeniedError):
            await call
    listed = await cp.list_sessions(strong, "admin", env.root.id)
    assert len(listed) == 2
    assert await cp.revoke_sessions(strong, "admin", env.root.id) == 2
    assert await cp.list_sessions(strong, "admin", env.root.id) == []
    assert len(await cp.list_sessions(strong, "admin", env.root.id, active_only=False)) == 2
    with pytest.raises(RevokedTokenError):
        await env.kit.admin_auth.refresh(refresh_token=victim_pair.refresh_token)
    revoked = await env.storage.audit_events.list(action="session.revoked")
    assert revoked[0].metadata == {"count": 2} and revoked[0].target_id == env.root.id
    assert reader.id != manager.id


async def test_deactivating_tenant_revokes_only_its_sessions(env: Env) -> None:
    admin = await env.admin_login()
    acme, (acme_user,) = await env.make_tenant(admin.claims, "acme", "a@example.com")
    _, (other_user,) = await env.make_tenant(admin.claims, "other", "o@example.com")
    acme_pair = await env.tenant_login("acme", acme_user.email)
    other_pair = await env.tenant_login("other", other_user.email)
    imp_acme = await _impersonate(env, admin, acme.id)
    other_tenant = await env.kit.control_plane.get_tenant(admin.claims, other_user.tenant_id)
    imp_other = await _impersonate(env, admin, other_tenant.id)
    await env.kit.control_plane.deactivate_tenant(admin.claims, acme.id)
    for session_id in (acme_pair.claims.sid, imp_acme.claims.sid):
        session = await env.storage.sessions.get(session_id)
        assert session is not None and session.revoked_reason == "tenant_deactivated"
    for session_id in (other_pair.claims.sid, imp_other.claims.sid, admin.claims.sid):
        session = await env.storage.sessions.get(session_id)
        assert session is not None and session.is_active
    await env.kit.tenant_auth.refresh(refresh_token=other_pair.refresh_token)


async def test_deactivation_and_password_change_revoke_sessions(env: Env) -> None:
    root = await env.admin_login()
    cp = env.kit.control_plane
    tenant, (user, user2, user3) = await env.make_tenant(
        root.claims, "acme", "u1@example.com", "u2@example.com", "u3@example.com"
    )
    p1 = await env.tenant_login("acme", user.email)
    p2 = await env.tenant_login("acme", user2.email)
    p3 = await env.tenant_login("acme", user3.email)
    await cp.deactivate_tenant_user(root.claims, user.id)
    await cp.update_tenant_user(root.claims, user2.id, password="another-passphrase-456")
    await env.kit.tenant_auth.change_password(
        actor=p3.claims, current=PASSWORD, new="yet-another-passphrase-789"
    )
    for pair, reason in (
        (p1, "subject_deactivated"),
        (p2, "password_changed"),
        (p3, "password_changed"),
    ):
        session = await env.storage.sessions.get(pair.claims.sid)
        assert session is not None and session.revoked_reason == reason
    # Admin deactivation (needs another managing admin) and admin password change.
    second = await cp.create_admin(
        root.claims, "second@example.com", PASSWORD, ["super_admin"], ImpersonationScope("all")
    )
    third = await cp.create_admin(root.claims, "third@example.com", PASSWORD, ["super_admin"])
    second_pair = await env.admin_login("second@example.com")
    third_pair = await env.admin_login("third@example.com")
    imp = await _impersonate(env, second_pair, tenant.id)
    await cp.deactivate_admin(root.claims, second.id)
    for sid, reason in (
        (second_pair.claims.sid, "subject_deactivated"),
        (imp.claims.sid, "parent_revoked"),
    ):
        session = await env.storage.sessions.get(sid)
        assert session is not None and session.revoked_reason == reason
    await env.kit.admin_auth.change_password(
        actor=third_pair.claims, current=PASSWORD, new="yet-another-passphrase-789"
    )
    session = await env.storage.sessions.get(third_pair.claims.sid)
    assert session is not None and session.revoked_reason == "password_changed"
    assert third.is_active


async def test_inactive_subject_on_refresh_revokes_session_that_persists(env: Env) -> None:
    root = await env.admin_login()
    _, (user,) = await env.make_tenant(root.claims, "acme", "u@example.com")
    pair = await env.tenant_login("acme", user.email)
    stored = await env.storage.tenant_users.get(user.id)
    assert stored is not None
    stored.is_active = False
    await env.storage.tenant_users.update(stored)
    with pytest.raises(InvalidTokenError):
        await env.kit.tenant_auth.refresh(refresh_token=pair.refresh_token)
    session = await env.storage.sessions.get(pair.claims.sid)
    assert session is not None and session.revoked_reason == "subject_deactivated"


async def test_revoked_admin_parent_blocks_impersonation_refresh_and_verify_active(
    env: Env,
) -> None:
    admin = await env.admin_login()
    tenant, _ = await env.make_tenant(admin.claims, "acme")
    imp = await _impersonate(env, admin, tenant.id)
    assert await env.kit.tokens.verify_active(imp.access_token)
    await env.storage.sessions.revoke(
        reason="logout", at=datetime.now(timezone.utc), session_id=admin.claims.sid
    )
    with pytest.raises(RevokedTokenError):
        await env.kit.tokens.verify_active(imp.access_token)
    with pytest.raises(RevokedTokenError):
        await env.kit.access.refresh_impersonation(imp.refresh_token)
    child = await env.storage.sessions.get(imp.claims.sid)
    assert child is not None and child.revoked_reason == "parent_revoked"


async def test_impersonation_session_never_outlives_parent(env: Env) -> None:
    admin = await env.admin_login()
    tenant, _ = await env.make_tenant(admin.claims, "acme")
    imp = await _impersonate(env, admin, tenant.id)
    parent = await env.storage.sessions.get(admin.claims.sid)
    child = await env.storage.sessions.get(imp.claims.sid)
    assert parent is not None and child is not None
    assert child.parent_id == parent.id and child.expires_at <= parent.expires_at
    refreshed = await env.kit.access.refresh_impersonation(imp.refresh_token)
    child = await env.storage.sessions.get(imp.claims.sid)
    assert child is not None and child.expires_at <= parent.expires_at
    assert refreshed.claims.sid == imp.claims.sid
    # Impersonation lifetime is also capped by the parent when the parent is nearly over.
    await env.storage.sessions.rotate(
        parent.id,
        expected_jti=parent.current_jti,
        new_jti=uuid4(),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
        used_at=datetime.now(timezone.utc),
    )
    short = await _impersonate(env, admin, tenant.id)
    assert short.refresh_expires_at <= datetime.now(timezone.utc) + timedelta(seconds=31)


async def test_end_impersonation(env: Env) -> None:
    admin = await env.admin_login()
    tenant, _ = await env.make_tenant(admin.claims, "acme")
    imp = await _impersonate(env, admin, tenant.id)
    await env.kit.access.end_impersonation(refresh_token=imp.refresh_token)
    await env.kit.access.end_impersonation(refresh_token=imp.refresh_token)
    with pytest.raises(RevokedTokenError):
        await env.kit.access.refresh_impersonation(imp.refresh_token)
    session = await env.storage.sessions.get(imp.claims.sid)
    assert session is not None and session.revoked_reason == "impersonation_ended"
    assert (await _audit_actions(env)).count("impersonation.ended") == 1
    parent = await env.storage.sessions.get(admin.claims.sid)
    assert parent is not None and parent.is_active


async def test_impersonate_requires_live_matching_admin_session(env: Env) -> None:
    admin = await env.admin_login()
    other = await env.admin_login()
    tenant, _ = await env.make_tenant(admin.claims, "acme")
    with pytest.raises(PermissionDeniedError):
        await env.kit.access.impersonate(
            actor=admin.claims,
            tenant_id=tenant.id,
            role="support",
            admin_refresh_token=other.refresh_token,
        )
    await env.kit.admin_auth.logout(refresh_token=admin.refresh_token)
    with pytest.raises(RevokedTokenError):
        await _impersonate(env, admin, tenant.id)


async def test_verify_is_storage_free_but_verify_active_rejects_revoked(env: Env) -> None:
    pair = await env.admin_login()
    await env.kit.admin_auth.logout(refresh_token=pair.refresh_token)

    class Exploding:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError("verify must not touch storage")

    bare = TokenService(make_config(), Exploding())  # type: ignore[arg-type]
    assert bare.verify(pair.access_token).sid == pair.claims.sid
    assert env.kit.tokens.verify(pair.access_token).sid == pair.claims.sid
    with pytest.raises(RevokedTokenError):
        await env.kit.tokens.verify_active(pair.access_token)
    with pytest.raises(WrongTokenTypeError):
        await env.kit.tokens.verify_active(pair.access_token, expected="tenant")
    # Unknown session -> InvalidTokenError (not Revoked).
    await env.storage.sessions.purge_expired(before=datetime.now(timezone.utc) + timedelta(days=1))
    with pytest.raises(InvalidTokenError) as info:
        await env.kit.tokens.verify_active(pair.access_token)
    assert not isinstance(info.value, RevokedTokenError)
    with pytest.raises(RuntimeError):
        await TokenService(make_config()).verify_active(pair.access_token)


async def test_tokens_without_sid_are_rejected(env: Env) -> None:
    pair = await env.admin_login()
    for token, kid, key in ((pair.access_token, "admin", "admin" * 32),):
        payload = jwt.decode(token, options={"verify_signature": False})
        del payload["sid"]
        legacy = jwt.encode(payload, key, algorithm="HS256", headers={"kid": kid})
        with pytest.raises(InvalidTokenError):
            env.kit.tokens.verify(legacy)
    payload = jwt.decode(pair.refresh_token, options={"verify_signature": False})
    del payload["sid"]
    legacy = jwt.encode(payload, "admin" * 32, algorithm="HS256", headers={"kid": "admin"})
    with pytest.raises(InvalidTokenError):
        await env.kit.admin_auth.refresh(refresh_token=legacy)


async def test_refresh_of_unknown_or_mismatched_session_is_rejected(env: Env) -> None:
    pair = await env.admin_login()
    await env.storage.sessions.purge_expired(
        before=datetime.now(timezone.utc) + timedelta(days=9999)
    )
    with pytest.raises(InvalidTokenError):
        await env.kit.admin_auth.refresh(refresh_token=pair.refresh_token)


async def test_purge_expired_sessions(env: Env) -> None:
    pair = await env.admin_login()
    assert await env.kit.sessions.purge_expired() == 0
    await env.kit.admin_auth.logout(refresh_token=pair.refresh_token)
    future = datetime.now(timezone.utc) + timedelta(seconds=5)
    assert await env.kit.sessions.purge_expired(before=future) == 1


async def test_lockout_still_trips_through_login_flow(env: Env) -> None:
    admin = await env.admin_login()
    _, (user,) = await env.make_tenant(admin.claims, "acme", "u@example.com")
    for subject in ("admin", "tenant"):
        for attempt in range(1, 7):
            expected = InvalidCredentialsError if attempt < 5 else AccountLockedError
            with pytest.raises(expected):
                if subject == "admin":
                    await env.kit.admin_auth.login(email="root@example.com", password="wrong")
                else:
                    await env.kit.tenant_auth.login(
                        tenant_slug="acme",
                        method="password",
                        credentials={"email": user.email, "password": "wrong"},
                    )
        attempt_row = await env.storage.login_attempts.get(
            "admin" if subject == "admin" else "tenant_user",
            env.root.id if subject == "admin" else user.id,
        )
        assert attempt_row is not None and attempt_row.failed_count == 5
        assert attempt_row.locked_until is not None
    locked = await env.storage.audit_events.list(action="auth.account.locked")
    assert len(locked) == 2
    failed = await env.storage.audit_events.list(action="auth.login.failed")
    assert len(failed) == 12
    # Correct password cannot log in while locked, and unlocking restores access.
    with pytest.raises(AccountLockedError):
        await env.kit.admin_auth.login(email="root@example.com", password=PASSWORD)
    await env.kit.control_plane.unlock_account(admin.claims, "admin", env.root.id)
    await env.admin_login()


async def test_admin_scope_object_defaults(env: Env) -> None:
    assert env.root.impersonation_scope == ImpersonationScope("all")


@pytest.mark.parametrize("round_", range(5))
async def test_racing_refreshes_trip_reuse_detection(env: Env, round_: int) -> None:
    """Decision A2: two refreshes with the same token end the session; one never wins both."""
    pair = await env.admin_login()
    results = await asyncio.gather(
        env.kit.admin_auth.refresh(refresh_token=pair.refresh_token),
        env.kit.admin_auth.refresh(refresh_token=pair.refresh_token),
        return_exceptions=True,
    )
    winners = [r for r in results if not isinstance(r, BaseException)]
    failures = [r for r in results if isinstance(r, BaseException)]
    assert len(winners) == 1 and len(failures) == 1, results
    assert isinstance(failures[0], RevokedTokenError)
    session = await env.storage.sessions.get(pair.claims.sid)
    assert session is not None and session.revoked_reason == "reuse_detected"
    reuse = await env.storage.audit_events.list(action="token.reuse_detected")
    assert len(reuse) == 1
    with pytest.raises(RevokedTokenError):
        await env.kit.admin_auth.refresh(refresh_token=winners[0].refresh_token)
