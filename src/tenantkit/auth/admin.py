from dataclasses import asdict
from typing import Any
from uuid import UUID, uuid4

from tenantkit.audit.service import AuditService, actor_fields
from tenantkit.auth.hashing import Hashing
from tenantkit.auth.providers.base import AuthProvider, AuthRequest, AuthResult
from tenantkit.config.models import TenantKitConfig
from tenantkit.domain.claims import TokenPair
from tenantkit.domain.errors import (
    AccountLockedError,
    ExpiredTokenError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
)
from tenantkit.domain.models import Admin, AuditEvent, RevokeReason
from tenantkit.sessions.service import SessionService
from tenantkit.storage.interfaces import Storage
from tenantkit.tokens.service import TokenService


class AdminAuthService:
    def __init__(
        self,
        config: TenantKitConfig,
        storage: Storage,
        tokens: TokenService,
        hashing: Hashing,
        providers: dict[str, AuthProvider],
        audit: AuditService,
        sessions: SessionService,
    ) -> None:
        self.config = config
        self.storage = storage
        self.tokens = tokens
        self.hashing = hashing
        self.providers = providers
        self.audit = audit
        self.sessions = sessions

    async def _fail(self, email: str, result: AuthResult | None) -> None:
        """Persist failure events before the caller raises; must run outside a transaction."""
        metadata: dict[str, Any] = {"subject_type": "admin"}
        if self.config.audit.include_failed_login_email:
            metadata["email"] = email
        async with self.audit.recorder() as rec:
            await rec.emit(
                AuditEvent(
                    action="auth.login.failed",
                    outcome="failure",
                    actor_type="anonymous",
                    metadata=metadata,
                )
            )
            if result is not None and result.newly_locked and result.subject_id is not None:
                await rec.emit(
                    AuditEvent(
                        action="auth.account.locked",
                        outcome="failure",
                        actor_type="anonymous",
                        target_type="account",
                        target_id=result.subject_id,
                        metadata={"subject_type": "admin"},
                    )
                )

    async def _authenticate(self, email: str, password: str) -> Admin:
        policy = self.config.admin_auth.policy
        result = await self.providers[policy.providers[0]].authenticate(
            AuthRequest("admin", {"email": email, "password": password}), policy
        )
        admin = None
        if result.status == "success" and result.subject_id is not None:
            admin = await self.storage.admins.get(result.subject_id)
        if admin is None or not admin.is_active:
            await self._fail(email, result)
            if result.reason == "locked":
                raise AccountLockedError()
            raise InvalidCredentialsError()
        return admin

    async def login(self, *, email: str, password: str) -> TokenPair:
        admin = await self._authenticate(email, password)
        session_id = uuid4()
        async with self.audit.recorder() as rec:
            pair = self.tokens.issue_pair(typ="admin", subject=admin, session_id=session_id)
            await self.sessions.create(pair=pair, kind="admin", subject_id=admin.id)
            await rec.emit(
                AuditEvent(
                    **{
                        **actor_fields(pair.claims),
                        "action": "auth.login.succeeded",
                        "outcome": "success",
                        "target_type": "session",
                        "target_id": session_id,
                    }
                )
            )
        return pair

    async def refresh(self, *, refresh_token: str) -> TokenPair:
        claims = self.tokens.verify_refresh(refresh_token, expected="admin")
        session = await self.sessions.load(claims)
        admin = await self.storage.admins.get(UUID(claims.sub))
        if admin is None or not admin.is_active:
            await self.sessions.revoke_standalone(
                session_id=session.id, reason=RevokeReason.SUBJECT_DEACTIVATED
            )
            raise InvalidTokenError("Inactive account")
        pair = self.tokens.issue_pair(typ="admin", subject=admin, session_id=session.id)
        await self.sessions.rotate(claims=claims, pair=pair, action="auth.token.refreshed")
        return pair

    async def logout(self, *, refresh_token: str) -> None:
        """Revoke the session behind a refresh token. Idempotent; expired tokens are a no-op."""
        try:
            claims = self.tokens.verify_refresh(refresh_token, expected="admin")
        except ExpiredTokenError:
            return
        async with self.audit.recorder() as rec:
            count = await self.sessions.revoke(
                session_id=claims.sid, reason=RevokeReason.LOGOUT, cascade_children=True
            )
            if count:
                await rec.emit(
                    AuditEvent(
                        **{
                            **actor_fields(claims),
                            "action": "auth.logout",
                            "outcome": "success",
                            "target_type": "session",
                            "target_id": claims.sid,
                        }
                    )
                )

    async def logout_all(self, *, actor: Any) -> int:
        admin = await self._subject(actor)
        async with self.audit.recorder() as rec:
            count = await self.sessions.revoke(
                kind="admin",
                subject_id=admin.id,
                reason=RevokeReason.LOGOUT_ALL,
                cascade_children=True,
            )
            await rec.emit(
                AuditEvent(
                    **{
                        **actor_fields(actor),
                        "action": "auth.logout_all",
                        "outcome": "success",
                        "target_type": "admin",
                        "target_id": admin.id,
                        "metadata": {"count": count},
                    }
                )
            )
        return count

    async def me(self, *, actor: Any) -> dict[str, Any]:
        admin = await self._subject(actor)
        data = asdict(admin)
        data.pop("password_hash")
        return data

    async def _subject(self, actor: Any) -> Admin:
        if actor.typ != "admin" or actor.use != "access":
            raise PermissionDeniedError("Admin access required")
        admin = await self.storage.admins.get(UUID(actor.sub))
        if admin is None or not admin.is_active:
            raise InvalidCredentialsError()
        return admin

    async def change_password(self, *, actor: Any, current: str, new: str) -> None:
        admin = await self._subject(actor)
        if not self.hashing.verify(admin.password_hash, current):
            raise InvalidCredentialsError()
        self.hashing.validate(new, admin.email, self.config.admin_auth.password)
        admin.password_hash = self.hashing.hash(new)
        async with self.audit.recorder() as rec:
            await self.storage.admins.update(admin)
            await self.sessions.revoke(
                kind="admin",
                subject_id=admin.id,
                reason=RevokeReason.PASSWORD_CHANGED,
                cascade_children=True,
            )
            await rec.emit(
                AuditEvent(
                    **{
                        **actor_fields(actor),
                        "action": "auth.password.changed",
                        "outcome": "success",
                        "target_type": "admin",
                        "target_id": admin.id,
                    }
                )
            )
