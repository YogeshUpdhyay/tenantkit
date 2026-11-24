"""Session lifecycle: create, load, rotate with reuse detection, and revoke."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from uuid import UUID

from tenantkit.audit.service import AuditService, actor_fields
from tenantkit.config.models import TenantKitConfig
from tenantkit.domain.claims import RefreshClaims, TokenPair
from tenantkit.domain.errors import InvalidTokenError, RevokedTokenError, StorageError
from tenantkit.domain.models import AuditEvent, RevokeReason, Session, SessionKind, now
from tenantkit.storage.interfaces import Storage
from tenantkit.tokens.service import TokenService


class SessionService:
    def __init__(
        self,
        config: TenantKitConfig,
        storage: Storage,
        audit: AuditService,
        tokens: TokenService,
    ) -> None:
        self.config = config
        self.storage = storage
        self.audit = audit
        self.tokens = tokens

    async def create(
        self,
        *,
        pair: TokenPair,
        kind: SessionKind,
        subject_id: UUID,
        tenant_id: UUID | None = None,
        parent_id: UUID | None = None,
    ) -> Session:
        return await self.storage.sessions.create(
            Session(
                id=pair.claims.sid,
                kind=kind,
                subject_id=subject_id,
                tenant_id=tenant_id,
                parent_id=parent_id,
                current_jti=pair.refresh_jti,
                expires_at=pair.refresh_expires_at,
            )
        )

    async def load(self, claims: RefreshClaims) -> Session:
        """The live session behind a verified refresh token."""
        session = await self.storage.sessions.get(claims.sid)
        if session is None or session.kind != claims.typ or str(session.subject_id) != claims.sub:
            raise InvalidTokenError("Unknown session")
        if not session.is_active:
            raise RevokedTokenError("Session revoked or expired")
        return session

    async def rotate(
        self,
        *,
        claims: RefreshClaims,
        pair: TokenPair,
        action: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Swap the session's refresh jti; a stale jti revokes the whole session."""
        rotated: Session | None
        try:
            async with self.audit.recorder() as rec:
                rotated = await self.storage.sessions.rotate(
                    claims.sid,
                    expected_jti=claims.jti,
                    new_jti=pair.refresh_jti,
                    expires_at=pair.refresh_expires_at,
                    used_at=now(),
                )
                if rotated is not None:
                    await rec.emit(
                        AuditEvent(
                            **{
                                **actor_fields(claims),
                                "action": action,
                                "outcome": "success",
                                "target_type": "session",
                                "target_id": claims.sid,
                                "metadata": metadata or {},
                            }
                        )
                    )
        except StorageError:
            # Adapters whose transactions run concurrently (MongoDB) can fail the losing
            # side of a refresh race with a write conflict instead of returning None.
            if not await self._lost_rotation_race(claims):
                raise
            rotated = None
        if rotated is None:
            # The recorder has exited, so no transaction is open and these writes persist
            # even though the error below propagates.
            async with self.audit.recorder() as rec:
                await self.storage.sessions.revoke(
                    reason=RevokeReason.REUSE_DETECTED,
                    at=now(),
                    session_id=claims.sid,
                    cascade_children=True,
                )
                await rec.emit(
                    AuditEvent(
                        **{
                            **actor_fields(claims),
                            "action": "token.reuse_detected",
                            "outcome": "failure",
                            "target_type": "session",
                            "target_id": claims.sid,
                        }
                    )
                )
            raise RevokedTokenError("Refresh token reuse detected")

    async def _lost_rotation_race(self, claims: RefreshClaims) -> bool:
        """True when the session moved on without us: another refresh won, or it was revoked."""
        for delay in (0.0, 0.02, 0.05, 0.1, 0.25, 0.5):
            await asyncio.sleep(delay)
            session = await self.storage.sessions.get(claims.sid)
            if session is None or session.revoked_at is not None:
                return True
            if session.current_jti != claims.jti:
                return True
        return False

    async def revoke(
        self,
        *,
        reason: str,
        session_id: UUID | None = None,
        kind: SessionKind | None = None,
        subject_id: UUID | None = None,
        tenant_id: UUID | None = None,
        cascade_children: bool = False,
    ) -> int:
        return await self.storage.sessions.revoke(
            reason=reason,
            at=now(),
            session_id=session_id,
            kind=kind,
            subject_id=subject_id,
            tenant_id=tenant_id,
            cascade_children=cascade_children,
        )

    async def revoke_standalone(self, **filters: Any) -> int:
        """Revoke in its own transaction, for use right before raising an error."""
        if self.storage.in_transaction():
            raise RuntimeError("revoke_standalone must not run inside a transaction")
        async with self.storage.transaction():
            return await self.revoke(**filters)

    async def purge_expired(self, *, before: datetime | None = None) -> int:
        async with self.storage.transaction():
            return await self.storage.sessions.purge_expired(before=before or now())
