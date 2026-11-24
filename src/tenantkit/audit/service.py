"""Append-only audit trail written in the same transaction as the change it records."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime
from typing import Any
from uuid import UUID

from tenantkit.domain.permissions import has_permission
from tenantkit.config.models import TenantKitConfig
from tenantkit.domain.errors import PermissionDeniedError
from tenantkit.domain.models import AuditEvent, now
from tenantkit.storage.interfaces import Storage

AuditHook = Callable[[AuditEvent], Awaitable[None]]
log = logging.getLogger("tenantkit.audit")


def actor_fields(claims: Any) -> dict[str, Any]:
    """Event fields describing the holder of a verified access or refresh token."""
    fields: dict[str, Any] = {
        "actor_id": UUID(claims.sub),
        "session_id": claims.sid,
        "token_jti": claims.jti,
    }
    tenant_id = getattr(claims, "tenant_id", None)
    if tenant_id is not None:
        fields["tenant_id"] = tenant_id
    if claims.typ == "tenant":
        fields["actor_type"] = "tenant_user"
    else:
        fields["actor_type"] = "admin"
        if claims.typ == "impersonation":
            act = getattr(claims, "act", None)
            fields["impersonator_id"] = UUID(act["sub"]) if act else UUID(claims.sub)
    return fields


class Recorder:
    """Handle yielded by ``AuditService.recorder``; events are queued until commit."""

    def __init__(self, storage: Storage) -> None:
        self._storage = storage
        self.events: list[AuditEvent] = []

    async def emit(self, event: AuditEvent) -> None:
        await self._storage.audit_events.append(event)
        self.events.append(event)


class AuditService:
    def __init__(
        self,
        config: TenantKitConfig,
        storage: Storage,
        hooks: Sequence[AuditHook] | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.hooks = tuple(hooks or ())
        self._active: ContextVar[tuple[asyncio.Task[Any] | None, Recorder] | None] = ContextVar(
            "tenantkit_audit_recorder", default=None
        )

    @asynccontextmanager
    async def recorder(self) -> AsyncIterator[Recorder]:
        """One transaction for a state change and its events; hooks fire after commit."""
        current = self._active.get()
        task = asyncio.current_task()
        if current is not None and current[0] is task:
            yield current[1]
            return
        if self.storage.in_transaction():
            raise RuntimeError(
                "tenantkit operations must not run inside a host-opened storage transaction"
            )
        rec = Recorder(self.storage)
        token = self._active.set((task, rec))
        try:
            async with self.storage.transaction():
                yield rec
        finally:
            self._active.reset(token)
        await self._dispatch(rec.events)

    async def emit_standalone(self, event: AuditEvent) -> None:
        """Write a failure event in its own transaction; never call inside a transaction."""
        if self.storage.in_transaction():
            raise RuntimeError("emit_standalone must not run inside a transaction")
        async with self.recorder() as rec:
            await rec.emit(event)

    async def _dispatch(self, events: Sequence[AuditEvent]) -> None:
        for event in events:
            for hook in self.hooks:
                try:
                    await hook(event)
                except Exception:
                    log.error("Audit hook failed for event %s (%s)", event.id, event.action)

    async def _visible_tenants(self, actor: Any) -> tuple[bool, set[UUID]]:
        if actor.typ != "admin" or actor.use != "access":
            raise PermissionDeniedError("Admin access required")
        admin = await self.storage.admins.get(UUID(actor.sub))
        if admin is None or not admin.is_active:
            raise PermissionDeniedError("Inactive admin")
        scope = admin.impersonation_scope
        if "*" in actor.perms or scope.mode == "all":
            return True, set()
        if scope.mode == "list":
            return False, set(scope.tenant_ids)
        raise PermissionDeniedError("Audit visibility denied")

    async def list(
        self,
        actor: Any,
        *,
        tenant_id: UUID | None = None,
        actor_id: UUID | None = None,
        target_id: UUID | None = None,
        action: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]:
        if actor.typ != "admin" or actor.use != "access" or not has_permission(actor, "audit:read"):
            raise PermissionDeniedError("Permission denied")
        everything, visible = await self._visible_tenants(actor)
        tenant_ids: list[UUID] | None
        if everything:
            tenant_ids = [tenant_id] if tenant_id is not None else None
        elif tenant_id is not None:
            if tenant_id not in visible:
                raise PermissionDeniedError("Tenant outside audit scope")
            tenant_ids = [tenant_id]
        else:
            tenant_ids = sorted(visible, key=str)
        return await self.storage.audit_events.list(
            tenant_ids=tenant_ids,
            actor_id=actor_id,
            target_id=target_id,
            action=action,
            since=since,
            until=until,
            limit=min(max(limit, 1), 500),
            offset=max(offset, 0),
        )

    async def purge(self, actor: Any, *, before: datetime) -> int:
        if (
            actor.typ != "admin"
            or actor.use != "access"
            or not has_permission(actor, "audit:purge")
        ):
            raise PermissionDeniedError("Permission denied")
        async with self.recorder() as rec:
            count = await self.storage.audit_events.purge(before=before)
            await rec.emit(
                AuditEvent(
                    action="audit.purged",
                    outcome="success",
                    occurred_at=now(),
                    metadata={"before": before.isoformat(), "count": count},
                    **actor_fields(actor),
                )
            )
        return count
