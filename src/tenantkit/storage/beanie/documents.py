"""Beanie documents, built per collection prefix and cached for the process (D11)."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from beanie import Document
from pydantic import Field
from pymongo import ASCENDING, DESCENDING, IndexModel

from tenantkit.domain.errors import ConfigError

COLLECTIONS = (
    "admins",
    "tenants",
    "tenant_users",
    "login_attempts",
    "sessions",
    "audit_events",
)


@dataclass(frozen=True)
class BeanieModels:
    """The adapter-internal Beanie document classes, one attribute per collection."""

    prefix: str
    admins: type[Document]
    tenants: type[Document]
    tenant_users: type[Document]
    login_attempts: type[Document]
    sessions: type[Document]
    audit_events: type[Document]

    @property
    def all(self) -> tuple[type[Document], ...]:
        return (
            self.admins,
            self.tenants,
            self.tenant_users,
            self.login_attempts,
            self.sessions,
            self.audit_events,
        )


_lock = threading.Lock()
_cached: BeanieModels | None = None


def _index(*keys: tuple[str, int], unique: bool = False) -> IndexModel:
    return IndexModel(list(keys), unique=unique)


def _build(prefix: str) -> BeanieModels:
    class AdminDoc(Document):
        id: UUID = Field(alias="_id")  # type: ignore[assignment]
        email: str
        password_hash: str
        roles: list[str]
        impersonation_mode: str
        impersonation_tenants: list[UUID]
        is_active: bool
        created_at: datetime
        updated_at: datetime

        class Settings:
            name = prefix + "admins"
            indexes = [_index(("email", ASCENDING), unique=True)]

    class TenantDoc(Document):
        id: UUID = Field(alias="_id")  # type: ignore[assignment]
        slug: str
        attributes: dict[str, Any]
        login_policy: dict[str, Any] | None = None
        is_active: bool
        created_at: datetime
        updated_at: datetime

        class Settings:
            name = prefix + "tenants"
            indexes = [_index(("slug", ASCENDING), unique=True)]

    class TenantUserDoc(Document):
        id: UUID = Field(alias="_id")  # type: ignore[assignment]
        tenant_id: UUID
        email: str
        password_hash: str
        roles: list[str]
        is_active: bool
        created_at: datetime
        updated_at: datetime

        class Settings:
            name = prefix + "tenant_users"
            indexes = [_index(("email", ASCENDING), unique=True), _index(("tenant_id", ASCENDING))]

    class LoginAttemptDoc(Document):
        id: UUID = Field(alias="_id")  # type: ignore[assignment]
        subject_type: str
        subject_id: UUID
        failed_count: int
        locked_until: datetime | None = None

        class Settings:
            name = prefix + "login_attempts"
            indexes = [_index(("subject_type", ASCENDING), ("subject_id", ASCENDING), unique=True)]

    class SessionDoc(Document):
        id: UUID = Field(alias="_id")  # type: ignore[assignment]
        kind: str
        subject_id: UUID
        tenant_id: UUID | None = None
        parent_id: UUID | None = None
        current_jti: UUID
        expires_at: datetime
        created_at: datetime
        last_used_at: datetime
        revoked_at: datetime | None = None
        revoked_reason: str | None = None

        class Settings:
            name = prefix + "sessions"
            indexes = [
                _index(("kind", ASCENDING), ("subject_id", ASCENDING), ("created_at", DESCENDING)),
                _index(("tenant_id", ASCENDING)),
                _index(("parent_id", ASCENDING)),
                _index(("expires_at", ASCENDING)),
            ]

    class AuditEventDoc(Document):
        id: UUID = Field(alias="_id")  # type: ignore[assignment]
        action: str
        outcome: str
        actor_type: str
        actor_id: UUID | None = None
        impersonator_id: UUID | None = None
        tenant_id: UUID | None = None
        target_type: str | None = None
        target_id: UUID | None = None
        session_id: UUID | None = None
        token_jti: UUID | None = None
        reason: str | None = None
        metadata: dict[str, Any]
        occurred_at: datetime

        class Settings:
            name = prefix + "audit_events"
            indexes = [
                _index(("occurred_at", DESCENDING), ("_id", DESCENDING)),
                _index(("tenant_id", ASCENDING), ("occurred_at", DESCENDING)),
                _index(("actor_id", ASCENDING)),
                _index(("target_id", ASCENDING)),
                _index(("action", ASCENDING)),
            ]

    return BeanieModels(
        prefix=prefix,
        admins=AdminDoc,
        tenants=TenantDoc,
        tenant_users=TenantUserDoc,
        login_attempts=LoginAttemptDoc,
        sessions=SessionDoc,
        audit_events=AuditEventDoc,
    )


def document_models(prefix: str = "mt_") -> BeanieModels:
    """Build (once per process) the document classes to pass to the host's ``init_beanie``."""
    global _cached
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", prefix):
        raise ConfigError("Invalid collection prefix")
    with _lock:
        if _cached is not None:
            if _cached.prefix != prefix:
                raise ConfigError(
                    "document_models was already called with a different prefix in this process"
                )
            return _cached
        _cached = _build(prefix)
        return _cached


def _reset_for_tests() -> None:
    """Forget the cached models. Only for tests that exercise the one-prefix rule."""
    global _cached
    with _lock:
        _cached = None
