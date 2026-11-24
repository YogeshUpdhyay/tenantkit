from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections.abc import Mapping
from typing import Any, Literal
from uuid import UUID, uuid4


def now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ImpersonationScope:
    mode: Literal["all", "list", "none"] = "none"
    tenant_ids: list[UUID] = field(default_factory=list)


@dataclass(kw_only=True)
class Admin:
    email: str
    password_hash: str = field(repr=False)
    roles: list[str] = field(default_factory=list)
    impersonation_scope: ImpersonationScope = field(default_factory=ImpersonationScope)
    id: UUID = field(default_factory=uuid4)
    is_active: bool = True
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)


@dataclass(kw_only=True)
class Tenant:
    slug: str
    attributes: dict[str, Any] = field(default_factory=dict)
    login_policy: Any = None
    id: UUID = field(default_factory=uuid4)
    is_active: bool = True
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)


@dataclass(kw_only=True)
class TenantUser:
    tenant_id: UUID
    email: str
    password_hash: str = field(repr=False)
    roles: list[str] = field(default_factory=list)
    id: UUID = field(default_factory=uuid4)
    is_active: bool = True
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)


@dataclass(kw_only=True)
class LoginAttempt:
    subject_type: str
    subject_id: UUID
    failed_count: int = 0
    locked_until: datetime | None = None


SessionKind = Literal["admin", "tenant", "impersonation"]  # equals the token `typ`


class RevokeReason:
    """String constants stored as text in ``Session.revoked_reason``."""

    LOGOUT = "logout"
    LOGOUT_ALL = "logout_all"
    ADMIN_REVOKED = "admin_revoked"
    SUBJECT_DEACTIVATED = "subject_deactivated"
    TENANT_DEACTIVATED = "tenant_deactivated"
    PASSWORD_CHANGED = "password_changed"
    REUSE_DETECTED = "reuse_detected"
    PARENT_REVOKED = "parent_revoked"
    IMPERSONATION_ENDED = "impersonation_ended"


@dataclass(kw_only=True)
class Session:
    kind: SessionKind
    subject_id: UUID  # admin id (admin, impersonation) or tenant user id
    tenant_id: UUID | None = None  # tenant user's tenant, or impersonation target
    parent_id: UUID | None = None  # impersonation only: the admin session that started it
    current_jti: UUID  # jti of the only refresh token currently accepted
    expires_at: datetime  # refresh expiry of the current refresh token
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=now)
    last_used_at: datetime = field(default_factory=now)
    revoked_at: datetime | None = None
    revoked_reason: str | None = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > now()


AuditOutcome = Literal["success", "failure"]
ActorType = Literal["admin", "tenant_user", "system", "anonymous"]


@dataclass(kw_only=True, frozen=True)
class AuditEvent:
    action: str
    outcome: AuditOutcome
    actor_type: ActorType
    actor_id: UUID | None = None
    impersonator_id: UUID | None = None
    tenant_id: UUID | None = None
    target_type: str | None = None
    target_id: UUID | None = None
    session_id: UUID | None = None
    token_jti: UUID | None = None
    reason: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=now)
