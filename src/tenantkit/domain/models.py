from dataclasses import dataclass, field
from datetime import datetime, timezone
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
