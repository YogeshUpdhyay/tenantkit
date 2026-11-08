from dataclasses import dataclass
from typing import Any, Literal, Protocol
from uuid import UUID


@dataclass(frozen=True)
class AuthRequest:
    subject_type: str
    credentials: dict[str, Any]
    tenant_id: UUID | None = None


@dataclass(frozen=True)
class AuthResult:
    status: Literal["success", "failure", "challenge"]
    subject_id: UUID | None = None
    reason: str | None = None
    challenge: Any = None


class AuthProvider(Protocol):
    name: str
    subject_types: set[str]

    async def authenticate(self, request: AuthRequest, policy: Any) -> AuthResult: ...
