from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

TokenType = Literal["admin", "tenant", "impersonation"]


class BaseClaims(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)
    iss: str
    aud: str
    sub: str
    typ: TokenType
    use: Literal["access", "refresh"]
    iat: int
    nbf: int
    exp: int
    jti: UUID
    roles: tuple[str, ...] = ()
    perms: tuple[str, ...] = ()
    email: str = ""


class AdminClaims(BaseClaims):
    typ: Literal["admin"] = "admin"


class TenantClaims(BaseClaims):
    typ: Literal["tenant"] = "tenant"
    tenant_id: UUID = Field(alias="tid")
    tenant_slug: str = Field(alias="tslug")


class ImpersonationClaims(BaseClaims):
    typ: Literal["impersonation"] = "impersonation"
    tenant_id: UUID = Field(alias="tid")
    tenant_slug: str = Field(alias="tslug")
    act: dict[str, str]
    reason: str | None = None


class RefreshClaims(BaseClaims):
    impersonation_role: str | None = None
    admin_refresh_exp: int | None = None
    reason: str | None = None
    tenant_id: UUID | None = Field(default=None, alias="tid")


class TokenPair(BaseModel):
    claims: AdminClaims | TenantClaims | ImpersonationClaims
    model_config = ConfigDict(frozen=True)
    access_token: str = Field(repr=False)
    refresh_token: str = Field(repr=False)
    token_type: str = "bearer"
    expires_in: int
