from datetime import timedelta
import re
from typing import Any, Literal, Self
from types import MappingProxyType
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
    field_serializer,
)
from tenantkit.domain.errors import ConfigError


class FrozenModel(BaseModel):
    @model_validator(mode="after")
    def freeze_mappings(self) -> Self:
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, dict):
                object.__setattr__(self, name, MappingProxyType(value))
        return self

    @field_serializer("*", check_fields=False)
    def serialize_value(self, value: Any) -> Any:
        return dict(value) if isinstance(value, MappingProxyType) else value

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


class TokenTypeConfig(FrozenModel):
    private_key: SecretStr
    public_key: SecretStr | None = None
    kid: str
    algorithm: Literal["HS256", "RS256", "ES256"] = "HS256"
    access_ttl: timedelta = timedelta(minutes=15)
    refresh_ttl: timedelta = timedelta(hours=8)

    @model_validator(mode="before")
    @classmethod
    def seconds(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            for name in ("access", "refresh"):
                key = name + "_ttl_seconds"
                if key in value:
                    value[name + "_ttl"] = timedelta(seconds=value.pop(key))
        return value


class TokensConfig(FrozenModel):
    admin: TokenTypeConfig
    tenant: TokenTypeConfig
    impersonation: TokenTypeConfig

    @model_validator(mode="before")
    @classmethod
    def defaults(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            for typ, access, refresh in [("tenant", 900, 604800), ("impersonation", 600, 3600)]:
                if isinstance(value.get(typ), dict):
                    item = dict(value[typ])
                    if "access_ttl" not in item and "access_ttl_seconds" not in item:
                        item["access_ttl_seconds"] = access
                    if "refresh_ttl" not in item and "refresh_ttl_seconds" not in item:
                        item["refresh_ttl_seconds"] = refresh
                    value[typ] = item
        return value


class PasswordRules(FrozenModel):
    max_length: int = 128
    disallow_email_in_password: bool = True
    min_length: int = Field(default=12, ge=8)


class LoginPolicy(FrozenModel):
    providers: tuple[str, ...] = ("password",)
    password: PasswordRules = Field(default_factory=PasswordRules)


class LockoutRules(FrozenModel):
    max_attempts: int = Field(default=5, ge=1)
    lock_minutes: int = Field(default=15, ge=1)


class AuthConfig(FrozenModel):
    policy: LoginPolicy = Field(default_factory=LoginPolicy)
    default_policy: LoginPolicy = Field(default_factory=LoginPolicy)
    password: PasswordRules = Field(default_factory=PasswordRules)
    lockout: LockoutRules = Field(default_factory=LockoutRules)


class RoleConfig(FrozenModel):
    permissions: tuple[str, ...] = ()


class RolesConfig(FrozenModel):
    admin: dict[str, RoleConfig] = Field(
        default_factory=lambda: {"super_admin": RoleConfig(permissions=("*",))}
    )
    tenant: dict[str, RoleConfig] = Field(default_factory=dict)
    impersonation: dict[str, RoleConfig] = Field(default_factory=dict)


class ImpersonationConfig(FrozenModel):
    enabled: bool = True
    default_scope: Literal["all", "list", "none"] = "none"
    allowed_roles: dict[str, tuple[str, ...]] = Field(default_factory=dict)


class Argon2Config(FrozenModel):
    time_cost: int = Field(default=3, ge=1)
    memory_cost_kib: int = Field(default=65536, ge=8192)
    parallelism: int = Field(default=2, ge=1)


class HashingConfig(FrozenModel):
    argon2: Argon2Config = Field(default_factory=Argon2Config)


class ClockConfig(FrozenModel):
    skew_seconds: int = Field(default=30, ge=0)


class TenantField(FrozenModel):
    name: str
    type: Literal["string", "integer", "number", "boolean", "date", "object", "list"]
    required: bool = False
    default: Any = None
    min_length: int | None = None
    max_length: int | None = None
    pattern: str | None = None
    choices: tuple[Any, ...] | None = None
    min: float | None = None
    max: float | None = None
    fields: tuple["TenantField", ...] = ()
    item_type: str | None = None
    min_items: int | None = None
    max_items: int | None = None


class TenantSchema(FrozenModel):
    fields: tuple[TenantField, ...] = ()


class TenantKitConfig(FrozenModel):
    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError as exc:
            raise ConfigError(
                "; ".join(
                    ".".join(map(str, e["loc"])) + ": " + e["type"]
                    for e in exc.errors(include_input=False)
                )
            ) from None

    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    tokens: TokensConfig
    admin_auth: AuthConfig = Field(default_factory=AuthConfig)
    tenant_auth: AuthConfig = Field(default_factory=AuthConfig)
    tenant_schema: TenantSchema = Field(default_factory=TenantSchema)
    roles: RolesConfig = Field(default_factory=RolesConfig)
    impersonation: ImpersonationConfig = Field(default_factory=ImpersonationConfig)
    hashing: HashingConfig = Field(default_factory=HashingConfig)
    clock: ClockConfig = Field(default_factory=ClockConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(
                "; ".join(
                    ".".join(map(str, e["loc"])) + ": " + e["msg"]
                    for e in exc.errors(include_input=False)
                )
            ) from None

    @model_validator(mode="after")
    def validate_tree(self) -> Self:
        errors: list[str] = []
        keys: set[str] = set()
        kids: set[str] = set()
        for typ in ("admin", "tenant", "impersonation"):
            cfg: TokenTypeConfig = getattr(self.tokens, typ)
            key = cfg.private_key.get_secret_value()
            if key in keys:
                errors.append(f"tokens.{typ}.private_key: shared key")
            if cfg.kid in kids:
                errors.append(f"tokens.{typ}.kid: duplicate")
            keys.add(key)
            kids.add(cfg.kid)
            if cfg.algorithm == "HS256" and len(key.encode()) < 32:
                errors.append(f"tokens.{typ}.private_key: minimum 32 bytes")
            if cfg.access_ttl.total_seconds() <= 0 or cfg.refresh_ttl <= cfg.access_ttl:
                errors.append(f"tokens.{typ}: invalid lifetimes")
        if (
            self.tokens.impersonation.access_ttl > self.tokens.admin.access_ttl
            or self.tokens.impersonation.refresh_ttl > self.tokens.admin.refresh_ttl
        ):
            errors.append("tokens.impersonation: exceeds admin lifetime")
        names: set[str] = set()
        for category in ("admin", "tenant", "impersonation"):
            registry: dict[str, RoleConfig] = getattr(self.roles, category)
            for name, role in registry.items():
                if name in names:
                    errors.append("roles: duplicate role " + name)
                names.add(name)
                if any(
                    "*" in p and p != "*" and (not p.endswith(":*") or p.count("*") != 1)
                    for p in role.permissions
                ):
                    errors.append("roles: invalid wildcard")
        for role, allowed in self.impersonation.allowed_roles.items():
            if role not in self.roles.admin or any(
                r not in self.roles.impersonation for r in allowed
            ):
                errors.append("impersonation.allowed_roles: unknown role")
        for policy in (self.admin_auth.policy, self.tenant_auth.default_policy):
            if not policy.providers or any(not p for p in policy.providers):
                errors.append("auth.policy: unregistered provider")
        if len({f.name for f in self.tenant_schema.fields}) != len(self.tenant_schema.fields):
            errors.append("tenant_schema.fields: duplicate names")

        def check_fields(fields: tuple[TenantField, ...], path: str) -> None:
            seen: set[str] = set()
            for field in fields:
                here = path + "." + field.name
                if not field.name or field.name in seen:
                    errors.append(here + ": duplicate or empty field name")
                seen.add(field.name)
                if field.pattern is not None:
                    try:
                        re.compile(field.pattern)
                    except re.error:
                        errors.append(here + ": invalid pattern")
                for minimum, maximum in (
                    (field.min, field.max),
                    (field.min_length, field.max_length),
                    (field.min_items, field.max_items),
                ):
                    if minimum is not None and maximum is not None and minimum > maximum:
                        errors.append(here + ": contradictory bounds")
                if any(
                    bound is not None and bound < 0
                    for bound in (
                        field.min_length,
                        field.max_length,
                        field.min_items,
                        field.max_items,
                    )
                ):
                    errors.append(here + ": negative length")
                if field.type == "list" and field.item_type not in (
                    "string",
                    "integer",
                    "number",
                    "boolean",
                    "date",
                    "object",
                    "list",
                ):
                    errors.append(here + ": invalid list item type")
                check_fields(field.fields, here)

        check_fields(self.tenant_schema.fields, "tenant_schema")
        if errors:
            raise ConfigError("; ".join(errors))
        return self
