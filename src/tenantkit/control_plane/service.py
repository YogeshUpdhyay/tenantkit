import re
from typing import Any, Literal, cast
from uuid import UUID
from tenantkit.config.models import LoginPolicy, TenantKitConfig
from tenantkit.audit.service import AuditService, actor_fields
from tenantkit.sessions.service import SessionService
from tenantkit.storage.interfaces import Storage
from tenantkit.access.checks import AccessService
from tenantkit.auth.hashing import Hashing
from tenantkit.domain.models import (
    Admin,
    AuditEvent,
    ImpersonationScope,
    RevokeReason,
    Session,
    Tenant,
    TenantUser,
)
from tenantkit.domain.errors import (
    AlreadyBootstrappedError,
    InvalidSlugError,
    LastAdminError,
    NotFoundError,
    PermissionDeniedError,
    TenantValidationError,
    ConfigError,
)
from tenantkit.control_plane.schema import validate_attributes


class ControlPlaneService:
    def __init__(
        self,
        config: TenantKitConfig,
        storage: Storage,
        access: AccessService,
        hashing: Hashing,
        providers: Any,
        audit: AuditService,
        sessions: SessionService,
    ) -> None:
        self.audit = audit
        self.sessions = sessions
        self.config = config
        self.storage = storage
        self.access = access
        self.hashing = hashing
        self.providers = providers

    def _authorize(self, actor: Any, permission: str) -> None:
        if actor.typ != "admin" or actor.use != "access":
            raise PermissionDeniedError("Admin access required")
        self.access.require_permission(actor, permission)

    @staticmethod
    def _event(actor: Any, action: str, **fields: Any) -> AuditEvent:
        return AuditEvent(
            **{**actor_fields(actor), "action": action, "outcome": "success", **fields}
        )

    def _roles(self, category: str, roles: list[str]) -> None:
        registry = getattr(self.config.roles, category)
        if any(role not in registry for role in roles):
            raise ConfigError("Unknown role for category " + category)

    def _policy(self, policy: Any) -> LoginPolicy:
        result = LoginPolicy.model_validate(policy) if isinstance(policy, dict) else policy
        if not result.providers or any(name not in self.providers for name in result.providers):
            raise ConfigError("Unknown provider")
        if result.password.min_length < self.config.tenant_auth.password.min_length:
            raise ConfigError("Tenant password policy cannot weaken minimum")
        return cast(LoginPolicy, result)

    async def bootstrap_super_admin(self, email: str, password: str) -> Admin:
        async with self.audit.recorder() as rec:
            if await self.storage.admins.list(limit=1):
                raise AlreadyBootstrappedError("Admin already exists")
            roles = list(self.config.roles.admin)
            self.hashing.validate(password, email, self.config.admin_auth.password)
            admin = await self.storage.admins.create(
                Admin(
                    email=email.strip().lower(),
                    password_hash=self.hashing.hash(password),
                    roles=roles,
                    impersonation_scope=ImpersonationScope("all"),
                )
            )
            await rec.emit(
                AuditEvent(
                    action="admin.bootstrapped",
                    outcome="success",
                    actor_type="system",
                    target_type="admin",
                    target_id=admin.id,
                    metadata={"roles": roles},
                )
            )
            return admin

    async def create_tenant(
        self, actor: Any, slug: str, attributes: dict[str, Any], login_policy: Any = None
    ) -> Tenant:
        self._authorize(actor, "tenants:create")
        if not re.fullmatch(r"[a-z0-9-]{3,63}", slug):
            raise InvalidSlugError("Invalid slug")
        policy = self._policy(login_policy or self.config.tenant_auth.default_policy)
        async with self.audit.recorder() as rec:
            tenant = await self.storage.tenants.create(
                Tenant(
                    slug=slug,
                    attributes=validate_attributes(attributes, self.config.tenant_schema),
                    login_policy=policy,
                )
            )
            await rec.emit(
                self._event(
                    actor,
                    "tenant.created",
                    tenant_id=tenant.id,
                    target_type="tenant",
                    target_id=tenant.id,
                    metadata={"slug": tenant.slug},
                )
            )
            return tenant

    async def get_tenant(self, actor: Any, tenant_id: UUID) -> Tenant:
        self._authorize(actor, "tenants:read")
        return await self._get_tenant(tenant_id)

    async def _get_tenant(self, tenant_id: UUID) -> Tenant:
        tenant = await self.storage.tenants.get(tenant_id)
        if tenant is None:
            raise NotFoundError("Tenant not found")
        return tenant

    async def list_tenants(
        self, actor: Any, active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[Tenant]:
        self._authorize(actor, "tenants:read")
        return await self.storage.tenants.list(active=active, limit=limit, offset=offset)

    async def update_tenant(
        self, actor: Any, tenant_id: UUID, attributes: dict[str, Any]
    ) -> Tenant:
        self._authorize(actor, "tenants:update")
        async with self.audit.recorder() as rec:
            tenant = await self._get_tenant(tenant_id)
            tenant.attributes = validate_attributes(
                {**tenant.attributes, **attributes}, self.config.tenant_schema
            )
            tenant = await self.storage.tenants.update(tenant)
            await rec.emit(
                self._event(
                    actor,
                    "tenant.updated",
                    tenant_id=tenant.id,
                    target_type="tenant",
                    target_id=tenant.id,
                    metadata={"changed": sorted(attributes)},
                )
            )
            return tenant

    async def set_login_policy(self, actor: Any, tenant_id: UUID, policy: Any) -> Tenant:
        self._authorize(actor, "tenants:update")
        async with self.audit.recorder() as rec:
            tenant = await self._get_tenant(tenant_id)
            tenant.login_policy = self._policy(policy)
            tenant = await self.storage.tenants.update(tenant)
            await rec.emit(
                self._event(
                    actor,
                    "tenant.login_policy_changed",
                    tenant_id=tenant.id,
                    target_type="tenant",
                    target_id=tenant.id,
                    metadata={"providers": list(tenant.login_policy.providers)},
                )
            )
            return tenant

    async def deactivate_tenant(self, actor: Any, tenant_id: UUID) -> Tenant:
        return await self._active_tenant(actor, tenant_id, False)

    async def reactivate_tenant(self, actor: Any, tenant_id: UUID) -> Tenant:
        return await self._active_tenant(actor, tenant_id, True)

    async def _active_tenant(self, actor: Any, tenant_id: UUID, active: bool) -> Tenant:
        self._authorize(actor, "tenants:deactivate")
        async with self.audit.recorder() as rec:
            tenant = await self._get_tenant(tenant_id)
            tenant.is_active = active
            tenant = await self.storage.tenants.update(tenant)
            revoked = 0
            if not active:
                # Covers tenant users and impersonation sessions into this tenant.
                revoked = await self.sessions.revoke(
                    tenant_id=tenant.id, reason=RevokeReason.TENANT_DEACTIVATED
                )
            await rec.emit(
                self._event(
                    actor,
                    "tenant.reactivated" if active else "tenant.deactivated",
                    tenant_id=tenant.id,
                    target_type="tenant",
                    target_id=tenant.id,
                    metadata={} if active else {"sessions_revoked": revoked},
                )
            )
            return tenant

    async def validate_all_tenants(self, actor: Any) -> dict[UUID, str]:
        self._authorize(actor, "tenants:read")
        errors = {}
        offset = 0
        while True:
            tenants = await self.storage.tenants.list(limit=100, offset=offset)
            for tenant in tenants:
                try:
                    validate_attributes(tenant.attributes, self.config.tenant_schema)
                except TenantValidationError as exc:
                    errors[tenant.id] = str(exc)
            if len(tenants) < 100:
                return errors
            offset += 100

    async def create_tenant_user(
        self, actor: Any, tenant_id: UUID, email: str, password: str, roles: list[str]
    ) -> TenantUser:
        self._authorize(actor, "tenant_users:manage")
        tenant = await self._get_tenant(tenant_id)
        self._roles("tenant", roles)
        email = email.strip().lower()
        self.hashing.validate(password, email, self.config.tenant_auth.password)
        self.hashing.validate(password, email, tenant.login_policy.password)
        async with self.audit.recorder() as rec:
            user = await self.storage.tenant_users.create(
                TenantUser(
                    tenant_id=tenant_id,
                    email=email,
                    password_hash=self.hashing.hash(password),
                    roles=roles,
                )
            )
            await rec.emit(
                self._event(
                    actor,
                    "tenant_user.created",
                    tenant_id=tenant_id,
                    target_type="tenant_user",
                    target_id=user.id,
                    metadata={"roles": list(roles)},
                )
            )
            return user

    async def update_tenant_user(
        self,
        actor: Any,
        user_id: UUID,
        *,
        roles: list[str] | None = None,
        password: str | None = None,
        is_active: bool | None = None,
    ) -> TenantUser:
        self._authorize(actor, "tenant_users:manage")
        async with self.audit.recorder() as rec:
            user = await self.storage.tenant_users.get(user_id)
            if user is None:
                raise NotFoundError("User not found")
            changed: list[str] = []
            was_active = user.is_active
            if roles is not None:
                self._roles("tenant", roles)
                user.roles = roles
                changed.append("roles")
            if password is not None:
                tenant = await self._get_tenant(user.tenant_id)
                self.hashing.validate(password, user.email, self.config.tenant_auth.password)
                self.hashing.validate(password, user.email, tenant.login_policy.password)
                user.password_hash = self.hashing.hash(password)
                changed.append("password")
            if is_active is not None:
                user.is_active = is_active
                changed.append("is_active")
            user = await self.storage.tenant_users.update(user)
            reason = (
                RevokeReason.SUBJECT_DEACTIVATED
                if is_active is False
                else RevokeReason.PASSWORD_CHANGED
                if password is not None
                else None
            )
            if reason is not None:
                await self.sessions.revoke(kind="tenant", subject_id=user.id, reason=reason)
            await rec.emit(
                self._event(
                    actor,
                    "tenant_user.deactivated"
                    if is_active is False and was_active
                    else "tenant_user.updated",
                    tenant_id=user.tenant_id,
                    target_type="tenant_user",
                    target_id=user.id,
                    metadata={"changed": changed},
                )
            )
            return user

    async def deactivate_tenant_user(self, actor: Any, user_id: UUID) -> TenantUser:
        return await self.update_tenant_user(actor, user_id, is_active=False)

    async def _grant(self, actor: Any, roles: list[str], scope: ImpersonationScope) -> None:
        self._roles("admin", roles)
        caller = await self.storage.admins.get(UUID(actor.sub))
        if caller is None or not caller.is_active:
            raise PermissionDeniedError("Inactive admin")
        for role in roles:
            for permission in self.config.roles.admin[role].permissions:
                if permission == "*":
                    allowed = "*" in actor.perms
                elif permission.endswith(":*"):
                    allowed = "*" in actor.perms or permission in actor.perms
                else:
                    allowed = self.access.has_permission(actor, permission)
                if not allowed:
                    raise PermissionDeniedError("Cannot grant greater permissions")
        caller_impersonation_roles = {
            r
            for role in caller.roles
            for r in self.config.impersonation.allowed_roles.get(role, ())
        }
        granted_impersonation_roles = {
            r for role in roles for r in self.config.impersonation.allowed_roles.get(role, ())
        }
        if not granted_impersonation_roles <= caller_impersonation_roles:
            raise PermissionDeniedError("Cannot grant greater impersonation roles")
        own = caller.impersonation_scope
        if own.mode != "all" and (
            scope.mode == "all"
            or (
                scope.mode == "list"
                and (own.mode != "list" or not set(scope.tenant_ids) <= set(own.tenant_ids))
            )
        ):
            raise PermissionDeniedError("Cannot grant broader scope")

    async def create_admin(
        self,
        actor: Any,
        email: str,
        password: str,
        roles: list[str],
        impersonation_scope: ImpersonationScope | None = None,
    ) -> Admin:
        self._authorize(actor, "admins:manage")
        scope = impersonation_scope or ImpersonationScope(self.config.impersonation.default_scope)
        await self._grant(actor, roles, scope)
        email = email.strip().lower()
        self.hashing.validate(password, email, self.config.admin_auth.password)
        async with self.audit.recorder() as rec:
            admin = await self.storage.admins.create(
                Admin(
                    email=email,
                    password_hash=self.hashing.hash(password),
                    roles=roles,
                    impersonation_scope=scope,
                )
            )
            await rec.emit(
                self._event(
                    actor,
                    "admin.created",
                    target_type="admin",
                    target_id=admin.id,
                    metadata={"roles": list(roles), "impersonation_scope": scope.mode},
                )
            )
            return admin

    def _manages(self, admin: Admin) -> bool:
        for role in admin.roles:
            definition = self.config.roles.admin.get(role)
            if definition and any(
                p in ("*", "admins:*", "admins:manage") for p in definition.permissions
            ):
                return True
        return False

    async def update_admin(
        self,
        actor: Any,
        admin_id: UUID,
        *,
        roles: list[str] | None = None,
        impersonation_scope: ImpersonationScope | None = None,
        is_active: bool | None = None,
    ) -> Admin:
        self._authorize(actor, "admins:manage")
        async with self.audit.recorder() as rec:
            admin = await self.storage.admins.get(admin_id)
            if admin is None:
                raise NotFoundError("Admin not found")
            was_active = admin.is_active
            changed: list[str] = []
            await self._grant(
                actor,
                roles if roles is not None else admin.roles,
                impersonation_scope or admin.impersonation_scope,
            )
            if roles is not None:
                admin.roles = roles
                changed.append("roles")
            if impersonation_scope is not None:
                admin.impersonation_scope = impersonation_scope
                changed.append("impersonation_scope")
            if is_active is not None:
                admin.is_active = is_active
                changed.append("is_active")
            if not admin.is_active or not self._manages(admin):
                others = await self.storage.admins.list(active=True, limit=1000000)
                if not any(a.id != admin.id and self._manages(a) for a in others):
                    raise LastAdminError("Last managing admin cannot be removed")
            admin = await self.storage.admins.update(admin)
            if is_active is False:
                await self.sessions.revoke(
                    kind="admin",
                    subject_id=admin.id,
                    reason=RevokeReason.SUBJECT_DEACTIVATED,
                    cascade_children=True,
                )
            metadata: dict[str, Any] = {"changed": changed}
            if roles is not None:
                metadata["roles"] = list(roles)
            if impersonation_scope is not None:
                metadata["impersonation_scope"] = impersonation_scope.mode
            await rec.emit(
                self._event(
                    actor,
                    "admin.deactivated" if is_active is False and was_active else "admin.updated",
                    target_type="admin",
                    target_id=admin.id,
                    metadata=metadata,
                )
            )
            return admin

    async def deactivate_admin(self, actor: Any, admin_id: UUID) -> Admin:
        return await self.update_admin(actor, admin_id, is_active=False)

    async def unlock_account(self, actor: Any, subject_type: str, subject_id: UUID) -> None:
        if subject_type not in ("admin", "tenant_user"):
            raise NotFoundError("Unknown subject type")
        self._authorize(
            actor, "admins:manage" if subject_type == "admin" else "tenant_users:manage"
        )
        async with self.audit.recorder() as rec:
            await self.storage.login_attempts.reset(subject_type, subject_id)
            tenant_id = None
            if subject_type == "tenant_user":
                user = await self.storage.tenant_users.get(subject_id)
                tenant_id = user.tenant_id if user is not None else None
            await rec.emit(
                self._event(
                    actor,
                    "auth.account.unlocked",
                    tenant_id=tenant_id,
                    target_type="account",
                    target_id=subject_id,
                    metadata={"subject_type": subject_type},
                )
            )

    async def revoke_sessions(
        self, actor: Any, subject_type: Literal["admin", "tenant"], subject_id: UUID
    ) -> int:
        self._authorize(actor, "sessions:revoke")
        if subject_type not in ("admin", "tenant"):
            raise NotFoundError("Unknown subject type")
        async with self.audit.recorder() as rec:
            tenant_id = None
            if subject_type == "tenant":
                user = await self.storage.tenant_users.get(subject_id)
                tenant_id = user.tenant_id if user is not None else None
            count = await self.sessions.revoke(
                kind=subject_type,
                subject_id=subject_id,
                reason=RevokeReason.ADMIN_REVOKED,
                cascade_children=True,
            )
            await rec.emit(
                self._event(
                    actor,
                    "session.revoked",
                    tenant_id=tenant_id,
                    target_type="admin" if subject_type == "admin" else "tenant_user",
                    target_id=subject_id,
                    metadata={"count": count},
                )
            )
            return count

    async def list_sessions(
        self,
        actor: Any,
        subject_type: Literal["admin", "tenant"],
        subject_id: UUID,
        *,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Session]:
        self._authorize(actor, "sessions:read")
        if subject_type not in ("admin", "tenant"):
            raise NotFoundError("Unknown subject type")
        return await self.storage.sessions.list(
            kind=subject_type,
            subject_id=subject_id,
            active_only=active_only,
            limit=limit,
            offset=offset,
        )
