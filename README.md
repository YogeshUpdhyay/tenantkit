# tenantkit

Async, framework-agnostic multi-tenancy, authentication and scoped impersonation for Python 3.11+.

Install `pip install tenantkit`, `pip install 'tenantkit[sqlalchemy]'` for the async SQLAlchemy adapter, or `pip install 'tenantkit[mongo]'` for the MongoDB adapter (Beanie 2.x). The host supplies keys, settings, database sessions and HTTP integration. The package reads no environment variables or files.

Install directly from GitHub (requires Git):

```bash
python -m pip install "tenantkit @ git+https://github.com/YogeshUpdhyay/tenantkit.git@main"
```

With the async SQLAlchemy adapter:

```bash
python -m pip install "tenantkit[sqlalchemy] @ git+https://github.com/YogeshUpdhyay/tenantkit.git@main"
```

With the MongoDB (Beanie) adapter:

```bash
python -m pip install "tenantkit[mongo] @ git+https://github.com/YogeshUpdhyay/tenantkit.git@main"
```

Replace `main` with a tag or full commit SHA to pin a specific version.

```python
from secrets import token_urlsafe
from tenantkit import TenantKit, TenantKitConfig
from tenantkit.storage.memory import InMemoryStorage

config = TenantKitConfig.from_dict({
    "issuer": "https://auth.example.com",
    "audience": "example-app",
    "tokens": {
        kind: {"kid": kind + "-1", "algorithm": "HS256", "private_key": token_urlsafe(48)}
        for kind in ("admin", "tenant", "impersonation")
    },
    "tenant_schema": {"fields": [
        {"name": "organisation_name", "type": "string", "required": True}
    ]},
    "roles": {
        "admin": {"super_admin": {"permissions": ["*"]}},
        "tenant": {"reader": {"permissions": ["data:read"]}},
        "impersonation": {"support_read": {"permissions": ["data:read"]}},
    },
    "impersonation": {"allowed_roles": {"super_admin": ["support_read"]}},
})
kit = TenantKit(config=config, storage=InMemoryStorage())
```

Persist signing keys securely in the host; generating new keys on every restart invalidates existing sessions. RS256 and ES256 accept PEM private and public keys; use a distinct key and key ID for each token category. Config also accepts timedelta lifetimes or `access_ttl_seconds` / `refresh_ttl_seconds`.

Run bootstrap once from an administrative script, never from an HTTP endpoint:

```python
async def setup():
    await kit.control_plane.bootstrap_super_admin(email="admin@example.com", password="a-long-admin-password")
    pair = await kit.admin_auth.login(email="admin@example.com", password="a-long-admin-password")
    actor = kit.tokens.verify(pair.access_token, expected="admin")
    tenant = await kit.control_plane.create_tenant(actor=actor, slug="acme", attributes={"organisation_name": "Acme"})
    await kit.control_plane.create_tenant_user(actor=actor, tenant_id=tenant.id,
        email="reader@example.com", password="a-long-user-password", roles=["reader"])
    user_pair = await kit.tenant_auth.login(tenant_slug="acme", method="password",
        credentials={"email": "reader@example.com", "password": "a-long-user-password"})
    claims = kit.tokens.verify(user_pair.access_token, expected="tenant")
    kit.access.require_permission(claims, "data:read")
    renewed = await kit.tenant_auth.refresh(refresh_token=user_pair.refresh_token)
    return renewed
```

Never log tokens, passwords or key material.

### Sessions, logout and revocation

Every login creates a session (`mt_sessions`). Refresh tokens rotate on every use; presenting an old refresh token again revokes the whole session (and any impersonation sessions started from it) and raises `RevokedTokenError`, a subclass of `InvalidTokenError`. Clients must serialise refresh calls: two refreshes racing with the same token end the session.

```python
await kit.admin_auth.logout(refresh_token=pair.refresh_token)       # idempotent
await kit.tenant_auth.logout_all(actor=claims)                      # all of the user's sessions
await kit.control_plane.revoke_sessions(actor, "tenant", user_id)   # needs sessions:revoke
await kit.access.end_impersonation(refresh_token=imp.refresh_token)
```

Deactivating a user, admin or tenant and changing a password revoke the affected sessions. `kit.tokens.verify()` stays synchronous and storage-free, so a revoked session's access token is accepted until it expires (15 minutes by default). For instant cut-off on sensitive routes call `await kit.tokens.verify_active(token, expected="tenant")`. Schedule `await kit.sessions.purge_expired()` to clean up old rows. Details: [docs/10-sessions-revocation.md](docs/10-sessions-revocation.md).

### Audit log

tenantkit records an append-only audit trail (`mt_audit_events`) of logins, failed logins, lockouts, token reuse, logout, password changes, impersonation and every control-plane change, written in the same transaction as the change. Admins with `audit:read` call `await kit.audit.list(actor, action="tenant.*")`; `audit:purge` allows `await kit.audit.purge(actor, before=cutoff)`. Failed-login events omit the attempted email unless `audit.include_failed_login_email` is set. Hooks observe events after commit; a failing hook is logged and never affects the operation:

```python
async def forward_to_siem(event):
    await siem.send({"action": event.action, "outcome": event.outcome, "actor": str(event.actor_id)})

kit = TenantKit(config=config, storage=storage, audit_hooks=[forward_to_siem])
```

Do not call tenantkit operations inside a `storage.transaction()` you opened yourself. Details: [docs/11-audit.md](docs/11-audit.md).

### Storage

For SQLAlchemy, pass a host-created `async_sessionmaker` to `SqlAlchemyStorage(session_factory=Session, table_prefix="mt_")`. The adapter creates no engine and runs no migrations. Include its metadata in the host Alembic `target_metadata`; for a custom prefix use `storage.metadata`. Keep the prefix stable once migrations exist. **Upgrading from 0.1 adds the `mt_sessions` and `mt_audit_events` tables: run `alembic revision --autogenerate` and migrate before deploying 0.2.** `storage.transaction()` provides atomic multi-step operations. In-memory storage is intended for tests and local prototypes.

For MongoDB (6.0+, replica set or mongos) the host owns `init_beanie`:

```python
from beanie import init_beanie
from pymongo import AsyncMongoClient
from tenantkit.storage.beanie import BeanieStorage, document_models

client = AsyncMongoClient(MONGO_URL, uuidRepresentation="standard", tz_aware=True)
db = client["app"]
tk_models = document_models(prefix="mt_")  # once per process
await init_beanie(database=db, document_models=[*app_models, *tk_models.all])
kit = await TenantKit.create(config=config, storage=BeanieStorage(database=db, models=tk_models))
```

`health_check()` fails fast on a standalone server, a non-`standard` UUID representation, or models that were not initialised. Details: [docs/12-mongo-storage.md](docs/12-mongo-storage.md).

## FastAPI integration

Install FastAPI and an ASGI server separately. Build one kit in the host startup/lifespan and call `create_app(kit)` below. With a SQLAlchemy engine, dispose the host engine on shutdown. The core has no framework dependency.

The complete runnable host integration below is identical to [examples/fastapi_app/app.py](examples/fastapi_app/app.py). It includes authentication middleware, authorization dependencies, login, refresh, logout and logout-all routes, error mapping, tenant-scoped data, an audit-log route and impersonation audit logging. `/tenant/profile` accepts tenant tokens only; `/orders` accepts tenant and impersonation tokens; `/admin/tenants` and `/admin/audit` accept admin tokens; `/tenant/billing` also checks the session with `verify_active`, so a logged-out user is refused immediately. The middleware resets its context variable after every request.

<!-- BEGIN FASTAPI EXAMPLE -->
```python
"""Host-owned integration. Inject a configured kit; no bootstrap HTTP endpoint."""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr

from tenantkit import TenantKit, errors

current_claims: ContextVar[Any] = ContextVar("current_claims", default=None)
log = logging.getLogger(__name__)


class AdminLogin(BaseModel):
    email: str
    password: SecretStr


class TenantLogin(BaseModel):
    tenant_slug: str
    method: str = "password"
    credentials: dict[str, Any] = Field(repr=False)


class Refresh(BaseModel):
    refresh_token: SecretStr


class Impersonate(BaseModel):
    tenant_id: UUID
    role: str
    admin_refresh_token: SecretStr
    reason: str | None = None


class Logout(BaseModel):
    refresh_token: SecretStr


class NewTenant(BaseModel):
    slug: str
    attributes: dict[str, Any]


def create_app(kit: TenantKit) -> FastAPI:
    app = FastAPI()
    app.state.kit = kit
    # An example host repository: all accesses use the verified tenant ID.
    orders: dict[UUID, list[dict[str, Any]]] = {}
    public = {
        "/health",
        "/auth/admin/login",
        "/auth/tenant/login",
        "/auth/admin/refresh",
        "/auth/tenant/refresh",
        "/auth/impersonation/refresh",
    }

    @app.middleware("http")
    async def authentication(request: Request, call_next: Any) -> Any:
        path = request.url.path
        request.state.claims = None
        if path in public or (path.startswith("/auth/tenant/") and path.endswith("/methods")):
            return await call_next(request)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        code = "missing_token"
        if scheme.lower() == "bearer" and token:
            try:
                claims = kit.tokens.verify(token)
            except errors.ExpiredTokenError:
                code = "token_expired"
            except errors.InvalidTokenError:
                code = "invalid_token"
            else:
                request.state.claims = claims
                reset = current_claims.set(claims)
                try:
                    if claims.typ == "impersonation":
                        log.info(
                            "impersonated_request",
                            extra={
                                "admin_id": claims.act["sub"],
                                "tenant_id": str(claims.tenant_id),
                                "jti": claims.jti,
                                "reason": claims.reason,
                                "path": path,
                            },
                        )
                    return await call_next(request)
                finally:
                    current_claims.reset(reset)
        return JSONResponse(
            {"error": code}, status_code=401, headers={"WWW-Authenticate": "Bearer"}
        )

    async def error_handler(request: Request, exc: Exception) -> JSONResponse:
        mappings = [
            (errors.WrongTokenTypeError, 403, "forbidden"),
            (errors.InvalidCredentialsError, 401, "invalid_credentials"),
            (errors.AccountLockedError, 403, "account_locked"),
            (errors.RevokedTokenError, 401, "token_revoked"),
            (errors.InvalidTokenError, 401, "invalid_token"),
            (errors.PermissionDeniedError, 403, "forbidden"),
            (errors.ImpersonationDisabledError, 403, "forbidden"),
            (errors.AlreadyExistsError, 409, "already_exists"),
            (errors.NotFoundError, 404, "not_found"),
            (errors.ValidationErrorBase, 422, "validation_failed"),
        ]
        for kind, status, code in mappings:
            if isinstance(exc, kind):
                body: dict[str, Any] = {"error": code}
                if code == "account_locked":
                    body["message"] = "Account locked. Contact your administrator."
                if isinstance(exc, errors.ValidationErrorBase):
                    body["details"] = exc.details
                return JSONResponse(body, status_code=status)
        return JSONResponse({"error": "internal_error"}, status_code=500)

    app.add_exception_handler(errors.TenantKitError, error_handler)

    def require(*types: str, permission: str | None = None) -> Any:
        def dependency(request: Request) -> Any:
            claims = request.state.claims
            kit.access.require_type(claims, *types)
            if permission:
                kit.access.require_permission(claims, permission)
            return claims

        return dependency

    def require_active(*types: str) -> Any:
        """Like ``require`` but also checks the session, for instant revocation."""

        async def dependency(request: Request) -> Any:
            token = request.headers.get("authorization", "").partition(" ")[2]
            claims = await kit.tokens.verify_active(token, expected=set(types))
            request.state.claims = claims
            return claims

        return dependency

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/admin/login")
    async def admin_login(body: AdminLogin) -> Any:
        return await kit.admin_auth.login(
            email=body.email, password=body.password.get_secret_value()
        )

    @app.post("/auth/tenant/login")
    async def tenant_login(body: TenantLogin) -> Any:
        return await kit.tenant_auth.login(
            tenant_slug=body.tenant_slug, method=body.method, credentials=body.credentials
        )

    @app.get("/auth/tenant/{slug}/methods")
    async def methods(slug: str) -> Any:
        return await kit.tenant_auth.login_methods(tenant_slug=slug)

    @app.post("/auth/admin/refresh")
    async def admin_refresh(body: Refresh) -> Any:
        return await kit.admin_auth.refresh(refresh_token=body.refresh_token.get_secret_value())

    @app.post("/auth/tenant/refresh")
    async def tenant_refresh(body: Refresh) -> Any:
        return await kit.tenant_auth.refresh(refresh_token=body.refresh_token.get_secret_value())

    @app.post("/auth/impersonation/refresh")
    async def impersonation_refresh(body: Refresh) -> Any:
        return await kit.access.refresh_impersonation(
            refresh_token=body.refresh_token.get_secret_value()
        )

    @app.post("/auth/logout")
    async def logout(
        body: Logout, claims: Any = Depends(require("admin", "tenant", "impersonation"))
    ) -> Any:
        token = body.refresh_token.get_secret_value()
        if claims.typ == "admin":
            await kit.admin_auth.logout(refresh_token=token)
        elif claims.typ == "tenant":
            await kit.tenant_auth.logout(refresh_token=token)
        else:
            await kit.access.end_impersonation(refresh_token=token)
        return {"status": "logged_out"}

    @app.post("/auth/logout-all")
    async def logout_all(claims: Any = Depends(require("admin", "tenant"))) -> Any:
        service = kit.admin_auth if claims.typ == "admin" else kit.tenant_auth
        return {"revoked": await service.logout_all(actor=claims)}

    @app.post("/auth/impersonate")
    async def impersonate(body: Impersonate, claims: Any = Depends(require("admin"))) -> Any:
        return await kit.access.impersonate(
            actor=claims,
            tenant_id=body.tenant_id,
            role=body.role,
            admin_refresh_token=body.admin_refresh_token.get_secret_value(),
            reason=body.reason,
        )

    @app.post("/admin/tenants")
    async def create_tenant(body: NewTenant, claims: Any = Depends(require("admin"))) -> Any:
        return await kit.control_plane.create_tenant(
            actor=claims, slug=body.slug, attributes=body.attributes
        )

    @app.get("/admin/audit")
    async def audit_events(
        action: str | None = None,
        tenant_id: UUID | None = None,
        limit: int = 50,
        claims: Any = Depends(require("admin")),
    ) -> Any:
        return await kit.audit.list(claims, action=action, tenant_id=tenant_id, limit=limit)

    @app.get("/tenant/billing")
    async def billing(claims: Any = Depends(require_active("tenant"))) -> Any:
        # A sensitive route: a revoked session is refused immediately, not at token expiry.
        return {"tenant_id": str(claims.tenant_id), "plan": "pro"}

    @app.get("/tenant/profile")
    async def profile(claims: Any = Depends(require("tenant"))) -> Any:
        return {"tenant_id": str(claims.tenant_id)}

    @app.get("/orders")
    async def list_orders(
        claims: Any = Depends(require("tenant", "impersonation", permission="data:read")),
    ) -> Any:
        return orders.get(claims.tenant_id, [])

    @app.post("/orders")
    async def create_order(
        body: dict[str, Any],
        claims: Any = Depends(require("tenant", "impersonation", permission="data:write")),
    ) -> Any:
        orders.setdefault(claims.tenant_id, []).append(body)
        return body

    return app
```
<!-- END FASTAPI EXAMPLE -->

## Development

Install `pip install -e ".[dev]"`, then run `ruff check .`, `mypy`, and `pytest --cov=tenantkit`. CI runs these checks with PostgreSQL and a single-node MongoDB replica set available (`TENANTKIT_TEST_DATABASE_URL`, `TENANTKIT_TEST_MONGO_URL`); MongoDB tests are skipped when the URL is unset. The requirements and deferred features are in `docs/`.
