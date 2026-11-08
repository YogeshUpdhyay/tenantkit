# 09 — FastAPI integration guide

tenantkit ships no FastAPI code. This guide shows how a host app builds its own authentication middleware, authorisation dependencies, and error handling from the package's utilities. The same code lives in `examples/fastapi_app/`, is tested end to end, and is reproduced in the project README as the single usage guide.

## Overview

| Layer | Owned by | What it does |
| --- | --- | --- |
| Setup | Host | Builds `TenantKit` once at startup |
| Authentication middleware | Host, using `kit.tokens.verify()` | Verifies the bearer token and stores claims on the request |
| Authorisation dependencies | Host, using `kit.access` helpers | Checks token type and permissions per endpoint |
| Error handlers | Host | Maps tenantkit errors to 401 and 403 responses |
| Auth endpoints | Host, calling auth services | Login, refresh, impersonation |

## 1. Setup

Build the kit once, in the app's lifespan, and keep it on `app.state`.

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from tenantkit import TenantKit, TenantKitConfig
from tenantkit.storage.sqlalchemy import SqlAlchemyStorage

from app.settings import load_tenantkit_dict   # host reads YAML, env vars, secrets

engine = create_async_engine(DATABASE_URL)
Session = async_sessionmaker(engine, expire_on_commit=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    config = TenantKitConfig.from_dict(load_tenantkit_dict())
    app.state.kit = TenantKit(config=config, storage=SqlAlchemyStorage(session_factory=Session))
    yield
    await engine.dispose()

app = FastAPI(lifespan=lifespan)
```

A small dependency gives routes access to the kit:

```python
from fastapi import Request

def get_kit(request: Request) -> TenantKit:
    return request.app.state.kit
```

## 2. Authentication middleware

The middleware only answers "who is calling?". It verifies the token if one is present and stores the claims; it never decides access. Public paths, such as login, are skipped.

```python
from contextvars import ContextVar
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from tenantkit.errors import InvalidTokenError, ExpiredTokenError

current_claims: ContextVar = ContextVar("current_claims", default=None)

PUBLIC_PATHS = {"/auth/admin/login", "/auth/tenant/login", "/auth/admin/refresh",
                "/auth/tenant/refresh", "/auth/impersonation/refresh", "/health"}
PUBLIC_PREFIXES = ("/auth/tenant/",)   # e.g. /auth/tenant/{slug}/methods

class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request.state.claims = None
        path = request.url.path
        if path in PUBLIC_PATHS or (path.startswith(PUBLIC_PREFIXES) and path.endswith("/methods")):
            return await call_next(request)

        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return _unauthorised("missing_token")

        try:
            claims = request.app.state.kit.tokens.verify(token)
        except ExpiredTokenError:
            return _unauthorised("token_expired")
        except InvalidTokenError:
            return _unauthorised("invalid_token")

        request.state.claims = claims
        reset = current_claims.set(claims)
        try:
            return await call_next(request)
        finally:
            current_claims.reset(reset)

def _unauthorised(code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=401,
                        headers={"WWW-Authenticate": "Bearer"})

app.add_middleware(AuthenticationMiddleware)
```

- Errors raised inside middleware do not reach FastAPI's exception handlers, so the middleware returns 401 responses itself.
- `request.state.claims` serves route code; the `current_claims` context variable serves deeper code, such as a repository that filters by tenant, without passing claims around.
- `token_expired` lets the frontend know to call refresh.

## 3. Authorisation dependencies

Authorisation is per endpoint, built from `kit.access` helpers. Each dependency returns the claims, so the route can use them.

```python
from fastapi import Depends, Request
from tenantkit.claims import BaseClaims

def claims_of(request: Request) -> BaseClaims:
    claims = request.state.claims
    if claims is None:
        raise NotAuthenticated()            # host-defined, mapped to 401
    return claims

def require(*types: str, perms: tuple[str, ...] = ()):
    def dependency(claims: BaseClaims = Depends(claims_of), kit: TenantKit = Depends(get_kit)):
        kit.access.require_type(claims, *types)
        for perm in perms:
            kit.access.require_permission(claims, perm)
        return claims
    return dependency

# Ready-made dependencies for the rules in the requirements
AdminOnly = require("admin")
TenantOrImpersonation = require("tenant", "impersonation")

def AdminWith(*perms: str):
    return require("admin", perms=perms)

def TenantWith(*perms: str):
    return require("tenant", "impersonation", perms=perms)
```

## 4. Error handling

Errors raised in routes and dependencies reach exception handlers. tenantkit errors are mapped once:

| tenantkit error | Status | Body `error` |
| --- | --- | --- |
| `InvalidCredentialsError` | 401 | `invalid_credentials` |
| `AccountLockedError` | 403 | `account_locked` ("Account locked. Contact your administrator.") |
| `InvalidTokenError` (and subclasses, in routes) | 401 | `invalid_token` |
| `WrongTokenTypeError` | 403 | `forbidden` |
| `PermissionDeniedError` | 403 | `forbidden` |
| `TenantValidationError`, `PasswordPolicyError`, `InvalidSlugError` | 422 | field-level details |
| `AlreadyExistsError` | 409 | `already_exists` |
| `NotFoundError` | 404 | `not_found` |
| `ImpersonationDisabledError` | 403 | `forbidden` |

```python
from fastapi.responses import JSONResponse
from tenantkit import errors as tk

STATUS = [
    (tk.InvalidCredentialsError, 401, "invalid_credentials"),
    (tk.AccountLockedError, 403, "account_locked"),
    (tk.WrongTokenTypeError, 403, "forbidden"),
    (tk.InvalidTokenError, 401, "invalid_token"),
    (tk.PermissionDeniedError, 403, "forbidden"),
    (tk.ImpersonationDisabledError, 403, "forbidden"),
    (tk.AlreadyExistsError, 409, "already_exists"),
    (tk.NotFoundError, 404, "not_found"),
]

for exc_type, status, code in STATUS:
    def handler(request, exc, status=status, code=code):
        body = {"error": code}
        if code == "account_locked":
            body["message"] = "Account locked. Contact your administrator."
        return JSONResponse(body, status_code=status)
    app.add_exception_handler(exc_type, handler)

@app.exception_handler(tk.ValidationErrorBase)   # TenantValidationError, PasswordPolicyError, InvalidSlugError
def validation_handler(request, exc):
    return JSONResponse({"error": "validation_failed", "details": exc.details}, status_code=422)
```

`WrongTokenTypeError` has its own handler, separate from its parent `InvalidTokenError`, so a valid token of the wrong type returns 403, not 401. Starlette picks the most specific registered class. Detailed failure reasons are logged, never returned.

## 5. Auth endpoints

```python
from fastapi import APIRouter
auth = APIRouter(prefix="/auth")

@auth.post("/admin/login")
async def admin_login(body: AdminLogin, kit: TenantKit = Depends(get_kit)):
    return await kit.admin_auth.login(email=body.email, password=body.password)

@auth.post("/tenant/login")
async def tenant_login(body: TenantLogin, kit: TenantKit = Depends(get_kit)):
    return await kit.tenant_auth.login(
        tenant_slug=body.tenant_slug,
        method=body.method,                      # "password" in v1
        credentials=body.credentials,
    )

@auth.get("/tenant/{slug}/methods")
async def tenant_methods(slug: str, kit: TenantKit = Depends(get_kit)):
    return await kit.tenant_auth.login_methods(tenant_slug=slug)

@auth.post("/admin/refresh")
async def admin_refresh(body: Refresh, kit: TenantKit = Depends(get_kit)):
    return await kit.admin_auth.refresh(refresh_token=body.refresh_token)

@auth.post("/tenant/refresh")
async def tenant_refresh(body: Refresh, kit: TenantKit = Depends(get_kit)):
    return await kit.tenant_auth.refresh(refresh_token=body.refresh_token)

@auth.post("/impersonate")
async def impersonate(body: ImpersonateBody, claims=Depends(AdminOnly), kit: TenantKit = Depends(get_kit)):
    return await kit.access.impersonate(
        actor=claims,
        tenant_id=body.tenant_id,
        role=body.role,
        admin_refresh_token=body.admin_refresh_token,
        reason=body.reason,                      # optional
    )

@auth.post("/impersonation/refresh")
async def impersonation_refresh(body: Refresh, kit: TenantKit = Depends(get_kit)):
    return await kit.access.refresh_impersonation(refresh_token=body.refresh_token)
```

The tenant slug usually comes from a subdomain (`acme.example.com`) or a login URL. The host fills `tenant_slug` from there, rather than trusting a value the user typed.

## 6. Protecting business endpoints

```python
from fastapi import APIRouter
api = APIRouter()

# Admin-only: tenant and impersonation tokens get 403
@api.post("/admin/tenants")
async def create_tenant(body: NewTenant, claims=Depends(AdminOnly), kit: TenantKit = Depends(get_kit)):
    return await kit.control_plane.create_tenant(actor=claims, slug=body.slug, attributes=body.attributes)

# Tenant or impersonation, needing a permission: plain admin tokens get 403
@api.get("/orders")
async def list_orders(claims=Depends(TenantWith("data:read"))):
    return await orders_repo.list(tenant_id=claims.tenant_id)

@api.post("/orders")
async def create_order(body: NewOrder, claims=Depends(TenantWith("data:write"))):
    return await orders_repo.create(tenant_id=claims.tenant_id, data=body)
```

## 7. Scoping host data by tenant

The host's own tables carry a `tenant_id` column, and every query filters by `tenant_id` from verified claims. Never take the tenant ID from the URL, body or query string.

One way to make this automatic is a repository base class that reads the context variable:

```python
class TenantScopedRepo:
    def tenant_id(self):
        claims = current_claims.get()
        if claims is None or claims.tenant_id is None:
            raise RuntimeError("No tenant in context")
        return claims.tenant_id
```

Impersonation tokens carry `tenant_id` too, so admin debugging sees exactly what the tenant sees.

## 8. Auditing impersonated requests

Add the actor to request logs when the token is an impersonation token:

```python
if claims.typ == "impersonation":
    log.info("impersonated_request", admin_id=claims.act.sub, tenant_id=claims.tenant_id,
             jti=claims.jti, reason=claims.reason, path=request.url.path)
```

## 9. Testing the integration

- Use `InMemoryStorage` and a test config with HS256 keys for speed.
- Fixtures log in an admin, a tenant user, and start an impersonation, returning headers for each.
- For every protected route, assert the allowed token types succeed and the others get 403, a missing token gets 401, and an expired token gets 401 with `token_expired`.
- Assert that tenant A's token never returns tenant B's data.

## Decisions

1. tenantkit ships no FastAPI or other framework code. This guide and the example app are the reference integration.
2. Missing or invalid tokens return 401. Valid tokens without the right type or permission return 403.
3. This guide is reproduced in the project README, which is the single point of usage documentation.
