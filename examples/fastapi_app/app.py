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
