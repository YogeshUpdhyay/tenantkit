from datetime import datetime, timezone
from uuid import uuid4

import jwt
import pytest

from tenantkit import TenantKit
from tenantkit.domain.errors import ExpiredTokenError, InvalidTokenError, PermissionDeniedError
from tenantkit.domain.models import Admin, ImpersonationScope, Tenant
from tenantkit.storage.memory import InMemoryStorage
from tenantkit.tokens.service import TokenService
from test_core import config


@pytest.mark.parametrize("mutation", ["expired", "audience", "issuer", "none", "missing"])
def test_invalid_security_claims_rejected(mutation):
    cfg = config()
    service = TokenService(cfg)
    admin = Admin(email="root@example.com", password_hash="hash", roles=["root"])
    pair = service.issue_pair(typ="admin", subject=admin, session_id=uuid4())
    payload = jwt.decode(pair.access_token, options={"verify_signature": False})
    if mutation == "expired":
        payload["exp"] = int(datetime.now(timezone.utc).timestamp()) - 120
    elif mutation == "audience":
        payload["aud"] = "other-app"
    elif mutation == "issuer":
        payload["iss"] = "other-issuer"
    elif mutation == "missing":
        del payload["sub"]
    token = jwt.encode(
        payload,
        "" if mutation == "none" else "a" * 32,
        algorithm="none" if mutation == "none" else "HS256",
        headers={"kid": "admin"},
    )
    with pytest.raises(ExpiredTokenError if mutation == "expired" else InvalidTokenError):
        service.verify(token)


async def test_impersonation_outside_scope_is_refused():
    cfg = config()
    storage = InMemoryStorage()
    service = TokenService(cfg)
    admin = await storage.admins.create(
        Admin(
            email="root@example.com",
            password_hash="hash",
            roles=["root"],
            impersonation_scope=ImpersonationScope("none"),
        )
    )
    tenant = await storage.tenants.create(Tenant(slug="acme"))
    pair = service.issue_pair(typ="admin", subject=admin, session_id=uuid4())
    access = TenantKit(config=cfg, storage=storage).access
    with pytest.raises(PermissionDeniedError):
        await access.impersonate(
            actor=service.verify(pair.access_token),
            tenant_id=tenant.id,
            role="reader",
            admin_refresh_token=pair.refresh_token,
        )
