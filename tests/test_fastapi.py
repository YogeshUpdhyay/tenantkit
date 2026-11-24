"""Exercise host middleware, auth routes and permission handling together."""

import asyncio
from uuid import UUID
import importlib.util
import pytest
from fastapi.testclient import TestClient
from examples.fastapi_app.app import create_app
from tenantkit import TenantKit, TenantKitConfig
from tenantkit.storage.memory import InMemoryStorage

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None, reason="argon2-cffi unavailable offline"
)


def test_login_and_authorized_routes_and_error_mapping():
    config = TenantKitConfig.from_dict(
        {
            "issuer": "tests",
            "audience": "tests",
            "tokens": {
                kind: {"private_key": kind * 32, "kid": kind}
                for kind in ["admin", "tenant", "impersonation"]
            },
        }
    )
    kit = TenantKit(config=config, storage=InMemoryStorage())
    asyncio.run(
        kit.control_plane.bootstrap_super_admin("root@example.com", "strong-passphrase-123")
    )
    with TestClient(create_app(kit)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/orders").status_code == 401
        bad = client.post(
            "/auth/admin/login", json={"email": "root@example.com", "password": "wrong"}
        )
        assert bad.status_code == 401
        assert bad.json()["error"] == "invalid_credentials"
        login = client.post(
            "/auth/admin/login",
            json={"email": "root@example.com", "password": "strong-passphrase-123"},
        )
        assert login.status_code == 200
        headers = {"authorization": "Bearer " + login.json()["access_token"]}
        assert client.get("/orders", headers=headers).status_code == 403
        tenant = client.post(
            "/admin/tenants", headers=headers, json={"slug": "acme", "attributes": {}}
        )
        assert tenant.status_code == 200
        duplicate = client.post(
            "/admin/tenants", headers=headers, json={"slug": "acme", "attributes": {}}
        )
        assert duplicate.status_code == 409


def test_logout_logout_all_audit_and_verify_active_routes():
    config = TenantKitConfig.from_dict(
        {
            "issuer": "tests",
            "audience": "tests",
            "tokens": {
                kind: {"private_key": kind * 32, "kid": kind}
                for kind in ["admin", "tenant", "impersonation"]
            },
            "roles": {"tenant": {"reader": {"permissions": ["data:read"]}}},
        }
    )
    kit = TenantKit(config=config, storage=InMemoryStorage())
    asyncio.run(
        kit.control_plane.bootstrap_super_admin("root@example.com", "strong-passphrase-123")
    )
    with TestClient(create_app(kit)) as client:
        admin = client.post(
            "/auth/admin/login",
            json={"email": "root@example.com", "password": "strong-passphrase-123"},
        ).json()
        admin_headers = {"authorization": "Bearer " + admin["access_token"]}
        assert (
            client.post(
                "/admin/tenants", headers=admin_headers, json={"slug": "acme", "attributes": {}}
            ).status_code
            == 200
        )
        tenant_id = client.post(
            "/admin/tenants", headers=admin_headers, json={"slug": "beta", "attributes": {}}
        ).json()["id"]
        asyncio.run(
            kit.control_plane.create_tenant_user(
                kit.tokens.verify(admin["access_token"]),
                UUID(tenant_id),
                "user@example.com",
                "strong-passphrase-123",
                ["reader"],
            )
        )
        login = client.post(
            "/auth/tenant/login",
            json={
                "tenant_slug": "beta",
                "credentials": {"email": "user@example.com", "password": "strong-passphrase-123"},
            },
        ).json()
        headers = {"authorization": "Bearer " + login["access_token"]}
        assert client.get("/tenant/billing", headers=headers).status_code == 200
        assert client.get("/tenant/billing", headers=admin_headers).status_code == 403
        out = client.post(
            "/auth/logout", headers=headers, json={"refresh_token": login["refresh_token"]}
        )
        assert out.status_code == 200
        # verify() still accepts the access token, verify_active() does not.
        assert client.get("/tenant/profile", headers=headers).status_code == 200
        revoked = client.get("/tenant/billing", headers=headers)
        assert revoked.status_code == 401 and revoked.json()["error"] == "token_revoked"
        again = client.post("/auth/tenant/refresh", json={"refresh_token": login["refresh_token"]})
        assert again.status_code == 401 and again.json()["error"] == "token_revoked"
        assert client.post("/auth/logout-all", headers=admin_headers).json() == {"revoked": 1}
        audit = client.get("/admin/audit", params={"action": "auth.*"}, headers=admin_headers)
        assert audit.status_code == 200
        assert {"auth.login.succeeded", "auth.logout", "auth.logout_all"} <= {
            event["action"] for event in audit.json()
        }
        assert client.get("/admin/audit", headers=headers).status_code == 403
