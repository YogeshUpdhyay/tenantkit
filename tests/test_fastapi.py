"""Exercise host middleware, auth routes and permission handling together."""

import asyncio
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
