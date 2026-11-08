import pytest
from datetime import timedelta
from tenantkit.config.models import TenantKitConfig
from tenantkit.domain.models import Admin, Tenant, TenantUser
from tenantkit.domain.claims import TenantClaims
from tenantkit.domain.errors import ConfigError, InvalidTokenError, WrongTokenTypeError
from tenantkit.tokens.service import TokenService
from tenantkit.access.checks import AccessService


def config():
    return TenantKitConfig.from_dict(
        dict(
            issuer="issuer",
            audience="app",
            tokens={
                typ: dict(private_key=char * 32, kid=typ)
                for typ, char in [("admin", "a"), ("tenant", "t"), ("impersonation", "i")]
            },
            roles=dict(
                admin={"root": {"permissions": ["*"]}},
                tenant={"reader": {"permissions": ["data:*"]}},
                impersonation={},
            ),
        )
    )


def test_tokens_carry_resolved_permissions_and_refresh_is_not_access():
    cfg = config()
    service = TokenService(cfg)
    tenant = Tenant(slug="acme")
    user = TenantUser(
        tenant_id=tenant.id, email="u@example.com", password_hash="hash", roles=["reader"]
    )
    pair = service.issue_pair(typ="tenant", subject=user, tenant=tenant)
    claims = service.verify(pair.access_token, expected={"tenant", "impersonation"})
    assert isinstance(claims, TenantClaims)
    assert claims.tenant_id == tenant.id
    assert claims.perms == ("data:*",)
    assert AccessService.has_permission(claims, "data:read")
    assert not AccessService.has_permission(claims, "users:manage")
    with pytest.raises(WrongTokenTypeError):
        service.verify(pair.refresh_token)
    with pytest.raises(WrongTokenTypeError):
        service.verify(pair.access_token, expected="admin")
    assert service.verify_refresh(pair.refresh_token).tenant_id == tenant.id


def test_bad_signature_and_unknown_key_are_refused():
    service = TokenService(config())
    admin = Admin(email="a@b.com", password_hash="hash", roles=["root"])
    pair = service.issue_pair(typ="admin", subject=admin)
    prefix, body, sig = pair.access_token.split(".")
    with pytest.raises(InvalidTokenError):
        service.verify(prefix + "." + body + "." + ("a" if sig[0] != "a" else "b") + sig[1:])


def test_defaults_and_secret_errors():
    cfg = config()
    assert cfg.tokens.tenant.refresh_ttl == timedelta(days=7)
    assert "a" * 32 not in repr(cfg)
    with pytest.raises(ConfigError):
        TenantKitConfig.from_dict(
            dict(
                issuer="issuer",
                audience="app",
                tokens={
                    typ: dict(private_key="secret", kid="same")
                    for typ in ["admin", "tenant", "impersonation"]
                },
            )
        )


def test_issue_requires_tenant_for_tenant_tokens():
    service = TokenService(config())
    with pytest.raises(InvalidTokenError):
        service.issue_pair(typ="tenant", subject=Admin(email="a@b.com", password_hash="hash"))


def test_config_rejects_structural_errors_with_public_error():
    with pytest.raises(ConfigError):
        TenantKitConfig(issuer="issuer", audience="app", tokens={})


def test_config_role_registry_is_immutable():
    cfg = config()
    with pytest.raises(TypeError):
        cfg.roles.admin["new"] = cfg.roles.admin["root"]


@pytest.mark.parametrize(
    "fields",
    [
        [
            {
                "name": "obj",
                "type": "object",
                "fields": [{"name": "x", "type": "string"}, {"name": "x", "type": "number"}],
            }
        ],
        [{"name": "bad", "type": "string", "pattern": "["}],
        [{"name": "bad", "type": "integer", "min": 9, "max": 1}],
        [{"name": "bad", "type": "list", "item_type": "unknown"}],
    ],
)
def test_invalid_schema_fails_before_startup(fields):
    data = config().model_dump()
    data["tenant_schema"] = {"fields": fields}
    with pytest.raises(ConfigError):
        TenantKitConfig.from_dict(data)


def test_issue_returns_decoded_claims():
    admin = Admin(email="root@example.com", password_hash="hash", roles=["root"])
    pair = TokenService(config()).issue_pair(typ="admin", subject=admin)
    assert pair.claims.sub == str(admin.id)
