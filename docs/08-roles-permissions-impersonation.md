# 08 — Roles, permissions and impersonation

Roles and permissions are defined in config under three fixed identity categories — admin, tenant and impersonation. The package resolves them into token claims and offers check helpers, while the host decides which endpoint needs what.

## Purpose and responsibilities

- Hold the role registry built from config: categories, roles, and the permissions each role grants.
- Resolve a subject's roles into permissions when tokens are issued.
- Provide helpers to check token type, roles and permissions.
- Run impersonation: check an admin's scope, then issue an impersonation token pair.

Out of scope: deciding endpoint access (the host's job), and tenant-defined custom roles (v2).

## Identity categories

| Category | Who | Token type | Roles come from |
| --- | --- | --- | --- |
| Admin | Platform operators | `admin` | `roles.admin` in config |
| Tenant | Users inside one tenant | `tenant` | `roles.tenant` in config |
| Impersonation | An admin acting inside a tenant | `impersonation` | `roles.impersonation` in config |

The three categories are fixed. Everything inside them — role names and permissions — is configurable. A role belongs to exactly one category, and can only be assigned to subjects of that category.

## Defining roles and permissions

```yaml
roles:
  admin:
    super_admin:
      permissions: [tenants:create, tenants:read, tenants:update, tenants:deactivate,
                    tenant_users:manage, admins:manage, impersonate]
    support_admin:
      permissions: [tenants:read, impersonate]
  tenant:
    tenant_admin:
      permissions: [data:read, data:write, users:manage]
    tenant_write:
      permissions: [data:read, data:write]
    tenant_read:
      permissions: [data:read]
  impersonation:
    impersonation_read:
      permissions: [data:read]
    impersonation_full:
      permissions: [data:read, data:write, users:manage]

impersonation:
  enabled: true
  default_scope: none
  allowed_roles:                    # which impersonation roles each admin role may use
    super_admin: [impersonation_read, impersonation_full]
    support_admin: [impersonation_read]
```

- Permission names are free-form strings. The suggested style is `resource:action`.
- The package only gives meaning to its own control plane permissions (sub-doc 03), `impersonate`, and the session and audit permissions `sessions:read`, `sessions:revoke`, `audit:read` and `audit:purge` (sub-docs 10 and 11). The default `super_admin` role (`*`) covers them. Every other permission, such as `data:write`, is meaningful only to the host.
- A subject can hold several roles. Their permissions are the union of those roles' permissions.
- Wildcards are supported in v1: `data:*` grants every `data:` permission, and `*` grants all permissions. Wildcards are allowed only in role definitions, never in the permission a check asks for. They are kept as written in the token's `perms` and matched by the check helpers.

## Resolution into claims

- At token issue time, the subject's stored role names are looked up in the registry and written to `roles` and `perms` in the token.
- A stored role name missing from config (for example, after it was removed) is skipped and logged, never fatal.
- Changing config changes permissions from the next login or refresh, with no data migration.

## Check helpers

`kit.access` offers small, pure functions on verified claims. None touch storage.

```python
kit.access.is_type(claims, "tenant", "impersonation")      # bool
kit.access.has_role(claims, "tenant_admin")                 # bool
kit.access.has_permission(claims, "data:write")             # bool
kit.access.has_all(claims, ["data:read", "data:write"])     # bool
kit.access.has_any(claims, ["users:manage", "data:write"])  # bool

kit.access.require_permission(claims, "data:write")         # raises PermissionDeniedError
kit.access.require_type(claims, "admin")                    # raises WrongTokenTypeError
```

The host combines these in its own authorisation layer. Example rules from the requirements:

- Tenant APIs: `require_type(claims, "tenant", "impersonation")`, then a permission check such as `data:read`.
- Admin APIs: `require_type(claims, "admin")`, then a permission check.

## Impersonation

### Scope

Each admin record holds an impersonation scope:

| Mode | Meaning |
| --- | --- |
| `all` | Can impersonate any active tenant |
| `list` | Can impersonate only the tenant IDs listed |
| `none` | Cannot impersonate |

New admins get `impersonation.default_scope` from config. Scope is set through the control plane with `admins:manage`, and an admin cannot grant scope wider than their own.

### Starting impersonation

```python
pair = await kit.access.impersonate(
    actor=admin_claims,                 # verified admin access token claims
    tenant_id=tenant.id,
    role="impersonation_read",
    admin_refresh_token=admin_refresh,  # used to cap the impersonation session
    reason="Debugging ticket 4821",     # optional, written into the token for audit
)
```

Checks, in order:

1. Impersonation is enabled in config.
2. `actor` is an admin access token holding the `impersonate` permission.
3. The admin is still active in storage, and their stored scope covers this tenant.
4. The tenant exists and is active.
5. The requested role is an impersonation role allowed for one of the admin's roles under `allowed_roles`.
6. The admin refresh token verifies, belongs to the same admin and the same session as the actor's access token, and its session is still active (otherwise `RevokedTokenError`).

A failed scope, role or permission check is audited as `impersonation.denied`.

On success, the token service issues an impersonation pair: claims as in sub-doc 07, with `act` naming the admin and an optional `reason` claim. The new impersonation session records the admin session as its parent, and its expiry is capped at the parent session's `expires_at`.

### During and after

- Impersonation refresh re-checks steps 1, 3, 4 and 5, and requires the parent admin session to be active, so removing scope, deactivating the tenant or revoking the admin session ends impersonation at the next refresh (deactivation and revocation also revoke the session itself).
- `kit.access.end_impersonation(refresh_token=...)` revokes an impersonation session early; the host also discards the impersonation tokens.
- Impersonation tokens cannot change passwords or call control plane operations.
- A tenant user's identity is never borrowed: `sub` is always the admin's ID.

### Audit

Every impersonation token carries the admin ID in `act`, the target tenant in `tid`, its own `jti` and `sid`, and the optional `reason`. The host still logs these with each request. In addition, tenantkit records `impersonation.started`, `.refreshed`, `.ended` and `.denied` events in its built-in audit log; see [11-audit.md](11-audit.md).

## Error cases

| Error | When |
| --- | --- |
| `PermissionDeniedError` | A missing permission, or impersonation outside scope or not allowed for the role |
| `WrongTokenTypeError` | `require_type` fails, or a non-admin token tries to impersonate |
| `ImpersonationDisabledError` | Impersonation is turned off in config |
| `NotFoundError` | The target tenant does not exist |
| `ConfigError` | At startup: unknown permission or role references, a role in two categories, or `allowed_roles` naming a non-impersonation role |

## Test cases

- Roles from config resolve to the union of their permissions in issued tokens.
- A role from one category cannot be assigned to another category's subject.
- Removed roles are skipped without errors; config changes apply after refresh.
- Every helper returns the right result for all three token types.
- Wildcards: `data:*` matches `data:read` and `data:write` but not `users:manage`; `*` matches everything; a check that asks for a wildcard is rejected.
- Scope `all`, `list`, and `none` allow and refuse correctly.
- Impersonation is refused for inactive tenants, inactive admins, missing `impersonate` permission, disallowed roles, and when disabled.
- Impersonation refresh fails after scope is removed or the tenant is deactivated.
- The impersonation session's expiry never passes its parent admin session's expiry.
- Ending or revoking the admin session ends impersonation sessions started from it.
- Impersonation tokens are refused by control plane and password change operations.
- `act`, `tid` and `jti` are present in impersonation tokens; impersonation without a `reason` succeeds, and the claim is simply absent.

## Decisions

1. `reason` stays optional when starting impersonation.
2. Permission wildcards (`resource:*` and `*`) are supported in v1, in role definitions only.
