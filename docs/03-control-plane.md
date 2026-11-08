# 03 — Control plane and tenant management

The control plane is a Python service, `kit.control_plane`, that admins use to create and manage tenants, tenant users, and other admins. Each call takes the caller's verified admin claims and checks permissions before acting.

## Purpose and responsibilities

- Create, read, list, update, deactivate, and reactivate tenants.
- Validate dynamic tenant fields against the schema from config.
- Set and change each tenant's login policy.
- Create and manage tenant users in v1, since tenant self-service is deferred to v2.
- Create and manage admins, including their roles and impersonation scope.
- Unlock locked accounts (see sub-doc 04).
- Bootstrap the first super admin.

Out of scope: HTTP endpoints or UI. The host exposes these operations however it likes.

## Calling convention

Every method that changes or reads control plane data takes `actor`, the verified admin claims returned by `kit.tokens.verify()`.

```python
claims = kit.tokens.verify(token, expected="admin")
tenant = await kit.control_plane.create_tenant(
    actor=claims,
    slug="acme",
    attributes={"organisation_name": "Acme Ltd", "seats": 50},
)
```

- The service checks that `actor` is an admin token, not tenant or impersonation, and that its roles carry the needed permission.
- A missing permission raises `PermissionDeniedError`, which the host maps to 403.
- The permission names below are defaults and can be renamed in config.

## Operations and permissions

| Operation | Method | Permission |
| --- | --- | --- |
| Create tenant | `create_tenant(actor, slug, attributes, login_policy=None)` | `tenants:create` |
| Get tenant | `get_tenant(actor, tenant_id)` | `tenants:read` |
| List tenants | `list_tenants(actor, active=None, limit, offset)` | `tenants:read` |
| Update tenant attributes | `update_tenant(actor, tenant_id, attributes)` | `tenants:update` |
| Set login policy | `set_login_policy(actor, tenant_id, policy)` | `tenants:update` |
| Deactivate or reactivate tenant | `deactivate_tenant` / `reactivate_tenant` | `tenants:deactivate` |
| Create tenant user | `create_tenant_user(actor, tenant_id, email, password, roles)` | `tenant_users:manage` |
| Update, deactivate tenant user | `update_tenant_user` / `deactivate_tenant_user` | `tenant_users:manage` |
| Create admin | `create_admin(actor, email, password, roles, impersonation_scope)` | `admins:manage` |
| Update, deactivate admin | `update_admin` / `deactivate_admin` | `admins:manage` |
| Unlock account | `unlock_account(actor, subject_type, subject_id)` | `tenant_users:manage` or `admins:manage` |

## Tenant lifecycle

1. **Create:** the slug is validated (lowercase letters, digits, hyphens, 3 to 63 characters) and must be unique. Attributes are validated against the schema. If no login policy is given, the default from config applies.
2. **Active:** tenant users can log in and receive tokens. Admins with scope can impersonate.
3. **Deactivated:** tenant users cannot log in or refresh. Existing access tokens stay valid until they expire, since revocation is deferred. Impersonation is refused.
4. **Reactivated:** login works again. Nothing is deleted at any point.

The slug cannot be changed after creation, because hosts may use it in URLs or subdomains.

## Dynamic tenant schema

The host defines tenant fields in config under `tenant_schema` (see sub-doc 01). The control plane turns that definition into a pydantic model at startup and validates every create and update against it.

| Type | Supported rules |
| --- | --- |
| `string` | required, min_length, max_length, pattern, choices |
| `integer` | required, min, max |
| `number` | required, min, max |
| `boolean` | required |
| `date` | required |
| `object` | required, nested fields |
| `list` | required, item type, min_items, max_items |

- Unknown fields are rejected, so typos never get stored silently.
- Updates are partial: only the fields sent are changed, then the whole result is validated.
- A default value can be set per field.
- **Schema changes:** adding an optional field is safe. Making a field required or narrowing a rule can leave old records invalid; those records still load, but the next update must fix them. `validate_all_tenants()` reports which tenants no longer match.

## Tenant login policy

Stored on the tenant as a small JSON document. v1 supports only the password provider.

```json
{ "providers": ["password"], "password": { "min_length": 10 } }
```

- A tenant policy can only name providers registered in the kit.
- A tenant policy can tighten password rules from config but never loosen them below the config minimum.

## Admin management and bootstrap

- **Bootstrap:** `kit.control_plane.bootstrap_super_admin(email, password)` creates the first admin with every admin permission. It works only when no admin exists, and raises `AlreadyBootstrappedError` otherwise. The host calls it from a CLI command or a one-off script, never from an HTTP endpoint.
- **Impersonation scope** is set per admin as all, a list of tenant IDs, or none (see sub-doc 08).
- **Safety rule:** the last active admin holding `admins:manage` cannot be deactivated or lose that permission.
- An admin cannot grant roles or impersonation scope beyond their own.

## Error cases

| Error | When |
| --- | --- |
| `PermissionDeniedError` | The actor is not an admin token or lacks the permission |
| `TenantValidationError` | Attributes fail the schema; lists every field error |
| `InvalidSlugError` | The slug breaks the format rules |
| `AlreadyExistsError` | The slug or an email is already taken |
| `NotFoundError` | The tenant, user, or admin does not exist |
| `AlreadyBootstrappedError` | Bootstrap is called when an admin already exists |
| `LastAdminError` | The change would leave no active admin who can manage admins |

## Test cases

- Each operation succeeds with the right permission and fails with `PermissionDeniedError` without it.
- Tenant and impersonation tokens are refused for every control plane operation.
- Schema validation: every type and rule, unknown fields rejected, partial updates, defaults applied.
- `validate_all_tenants()` reports records that no longer match after a schema change.
- Slug format and uniqueness; slug cannot be changed.
- Deactivated tenants block login, refresh, and impersonation; reactivation restores them.
- Tenant user email already used in any tenant is rejected.
- Bootstrap works once and only once.
- The last admin with `admins:manage` cannot be removed or demoted.
- An admin cannot grant roles or scope beyond their own.
- Deactivating a tenant leaves its user records unchanged.

## Decisions

1. Deactivating a tenant blocks login, refresh and impersonation at tenant level. User records are left untouched.
2. Slug rules stay as written: 3 to 63 characters, lowercase letters, digits and hyphens.
3. Hooks are out of scope for v1.
