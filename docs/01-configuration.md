# 01 — Configuration and initialisation

The host builds one validated `TenantKitConfig` object and passes it to `TenantKit`. Every other module reads its settings from that object, and the package refuses to start if the config is invalid.

## Purpose and responsibilities

- Define the full set of settings the package accepts, as typed pydantic models.
- Accept signing keys as config values passed in by the host.
- Validate everything at startup and fail fast with clear errors.
- Wire the configured services together inside the `TenantKit` facade.
- Keep secrets out of logs, exceptions, and `repr` output.

Out of scope: storing config in the database, or changing config at runtime. Config is immutable once the kit is built.

## Public interface

```python
from tenantkit import TenantKit, TenantKitConfig

config = TenantKitConfig(...)          # or TenantKitConfig.from_dict(d)
kit = TenantKit(config=config, storage=storage_adapter)

kit.control_plane   # ControlPlaneService
kit.admin_auth      # AdminAuthService
kit.tenant_auth     # TenantAuthService
kit.tokens          # TokenService
kit.access          # AccessService
```

- `TenantKitConfig` is frozen. Building it validates the whole tree.
- `TenantKit(...)` resolves keys, checks storage is reachable if the adapter supports a health check, and builds the services.
- Storage is passed separately from config, because it is an object (the adapter), not a setting.

All configuration arrives as arguments at initialisation. The package never reads environment variables, files, or YAML on its own. The host decides where settings come from and passes them in.

## Config tree

| Section | Key settings | Notes |
| --- | --- | --- |
| `issuer` / `audience` | issuer string, default audience | Written into every token and checked on verify |
| `tokens.admin` | signing key, algorithm, access lifetime, refresh lifetime | Its own key, never shared |
| `tokens.tenant` | signing key, algorithm, access lifetime, refresh lifetime | Its own key, never shared |
| `tokens.impersonation` | signing key, algorithm, access lifetime, refresh lifetime | Its own key; short lifetimes by default |
| `admin_auth` | admin login policy (v1: password), password rules, lockout rules | The super admin policy from the host config |
| `tenant_auth` | default tenant login policy, password rules, lockout rules | Each tenant can override within allowed providers |
| `tenant_schema` | dynamic tenant field definitions | Detailed in sub-doc 03 |
| `roles` | admin, tenant and impersonation roles, their permissions | Detailed in sub-doc 08 |
| `impersonation` | enabled flag, default scope for new admins, allowed roles per admin role | Detailed in sub-doc 08 |
| `hashing` | argon2 parameters | Safe defaults; override only with care |
| `clock` | allowed clock skew in seconds | Default 30 |

### Default lifetimes

Every lifetime is configurable. These apply when a value is left out.

| Token type | Access lifetime | Refresh lifetime |
| --- | --- | --- |
| Admin | 15 minutes | 8 hours |
| Tenant | 15 minutes | 7 days |
| Impersonation | 10 minutes | 1 hour, never beyond the admin's own session |

## Signing keys

Each token type has its own key, passed in at initialisation. The package only checks and uses the keys it is given.

- **How keys arrive:** the host passes key material (PEM text or a secret) as config values. Reading it from a file, environment variable or vault is the host's job.
- **Algorithms:** RS256 and ES256 are recommended. HS256 is allowed for simple setups. `none` is always rejected.
- **Key IDs:** every key carries a `kid`, written into the token header.
- **Key rotation:** out of scope for v1. The `kid` is kept so rotation can be added later without changing token format.

```python
tokens = TokensConfig(
    admin=TokenTypeConfig(
        private_key=admin_private_pem,
        public_key=admin_public_pem,
        kid="admin-1",
        algorithm="RS256",
        access_ttl=timedelta(minutes=15),
        refresh_ttl=timedelta(hours=8),
    ),
    tenant=TokenTypeConfig(...),
    impersonation=TokenTypeConfig(...),
)
```

## Example config in YAML (documentation only)

This YAML shows the shape of the config. The package does not read YAML. The host loads it however it likes, fills in secrets, and passes the result to `TenantKitConfig.from_dict()`. Every lifetime shown is configurable; if left out, the defaults apply.

```yaml
issuer: "https://auth.example.com"
audience: "example-app"

tokens:
  admin:
    algorithm: RS256
    kid: admin-1
    private_key: "<PEM text supplied by host>"
    public_key: "<PEM text supplied by host>"
    access_ttl_seconds: 900        # 15 minutes
    refresh_ttl_seconds: 28800     # 8 hours
  tenant:
    algorithm: RS256
    kid: tenant-1
    private_key: "<PEM text supplied by host>"
    public_key: "<PEM text supplied by host>"
    access_ttl_seconds: 900        # 15 minutes
    refresh_ttl_seconds: 604800    # 7 days
  impersonation:
    algorithm: RS256
    kid: imp-1
    private_key: "<PEM text supplied by host>"
    public_key: "<PEM text supplied by host>"
    access_ttl_seconds: 600        # 10 minutes
    refresh_ttl_seconds: 3600      # 1 hour

admin_auth:
  policy:
    providers: [password]
  password:
    min_length: 12
  lockout:
    max_attempts: 5
    lock_minutes: 15

tenant_auth:
  default_policy:
    providers: [password]
  password:
    min_length: 10
  lockout:
    max_attempts: 5
    lock_minutes: 15

tenant_schema:
  fields:
    - name: organisation_name
      type: string
      required: true
      max_length: 200
    - name: country
      type: string
      required: false
    - name: seats
      type: integer
      required: false
      min: 1

roles:
  admin:
    super_admin:
      permissions: [tenants:create, tenants:read, tenants:update, tenants:deactivate, tenant_users:manage, admins:manage, impersonate]
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
  default_scope: none              # all | list | none
  allowed_roles:
    super_admin: [impersonation_read, impersonation_full]
    support_admin: [impersonation_read]

hashing:
  argon2:
    time_cost: 3
    memory_cost_kib: 65536
    parallelism: 2

clock:
  skew_seconds: 30
```

## Validation rules (fail fast)

1. All three token types must be configured.
2. No two token types may use the same key material or the same `kid`.
3. The algorithm must match the key type, for example an RSA key with RS256.
4. Refresh lifetime must be longer than access lifetime.
5. Impersonation lifetimes must not exceed admin lifetimes.
6. Every login policy must name a registered provider.
7. Every role must reference only defined permissions (or valid wildcards), and role names must be unique across categories.
8. The tenant field schema must be valid, with unique field names and supported types.
9. HS256 secrets must be at least 32 bytes.

All failures raise `ConfigError`, listing every problem found, not just the first.

## Error cases

| Error | When |
| --- | --- |
| `ConfigError` | Any validation rule fails |
| `KeyLoadError` | Key material passed in config cannot be parsed |
| `StorageUnavailableError` | The adapter's health check fails at startup |

Error messages name the setting path, for example `tokens.tenant.private_key`, but never include key material.

## Test cases

- A valid minimal config builds a working kit.
- Each validation rule has a test that triggers it, and a test that collects multiple errors at once.
- Shared keys or shared `kid` values across token types are rejected.
- Algorithm `none` and mismatched algorithms are rejected.
- Keys passed as config values load correctly for each supported algorithm.
- `repr` and `str` of the config and of `ConfigError` never contain secrets.
- `from_dict` on the documented YAML shape produces the same config as direct construction.
- Omitted lifetimes fall back to the defaults; supplied lifetimes override them.
- The config object cannot be modified after creation.

## Decisions

1. All settings come in as arguments at initialisation. The package reads no environment variables or files.
2. Key rotation is out of scope for v1.
3. The listed lifetimes are the defaults, and every lifetime can be overridden in config.
