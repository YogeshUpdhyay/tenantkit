# tenantkit — Parent Design Doc

Package name: `tenantkit` (confirmed)

This is the top-level guideline for the project. It sets out the goals, scope, constraints, architecture, project tree, and testing strategy, and links to the sub-docs that hold the details for each module. Detailed behaviour belongs in the sub-docs, not here.

## 1. Purpose

Build an in-house, pip-installable Python package that adds multi-tenancy, authentication, token issuing and verification, and configurable roles and permissions to any Python application. It replaces external identity platforms such as Keycloak, so we avoid their cost and operating overhead.

The first consumer is our FastAPI application, but the package must stay framework-agnostic.

## 2. Goals

1. Give the host application a control plane where super admins create and manage tenants.
2. Support dynamic tenant data. The host defines which fields a tenant has, and the package validates them without code changes.
3. Own the authentication lifecycle: login, token issuing, and token verification.
4. Issue three distinct token types: admin, tenant, and impersonation.
5. Let admins impersonate tenants within scoped rights, with full traceability.
6. Make roles and permissions configurable from v1.
7. Expose a simple verification utility that returns validated claims, so the host builds its own authentication and authorisation layers.
8. Make everything configurable at initialisation: keys, token lifetimes, login policies, roles, and storage.
9. Stay pluggable: login providers and storage backends can be added without changing core code.

## 3. Non-goals for v1

- No built-in web framework middleware, routers, or HTTP error handling. Framework integration is shown through examples only.
- No SSO, ADFS, LDAP, or MFA implementations yet. The provider interface must make them easy to add later.
- No tenant self-service user management (tenant admins adding users). This is planned for a later version.
- No admin UI. The control plane is a Python API that the host can expose however it likes.

## 4. Requirements summary

### 4.1 Control plane

- A super admin's login policy is defined in the host config and passed in at initialisation.
- Super admins can create, read, update, deactivate, reactivate, and list tenants, and in v1 they also manage tenant users and admins. The first super admin is created by a one-time bootstrap call.
- Tenant metadata (for example, organisation name) is defined by a host-supplied schema and stored as validated dynamic data.

### 4.2 Authentication

- Admin authentication and tenant authentication are separate flows with separate policies.
- Each tenant has its own login policy, and users log in with whatever methods it enables. In v1 the only method is platform-managed email and password. Every tenant login must name the tenant by its slug.
- Login methods are implemented as providers behind a common interface. Failed logins return a generic invalid-credentials error, locked accounts show "Account locked. Contact your administrator.", and admins can unlock accounts.

### 4.3 Tokens

- There are three token types: admin, tenant, and impersonation.
- Each type has its own signing key, lifetime, and claims. Keys are never shared across token types. v1 includes refresh tokens for each type, with their own configurable lifetimes.
- An impersonation token records both the acting admin and the target tenant.
- A verification utility checks signature, expiry, issuer, audience, and token type, then returns typed claims or raises a typed error.

### 4.4 Roles, permissions, and impersonation

- There are three built-in identity categories: admin, impersonation, and tenant.
- Roles and permissions within each category are configurable, including impersonation roles such as read-only or full access. Wildcards (`resource:*` and `*`) are supported in role definitions.
- Roles and permissions are carried in token claims.
- The package provides helpers to check roles and permissions, but the host decides endpoint access.
- An admin's impersonation rights are scoped to all tenants, a list of tenants, or none. Config sets which impersonation roles each admin role may use, and giving a reason is optional.

### 4.5 Storage

- The core depends only on abstract repository interfaces.
- An optional SQLAlchemy adapter (`pip install tenantkit[sqlalchemy]`) uses the host's engine and session.
- Tables use a configurable prefix (default `mt_`).
- The adapter's metadata is exposed so the host's Alembic migrations can include it.
- Dynamic tenant fields are stored in a JSON column. Tenant user emails are globally unique, so each user belongs to one tenant. v1 has no schema name option and no sync adapter.

## 5. Constraints

- Python 3.11 or later, fully type-hinted, and checked with mypy in strict mode.
- Core dependencies are kept minimal: a JWT library, a password hashing library (argon2), and pydantic for config and schema validation.
- Framework-agnostic. The core never imports FastAPI, Starlette, Django, or Flask.
- No global mutable state. All behaviour flows from an explicit configured instance.
- Secrets never appear in logs, exceptions, or `repr` output.
- Async-first public API. Pure checks that touch no storage, such as token verification, are plain functions.

## 6. Design principles

- **Separation of concerns:** domain models, services, providers, tokens, and storage live in separate modules with one-way dependencies.
- **Dependency inversion:** services depend on interfaces (repositories, providers), never on concrete implementations.
- **Open/closed:** new login providers and storage adapters are added by implementing an interface, not by editing the core.
- **Explicit configuration:** one validated config object, built at initialisation. The package fails fast on invalid config.
- **Typed errors:** a single exception hierarchy, so hosts can map errors to their own responses (for example, 401 or 403).
- **Secure by default:** short token lifetimes, strong hashing, strict claim validation, and no algorithm `none`.
- **Small public surface:** everything public is exported from the top-level package. Everything else is internal.

## 7. Architecture overview

Dependencies point inward, from the outer layers to the core:

- **Facade:** a single `TenantKit` object, built from config, that wires the services together and is the host's entry point.
- **Services:** ControlPlaneService, AdminAuthService, TenantAuthService, TokenService, and AccessService (roles, permissions, and impersonation checks).
- **Interfaces:** repositories and auth providers.
- **Domain:** plain models and the exception hierarchy, with no I/O.
- **Adapters (outer layer):** SQLAlchemy storage and in-memory storage for tests.

The typical request flow is:

1. The host's middleware extracts the bearer token.
2. It calls `kit.tokens.verify(token)`.
3. It receives typed claims, or catches a typed error.
4. It stores the claims in its own request context.
5. The host's authorisation layer uses `kit.access` helpers or its own logic.

## 8. Project tree

```
tenantkit/
├── pyproject.toml
├── README.md              # single usage guide, includes the full FastAPI integration
├── docs/
│   ├── 00-parent-design.md
│   ├── 01-configuration.md
│   ├── 02-storage.md
│   ├── 03-control-plane.md
│   ├── 04-auth-providers.md
│   ├── 05-admin-auth.md
│   ├── 06-tenant-auth.md
│   ├── 07-tokens.md
│   ├── 08-roles-permissions-impersonation.md
│   └── integrations/
│       └── fastapi.md
├── src/tenantkit/
│   ├── __init__.py            # public API exports
│   ├── kit.py                 # TenantKit facade
│   ├── config/
│   │   ├── models.py          # pydantic config models
│   │   └── loader.py          # building and validating config
│   ├── domain/
│   │   ├── models.py          # Admin, Tenant, User, Role, Permission
│   │   ├── claims.py          # typed claim models per token type
│   │   └── errors.py          # exception hierarchy
│   ├── storage/
│   │   ├── interfaces.py      # repository protocols
│   │   ├── memory/            # in-memory adapter (tests, prototyping)
│   │   └── sqlalchemy/        # optional adapter: tables, repos, metadata
│   ├── control_plane/
│   │   ├── service.py         # tenant management
│   │   └── schema.py          # dynamic tenant field schema and validation
│   ├── auth/
│   │   ├── providers/
│   │   │   ├── base.py        # AuthProvider interface
│   │   │   └── password.py    # email and password provider
│   │   ├── hashing.py
│   │   ├── admin.py           # AdminAuthService
│   │   └── tenant.py          # TenantAuthService
│   ├── tokens/
│   │   ├── service.py         # issue and verify
│   │   ├── keys.py            # key loading and checks from config values
│   │   └── types.py           # token type definitions
│   └── access/
│       ├── roles.py           # role and permission registry
│       ├── checks.py          # has_role, has_permission helpers
│       └── impersonation.py   # scope rules and checks
├── examples/
│   └── fastapi_app/           # reference integration
└── tests/
    ├── unit/
    ├── integration/
    └── security/
```

## 9. Sub-docs index

| # | Sub-doc | Covers |
| --- | --- | --- |
| 01 | [Configuration and initialisation](01-configuration.md) | Config models, signing keys, token lifetimes, admin login policy, validation and fail-fast rules, YAML example |
| 02 | [Storage layer](02-storage.md) | Domain models, repository interfaces, SQLAlchemy adapter, table prefix, Alembic integration, in-memory adapter |
| 03 | [Control plane and tenant management](03-control-plane.md) | Tenant lifecycle, dynamic field schema, validation, deactivation, admin bootstrap |
| 04 | [Authentication providers](04-auth-providers.md) | Provider interface, email and password provider, lockout and unlock, extension path for SSO, LDAP, and MFA |
| 05 | [Admin authentication](05-admin-auth.md) | Super admin login using the policy from config |
| 06 | [Tenant authentication](06-tenant-auth.md) | Policy-driven tenant login with a required slug |
| 07 | [Token service](07-tokens.md) | Three token types, claim structure, signing and keys, expiry and refresh, verification utility |
| 08 | [Roles, permissions, and impersonation](08-roles-permissions-impersonation.md) | Identity categories, configurable roles, wildcards, claims mapping, scoped impersonation, audit fields |
| 09 | [FastAPI integration guide](integrations/fastapi.md) | Example authentication middleware, authorisation dependencies, and mapping errors to 401 or 403 |

Each sub-doc follows the same template: purpose, responsibilities, public interface, data and claims, configuration, error cases, test cases, and decisions.

## 10. Testing strategy

- **Unit tests:** every service is tested against the in-memory adapter and fake providers.
- **Integration tests:** the SQLAlchemy adapter is tested against SQLite and PostgreSQL, including migrations generated through Alembic.
- **Security tests:** cover expired tokens, tampered signatures, the wrong token type, the wrong audience, algorithm `none`, cross-tenant access, impersonation outside scope, and timing-safe password checks.
- **Contract tests:** a shared test suite that any storage adapter or auth provider must pass.
- **Example test:** the FastAPI example app is exercised end to end.
- **Quality gates:** at least 90% coverage on core modules, mypy strict, ruff, and all checks run in CI.

### Acceptance criteria for v1

1. A super admin can log in with the policy from config and receive an admin token.
2. A super admin can create a tenant with dynamic fields that are validated against the configured schema.
3. A tenant user can log in through their tenant's slug with email and password and receive a tenant token carrying their tenant ID and roles.
4. An admin with the right scope can obtain an impersonation token for a tenant. An admin without that scope is refused.
5. `verify()` returns correct typed claims for all three token types and rejects tokens that are invalid, expired, or of the wrong type.
6. Roles and permissions defined in config appear in the claims and can be checked with the access helpers.
7. The FastAPI example demonstrates authentication middleware and authorisation for admin-only, tenant-only, and tenant-or-impersonation endpoints, and the README contains the same integration guide.

## README

The README is the single point of usage documentation. When the code is generated, it must cover installation (including the SQLAlchemy extra), a minimal config, building the kit, admin bootstrap, and login and refresh.

It must also contain the full FastAPI integration from sub-doc 09: setup, authentication middleware, authorisation dependencies, error mapping, auth endpoints, tenant data scoping, and impersonation logging. README examples are kept identical to `examples/fastapi_app/` and are tested in CI.

## 11. Roadmap

- **v1:** everything above.
- **v1.x:** token revocation (deferred from v1), plus audit log hooks.
- **v2:** tenant admins can manage users within their own organisation, plus ending sessions on password change, an async verify, key rotation, tenant lifecycle hooks, and a sync SQLAlchemy adapter.
- **v2.x:** SSO, ADFS, and LDAP providers, plus MFA as a second step in a login policy.

## 12. Decisions

1. Refresh tokens: included in v1.
2. Token revocation: deferred beyond v1.
3. Signing keys: each token type has its own key.
4. Package name: tenantkit.
