# 06 — Tenant authentication

`kit.tenant_auth` logs tenant users in using whatever methods their tenant's login policy enables, and returns a tenant access token and refresh token. In v1 the only method a policy can enable is email and password; SSO, LDAP and MFA become extra options later. Every login names the tenant by its slug.

## Purpose and responsibilities

- Find the tenant from the slug, and the user within it.
- Apply the tenant's login policy, falling back to `tenant_auth.default_policy` from config.
- Refuse login when the user or the tenant is inactive.
- Issue tenant access and refresh tokens.
- Refresh tenant sessions and let users change their own password.

Out of scope: creating tenant users (sub-doc 03 in v1, tenant self-service in v2), and impersonation (sub-doc 08).

## Public interface

```python
result = await kit.tenant_auth.login(
    tenant_slug="acme",
    method="password",                       # must be enabled in the tenant's policy
    credentials={"email": "jane@acme.com", "password": "..."},
)

result = await kit.tenant_auth.refresh(refresh_token="...")
await kit.tenant_auth.change_password(actor=claims, current="...", new="...")
methods = await kit.tenant_auth.login_methods(tenant_slug="acme")   # for the host's login page
user = await kit.tenant_auth.me(actor=claims)
```

- `tenant_slug` is required. The host gets it from a subdomain, URL or login form. Login fails if the user does not belong to that tenant, so nobody can log in through another tenant's page.
- `method` names a login method. The package refuses any method the tenant's policy does not enable.
- `credentials` depends on the method. For password it is email and password.
- `login_methods` returns the methods a tenant has enabled, so the host can show the right login form. In v1 it always returns password.
- `login` and `refresh` return the same `TokenPair` shape as admin auth.

## Login flow

1. Find the tenant by slug. If it is missing or inactive, fail.
2. Load the tenant's login policy, or the config default if none is set.
3. Check that the requested method is enabled in that policy. If not, fail.
4. Hand the credentials to that method's provider. For password, the email is trimmed and lowercased.
5. The provider finds the user, checks they belong to this tenant and are active, then checks the credentials and lockout.
6. On success, issue a tenant access token and refresh token.

All failures raise `InvalidCredentialsError`, except a locked account, which raises `AccountLockedError`. An inactive tenant also returns `InvalidCredentialsError`, so the response does not reveal tenant status; the host can log the detailed reason.

## Tenant token claims

Full structure in sub-doc 07. Tenant-specific claims:

| Claim | Meaning |
| --- | --- |
| `typ` | Always `tenant` |
| `sub` | Tenant user ID |
| `tid` | Tenant ID |
| `tslug` | Tenant slug, for convenience in host routing |
| `email` | User email |
| `roles` | Tenant role names, for example `tenant_write` |
| `perms` | Permissions resolved from those roles at issue time |

The host should always scope its own data by `tid` from verified claims, never by a tenant ID sent in the request body or URL.

## Refresh flow

1. Verify the refresh token with the tenant key and check it is a tenant refresh token.
2. Reload the user and tenant. Refuse if either is missing or inactive.
3. Re-read roles, so role changes apply at the next refresh.
4. Issue a new access token and a new refresh token.

As with admins, refresh tokens are stateless in v1, so there is no server-side logout. Deactivating a user or tenant stops the next refresh.

## Password change

- Needs a valid tenant access token and the current password.
- The new password must pass the config tenant rules, tightened by the tenant's policy if set.
- Impersonation tokens cannot change a tenant user's password.

## Error cases

| Error | When |
| --- | --- |
| `InvalidCredentialsError` | Wrong credentials, unknown or inactive user, inactive tenant, slug mismatch, or a method not enabled |
| `AccountLockedError` | Too many failed attempts |
| `InvalidTokenError` | Refresh token is invalid, expired, or not a tenant refresh token |
| `PasswordPolicyError` | New password breaks the rules |
| `PermissionDeniedError` | Password change attempted with an impersonation token |

## Test cases

- A correct login returns a token with the right `tid`, `tslug`, roles and permissions.
- Login without a slug is rejected; a user logging in through another tenant's slug fails with the generic error.
- A method not enabled in the tenant's policy is refused, and `login_methods` returns only enabled methods.
- Users of an inactive tenant cannot log in or refresh, and get the generic error.
- Inactive users cannot log in or refresh.
- The tenant's login policy is used when set; otherwise the config default applies.
- A tenant policy's stricter password rules are enforced on password change.
- Admin and impersonation refresh tokens are refused by tenant refresh.
- Role changes appear after the next refresh.
- An impersonation token cannot change the user's password.

## Decisions

1. `tenant_slug` is required on every tenant login.
2. Login is policy-driven: users log in with whatever methods their tenant's policy enables. In v1 the only method available is email and password.
