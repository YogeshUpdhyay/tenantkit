# 05 — Admin authentication

`kit.admin_auth` logs admins in with the login policy from config and returns an admin access token and refresh token. It never issues tenant or impersonation tokens; impersonation is a separate call covered in sub-doc 08.

## Purpose and responsibilities

- Log admins in using the provider named in `admin_auth.policy`.
- Issue admin access and refresh tokens through the token service.
- Refresh admin sessions (rotating the refresh token) and end them with logout (sub-doc 10).
- Let admins change their own password.
- Apply the admin password rules and lockout settings from config.

Out of scope: creating admins and bootstrap (sub-doc 03), and impersonation (sub-doc 08).

## Public interface

```python
result = await kit.admin_auth.login(email="ops@example.com", password="...")
# result.access_token, result.refresh_token, result.expires_in, result.claims

result = await kit.admin_auth.refresh(refresh_token="...")

await kit.admin_auth.change_password(actor=claims, current="...", new="...")

admin = await kit.admin_auth.me(actor=claims)   # current Admin record, without the hash
```

`login` and `refresh` return a `TokenPair`: access token, refresh token, access lifetime in seconds, and the decoded access claims so the host does not need to verify what it just received.

## Login flow

1. Normalise the email: trim spaces and lowercase it.
2. Pick the provider from `admin_auth.policy` (v1: password).
3. The provider checks the credentials, lockout, and that the admin is active.
4. On success, load the admin's roles.
5. In one transaction: create the session, ask the token service for an admin access token and an admin refresh token carrying its `sid`, and audit `auth.login.succeeded`. Failures (and lockout counting) are audited outside that transaction as `auth.login.failed` / `auth.account.locked`.
6. Return the `TokenPair`.

Every failure raises `InvalidCredentialsError`, except a locked account, which raises `AccountLockedError` (sub-doc 04).

## Admin token claims

The full claim structure lives in sub-doc 07. The admin-specific claims are:

| Claim | Meaning |
| --- | --- |
| `typ` | Always `admin` |
| `sub` | Admin ID |
| `email` | Admin email |
| `roles` | Admin role names, for example `super_admin` |
| `perms` | Permissions resolved from those roles at issue time |

Impersonation scope is not put in the token. It is checked from storage when an impersonation token is requested, so scope changes apply immediately.

## Refresh flow

1. Verify the refresh token with the admin key, and check that it is an admin refresh token.
2. Load the session from `sid`. Unknown: `InvalidTokenError`. Revoked or expired: `RevokedTokenError`.
3. Load the admin from storage. If they are missing or inactive, revoke the session and refuse.
4. Re-read their roles, so role changes take effect at the next refresh.
5. Issue a new access token and a new refresh token with the same `sid`, and rotate the session's `current_jti`.

An old refresh token is no longer accepted after rotation. Presenting it again is treated as theft: the session and its impersonation sessions are revoked, `token.reuse_detected` is audited, and `RevokedTokenError` is raised. Clients must serialise refresh calls. See [10-sessions-revocation.md](10-sessions-revocation.md).

## Logout

`await kit.admin_auth.logout(refresh_token=...)` revokes the session and any impersonation sessions started from it; it is idempotent and a no-op for an expired token. `await kit.admin_auth.logout_all(actor=claims)` revokes all of the admin's sessions (impersonation actors are refused). Deactivating an admin revokes their sessions. An access token already issued stays valid until it expires unless the host uses `verify_active`.

## Password change

- Needs a valid admin access token and the current password.
- The new password must pass the admin password rules.
- All of the admin's sessions are revoked (reason `password_changed`), including the current one: the admin logs in again. Already-issued access tokens work until they expire, or until `verify_active` is used.

## Error cases

| Error | When |
| --- | --- |
| `InvalidCredentialsError` | Wrong email or password, unknown or inactive admin |
| `AccountLockedError` | Too many failed attempts |
| `InvalidTokenError` | Refresh token is invalid, expired, not an admin refresh token, or has no matching session |
| `RevokedTokenError` | The session is revoked or expired, or the refresh token was reused |
| `PasswordPolicyError` | New password breaks the rules |

## Test cases

- A correct login returns a pair whose access token verifies as an admin token with the right roles and permissions.
- Email matching ignores case and surrounding spaces.
- Inactive admins cannot log in or refresh.
- Tenant and impersonation refresh tokens are refused by admin refresh.
- Role changes appear in the claims after the next refresh.
- Refresh returns a new refresh token each time; the previous one is rejected, and reuse revokes the session.
- Logout, logout-all and password change revoke sessions.
- Password change enforces the current password and the rules.
- Lockout and unlock behave as in sub-doc 04.

## Decisions

1. Ending existing sessions on password change is deferred to v2, together with token revocation.
