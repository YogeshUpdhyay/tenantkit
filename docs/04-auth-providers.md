# 04 — Authentication providers

Every login method is a provider behind one interface. v1 ships the password provider only; SSO, LDAP and MFA are added later by writing new providers, without changing the auth services.

## Purpose and responsibilities

- Define the `AuthProvider` interface and the result it returns.
- Keep a registry of providers, so login policies can refer to them by name.
- Implement the password provider: hashing, verification, password rules, and lockout.
- Leave a clear path for multi-step logins such as MFA.

Out of scope: issuing tokens. Providers only prove who someone is. The admin and tenant auth services (sub-docs 05 and 06) turn a successful result into tokens.

## How a login flows

1. The host calls an auth service, for example `kit.tenant_auth.login(...)`, with the credentials.
2. The service finds the subject's login policy and picks the provider it names.
3. The provider checks the credentials and returns an `AuthResult`.
4. On success, the service asks the token service for tokens. On failure, it raises a typed error.

## The provider interface

```python
class AuthProvider(Protocol):
    name: str                                   # e.g. "password", used in login policies
    subject_types: set[SubjectType]             # {"admin", "tenant_user"}

    async def authenticate(
        self,
        request: AuthRequest,                   # subject_type, tenant_id (if tenant), credentials
        policy: ProviderPolicy,                 # this provider's settings from the login policy
    ) -> AuthResult: ...

@dataclass(frozen=True)
class AuthResult:
    status: Literal["success", "failure", "challenge"]
    subject_id: UUID | None = None
    reason: FailureReason | None = None         # internal only, never shown to end users
    challenge: Challenge | None = None          # for multi-step logins, unused in v1
```

- Providers receive storage through their constructor, never through globals.
- Providers never raise for bad credentials. They return a failure result, so the service controls what is exposed.
- `challenge` is reserved for MFA: a provider can say "one more step needed" and the service hands back a short-lived challenge instead of tokens. v1 never returns it.

## Provider registry

```python
kit = TenantKit(config=config, storage=storage, providers=[PasswordProvider()])
```

- The password provider is registered by default.
- Provider names must be unique, and every login policy in config or on a tenant must name a registered provider, checked at startup and on policy changes.
- A host can register its own provider, for example a custom SSO one, by implementing the interface.

## Password provider

### Hashing

- Argon2id through `argon2-cffi`, with parameters from `hashing.argon2` in config.
- On a successful login, if the stored hash used older parameters, it is re-hashed with the current ones.
- When the email is not found, the provider still runs a dummy hash check, so response time does not reveal whether an account exists.

### Password rules

Rules come from config and, for tenants, from the tenant's policy, which can only tighten them.

| Rule | Default | Notes |
| --- | --- | --- |
| `min_length` | 12 admin, 10 tenant | Counted in characters |
| `max_length` | 128 | Protects against very long hashing inputs |
| `disallow_email_in_password` | true | Case-insensitive check |

Rules are checked when a password is set or changed, not at login.

### Lockout

- Each failed login increments a counter in `LoginAttempt` for that subject.
- After `max_attempts` failures, the account is locked for `lock_minutes`.
- A successful login resets the counter.
- While locked, the provider returns failure without checking the password.
- Failures for an email that does not exist are not stored, to avoid filling the table.

Admins can unlock an account early through the control plane with `unlock_account(actor, subject_type, subject_id)`. It resets the counter and clears `locked_until`. Unlocking a tenant user needs `tenant_users:manage`; unlocking an admin needs `admins:manage`.

### Password changes

- `change_password(subject, current, new)` checks the current password and the rules.
- Admins can set a tenant user's password through the control plane.
- Self-service reset by email is out of scope for v1, because it needs email sending, which belongs to the host.

## What users see

Wrong email, wrong password, unknown account and inactive account all raise one generic `InvalidCredentialsError`. A locked account raises `AccountLockedError`, which the host shows as "Account locked. Contact your administrator." The detailed reason is available to the host for logging only.

Trade-off: the locked message reveals that the account exists. This is accepted, because lockout only applies to real accounts after several failed attempts.

## Adding providers later

| Provider | Shape |
| --- | --- |
| SSO (OIDC, SAML) | Redirect-based: a start step returns a redirect URL, a callback step returns `AuthResult` |
| LDAP or ADFS | Same as password: credentials in, result out, checked against the directory |
| MFA (TOTP) | A second-step provider: the first provider returns `challenge`, the MFA provider completes it |

The interface may gain a `start()` method for redirect flows when SSO is added. That will be an addition, not a breaking change.

## Error cases

| Error | When |
| --- | --- |
| `InvalidCredentialsError` | Any failed login other than a locked account |
| `AccountLockedError` | The account is locked; shown as "contact your administrator" |
| `PasswordPolicyError` | A new password breaks the rules; lists every broken rule |
| `ProviderNotFoundError` | A policy names a provider that is not registered |

## Test cases

- Correct password succeeds; wrong password, unknown email and inactive account all fail with the same error.
- Timing for unknown email is close to timing for wrong password.
- Lockout triggers after the configured attempts, expires after the configured time, and resets on success.
- A locked account raises `AccountLockedError`; an admin unlock clears it and the next correct login succeeds.
- Hashes are re-hashed when parameters change.
- Password rules reject short, long and email-containing passwords.
- A tenant policy cannot loosen config password rules.
- Unknown provider names are rejected at startup and on policy update.
- A custom provider registered by the host is used when a policy names it.

## Decisions

1. Locked accounts get their own message, "Account locked. Contact your administrator." Every other failure is "invalid credentials".
2. Admins can unlock accounts early through the control plane.
