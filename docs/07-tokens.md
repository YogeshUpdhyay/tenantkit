# 07 — Token service

`kit.tokens` issues and verifies signed JWTs for three token types — admin, tenant and impersonation — each with its own signing key, and each with an access and a refresh form. Its `verify()` utility is what the host calls in its own middleware to get trusted claims.

## Purpose and responsibilities

- Issue access and refresh tokens for each token type, using that type's key and lifetimes from config.
- Verify tokens: signature, algorithm, expiry, issuer, audience, token type, and token use.
- Return typed claim objects, or raise a typed error.
- Carry a session id (`sid`) in every token. `verify()` stays stateless and storage-free; the opt-in `verify_active()` additionally checks the session.

Out of scope: key rotation (deferred), and any HTTP handling (the host's middleware). Sessions and revocation are covered in [10](10-sessions-revocation.md).

## Token matrix

| Token type | Use | Signed with | Default lifetime | Issued by |
| --- | --- | --- | --- | --- |
| Admin | access | admin key | 15 minutes | admin login, admin refresh |
| Admin | refresh | admin key | 8 hours | admin login, admin refresh |
| Tenant | access | tenant key | 15 minutes | tenant login, tenant refresh |
| Tenant | refresh | tenant key | 7 days | tenant login, tenant refresh |
| Impersonation | access | impersonation key | 10 minutes | impersonation start, impersonation refresh |
| Impersonation | refresh | impersonation key | 1 hour, capped | impersonation start, impersonation refresh |

Access and refresh tokens of the same type share a key, and are told apart by the `use` claim. A refresh token is never accepted where an access token is expected, and the other way round.

## Common claims

Every token carries these:

| Claim | Meaning |
| --- | --- |
| `iss` | Issuer from config |
| `aud` | Audience from config |
| `sub` | Subject ID: admin ID or tenant user ID |
| `typ` | `admin`, `tenant`, or `impersonation` |
| `use` | `access` or `refresh` |
| `iat`, `nbf`, `exp` | Issued at, not before, expiry (Unix seconds) |
| `jti` | Unique token ID, a random UUID. A refresh token's `jti` is its session's `current_jti` |
| `sid` | Session ID (UUID). Required: tokens without it are rejected |

The JWT header carries `alg` and `kid`. Access tokens also carry the type-specific claims below. Refresh tokens carry only the common claims, plus `tid` for tenant and impersonation types and the chosen role (and reason) for impersonation, because other roles are re-read from storage on every refresh.

## Type-specific claims (access tokens)

| Claim | Admin | Tenant | Impersonation |
| --- | --- | --- | --- |
| `email` | admin email | user email | admin email |
| `roles` | admin roles | tenant roles | impersonation roles (sub-doc 08) |
| `perms` | resolved permissions | resolved permissions | resolved permissions |
| `tid` | — | tenant ID | target tenant ID |
| `tslug` | — | tenant slug | target tenant slug |
| `act` | — | — | `{"sub": admin ID, "email": admin email}` |
| `reason` | — | — | optional reason given at impersonation start |

For impersonation, `sub` is the admin ID, and `act` follows the RFC 8693 "actor" convention, so audit logs always show which admin acted. Roles and permissions in an impersonation token come from impersonation roles, never from a tenant user, so an admin never silently gains a real user's identity.

## Public interface

```python
# Verify (what the host calls in its middleware)
claims = kit.tokens.verify(token)                            # any access token type
claims = kit.tokens.verify(token, expected="admin")          # only admin access tokens
claims = kit.tokens.verify(token, expected={"tenant", "impersonation"})

if isinstance(claims, TenantClaims): ...
claims.typ, claims.sub, claims.roles, claims.perms, claims.tenant_id

# Issue (used internally by the auth services; also public for advanced hosts)
pair = kit.tokens.issue_pair(typ="tenant", subject=user, tenant=tenant, session_id=session.id)
# pair.refresh_jti and pair.refresh_expires_at let the caller persist the session

# Verify and also require a live session (async, reads storage)
claims = await kit.tokens.verify_active(token, expected="tenant")
```

- `verify` is synchronous and touches no storage, so it is cheap to call on every request.
- It returns one of `AdminClaims`, `TenantClaims`, or `ImpersonationClaims`, all frozen pydantic models sharing a `BaseClaims` with the common fields.
- `verify` accepts access tokens only. Refresh tokens are handled inside the auth services' `refresh()` calls.
- `verify_active` runs `verify`, then loads the session: unknown raises `InvalidTokenError`, revoked or expired raises `RevokedTokenError`. For impersonation tokens the parent admin session must be live too. A revoked session otherwise stops working when its access token expires (15 minutes by default, 10 for impersonation).
- `expected` lets the host reject the wrong token type before any authorisation logic runs.

## How verification works

1. Read the unverified header. Reject if `alg` is `none` or not the algorithm configured for that `kid`.
2. Pick the verification key by `kid`. An unknown `kid` is rejected.
3. Verify the signature with that key only.
4. Check `iss`, `aud`, `exp` and `nbf`, allowing the configured clock skew.
5. Check that `typ` matches the key's token type. A token signed with the tenant key but claiming `typ: admin` is rejected.
6. Check `use` is `access`, and `typ` is in `expected` if given.
7. Parse into the claim model for that type. Missing or malformed claims, including a missing `sid`, are rejected.

Because each type has its own key, step 5 means a leaked tenant key can never mint admin tokens.

## Issuing rules

- Lifetimes come from config per type and use.
- An impersonation refresh token never outlives the admin session that started it: `issue_pair` receives `refresh_cap`, the parent session's `expires_at`, and caps both refresh and access `exp` at it.
- Permissions are resolved from roles at issue time and written into `perms`, so `verify` needs no lookup.
- Every new pair gets new `jti` values; the session id stays the same across refreshes.

## Error cases

| Error | When |
| --- | --- |
| `InvalidTokenError` | Bad format, bad signature, wrong algorithm, unknown `kid`, bad issuer or audience, missing claims |
| `ExpiredTokenError` | `exp` has passed (a subclass of `InvalidTokenError`) |
| `RevokedTokenError` | `verify_active` finds the session revoked or expired (a subclass of `InvalidTokenError`) |
| `WrongTokenTypeError` | Token type or use does not match what was expected (also a subclass) |

The host can catch `InvalidTokenError` alone and map it to 401, or catch the subclasses for finer messages. Error messages never include the token itself.

## Test cases

- Each of the six token forms is issued with the right key, lifetime, and claims.
- `verify` returns the correct claims model for each access token type.
- Expired, not-yet-valid, wrong issuer, wrong audience, and tampered tokens are rejected.
- Algorithm `none`, algorithm swap (such as RS256 to HS256 using the public key as a secret), and unknown `kid` are rejected.
- A token signed with one type's key but claiming another `typ` is rejected.
- Refresh tokens are rejected by `verify`; access tokens are rejected by `refresh()`.
- `expected` filters by type correctly for single values and sets.
- Impersonation tokens carry `act` with the admin ID, and their refresh expiry never exceeds the admin's.
- Clock skew is applied within the configured limit and no further.
- `verify` makes no storage calls, and still accepts the access token of a revoked session until it expires; `verify_active` rejects it.
- Tokens without `sid` (issued by 0.1.x) are rejected by `verify` and `refresh`.

## Decisions

1. `verify` is a plain synchronous function and stays storage-free. Revocation is opt-in through the async `verify_active`; an async-only `verify` is deferred to v2.
2. Revocation covers refresh tokens and sessions. Access tokens of a revoked session live until they expire.
