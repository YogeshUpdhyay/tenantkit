# 07 — Token service

`kit.tokens` issues and verifies signed JWTs for three token types — admin, tenant and impersonation — each with its own signing key, and each with an access and a refresh form. Its `verify()` utility is what the host calls in its own middleware to get trusted claims.

## Purpose and responsibilities

- Issue access and refresh tokens for each token type, using that type's key and lifetimes from config.
- Verify tokens: signature, algorithm, expiry, issuer, audience, token type, and token use.
- Return typed claim objects, or raise a typed error.
- Stay stateless in v1: nothing is stored about issued tokens.

Out of scope: revocation and key rotation (deferred), and any HTTP handling (the host's middleware).

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
| `jti` | Unique token ID, a random UUID, for logging and future revocation |

The JWT header carries `alg` and `kid`. Access tokens also carry the type-specific claims below. Refresh tokens carry only the common claims, plus `tid` for tenant and impersonation types, because roles are re-read from storage on every refresh.

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
pair = kit.tokens.issue_pair(typ="tenant", subject=user, tenant=tenant)
```

- `verify` is synchronous and touches no storage, so it is cheap to call on every request.
- It returns one of `AdminClaims`, `TenantClaims`, or `ImpersonationClaims`, all frozen pydantic models sharing a `BaseClaims` with the common fields.
- `verify` accepts access tokens only. Refresh tokens are handled inside the auth services' `refresh()` calls.
- `expected` lets the host reject the wrong token type before any authorisation logic runs.

## How verification works

1. Read the unverified header. Reject if `alg` is `none` or not the algorithm configured for that `kid`.
2. Pick the verification key by `kid`. An unknown `kid` is rejected.
3. Verify the signature with that key only.
4. Check `iss`, `aud`, `exp` and `nbf`, allowing the configured clock skew.
5. Check that `typ` matches the key's token type. A token signed with the tenant key but claiming `typ: admin` is rejected.
6. Check `use` is `access`, and `typ` is in `expected` if given.
7. Parse into the claim model for that type. Missing or malformed claims are rejected.

Because each type has its own key, step 5 means a leaked tenant key can never mint admin tokens.

## Issuing rules

- Lifetimes come from config per type and use.
- An impersonation refresh token never outlives the admin session that started it: its `exp` is capped at the admin refresh token's `exp`, passed in by the impersonation service.
- Permissions are resolved from roles at issue time and written into `perms`, so `verify` needs no lookup.
- Every new pair gets new `jti` values.

## Error cases

| Error | When |
| --- | --- |
| `InvalidTokenError` | Bad format, bad signature, wrong algorithm, unknown `kid`, bad issuer or audience, missing claims |
| `ExpiredTokenError` | `exp` has passed (a subclass of `InvalidTokenError`) |
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
- `verify` makes no storage calls.

## Decisions

1. `verify` is a plain synchronous function in v1. An awaitable version is deferred to v2.
