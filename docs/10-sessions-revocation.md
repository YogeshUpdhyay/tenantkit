# 10 — Sessions and revocation

Every login creates a *session*. Refresh tokens are stateful: each refresh rotates the token, and a reused refresh token ends the whole session. Sessions can also be ended by logout, by an admin, and automatically when an account is deactivated or its password changes. `verify()` stays synchronous and storage-free; the opt-in `await kit.tokens.verify_active()` additionally checks the session.

## Purpose and responsibilities

- Persist one `Session` record per refresh-token family (`mt_sessions`).
- Rotate the refresh token on every refresh and detect reuse.
- Revoke sessions on logout, logout-all, admin action, deactivation, password change and early end of impersonation.
- Cascade revocation from an admin session to the impersonation sessions started from it.
- Offer `verify_active()` for hosts that need instant cut-off.

Out of scope: revocation checks inside the synchronous `verify()`, key rotation, and automatic expiry of rows (hosts schedule `kit.sessions.purge_expired()`).

## Model

```python
@dataclass(kw_only=True)
class Session:
    kind: Literal["admin", "tenant", "impersonation"]   # equals the token typ
    subject_id: UUID            # admin id (admin, impersonation) or tenant user id
    tenant_id: UUID | None      # tenant user's tenant, or impersonation target
    parent_id: UUID | None      # impersonation only: the admin session that started it
    current_jti: UUID           # the only refresh jti currently accepted
    expires_at: datetime        # refresh expiry of the current refresh token
    id, created_at, last_used_at, revoked_at, revoked_reason
    is_active -> bool           # not revoked and expires_at > now
```

`RevokeReason` constants: `logout`, `logout_all`, `admin_revoked`, `subject_deactivated`, `tenant_deactivated`, `password_changed`, `reuse_detected`, `parent_revoked`, `impersonation_ended`.

Every token (access and refresh, all three types) carries the claim `sid` (the session id). The refresh token's `jti` is `Session.current_jti`. Tokens without `sid` are rejected.

## Repository contract

`SessionRepository` (see [02-storage.md](02-storage.md)): `create`, `get`, `rotate`, `revoke`, `list`, `purge_expired`.

- `rotate` is an atomic compare-and-set on `current_jti`: it succeeds only when the session exists, is not revoked, and `current_jti == expected_jti`. Two concurrent rotations with the same expected jti produce exactly one winner.
- `revoke` revokes every not-yet-revoked row matching all given filters (`session_id`, `kind`, `subject_id`, `tenant_id`), keeps the original reason of rows that were already revoked, and returns the count. A call without filters raises `ValueError`. `cascade_children=True` also revokes live rows whose `parent_id` is a matched row, with reason `parent_revoked`.
- `list` returns newest first. `purge_expired` hard-deletes rows with `expires_at < before` or `revoked_at < before`.

## Lifecycle

**Login** (admin and tenant): authenticate outside any transaction (failures, lockout counting and failure events are written there), then in one transaction create the session, issue the pair with the session's `sid`, and audit `auth.login.succeeded`.

**Refresh** (admin, tenant, impersonation):

1. Verify the refresh token (signature, expiry, type).
2. Load the session. Unknown: `InvalidTokenError`. Revoked or expired: `RevokedTokenError`.
3. Impersonation only: the parent session must be active, otherwise this session is revoked (`parent_revoked`) and `RevokedTokenError` is raised.
4. Reload the subject (and tenant). If inactive, revoke the session (`subject_deactivated` or `tenant_deactivated`) and raise `InvalidTokenError`.
5. Issue a new pair with the same `sid`. Impersonation passes `refresh_cap = parent.expires_at`.
6. Rotate the session; audit `auth.token.refreshed` or `impersonation.refreshed` in the same transaction.
7. If the rotation lost (the presented jti is not current), this is **reuse**: after leaving the transaction, revoke the session and its children (`reuse_detected`), audit `token.reuse_detected`, and raise `RevokedTokenError`. The newly minted pair is discarded.

Sessions are **sliding**: each refresh extends `expires_at` by the type's `refresh_ttl` (capped for impersonation). There is no absolute maximum.

There is **no concurrency grace window**. Two refreshes racing with the same token trip reuse detection and end the session. Single-page apps that refresh from several tabs must serialise refresh calls client-side (for example with a lock in the browser).

**Impersonation start**: the admin refresh token's `sid` becomes the child's `parent_id`; the parent must be active. The impersonation refresh and access expiry never exceed the parent session's `expires_at`.

## Transaction discipline

Both existing adapters make an inner `transaction()` *join* an open outer one, so anything written inside a transaction is lost if it rolls back. Therefore:

- Writes that must survive an error (lockout counting, failure audit events, the reuse-detection revoke) run **outside** any transaction, after the success-path transaction block has exited.
- `storage.in_transaction()` reports whether a transaction is open in the current context. `audit.emit_standalone()` and the standalone revoke helper raise `RuntimeError` when it is true, so a misplaced failure write fails loudly.
- Do not call tenantkit operations inside a transaction you opened yourself; see [11-audit.md](11-audit.md).

## Public interface

| Call | Effect | Audit action |
| --- | --- | --- |
| `kit.admin_auth.logout(refresh_token=)` / `kit.tenant_auth.logout(...)` | Revoke the session (and impersonation children). Idempotent; expired tokens are a no-op | `auth.logout` |
| `kit.access.end_impersonation(refresh_token=)` | Revoke one impersonation session, reason `impersonation_ended` | `impersonation.ended` |
| `kit.admin_auth.logout_all(actor=)` / `kit.tenant_auth.logout_all(actor=)` | Revoke all of the actor's sessions. Impersonation actors are refused | `auth.logout_all` |
| `kit.control_plane.revoke_sessions(actor, subject_type, subject_id)` | Needs `sessions:revoke` | `session.revoked` |
| `kit.control_plane.list_sessions(actor, subject_type, subject_id, ...)` | Needs `sessions:read` | not audited |
| `change_password` (admin, tenant) | Revoke all of the subject's sessions, including the current one; the client logs in again | `auth.password.changed` |
| deactivate admin / tenant user / tenant | Revoke the subject's sessions, or every session of the tenant (users and impersonation into it) | `*.deactivated` |
| `kit.sessions.purge_expired(before=None)` | Maintenance; hosts schedule it | none |
| `await kit.tokens.verify_active(token, expected=None)` | `verify`, then require a live session (and live parent for impersonation) | none |

A password set for a tenant user through `update_tenant_user(password=...)` also revokes that user's sessions (`password_changed`).

`verify()` keeps accepting an access token of a revoked session until it expires (at most the access lifetime: 15 minutes by default, 10 for impersonation). Use `verify_active()` on sensitive routes for instant cut-off.

## Errors

| Error | When |
| --- | --- |
| `InvalidTokenError` | Unknown session, token without `sid`, inactive subject on refresh |
| `RevokedTokenError` (subclass of `InvalidTokenError`) | The session is revoked or expired, a refresh token is reused, or the parent admin session is gone |

Hosts that map `InvalidTokenError` to 401 keep working.

## Test cases

See the session cases in the change spec: login creates one session, rotation keeps `sid`, reuse revokes the session and its children and persists after the error, logout idempotency, logout-all, permission checks, tenant deactivation scope, parent revocation, expiry cap, `verify` makes no storage calls, tokens without `sid` are rejected, and lockout still trips through the new login flow. The same service tests run on the in-memory and SQLite adapters, and on MongoDB when `TENANTKIT_TEST_MONGO_URL` is set.

## Decisions

1. A session record per refresh-token family, not a jti denylist.
2. Sliding sessions with no absolute maximum.
3. No concurrency grace window for refresh.
4. `change_password` ends every session including the current one.
5. The impersonation cap comes from the parent session's `expires_at`; the `admin_refresh_exp` claim is gone.
