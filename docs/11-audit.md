# 11 — Audit log

tenantkit stores an append-only audit trail of every security-relevant action in its own storage (`mt_audit_events`), written in the same transaction as the action. Hosts may register hooks that observe each event after commit, for example to forward it to a SIEM.

## Purpose and responsibilities

- Record who did what, to what, when, and with which outcome, for every action in the catalogue below.
- Make state-changing events fail-closed: if the audit write fails, the change rolls back.
- Persist failure events (bad login, lockout, token reuse, denied impersonation) even though the operation raises.
- Notify optional hooks after commit; hook errors never affect the operation.
- Expose a permission-gated read and purge API.

Out of scope: export formats, an audit UI, tamper-evident (hash-chained) logs, automatic expiry (hosts schedule `purge`).

## Event model

```python
@dataclass(kw_only=True, frozen=True)
class AuditEvent:
    action: str                     # dotted name
    outcome: Literal["success", "failure"]
    actor_type: Literal["admin", "tenant_user", "system", "anonymous"]
    actor_id: UUID | None
    impersonator_id: UUID | None    # set when the actor is an impersonation token
    tenant_id: UUID | None
    target_type: str | None         # tenant | tenant_user | admin | session | account
    target_id: UUID | None
    session_id: UUID | None
    token_jti: UUID | None
    reason: str | None
    metadata: Mapping[str, Any]
    id: UUID
    occurred_at: datetime
```

**No event ever contains a password, a password hash, a token string or a signing key.** `metadata` for updates holds changed field names, and for role or scope changes the new role names or scope mode, never values of tenant `attributes`. Failed-login events contain the attempted email only when `audit.include_failed_login_email` is `true` (default `false`).

## Action catalogue

| Action | Outcome | Emitted by |
| --- | --- | --- |
| `admin.bootstrapped` | success | `bootstrap_super_admin` (actor `system`) |
| `auth.login.succeeded` | success | admin and tenant login |
| `auth.login.failed` | failure | admin and tenant login (actor `anonymous`) |
| `auth.account.locked` | failure | the failed attempt that sets the lock |
| `auth.account.unlocked` | success | `unlock_account` |
| `auth.token.refreshed` | success | admin and tenant refresh |
| `auth.logout`, `auth.logout_all` | success | logout and logout-all |
| `auth.password.changed` | success | `change_password` |
| `token.reuse_detected` | failure | refresh-token reuse |
| `session.revoked` | success | `control_plane.revoke_sessions` |
| `impersonation.started`, `.refreshed`, `.ended` | success | access service |
| `impersonation.denied` | failure | `impersonate` when a scope, role or permission check fails |
| `tenant.created`, `.updated`, `.login_policy_changed`, `.deactivated`, `.reactivated` | success | control plane |
| `tenant_user.created`, `.updated`, `.deactivated` | success | control plane |
| `admin.created`, `.updated`, `.deactivated` | success | control plane |
| `audit.purged` | success | `kit.audit.purge` |

Permission-denied attempts on control-plane methods are **not** audited (to avoid log flooding); `impersonation.denied` is the one denied-attempt event because it is a cross-tenant attempt.

## Repository

`AuditEventRepository` (see [02-storage.md](02-storage.md)): `append`, `list`, `purge`. There is no update and no single-row delete. `list` returns newest first (`occurred_at DESC, id DESC`); `tenant_ids=None` means no tenant filter and an empty sequence returns nothing; `action` matches exactly or, if it ends with `.*`, by prefix.

## Service and hooks

`kit.audit` is an `AuditService`. The kit accepts hooks:

```python
async def forward(event: AuditEvent) -> None:
    await siem.send(event)

kit = TenantKit(config=config, storage=storage, audit_hooks=[forward])
```

- Hooks run **after commit**, sequentially in registration order, each awaited. They are never called for rolled-back events.
- A hook that raises is logged on the `tenantkit.audit` logger at `ERROR` with the event id and action (never the event's metadata) and otherwise ignored.
- Internally, `audit.recorder()` opens one transaction per operation; nested recorders join the outer one, and hooks fire only when the outermost transaction commits. `audit.emit_standalone(event)` writes a failure event in its own transaction.
- **Do not call tenantkit operations inside a `storage.transaction()` you opened yourself.** Hooks could fire before your commit, and the recorder raises `RuntimeError` to stop you.

## Read and retention API

- `await kit.audit.list(actor, *, tenant_id=None, actor_id=None, target_id=None, action=None, since=None, until=None, limit=50, offset=0)` needs `audit:read` on an admin access token.
  - Visibility follows the admin's impersonation scope: `*` or scope `all` sees everything; scope `list` sees only events whose `tenant_id` is in the list (platform events with no tenant are hidden); scope `none` without `*` is denied.
  - A requested `tenant_id` outside the visible set raises `PermissionDeniedError`. `limit` is clamped to 1–500.
- `await kit.audit.purge(actor, *, before)` needs `audit:purge`. The `audit.purged` event is written after the purge in the same transaction, so it survives it.
- `await kit.sessions.purge_expired()` is the matching session maintenance call.

## Configuration

```yaml
audit:
  include_failed_login_email: false   # default
```

New permission names: `audit:read`, `audit:purge`, `sessions:read`, `sessions:revoke` (see [08](08-roles-permissions-impersonation.md)). The default `super_admin` (`*`) covers them.

## Errors

| Error | When |
| --- | --- |
| `PermissionDeniedError` | Missing `audit:read` or `audit:purge`, impersonation or tenant actor, empty visibility, or a tenant outside scope |
| `RuntimeError` | A recorder or standalone write is attempted inside a transaction the host opened, or `emit_standalone` is called inside a transaction |
| `StorageError` | The audit write failed; the surrounding change was rolled back |

With the MongoDB adapter and `transactions=False`, the fail-closed guarantee does not hold.

## Test cases

Every action is emitted with the documented fields; a failing `append` rolls the change back; failure events persist when the operation raises; hooks see committed events in order, raising hooks are logged and swallowed, and nothing fires on rollback; the failed-login email is opt-in; no secret appears in any event; visibility rules; purge keeps its own event. These run on the in-memory and SQLite adapters, and on MongoDB when configured.

## Decisions

1. The built-in store is the source of truth; hooks are observers.
2. State-changing events are fail-closed; failure events are written in their own transaction before the error is raised.
3. No automatic TTL; hosts schedule purges.
4. `audit.list` visibility follows the impersonation scope.
