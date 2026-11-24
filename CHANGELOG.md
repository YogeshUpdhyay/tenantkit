# Changelog

## 0.2.0

### Added

- **Session revocation.** Every login creates a session (`mt_sessions`); refresh tokens rotate and reuse of a rotated token revokes the session. Logout, logout-all, admin `revoke_sessions`/`list_sessions`, automatic revocation on deactivation and password change, and `kit.access.end_impersonation`. New opt-in `await kit.tokens.verify_active()`; `verify()` stays synchronous and storage-free. New `RevokedTokenError` (a subclass of `InvalidTokenError`), `kit.sessions.purge_expired()`.
- **Audit log.** Append-only `mt_audit_events` written in the same transaction as each action (fail-closed), failure events persisted even when the operation raises, optional post-commit `audit_hooks=[...]`, `kit.audit.list(...)` (`audit:read`) and `kit.audit.purge(...)` (`audit:purge`), and the `audit.include_failed_login_email` option.
- **MongoDB storage.** `tenantkit.storage.beanie` (`BeanieStorage`, `document_models`), installed with `pip install tenantkit[mongo]` (Beanie 2.x). Requires MongoDB 6.0+ as a replica set or behind mongos.
- New permissions: `sessions:read`, `sessions:revoke`, `audit:read`, `audit:purge`.
- Docs `10-sessions-revocation.md`, `11-audit.md`, `12-mongo-storage.md`.

### Breaking changes

1. **All refresh tokens issued by 0.1.x are rejected** after upgrading (they carry no `sid`). Every user and admin must log in once. Access tokens without `sid` are rejected too (they expire within minutes anyway).
2. **`Storage` protocol** gains required attributes `sessions: SessionRepository` and `audit_events: AuditEventRepository`, and a required method `in_transaction() -> bool`. Custom adapters must implement them and pass the extended `StorageContract`.
3. **SQLAlchemy hosts** must generate and run an Alembic migration for the two new tables (`{prefix}sessions`, `{prefix}audit_events`).
4. **`TokenService.issue_pair`** requires a new `session_id` keyword and returns the refresh `jti` (and expiry) on the `TokenPair`; the `admin_refresh_exp` argument became `refresh_cap`. Hosts calling it directly must create the session themselves or switch to the auth services.
5. **`change_password`** (admin and tenant) now revokes all of the subject's sessions, including the one in use; the client must log in again.
6. **Claims models** gain a required `sid` field.
7. The `AccessService`, `ControlPlaneService`, `AdminAuthService`, `TenantAuthService` and `TokenService` constructors take the new audit and session services; build everything through `TenantKit`.
8. Clients must serialise refresh calls: two refreshes racing with the same token end the session.

### Notes

- `StorageContract` compares lock expiries at millisecond precision so BSON-backed adapters can pass it.
- Ruff is pinned to the `E4, E7, E9, F` rule set and pytest gets `pythonpath = ["."]`, so the example app is importable.
