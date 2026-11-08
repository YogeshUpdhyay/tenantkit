from datetime import datetime, timezone, timedelta
from typing import Any
from tenantkit.auth.hashing import Hashing
from tenantkit.auth.providers.base import AuthRequest, AuthResult
from tenantkit.storage.interfaces import Storage
from tenantkit.domain.models import Admin
from tenantkit.config.models import TenantKitConfig


class PasswordProvider:
    name = "password"
    subject_types = {"admin", "tenant_user"}

    def __init__(self, storage: Storage, hashing: Hashing, config: TenantKitConfig) -> None:
        self.storage = storage
        self.hashing = hashing
        self.config = config

    async def authenticate(self, request: AuthRequest, policy: Any) -> AuthResult:
        email = str(request.credentials.get("email", "")).strip().lower()
        password = str(request.credentials.get("password", ""))
        repo = self.storage.admins if request.subject_type == "admin" else self.storage.tenant_users
        subject = await repo.get_by_email(email)
        if (
            subject is None
            or not subject.is_active
            or (
                request.tenant_id is not None
                and getattr(subject, "tenant_id", None) != request.tenant_id
            )
        ):
            self.hashing.verify(self.hashing.dummy, password)
            return AuthResult("failure")
        settings = (
            self.config.admin_auth if request.subject_type == "admin" else self.config.tenant_auth
        )
        attempt = await self.storage.login_attempts.get(request.subject_type, subject.id)
        now = datetime.now(timezone.utc)
        if attempt and attempt.locked_until and attempt.locked_until > now:
            return AuthResult("failure", reason="locked")
        if attempt and attempt.locked_until and attempt.locked_until <= now:
            await self.storage.login_attempts.reset(request.subject_type, subject.id)
            attempt = None
        if len(password) > settings.password.max_length or not self.hashing.verify(
            subject.password_hash, password
        ):
            recorded = await self.storage.login_attempts.record_failure(
                request.subject_type,
                subject.id,
                max_attempts=settings.lockout.max_attempts,
                locked_until=now + timedelta(minutes=settings.lockout.lock_minutes),
            )
            return AuthResult("failure", reason="locked" if recorded.locked_until else None)
        await self.storage.login_attempts.reset(request.subject_type, subject.id)
        if self.hashing.hasher.check_needs_rehash(subject.password_hash):
            subject.password_hash = self.hashing.hash(password)
            if isinstance(subject, Admin):
                await self.storage.admins.update(subject)
            else:
                await self.storage.tenant_users.update(subject)
        return AuthResult("success", subject_id=subject.id)
