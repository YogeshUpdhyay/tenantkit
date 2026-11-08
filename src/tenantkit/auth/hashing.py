from typing import Any
from tenantkit.domain.errors import PasswordValidationError


class Hashing:
    def __init__(self, config: Any) -> None:
        from argon2 import PasswordHasher

        self.hasher = PasswordHasher(
            time_cost=config.time_cost,
            memory_cost=config.memory_cost_kib,
            parallelism=config.parallelism,
        )
        self.dummy = self.hasher.hash("dummy-password-not-a-real-account")

    def hash(self, password: str) -> str:
        return str(self.hasher.hash(password))

    def verify(self, hashed: str, password: str) -> bool:
        from argon2.exceptions import VerificationError

        try:
            return bool(self.hasher.verify(hashed, password))
        except VerificationError:
            return False

    def validate(self, password: str, email: str, rules: Any) -> None:
        errors = []
        if len(password) < rules.min_length:
            errors.append("Password too short")
        if len(password) > rules.max_length:
            errors.append("Password too long")
        if rules.disallow_email_in_password and email.lower() in password.lower():
            errors.append("Password contains email")
        if errors:
            raise PasswordValidationError("; ".join(errors))
