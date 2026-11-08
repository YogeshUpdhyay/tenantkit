"""Public typed failures. Messages never contain credentials."""


class TenantKitError(Exception):
    pass


class ConfigError(TenantKitError):
    pass


class KeyLoadError(ConfigError):
    pass


class StorageError(TenantKitError):
    pass


class StorageUnavailableError(StorageError):
    pass


class AlreadyExistsError(StorageError):
    pass


class NotFoundError(TenantKitError):
    pass


class PermissionDeniedError(TenantKitError):
    pass


class InvalidCredentialsError(TenantKitError):
    def __init__(self) -> None:
        super().__init__("Invalid credentials")


class AccountLockedError(TenantKitError):
    def __init__(self) -> None:
        super().__init__("Account locked. Contact your administrator.")


class ProviderNotAllowedError(TenantKitError):
    pass


class ValidationErrorBase(TenantKitError):
    def __init__(self, message: str = "Validation failed", *, details: object = None) -> None:
        super().__init__(message)
        self.details = details if details is not None else [message]


class PasswordValidationError(ValidationErrorBase):
    pass


class TenantValidationError(ValidationErrorBase):
    pass


class InvalidSlugError(ValidationErrorBase):
    pass


class AlreadyBootstrappedError(TenantKitError):
    pass


class LastAdminError(TenantKitError):
    pass


class InvalidTokenError(TenantKitError):
    pass


class ExpiredTokenError(InvalidTokenError):
    pass


class WrongTokenTypeError(InvalidTokenError):
    pass


class ImpersonationDisabledError(TenantKitError):
    pass


PasswordPolicyError = PasswordValidationError


class ProviderNotFoundError(TenantKitError):
    pass
