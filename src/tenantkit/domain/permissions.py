"""Permission matching shared by the access, audit and control-plane services."""

from tenantkit.domain.claims import BaseClaims


def has_permission(claims: BaseClaims, permission: str) -> bool:
    if "*" in permission:
        raise ValueError("Permission checks require concrete permissions")
    return any(
        p == "*" or p == permission or (p.endswith(":*") and permission.startswith(p[:-1]))
        for p in claims.perms
    )
