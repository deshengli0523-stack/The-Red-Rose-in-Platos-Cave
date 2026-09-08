"""Windows security primitives for the consultation knowledge base."""

from consultation_kb.security.dpapi import (
    InvalidSecretContext,
    SecretDecryptionFailed,
    SecretProtectionFailed,
    SecretProtector,
    UnsupportedSecurityPlatform,
    WindowsDpapiProtector,
    create_secret_protector,
)
from consultation_kb.security.ntfs_acl import (
    AclPolicy,
    AclPolicyViolation,
    AclVerification,
)
from consultation_kb.security.path_guard import PathGuard, ScopePathDenied

__all__ = [
    "AclPolicy",
    "AclPolicyViolation",
    "AclVerification",
    "InvalidSecretContext",
    "PathGuard",
    "ScopePathDenied",
    "SecretDecryptionFailed",
    "SecretProtectionFailed",
    "SecretProtector",
    "UnsupportedSecurityPlatform",
    "WindowsDpapiProtector",
    "create_secret_protector",
]
