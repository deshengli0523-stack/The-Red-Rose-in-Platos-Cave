"""Stable, body-free identities for fixed security scopes."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


def global_approval_scope_sha256(vault_root: Path) -> str:
    """Bind global P1 authority to one normalized local vault root."""

    if not isinstance(vault_root, Path) or not vault_root.is_absolute():
        raise TypeError("GLOBAL_APPROVAL_SCOPE_ROOT_REQUIRED")
    identity = os.path.normcase(os.path.normpath(os.fspath(vault_root)))
    payload = (
        b"consultation-kb/global-approval-scope/v1\x00"
        + identity.encode("utf-8", errors="strict")
    )
    return hashlib.sha256(payload).hexdigest()


__all__ = ["global_approval_scope_sha256"]
