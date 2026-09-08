"""Test-only crash fault points with a fail-closed production boundary."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Mapping, TypeAlias


FaultPoint: TypeAlias = Literal[
    "after_stage_write",
    "after_file_fsync",
    "before_prepared_tx",
    "after_prepared_tx",
    "after_verify",
    "before_active_tx",
    "after_active_tx",
    "before_cleanup",
    "after_approval_claim",
    "before_target_commit",
    "after_target_commit_before_ack",
    "after_source_outbox",
    "after_global_copy",
    "after_global_prepare",
    "after_global_activate",
    "before_source_ack",
]

FAULT_ENV = "CONSULTATION_FAULT_POINT"
FAULT_VAULT_MARKER_NAME = ".consultation-fault-test-vault"
FAULT_VAULT_MARKER_BODY = "consultation-kb-fault-test-v1\n"
FAULT_EXIT_CODE = 137
_PHASE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")

MANIFEST_PUBLICATION_FAULT_POINTS: tuple[FaultPoint, ...] = (
    "after_stage_write",
    "after_file_fsync",
    "before_prepared_tx",
    "after_prepared_tx",
    "after_verify",
    "before_active_tx",
    "after_active_tx",
    "before_cleanup",
)
APPROVAL_EXECUTION_FAULT_POINTS: tuple[FaultPoint, ...] = (
    "after_approval_claim",
    "before_target_commit",
    "after_target_commit_before_ack",
)
OUTBOX_SAGA_FAULT_POINTS: tuple[FaultPoint, ...] = (
    "after_source_outbox",
    "after_global_copy",
    "after_global_prepare",
    "after_global_activate",
    "before_source_ack",
)

_REGISTRY: dict[str, tuple[FaultPoint, ...]] = {
    "manifest_publication": MANIFEST_PUBLICATION_FAULT_POINTS,
    "approval_execution": APPROVAL_EXECUTION_FAULT_POINTS,
    "client_publication": MANIFEST_PUBLICATION_FAULT_POINTS,
    "global_knowledge_publication": MANIFEST_PUBLICATION_FAULT_POINTS,
    "outbox_saga": OUTBOX_SAGA_FAULT_POINTS,
}
FAULT_POINT_REGISTRY: Mapping[str, tuple[FaultPoint, ...]] = MappingProxyType(_REGISTRY)
FAULT_POINTS: frozenset[FaultPoint] = frozenset(
    point for family in FAULT_POINT_REGISTRY.values() for point in family
)


class FaultConfigurationError(RuntimeError):
    """Fault injection was requested outside the closed test boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class FaultInjector:
    """An immutable, optionally armed exact-point process killer."""

    selected: FaultPoint | None

    @classmethod
    def from_environment(
        cls,
        *,
        test_mode: bool,
        vault_root: Path,
    ) -> FaultInjector:
        raw = os.environ.get(FAULT_ENV)
        if raw is None:
            return cls(selected=None)
        if test_mode is not True:
            raise FaultConfigurationError("FAULT_ENV_FORBIDDEN")
        if raw not in FAULT_POINTS:
            raise FaultConfigurationError("FAULT_POINT_UNKNOWN")
        if not isinstance(vault_root, Path):
            raise FaultConfigurationError("FAULT_VAULT_INVALID")
        try:
            root = vault_root.resolve(strict=True)
            marker = root / FAULT_VAULT_MARKER_NAME
            if (
                marker.is_symlink()
                or marker.resolve(strict=True).parent != root
                or marker.read_text(encoding="ascii") != FAULT_VAULT_MARKER_BODY
            ):
                raise FaultConfigurationError("FAULT_VAULT_MARKER_REQUIRED")
        except FaultConfigurationError:
            raise
        except (OSError, UnicodeError):
            raise FaultConfigurationError("FAULT_VAULT_MARKER_REQUIRED") from None
        return cls(selected=raw)

    def hit(self, point: str) -> None:
        if point not in FAULT_POINTS:
            raise FaultConfigurationError("FAULT_POINT_UNKNOWN")
        if self.selected == point:
            os._exit(FAULT_EXIT_CODE)

    def guarded_hook(
        self,
        *,
        allowed_passthrough: tuple[str, ...] = (),
    ) -> Callable[[str], None]:
        """Adapt exact crash points to a pipeline that has legacy test hooks.

        Canonical P8 points still route through :meth:`hit`; explicitly named
        legacy phases are inert.  Everything else remains fail closed so a
        misspelled production hook cannot silently weaken crash coverage.
        """

        if (
            type(allowed_passthrough) is not tuple
            or len(allowed_passthrough) != len(set(allowed_passthrough))
            or any(
                type(point) is not str
                or _PHASE_RE.fullmatch(point) is None
                or point in FAULT_POINTS
                for point in allowed_passthrough
            )
        ):
            raise FaultConfigurationError("FAULT_PASSTHROUGH_INVALID")
        allowed = frozenset(allowed_passthrough)

        def hook(point: str) -> None:
            if point in FAULT_POINTS:
                self.hit(point)
                return
            if point not in allowed:
                raise FaultConfigurationError("FAULT_POINT_UNKNOWN")

        return hook


def reject_fault_environment_in_production() -> None:
    """Fail startup if the fault environment variable exists in production."""

    if os.environ.get(FAULT_ENV) is not None:
        raise FaultConfigurationError("FAULT_ENV_FORBIDDEN")


__all__ = [
    "APPROVAL_EXECUTION_FAULT_POINTS",
    "FAULT_ENV",
    "FAULT_EXIT_CODE",
    "FAULT_POINTS",
    "FAULT_POINT_REGISTRY",
    "FAULT_VAULT_MARKER_BODY",
    "FAULT_VAULT_MARKER_NAME",
    "FaultConfigurationError",
    "FaultInjector",
    "FaultPoint",
    "MANIFEST_PUBLICATION_FAULT_POINTS",
    "OUTBOX_SAGA_FAULT_POINTS",
    "reject_fault_environment_in_production",
]
