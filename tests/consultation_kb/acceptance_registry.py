from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping


@dataclass(frozen=True, slots=True)
class AcceptanceSpec:
    primary_module: str
    extension_modules: tuple[str, ...] = ()

    @property
    def modules(self) -> tuple[str, ...]:
        return (self.primary_module, *self.extension_modules)


_TX_CRASH_EXTENSIONS = (
    "fault/test_manifest_process_crash.py",
    "fault/test_outbox_process_crash.py",
    "fault/test_approval_execution_crash.py",
    "fault/test_client_publication_crash.py",
    "fault/test_global_knowledge_publication_crash.py",
    "fault/test_production_process_crash.py",
)

_REGISTRY: Final[dict[str, AcceptanceSpec]] = {
    "ISO-01": AcceptanceSpec(
        "integration/test_iso_01.py",
        ("integration/test_mcp_iso_01.py",),
    ),
    "ISO-02": AcceptanceSpec("integration/test_iso_02.py"),
    "CASE-01": AcceptanceSpec("integration/test_case_01_full_lineage.py"),
    "CASE-02": AcceptanceSpec("integration/test_case_02_authorization.py"),
    "TURN-01": AcceptanceSpec(
        "golden/test_turn_01.py",
        ("integration/test_two_turn_session.py",),
    ),
    "FACT-01": AcceptanceSpec("golden/test_fact_01.py"),
    "THEORY-01": AcceptanceSpec("golden/test_theory_01_governance.py"),
    "GRAPH-01": AcceptanceSpec(
        "golden/test_graph_01_client.py",
        ("golden/test_graph_01_global.py",),
    ),
    "WRITE-01": AcceptanceSpec("integration/test_write_01.py"),
    "TX-01": AcceptanceSpec(
        "integration/test_manifest_visibility.py",
        ("fault/test_outbox_saga_exceptions.py", *_TX_CRASH_EXTENSIONS),
    ),
    "VER-01": AcceptanceSpec(
        "integration/test_manifest_visibility.py",
        ("integration/test_ver_01.py",),
    ),
    "DEL-01": AcceptanceSpec("golden/test_del_01.py"),
    "REBUILD-01": AcceptanceSpec("golden/test_rebuild_01.py"),
    "RISK-01": AcceptanceSpec("golden/test_risk_01.py"),
    "ARCHIVE-01": AcceptanceSpec("golden/test_archive_01.py"),
}

ACCEPTANCE_REGISTRY: Final[Mapping[str, AcceptanceSpec]] = MappingProxyType(_REGISTRY)
ACCEPTANCE_IDS: Final[tuple[str, ...]] = tuple(_REGISTRY)
