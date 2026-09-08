"""Export the frozen consultation JSON Schema registry deterministically."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pydantic import BaseModel  # noqa: E402

from consultation_kb.core.errors import ToolError  # noqa: E402
from consultation_kb.models.client import BitemporalWindow, FactState  # noqa: E402
from consultation_kb.models.common import SessionScope, VersionRef  # noqa: E402
from consultation_kb.models.evidence import (  # noqa: E402
    AuthoritativeFilterSnapshot,
    AuthoritySnapshotBinding,
    C1ApplicabilityDecision,
    EvidenceCandidate,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    EvidencePack,
    EvidenceProvenanceView,
    Provenance,
    RetrievalScope,
)
from consultation_kb.models.generation import (  # noqa: E402
    ClientReplyOutput,
    GenerationStageEnvelope,
)
from consultation_kb.models.manifests import (  # noqa: E402
    ApprovalExecution,
    ApprovalReceipt,
    DraftDescriptor,
)
from consultation_kb.models.risk import InternalRiskObservation  # noqa: E402


ROOT_MODELS: dict[str, type[BaseModel]] = {
    "version_ref.schema.json": VersionRef,
    "tool_error.schema.json": ToolError,
    "session_scope.schema.json": SessionScope,
    "draft_descriptor.schema.json": DraftDescriptor,
    "approval_receipt.schema.json": ApprovalReceipt,
    "approval_execution.schema.json": ApprovalExecution,
    "fact_state.schema.json": FactState,
    "bitemporal_window.schema.json": BitemporalWindow,
    "provenance.schema.json": Provenance,
    "retrieval_scope.schema.json": RetrievalScope,
    "authoritative_filter_snapshot.schema.json": AuthoritativeFilterSnapshot,
    "authority_snapshot_binding.schema.json": AuthoritySnapshotBinding,
    "evidence_provenance_view.schema.json": EvidenceProvenanceView,
    "evidence_locator.schema.json": EvidenceLocator,
    "evidence_freshness_snapshot.schema.json": EvidenceFreshnessSnapshot,
    "evidence_candidate.schema.json": EvidenceCandidate,
    "c1_applicability_decision.schema.json": C1ApplicabilityDecision,
    "evidence_pack.schema.json": EvidencePack,
    "internal_risk_observation.schema.json": InternalRiskObservation,
    "generation_stage_envelope.schema.json": GenerationStageEnvelope,
    "client_reply_output.schema.json": ClientReplyOutput,
}


def export_schemas(output_dir: Path) -> None:
    """Write exactly the public root registry into *output_dir*."""

    output_dir.mkdir(parents=True, exist_ok=True)
    expected = set(ROOT_MODELS)
    for stale in output_dir.glob("*.schema.json"):
        if stale.name not in expected:
            stale.unlink()

    for filename, model in ROOT_MODELS.items():
        encoded = json.dumps(
            model.model_json_schema(mode="validation"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        (output_dir / filename).write_text(encoded, encoding="utf-8", newline="\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "schemas",
    )
    args = parser.parse_args(argv)
    export_schemas(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
