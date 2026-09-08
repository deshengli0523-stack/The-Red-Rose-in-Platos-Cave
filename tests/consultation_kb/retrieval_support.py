from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.evidence import (
    AuthoritativeFilterSnapshot,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    Provenance,
    RetrievalScope,
)
from consultation_kb.retrieval.contracts import CandidateMetadata, CandidateRef
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    RetrievalInputAssignment,
    RetrievalInputDescriptor,
)
from consultation_kb.retrieval.contracts import canonical_json_bytes
from consultation_kb.retrieval.embeddings import ModelDescriptor, ModelFileHash


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
CLIENT_A = "client_" + "a1b2c3d4e5f6"
CLIENT_B = "client_" + "b1c2d3e4f5a6"


def object_id(kind: str, index: int) -> str:
    return IdFactory(FixedClock(NOW), lambda: index).object_id(kind)


def reference(kind: str, index: int, *, version: int = 1) -> VersionRef:
    return VersionRef(
        object_id=object_id(kind, index),
        version=version,
        content_sha256=f"{index + 1:064x}",
    )


def global_provenance(index: int) -> Provenance:
    return Provenance(
        source_ids=frozenset({object_id("source", index + 100)}),
        passage_ids=frozenset({object_id("passage", index)}),
        provenance_scope="global_source",
        derivation_rule_ref=reference("derivation_rule", index + 200),
    )


def case_provenance(index: int, *clients: str) -> Provenance:
    return Provenance(
        case_ids=frozenset({object_id("case", index + 100)}),
        client_ids=frozenset(clients),
        case_contributor_client_ids=frozenset(clients),
        provenance_scope="case_derived",
        derivation_rule_ref=reference("derivation_rule", index + 200),
    )


def private_provenance(index: int, client_id: str = CLIENT_A) -> Provenance:
    return Provenance(
        client_ids=frozenset({client_id}),
        provenance_scope="client_private",
        private_owner_client_id=client_id,
        derivation_rule_ref=reference("derivation_rule", index + 200),
    )


def candidate(
    index: int,
    *,
    provenance: Provenance | None = None,
    channel: str = "lexical",
    object_type: str = "passage",
    allowed_uses: frozenset[str] = frozenset({"answer_support"}),
    size_bytes: int = 3,
    text: str | None = None,
) -> CandidateRef:
    evidence_ref = reference(object_type, index)
    if text is not None:
        encoded = text.encode("utf-8")
        evidence_ref = evidence_ref.model_copy(
            update={"content_sha256": hashlib.sha256(encoded).hexdigest()}
        )
        size_bytes = len(encoded)
    return CandidateRef(
        reference=evidence_ref,
        content_ref=evidence_ref,
        object_type=object_type,
        channel=channel,
        metadata=CandidateMetadata(
            manifest_ref=reference("artifact_manifest", index + 300),
            review_status="approved",
            allowed_uses=allowed_uses,
            approved_at=NOW - timedelta(days=1),
            effective_from=NOW - timedelta(days=30),
            review_due_at=NOW + timedelta(days=30),
            sensitivity=1,
            source_grade="T1",
            source_count=1,
            media_type="text/plain",
            size_bytes=size_bytes,
        ),
        provenance=provenance or global_provenance(index),
        location=EvidenceLocator(
            locator_kind="source_line_span",
            anchor_refs=(evidence_ref,),
            display_locator="lines:1-1",
            locator_policy_ref=reference("locator_policy", index + 400),
        ),
        freshness=EvidenceFreshnessSnapshot(
            status="current",
            evaluated_at=NOW,
            source_observed_at=NOW - timedelta(days=2),
            last_reviewed_at=NOW - timedelta(days=1),
            review_due_at=NOW + timedelta(days=30),
            policy_ref=reference("freshness_policy", index + 500),
        ),
        score=0.0,
    )


def snapshot(*candidates: CandidateRef, index: int = 900) -> AuthoritativeFilterSnapshot:
    return AuthoritativeFilterSnapshot(
        run_id=IdFactory(FixedClock(NOW), lambda: index).uuid7(),
        global_runtime_epoch=1,
        client_runtime_epoch=1,
        tombstone_epoch=0,
        authorization_epoch=0,
        allowed_ref_ids=frozenset(
            item.reference.object_id for item in candidates
        ),
        policy_ref=reference("authority_policy", index + 1),
        created_at=NOW,
    )


def scope(
    *,
    client_id: str = CLIENT_A,
    use: str = "answer_support",
) -> RetrievalScope:
    return RetrievalScope(
        current_client_id=client_id,
        allowed_uses=frozenset({use}),
        maximum_sensitivity=3,
        effective_at=NOW,
        known_at=NOW,
    )


def model_descriptor(**updates: object) -> ModelDescriptor:
    values: dict[str, object] = {
        "repo": "local/test-embedding",
        "revision": "a" * 40,
        "model_files": (
            ModelFileHash(relative_path="config.json", sha256="b" * 64),
        ),
        "adapter_class": "DeterministicFakeEmbedder",
        "adapter_version": "1",
        "sentence_transformers_version": "3.4.1",
        "transformers_version": "4.49.0",
        "tokenizer_version": "1",
        "tokenizer_sha256": "c" * 64,
        "query_prompt": "query: ",
        "document_prompt": "document: ",
        "pooling": "mean",
        "normalize_embeddings": True,
        "max_sequence_length": 512,
        "truncation": "longest_first",
        "dtype": "float32",
        "precision": "float32",
        "dimension": 2,
        "score_function": "cosine",
    }
    values.update(updates)
    return ModelDescriptor.model_validate(values)


def derived_builder_input(
    artifact_kind: str,
    *candidates: CandidateRef,
    source_catalog_version: int,
    target_runtime_epoch: int = 1,
) -> DerivedArtifactBuilderInputV2:
    descriptor = RetrievalInputDescriptor.from_assignments(
        tuple(
            RetrievalInputAssignment.from_candidate(
                value,
                target_channels=frozenset({artifact_kind}),
            )
            for value in candidates
        ),
        route_policy_ref=reference(
            "retrieval_route_policy",
            50_000 + source_catalog_version,
            version=source_catalog_version,
        ),
    )
    maximum = target_runtime_epoch - 1
    authority = {
        "authorization_epoch": 0,
        "catalog_version": max(0, source_catalog_version - 1),
        "claims": (),
        "expected_current_epoch": None if maximum == 0 else maximum,
        "maximum_runtime_epoch": maximum,
        "publication_authority_version": source_catalog_version,
        "target_runtime_epoch": target_runtime_epoch,
        "theory": None,
        "tombstone_epoch": 0,
        "wiki": None,
    }
    return DerivedArtifactBuilderInputV2(
        artifact_kind=artifact_kind,
        authority_closure_sha256=hashlib.sha256(
            canonical_json_bytes(authority)
        ).hexdigest(),
        authority_snapshot=authority,
        retrieval_input_descriptor=descriptor,
        target_runtime_epoch=target_runtime_epoch,
    )
