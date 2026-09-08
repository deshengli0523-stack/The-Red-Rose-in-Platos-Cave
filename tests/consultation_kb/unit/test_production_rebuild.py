from __future__ import annotations

import json
from pathlib import Path

import pytest

from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.lifecycle.production_rebuild import (
    CONFIG_FILENAME,
    ProductionRebuildConfig,
    ProductionRebuildError,
    load_production_rebuild_config,
)
from consultation_kb.lifecycle.structured_artifact import (
    StructuredArtifactEnvelope,
    StructuredArtifactError,
    StructuredArtifactMember,
    parse_structured_artifact,
)
from tests.consultation_kb.retrieval_support import model_descriptor


def test_client_production_config_round_trips_as_exact_scoped_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    config = ProductionRebuildConfig.create_client(scope_sha256="a" * 64)
    (root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)

    loaded = load_production_rebuild_config(
        root,
        database_scope="client",
        scope_sha256="a" * 64,
    )

    assert loaded == config
    assert loaded.canonical_bytes == (root / CONFIG_FILENAME).read_bytes()


def test_production_config_rejects_missing_mutated_or_cross_scope_bindings(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    with pytest.raises(
        ProductionRebuildError, match="REBUILD_PRODUCTION_CONFIG_INVALID"
    ):
        load_production_rebuild_config(
            root,
            database_scope="client",
            scope_sha256="a" * 64,
        )

    config = ProductionRebuildConfig.create_client(scope_sha256="a" * 64)
    payload = json.loads(config.canonical_bytes)
    payload["build_directory"] = "different-build-root"
    (root / CONFIG_FILENAME).write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    with pytest.raises(
        ProductionRebuildError, match="REBUILD_PRODUCTION_CONFIG_INVALID"
    ):
        load_production_rebuild_config(
            root,
            database_scope="client",
            scope_sha256="a" * 64,
        )

    (root / CONFIG_FILENAME).write_bytes(config.canonical_bytes)
    with pytest.raises(
        ProductionRebuildError, match="REBUILD_PRODUCTION_CONFIG_MISMATCH"
    ):
        load_production_rebuild_config(
            root,
            database_scope="global",
            scope_sha256="a" * 64,
        )


def test_global_production_config_binds_model_tokenizers_graphify_and_policy() -> None:
    descriptor = model_descriptor()

    config = ProductionRebuildConfig.create_global(
        scope_sha256="b" * 64,
        model_descriptor=descriptor,
        embedder_kind="deterministic_test",
        deterministic_vocabulary={"test": (1.0, 0.0)},
        test_mode=True,
        graphify_seed=7,
        graphify_production=False,
        case_contributor_aliases={
        "8" * 64: "client" + "_abcdefghijkl",
        },
    )

    assert config.model_descriptor_sha256 == descriptor.id
    assert config.lexical_tokenizer_descriptor_sha256 is not None
    assert config.wiki_tokenizer_descriptor_sha256 is not None
    assert config.graphify_seed == 7
    assert config.graphify_production is False
    assert config.case_contributor_aliases[0].contributor_client_hash == "8" * 64
    assert (
        config.case_contributor_aliases[0].pseudonymous_client_id
        == "client" + "_abcdefghijkl"
    )
    assert ProductionRebuildConfig.model_validate_json(
        config.canonical_bytes, strict=True
    ) == config


def test_global_sentence_transformers_config_round_trips_without_test_fallback(
    tmp_path: Path,
) -> None:
    descriptor = model_descriptor()
    config = ProductionRebuildConfig.create_global(
        scope_sha256="b" * 64,
        model_descriptor=descriptor,
        embedder_kind="sentence_transformers",
        model_directory="models/exact-snapshot",
        graphify_seed=99,
        graphify_production=True,
    )
    (tmp_path / CONFIG_FILENAME).write_bytes(config.canonical_bytes)

    loaded = load_production_rebuild_config(
        tmp_path.resolve(),
        database_scope="global",
        scope_sha256="b" * 64,
    )

    assert loaded == config
    assert loaded.embedder_kind == "sentence_transformers"
    assert loaded.model_directory == "models/exact-snapshot"
    assert loaded.deterministic_vocabulary is None
    assert loaded.test_mode is False
    with pytest.raises(ValueError, match="local model configuration is incomplete"):
        ProductionRebuildConfig.create_global(
            scope_sha256="b" * 64,
            model_descriptor=descriptor,
            embedder_kind="sentence_transformers",
            model_directory="models/exact-snapshot",
            test_mode=True,
        )
    with pytest.raises(ValueError, match="deterministic embedder is test-only"):
        ProductionRebuildConfig.create_global(
            scope_sha256="b" * 64,
            model_descriptor=descriptor,
            embedder_kind="deterministic_test",
            deterministic_vocabulary={"test": (1.0, 0.0)},
        )


def test_structured_artifact_supports_exact_ordered_repeated_roles() -> None:
    first = StructuredArtifactMember.from_bytes(
        role="private_archive_draft",
        media_type="application/json",
        payload=b'{"archive":1}',
    )
    second = StructuredArtifactMember.from_bytes(
        role="private_archive_draft",
        media_type="application/json",
        payload=b'{"archive":2}',
    )
    envelope = StructuredArtifactEnvelope(
        artifact_key="private_archive",
        artifact_kind="private_archive",
        source_version=1,
        semantic_basis_sha256="3" * 64,
        members=(first, second),
    )

    assert parse_structured_artifact(envelope.canonical_bytes) == envelope
    assert [member.payload for member in envelope.members] == [
        b'{"archive":1}',
        b'{"archive":2}',
    ]


def test_structured_artifact_preserves_member_identity_but_excludes_it_from_equivalence() -> None:
    def envelope(object_id: str) -> StructuredArtifactEnvelope:
        return StructuredArtifactEnvelope(
            artifact_key="test_registry",
            artifact_kind="test_registry",
            source_version=7,
            semantic_basis_sha256="3" * 64,
            members=(
                StructuredArtifactMember.from_bytes(
                    role="retrieval_route_policy",
                    object_id=object_id,
                    media_type="application/json",
                    payload=b'{"policy":1}',
                ),
            ),
        )

    first = envelope(
        "retrieval_route_policy_019f7a4f-ea7c-70b0-b318-653da03a9f7c"
    )
    second = envelope(
        "retrieval_route_policy_019f7a4f-ea7c-70b0-b318-653da03a9f7d"
    )

    assert first.canonical_bytes != second.canonical_bytes
    assert first.comparison_content_sha256 == second.comparison_content_sha256
    assert first.semantic_fingerprint_sha256 == second.semantic_fingerprint_sha256

    changed_binding = first.model_copy(
        update={"semantic_basis_sha256": "5" * 64}
    )
    assert (
        changed_binding.comparison_content_sha256
        == first.comparison_content_sha256
    )
    assert (
        changed_binding.semantic_fingerprint_sha256
        != first.semantic_fingerprint_sha256
    )

    changed_role = first.model_copy(
        update={
            "members": (
                StructuredArtifactMember.from_bytes(
                    role="knowledge_registry",
                    media_type="application/json",
                    payload=b'{"policy":1}',
                ),
            )
        }
    )
    assert changed_role.comparison_content_sha256 != first.comparison_content_sha256
    assert (
        changed_role.semantic_fingerprint_sha256
        != first.semantic_fingerprint_sha256
    )


def test_structured_artifact_rejects_mismatched_or_duplicate_member_identity() -> None:
    with pytest.raises(ValueError):
        StructuredArtifactMember.from_bytes(
            role="retrieval_route_policy",
            object_id="wrong_role_019f7a4f-ea7c-70b0-b318-653da03a9f7c",
            media_type="application/json",
            payload=b'{"policy":1}',
        )

    member = StructuredArtifactMember.from_bytes(
        role="private_archive_draft",
        object_id="private_archive_draft_019f7a4f-ea7c-70b0-b318-653da03a9f7c",
        media_type="application/json",
        payload=b'{"archive":1}',
    )
    with pytest.raises(ValueError):
        StructuredArtifactEnvelope(
            artifact_key="private_archive",
            artifact_kind="private_archive",
            source_version=1,
            semantic_basis_sha256="3" * 64,
            members=(member, member),
        )


def test_structured_artifact_comparison_hashes_actual_semantics_only() -> None:
    def basis(*, policy: str = "p1", model: str = "m1") -> str:
        return canonical_sha256({"policy": policy, "model": model})

    def envelope(
        *,
        payload: bytes,
        role: str = "wiki_index_builder_input",
        media_type: str = "application/json",
        lineage: tuple[str, ...] = ("1" * 64,),
        policy: str = "p1",
        model: str = "m1",
    ) -> StructuredArtifactEnvelope:
        return StructuredArtifactEnvelope(
            artifact_key="test_wiki_index",
            artifact_kind="test_wiki_index",
            source_version=1,
            semantic_basis_sha256=basis(policy=policy, model=model),
            members=(
                StructuredArtifactMember.from_bytes(
                    role=role,
                    media_type=media_type,
                    payload=payload,
                    source_lineage_hashes=lineage,
                ),
            ),
        )

    def operational_payload(*, epoch: int, suffix: str) -> bytes:
        return json.dumps(
            {
                "target_runtime_epoch": epoch,
                "route_policy_ref": {
                    "object_id": f"retrieval_route_policy_{suffix}",
                    "version": 1,
                    "content_sha256": "2" * 64,
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    first = envelope(
        payload=operational_payload(
            epoch=1,
            suffix="019f7a4f-ea7c-70b0-b318-653da03a9f7c",
        )
    )
    restarted = envelope(
        payload=operational_payload(
            epoch=9,
            suffix="019f7a4f-ea7c-70b0-b318-653da03a9f7d",
        )
    )
    assert first.comparison_content_sha256 == restarted.comparison_content_sha256
    assert first.semantic_fingerprint_sha256 == restarted.semantic_fingerprint_sha256

    changed_payload = envelope(payload=b'{"semantic_rows":[{"value":2}]}')
    changed_policy = envelope(payload=first.members[0].payload, policy="p2")
    changed_model = envelope(payload=first.members[0].payload, model="m2")
    changed_role = envelope(
        payload=first.members[0].payload,
        role="knowledge_registry_builder_input",
    )
    changed_media = envelope(
        payload=first.members[0].payload,
        media_type="text/plain",
    )
    changed_lineage = envelope(
        payload=first.members[0].payload,
        lineage=("3" * 64,),
    )
    for changed in (
        changed_payload,
        changed_policy,
        changed_model,
        changed_role,
        changed_media,
        changed_lineage,
    ):
        assert changed.semantic_fingerprint_sha256 != first.semantic_fingerprint_sha256

    with pytest.raises(StructuredArtifactError):
        StructuredArtifactMember.from_bytes(
            role="retrieval_route_policy",
            media_type="application/json",
            payload=b'{"policy":1}',
            comparison_sha256="0" * 64,
        )


@pytest.mark.parametrize(
    ("artifact_key", "artifact_kind", "roles"),
    (
        (
            "client_profile",
            "profile",
            (("profile_json", "application/json"),),
        ),
        (
            "client_graph",
            "profile",
            (("client_graph", "application/json"),),
        ),
        (
            "private_archive",
            "private_archive",
            (("private_archive_draft", "text/plain"),),
        ),
        (
            "wiki_page",
            "wiki_page",
            (("claim", "application/json"),),
        ),
        (
            "claims",
            "wiki_page",
            (("claim", "application/json"),),
        ),
        (
            "c1_revision",
            "c1_absence",
            (("theory", "application/json"),),
        ),
        (
            "c1_revision",
            "c1_revision",
            (("evidence", "application/json"),),
        ),
        (
            "c1_revision",
            "c1_absence",
            (
                ("c1_absence", "application/json"),
                ("c1_absence", "application/json"),
            ),
        ),
    ),
)
def test_structured_artifact_rejects_known_production_layout_drift(
    artifact_key: str,
    artifact_kind: str,
    roles: tuple[tuple[str, str], ...],
) -> None:
    with pytest.raises(ValueError, match="structured .*layout is invalid"):
        StructuredArtifactEnvelope(
            artifact_key=artifact_key,
            artifact_kind=artifact_kind,
            source_version=1,
            semantic_basis_sha256="3" * 64,
            members=tuple(
                StructuredArtifactMember.from_bytes(
                    role=role,
                    media_type=media_type,
                    payload=(
                        b'{"value":1}'
                        if media_type == "application/json"
                        else b"value"
                    ),
                )
                for role, media_type in roles
            ),
        )
