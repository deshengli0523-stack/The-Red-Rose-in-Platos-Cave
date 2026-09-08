from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

import pytest

from consultation_kb.lifecycle.publish import publication_closure_sha256
from consultation_kb.models.common import VersionRef
from consultation_kb.retrieval.artifact_contracts import (
    DerivedArtifactBuilderInputV2,
    GenericDerivedBuildManifestV2,
    KnowledgeRegistryPayloadV1,
    RetrievalInputAssignment,
    RetrievalInputDescriptor,
)
from consultation_kb.retrieval.contracts import canonical_json_bytes
from consultation_kb.retrieval.lexical_builder import (
    LexicalDocument,
    LexicalIndexBuilder,
)
from tests.consultation_kb.retrieval_support import candidate, object_id, reference
from tests.consultation_kb.wiki_index_support import build_fixture, wiki_fixture


def _publication_module():
    try:
        return importlib.import_module(
            "consultation_kb.retrieval.artifact_publication"
        )
    except ModuleNotFoundError:
        pytest.fail("retrieval artifact publication is not implemented", pytrace=False)


def _input(
    value,
    *,
    maximum: int = 0,
    artifact_kind: str = "lexical",
    route_policy_ref: VersionRef | None = None,
) -> DerivedArtifactBuilderInputV2:
    targets = (
        frozenset({"lexical"})
        if artifact_kind == "knowledge_registry"
        else frozenset({artifact_kind})
    )
    descriptor = RetrievalInputDescriptor.from_assignments(
        (
            RetrievalInputAssignment.from_candidate(
                value,
                target_channels=targets,
            ),
        ),
        route_policy_ref=route_policy_ref
        or reference("retrieval_route_policy", 600),
    )
    snapshot = {
        "authorization_epoch": 0,
        "catalog_version": 6,
        "claims": (),
        "expected_current_epoch": None if maximum == 0 else maximum,
        "maximum_runtime_epoch": maximum,
        "publication_authority_version": 7,
        "target_runtime_epoch": maximum + 1,
        "theory": None,
        "tombstone_epoch": 0,
        "wiki": None,
    }
    return DerivedArtifactBuilderInputV2(
        artifact_kind=artifact_kind,
        authority_closure_sha256=hashlib.sha256(
            canonical_json_bytes(snapshot)
        ).hexdigest(),
        authority_snapshot=snapshot,
        retrieval_input_descriptor=descriptor,
        target_runtime_epoch=maximum + 1,
    )


@pytest.mark.parametrize("artifact_kind", ["wiki_index", "knowledge_registry"])
def test_generic_factory_enforces_every_other_fixed_p1_layout(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    module = _publication_module()
    roles = module.derived_artifact_role_layout(artifact_kind)
    ids = _ids(module, artifact_kind, 6000 + len(roles) * 100)
    paths: dict[str, Path] = {}
    media_types: dict[str, str] = {}
    policy_ref = None
    policy_payload = b""
    if artifact_kind == "knowledge_registry":
        policy_payload = canonical_json_bytes({"contract": "test_route_policy_v1"})
        policy_ref = VersionRef(
            object_id=ids.member_object_ids["retrieval_route_policy"],
            version=7,
            content_sha256=hashlib.sha256(policy_payload).hexdigest(),
        )
    value = candidate(69)
    if artifact_kind == "wiki_index":
        value = value.model_copy(
            update={
                "reference": reference("claim", 691),
                "content_ref": reference("passage", 692),
                "object_type": "claim",
                "channel": "wiki",
            }
        )
    if artifact_kind == "wiki_index":
        fixture = wiki_fixture()
        builder_input = fixture.builder_input
        wiki_artifacts = build_fixture(fixture)
        data_payloads = {"wiki_index": wiki_artifacts.index_bytes}
        manifest = wiki_artifacts.build_manifest
    else:
        builder_input = _input(
            value,
            artifact_kind=artifact_kind,
            route_policy_ref=policy_ref,
        )
        data_payloads = {
            "retrieval_route_policy": policy_payload,
            "knowledge_registry": canonical_json_bytes(
                KnowledgeRegistryPayloadV1.from_descriptor(
                    builder_input.retrieval_input_descriptor
                ).model_dump(mode="json")
            ),
        }
    for role, payload in data_payloads.items():
        path = tmp_path / artifact_kind / f"{role}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        paths[role] = path
        media_types[role] = "application/json"
    if artifact_kind == "knowledge_registry":
        manifest = GenericDerivedBuildManifestV2.create(
            artifact_kind=artifact_kind,
            builder_input=builder_input,
            member_content_sha256={
                role: hashlib.sha256(path.read_bytes()).hexdigest()
                for role, path in paths.items()
            },
        )
    manifest_role = roles[1]
    manifest_path = tmp_path / artifact_kind / f"{manifest_role}.json"
    manifest_path.write_bytes(
        canonical_json_bytes(manifest.model_dump(mode="json"))
    )
    paths[manifest_role] = manifest_path
    media_types[manifest_role] = "application/json"

    factory = module.RetrievalArtifactDraftFactory(tmp_path)
    draft = factory.fixed_layout(
        artifact_kind=artifact_kind,
        builder_input=builder_input,
        member_paths=paths,
        member_media_types=media_types,
        ids=ids,
        source_lineage=(),
    )

    assert tuple(member.object_type for member in draft.members) == roles
    if artifact_kind == "knowledge_registry":
        wrong_input = _input(
            value,
            artifact_kind=artifact_kind,
            route_policy_ref=reference("retrieval_route_policy", 699),
        )
        wrong_registry = canonical_json_bytes(
            KnowledgeRegistryPayloadV1.from_descriptor(
                wrong_input.retrieval_input_descriptor
            ).model_dump(mode="json")
        )
        paths["knowledge_registry"].write_bytes(wrong_registry)
        wrong_manifest = GenericDerivedBuildManifestV2.create(
            artifact_kind="knowledge_registry",
            builder_input=wrong_input,
            member_content_sha256={
                "retrieval_route_policy": hashlib.sha256(
                    policy_payload
                ).hexdigest(),
                "knowledge_registry": hashlib.sha256(
                    wrong_registry
                ).hexdigest(),
            },
        )
        paths["knowledge_registry_build_manifest"].write_bytes(
            canonical_json_bytes(wrong_manifest.model_dump(mode="json"))
        )
        with pytest.raises(
            RuntimeError,
            match="RETRIEVAL_ARTIFACT_PUBLICATION_INVALID",
        ):
            factory.fixed_layout(
                artifact_kind="knowledge_registry",
                builder_input=wrong_input,
                member_paths=paths,
                member_media_types=media_types,
                ids=ids,
                source_lineage=(),
            )


def test_publication_ids_reject_an_extra_member_role() -> None:
    module = _publication_module()
    ids = _ids(module, "lexical", 6800)
    changed = ids.model_copy(
        update={
            "member_object_ids": {
                **ids.member_object_ids,
                "extra_role": object_id("extra_role", 6899),
            }
        }
    )

    with pytest.raises(
        RuntimeError,
        match="RETRIEVAL_ARTIFACT_PUBLICATION_INVALID",
    ):
        changed.require_layout("lexical")


def _ids(module, kind: str, start: int):
    roles = module.derived_artifact_role_layout(kind)
    return module.ArtifactPublicationIds(
        manifest_id=object_id("manifest", start),
        member_object_ids={
            role: object_id(role, start + index + 1)
            for index, role in enumerate(roles)
        },
    )


def test_real_lexical_bytes_and_v2_input_become_one_p1_artifact_draft(
    tmp_path: Path,
) -> None:
    module = _publication_module()
    value = candidate(70, text="exact authority text", channel="lexical")
    builder_input = _input(value)
    index = tmp_path / "build" / "lexical.sqlite3"
    manifest = LexicalIndexBuilder().build(
        (LexicalDocument(candidate=value, text="exact authority text"),),
        index,
        builder_input=builder_input,
    )

    draft = module.RetrievalArtifactDraftFactory(tmp_path).lexical(
        builder_input=builder_input,
        build_manifest=manifest,
        index_path=index,
        ids=_ids(module, "lexical", 700),
        source_lineage=(),
    )

    assert draft.artifact_key == draft.artifact_kind == "lexical"
    assert draft.source_version == 7
    assert tuple(member.object_type for member in draft.members) == (
        "lexical_builder_input",
        "lexical_build_manifest",
        "lexical_index",
    )
    assert draft.members[-1].data == index.read_bytes()
    payload = json.loads(draft.members[0].data)
    assert payload["contract"] == "knowledge_builder_input_v2"
    assert payload["target_runtime_epoch"] == 1
    assert payload["retrieval_input_descriptor"]["descriptor_sha256"] == (
        builder_input.retrieval_input_descriptor.descriptor_sha256
    )


def test_target_epoch_and_authority_manifest_are_inside_p1_closure_hash(
    tmp_path: Path,
) -> None:
    module = _publication_module()
    value = candidate(71, text="closure", channel="lexical")
    first_input = _input(value, maximum=0)
    second_input = _input(value, maximum=1)

    def build(builder_input, name: str, start: int):
        index = tmp_path / name / "lexical.sqlite3"
        manifest = LexicalIndexBuilder().build(
            (LexicalDocument(candidate=value, text="closure"),),
            index,
            builder_input=builder_input,
        )
        return module.RetrievalArtifactDraftFactory(tmp_path).lexical(
            builder_input=builder_input,
            build_manifest=manifest,
            index_path=index,
            ids=_ids(module, "lexical", start),
            source_lineage=(),
        )

    first = build(first_input, "first", 800)
    second = build(second_input, "second", 900)

    first_hash = publication_closure_sha256(
        purpose="rebuild",
        authority_base_version=7,
        expected_current_epoch=None,
        artifacts=(first,),
    )
    second_hash = publication_closure_sha256(
        purpose="rebuild",
        authority_base_version=7,
        expected_current_epoch=1,
        artifacts=(second,),
    )
    assert first_hash != second_hash


def test_publication_rejects_tampered_index_even_with_original_manifest(
    tmp_path: Path,
) -> None:
    module = _publication_module()
    value = candidate(72, text="tamper", channel="lexical")
    builder_input = _input(value)
    index = tmp_path / "tampered" / "lexical.sqlite3"
    manifest = LexicalIndexBuilder().build(
        (LexicalDocument(candidate=value, text="tamper"),),
        index,
        builder_input=builder_input,
    )
    index.write_bytes(index.read_bytes() + b"tampered")

    with pytest.raises(RuntimeError, match="RETRIEVAL_ARTIFACT_PUBLICATION_INVALID"):
        module.RetrievalArtifactDraftFactory(tmp_path).lexical(
            builder_input=builder_input,
            build_manifest=manifest,
            index_path=index,
            ids=_ids(module, "lexical", 1000),
            source_lineage=(),
        )
