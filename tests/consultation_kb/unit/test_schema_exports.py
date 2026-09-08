from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import sys
from itertools import product
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from consultation_kb.core.errors import ToolError
from consultation_kb.models.common import (
    ClientId,
    NonEmptyStr,
    ObjectId,
    SafeLocatorText,
    SafePolicyKey,
    Sha256Hex,
    Uuid7String,
    VersionRef,
)
from consultation_kb.models.evidence import (
    C1ApplicabilityDecision,
    EvidenceCandidate,
    EvidenceFreshnessSnapshot,
    EvidenceLocator,
    EvidencePack,
    EvidenceProvenanceView,
    Provenance,
)
from consultation_kb.models.generation import ClientReplyOutput, GenerationStageEnvelope
from consultation_kb.models.manifests import ApprovalExecution, DraftDescriptor
from consultation_kb.models.risk import InternalRiskObservation
from scripts.export_consultation_schemas import ROOT_MODELS, export_schemas


EXPECTED_SCHEMA_FILES = {
    "version_ref.schema.json",
    "tool_error.schema.json",
    "session_scope.schema.json",
    "draft_descriptor.schema.json",
    "approval_receipt.schema.json",
    "approval_execution.schema.json",
    "fact_state.schema.json",
    "bitemporal_window.schema.json",
    "provenance.schema.json",
    "retrieval_scope.schema.json",
    "authoritative_filter_snapshot.schema.json",
    "authority_snapshot_binding.schema.json",
    "evidence_provenance_view.schema.json",
    "evidence_locator.schema.json",
    "evidence_freshness_snapshot.schema.json",
    "evidence_candidate.schema.json",
    "c1_applicability_decision.schema.json",
    "evidence_pack.schema.json",
    "internal_risk_observation.schema.json",
    "generation_stage_envelope.schema.json",
    "client_reply_output.schema.json",
}
CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}")
VALID_UUID7 = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
VALID_SHA256 = "a" * 64
VALID_OBJECT_ID = f"claim_{VALID_UUID7}"
VALID_CLIENT_ID = "client_" + "a1b2" + "c3d4" + "e5f6"
VALID_SECOND_CLIENT_ID = "client_" + "b1c2" + "d3e4" + "f5a6"
JSON_LINE_TERMINATORS = ("\n", "\r\n", "\u2028", "\u2029")
JSON_LINE_SEPARATOR_PATTERN = r"[\r\n\u2028\u2029]"
FROZEN_PYTHON_STRIP_CODEPOINTS = (
    0x0009,
    0x000A,
    0x000B,
    0x000C,
    0x000D,
    0x001C,
    0x001D,
    0x001E,
    0x001F,
    0x0020,
    0x0085,
    0x00A0,
    0x1680,
    0x2000,
    0x2001,
    0x2002,
    0x2003,
    0x2004,
    0x2005,
    0x2006,
    0x2007,
    0x2008,
    0x2009,
    0x200A,
    0x2028,
    0x2029,
    0x202F,
    0x205F,
    0x3000,
)
FROZEN_PYTHON_STRIP_CHARS = tuple(chr(value) for value in FROZEN_PYTHON_STRIP_CODEPOINTS)
SAFE_LOCATOR_BLANK_CHARS = tuple(
    value
    for value in FROZEN_PYTHON_STRIP_CHARS
    if not (ord(value) <= 0x1F or ord(value) == 0x7F or value in {"\u2028", "\u2029"})
)
EVIDENCE_CHANNELS = (
    "profile",
    "client_history",
    "wiki",
    "lexical",
    "vector",
    "global_graph",
    "case",
)
CHANNELS_BY_SCOPE = {
    "global_source": frozenset({"wiki", "lexical", "vector", "global_graph"}),
    "client_private": frozenset({"profile", "client_history"}),
    "case_derived": frozenset({"case", "wiki", "lexical", "vector", "global_graph"}),
    "mixed": frozenset({"case", "wiki", "lexical", "vector", "global_graph"}),
}
VALID_REF = {
    "object_id": VALID_OBJECT_ID,
    "version": 1,
    "content_sha256": VALID_SHA256,
}


def _walk_json(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _walk_schema_context(value, *, under_not: bool = False):
    yield value, under_not
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_schema_context(
                child,
                under_not=under_not or key == "not",
            )
    elif isinstance(value, list):
        for child in value:
            yield from _walk_schema_context(child, under_not=under_not)


def _node_executable() -> str:
    node = shutil.which("node") or shutil.which("node.exe")
    if node is None:
        pytest.skip("Node.js is unavailable; CI installs Node 22 for the ECMA gate")
    return node


def _node_regex_matches(pattern: str, values: tuple[str, ...]) -> tuple[bool, ...]:
    node = _node_executable()
    script = (
        'const pattern = JSON.parse(process.argv[1]);'
        'const values = JSON.parse(process.argv[2]);'
        'const regex = new RegExp(pattern, "u");'
        "process.stdout.write(JSON.stringify(values.map(value => regex.test(value))));"
    )
    result = subprocess.run(
        [node, "-e", script, json.dumps(pattern), json.dumps(values)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list) and all(type(item) is bool for item in parsed)
    return tuple(parsed)


def _node_compile_patterns(patterns: tuple[str, ...]) -> int:
    script = (
        'const patterns = JSON.parse(process.argv[1]);'
        'patterns.forEach(pattern => new RegExp(pattern, "u"));'
        "process.stdout.write(String(patterns.length));"
    )
    result = subprocess.run(
        [_node_executable(), "-e", script, json.dumps(patterns)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return int(result.stdout)


def test_registry_contains_exactly_the_twenty_one_frozen_roots() -> None:
    assert set(ROOT_MODELS) == EXPECTED_SCHEMA_FILES
    assert len(ROOT_MODELS) == len(EXPECTED_SCHEMA_FILES) == 21
    assert len(set(ROOT_MODELS.values())) == 21


def test_all_root_property_sets_are_frozen(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    expected = {
        "version_ref.schema.json": {"object_id", "version", "content_sha256"},
        "tool_error.schema.json": {"code", "message", "retryable", "safe_details"},
        "session_scope.schema.json": {"session_handle", "session_id", "permissions", "expires_at"},
        "draft_descriptor.schema.json": {"purpose", "target_id", "client_id", "base_version", "draft_sha256", "session_id"},
        "approval_receipt.schema.json": {"request_id", "descriptor_sha256", "approver_role", "approved_at", "expires_at", "nonce", "provider_id", "signature"},
        "approval_execution.schema.json": {"operation_id", "request_id", "descriptor_sha256", "target_scope_hash", "state", "applied_commit_version"},
        "fact_state.schema.json": {"review_status", "validity_status", "resolution_status", "epistemic_status"},
        "bitemporal_window.schema.json": {"effective_from", "effective_to", "recorded_at", "superseded_at"},
        "provenance.schema.json": {"source_ids", "passage_ids", "case_ids", "client_ids", "provenance_scope", "private_owner_client_id", "case_contributor_client_ids", "derivation_rule_ref"},
        "retrieval_scope.schema.json": {"current_client_id", "allowed_uses", "maximum_sensitivity", "effective_at", "known_at"},
        "authoritative_filter_snapshot.schema.json": {"run_id", "global_runtime_epoch", "client_runtime_epoch", "tombstone_epoch", "authorization_epoch", "allowed_ref_ids", "policy_ref", "created_at"},
        "authority_snapshot_binding.schema.json": {"snapshot_ref", "run_id", "global_runtime_epoch", "client_runtime_epoch", "tombstone_epoch", "authorization_epoch", "policy_ref", "created_at"},
        "evidence_provenance_view.schema.json": {"provenance_ref", "provenance_scope", "derivation_rule_ref", "source_count", "passage_count", "case_count", "case_contributor_count", "independent_source_count", "client_exclusion_status"},
        "evidence_locator.schema.json": {"locator_kind", "anchor_refs", "display_locator", "locator_policy_ref"},
        "evidence_freshness_snapshot.schema.json": {"status", "evaluated_at", "source_observed_at", "last_reviewed_at", "review_due_at", "policy_ref"},
        "evidence_candidate.schema.json": {"evidence_id", "text_ref", "location", "freshness", "channel", "review_status", "source_grade", "framework_priority", "empirical_support", "provenance", "supports_evidence_ids", "contradicts_evidence_ids", "score"},
        "c1_applicability_decision.schema.json": {"status", "revision", "scope_policy_ref", "matched_rule_ids", "missing_context_fields", "effective_status", "empirical_support", "conflict_evidence_ids"},
        "evidence_pack.schema.json": {"schema_version", "run_id", "authority", "client_snapshot_ref", "temporary_fact_refs", "supporting", "contradicting", "unresolved_conflict_refs", "c1_applicability", "exclusion_proof_ref", "wiki_manifest_ref", "lexical_manifest_ref", "vector_manifest_ref", "graph_manifest_ref", "reranker_descriptor_ref"},
        "internal_risk_observation.schema.json": {"schema_version", "observation_id", "category", "level", "trigger_turn_ids", "rule_ref", "detected_at", "suggested_questions", "client_facing_visibility"},
        "generation_stage_envelope.schema.json": {"schema_version", "stage", "turn_id", "run_id", "parent_sha256s", "created_at"},
        "client_reply_output.schema.json": {"schema_version", "text"},
    }
    assert set(expected) == EXPECTED_SCHEMA_FILES
    for filename, properties in expected.items():
        schema = json.loads((tmp_path / filename).read_text(encoding="utf-8"))
        assert set(schema["properties"]) == properties, filename


def test_schema_export_is_exact_deterministic_utf8_and_removes_stale_files(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    (first / "stale.schema.json").write_text("stale", encoding="utf-8")

    export_schemas(first)
    first_bytes = {path.name: path.read_bytes() for path in first.iterdir()}
    export_schemas(second)
    second_bytes = {path.name: path.read_bytes() for path in second.iterdir()}

    assert set(first_bytes) == EXPECTED_SCHEMA_FILES
    assert first_bytes == second_bytes
    for content in first_bytes.values():
        assert not content.startswith(b"\xef\xbb\xbf")
        assert content.endswith(b"\n") and not content.endswith(b"\n\n")
        decoded = content.decode("utf-8")
        assert decoded == json.dumps(
            json.loads(decoded), ensure_ascii=False, indent=2, sort_keys=True
        ) + "\n"


def test_exporter_runs_as_a_repository_script(repo_root: Path, tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "export_consultation_schemas.py"),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert {path.name for path in tmp_path.iterdir()} == EXPECTED_SCHEMA_FILES


def test_checked_in_schemas_match_fresh_export(repo_root: Path, tmp_path: Path) -> None:
    export_schemas(tmp_path)
    checked_in = repo_root / "schemas"
    expected = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    actual = {path.name: path.read_bytes() for path in checked_in.glob("*.schema.json")}
    assert actual == expected


def test_every_object_schema_is_closed_except_scalar_safe_details(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    saw_safe_details = False
    for path in tmp_path.iterdir():
        schema = json.loads(path.read_text(encoding="utf-8"))
        for node in _walk_json(schema):
            if not isinstance(node, dict):
                continue
            if node.get("type") == "object" and "properties" in node:
                assert node.get("additionalProperties") is False, (path.name, node)
            title = node.get("title")
            if title == "FrozenSafeDetails":
                saw_safe_details = True
                assert node.get("type") == "object"
                assert node.get("default") == {}
                allowed = node["additionalProperties"]
                serialized = json.dumps(allowed, sort_keys=True)
                assert '"array"' not in serialized and '"object"' not in serialized
                assert {item.get("type") for item in allowed["anyOf"]} == {
                    "string", "integer", "boolean"
                }
    assert saw_safe_details


def test_every_datetime_schema_declares_utc_only(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    saw_datetime = False
    for path in tmp_path.iterdir():
        schema = json.loads(path.read_text(encoding="utf-8"))
        for node in _walk_json(schema):
            if isinstance(node, dict) and node.get("format") == "date-time":
                saw_datetime = True
                assert node.get("x-utc-only") is True, (path.name, node)
    assert saw_datetime


def test_identifier_and_policy_key_schemas_publish_canonical_patterns(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    version_ref = json.loads(
        (tmp_path / "version_ref.schema.json").read_text(encoding="utf-8")
    )
    object_pattern = version_ref["properties"]["object_id"]["pattern"]
    assert "[a-z]" in object_pattern and "-7" in object_pattern

    pack = json.loads((tmp_path / "evidence_pack.schema.json").read_text(encoding="utf-8"))
    defs = pack["$defs"]
    uuid_pattern = defs["AuthoritySnapshotBinding"]["properties"]["run_id"]["pattern"]
    policy_pattern = defs["C1ApplicabilityDecision"]["properties"]["matched_rule_ids"][
        "items"
    ]["pattern"]
    assert "-7" in uuid_pattern and "[89ab]" in uuid_pattern
    assert policy_pattern == r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"


def test_every_root_and_nested_definition_uses_absolute_canonical_patterns(
    tmp_path: Path,
) -> None:
    """Every soft ``$`` is closed by exact length or a sibling separator guard."""

    export_schemas(tmp_path)
    saw_separator_guard = False
    saw_exact_length = False
    for filename in EXPECTED_SCHEMA_FILES:
        schema = json.loads((tmp_path / filename).read_text(encoding="utf-8"))
        for node, under_not in _walk_schema_context(schema):
            if not isinstance(node, dict):
                continue
            pattern = node.get("pattern")
            if not isinstance(pattern, str):
                continue
            assert not any(
                token in pattern for token in ("(?!", "(?=", "(?<!", "(?<=")
            ), (filename, node)
            if under_not or not pattern.startswith("^"):
                continue
            assert pattern.endswith("$"), (filename, node)
            separator_guarded = any(
                isinstance(child, dict)
                and child.get("pattern") == JSON_LINE_SEPARATOR_PATTERN
                for child in _walk_json(node.get("not"))
            )
            if separator_guarded:
                saw_separator_guard = True
            else:
                assert node.get("minLength") == node.get("maxLength"), (
                    filename,
                    node,
                )
                saw_exact_length = True
    assert saw_separator_guard and saw_exact_length


def test_draft_2020_12_identifier_and_tuple_constraints_match_runtime(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    version_schema = json.loads(
        (tmp_path / "version_ref.schema.json").read_text(encoding="utf-8")
    )
    generation_schema = json.loads(
        (tmp_path / "generation_stage_envelope.schema.json").read_text(encoding="utf-8")
    )
    risk_schema = json.loads(
        (tmp_path / "internal_risk_observation.schema.json").read_text(encoding="utf-8")
    )
    locator_schema = json.loads(
        (tmp_path / "evidence_locator.schema.json").read_text(encoding="utf-8")
    )
    draft_schema = json.loads(
        (tmp_path / "draft_descriptor.schema.json").read_text(encoding="utf-8")
    )

    valid_version = dict(VALID_REF)
    bad_object_version = {
        **valid_version,
        "object_id": f"prefix_{VALID_CLIENT_ID}_suffix_{VALID_UUID7}",
    }
    controlled_object_versions = tuple(
        {**valid_version, "object_id": f"claim_{VALID_UUID7}{terminator}"}
        for terminator in JSON_LINE_TERMINATORS
    )
    valid_generation = {
        "schema_version": "1.0",
        "stage": "query_plan",
        "turn_id": VALID_UUID7,
        "run_id": VALID_UUID7,
        "parent_sha256s": [VALID_SHA256],
        "created_at": "2022-02-22T19:22:22Z",
    }
    duplicate_generation = {
        **valid_generation,
        "parent_sha256s": [VALID_SHA256, VALID_SHA256],
    }
    valid_risk = {
        "schema_version": "1.0",
        "observation_id": f"risk_{VALID_UUID7}",
        "category": "safety_review",
        "level": "general",
        "trigger_turn_ids": [VALID_UUID7],
        "rule_ref": VALID_REF,
        "detected_at": "2022-02-22T19:22:22Z",
        "suggested_questions": ["synthetic question"],
        "client_facing_visibility": "never",
    }
    unsafe_policy_risk = {
        **valid_risk,
        "category": f"prefix_{VALID_CLIENT_ID}_suffix",
    }
    controlled_policy_risks = tuple(
        {**valid_risk, "category": f"safety_review{terminator}"}
        for terminator in JSON_LINE_TERMINATORS
    )
    empty_risk = {**valid_risk, "trigger_turn_ids": [], "suggested_questions": []}
    duplicate_risk = {
        **valid_risk,
        "trigger_turn_ids": [VALID_UUID7, VALID_UUID7],
        "suggested_questions": ["same", "same"],
    }
    valid_locator = {
        "locator_kind": "source_line_span",
        "anchor_refs": [VALID_REF],
        "display_locator": "lines:1-2",
        "locator_policy_ref": VALID_REF,
    }
    empty_locator = {**valid_locator, "anchor_refs": []}
    duplicate_locator = {**valid_locator, "anchor_refs": [VALID_REF, VALID_REF]}
    valid_draft = {
        "purpose": "create_client",
        "target_id": "synthetic-target",
        "client_id": VALID_CLIENT_ID,
        "base_version": 0,
        "draft_sha256": VALID_SHA256,
        "session_id": None,
    }
    controlled_client_drafts = tuple(
        {**valid_draft, "client_id": f"{VALID_CLIENT_ID}{terminator}"}
        for terminator in JSON_LINE_TERMINATORS
    )
    controlled_uuid_generations = tuple(
        {**valid_generation, "turn_id": f"{VALID_UUID7}{terminator}"}
        for terminator in JSON_LINE_TERMINATORS
    )
    controlled_sha_generations = tuple(
        {**valid_generation, "parent_sha256s": [f"{VALID_SHA256}{terminator}"]}
        for terminator in JSON_LINE_TERMINATORS
    )

    cases = (
        (VersionRef, version_schema, valid_version, True),
        (VersionRef, version_schema, bad_object_version, False),
        *((VersionRef, version_schema, payload, False) for payload in controlled_object_versions),
        (GenerationStageEnvelope, generation_schema, valid_generation, True),
        (GenerationStageEnvelope, generation_schema, duplicate_generation, False),
        *(
            (GenerationStageEnvelope, generation_schema, payload, False)
            for payload in controlled_uuid_generations
        ),
        *(
            (GenerationStageEnvelope, generation_schema, payload, False)
            for payload in controlled_sha_generations
        ),
        (InternalRiskObservation, risk_schema, valid_risk, True),
        (InternalRiskObservation, risk_schema, unsafe_policy_risk, False),
        *(
            (InternalRiskObservation, risk_schema, payload, False)
            for payload in controlled_policy_risks
        ),
        (InternalRiskObservation, risk_schema, empty_risk, False),
        (InternalRiskObservation, risk_schema, duplicate_risk, False),
        (EvidenceLocator, locator_schema, valid_locator, True),
        (EvidenceLocator, locator_schema, empty_locator, False),
        (EvidenceLocator, locator_schema, duplicate_locator, False),
        (DraftDescriptor, draft_schema, valid_draft, True),
        *((DraftDescriptor, draft_schema, payload, False) for payload in controlled_client_drafts),
    )
    for model, schema, payload, expected in cases:
        try:
            model.model_validate_json(json.dumps(payload))
            runtime_valid = True
        except ValidationError:
            runtime_valid = False
        schema_valid = Draft202012Validator(schema).is_valid(payload)
        assert runtime_valid is schema_valid is expected, (model, payload)

    object_adapter = TypeAdapter(ObjectId)
    policy_adapter = TypeAdapter(SafePolicyKey)
    client_adapter = TypeAdapter(ClientId)
    uuid_adapter = TypeAdapter(Uuid7String)
    sha_adapter = TypeAdapter(Sha256Hex)
    with pytest.raises(ValidationError):
        object_adapter.validate_python(bad_object_version["object_id"])
    with pytest.raises(ValidationError):
        policy_adapter.validate_python(unsafe_policy_risk["category"])
    for payload in controlled_client_drafts:
        with pytest.raises(ValidationError):
            client_adapter.validate_python(payload["client_id"])
    for terminator in JSON_LINE_TERMINATORS:
        with pytest.raises(ValidationError):
            uuid_adapter.validate_python(f"{VALID_UUID7}{terminator}")
        with pytest.raises(ValidationError):
            sha_adapter.validate_python(f"{VALID_SHA256}{terminator}")


def test_draft_2020_12_safe_locator_text_rejects_line_terminators(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "evidence_locator.schema.json").read_text(encoding="utf-8")
    )["properties"]["display_locator"]
    adapter = TypeAdapter(SafeLocatorText)

    assert adapter.validate_python("synthetic-locator") == "synthetic-locator"
    assert Draft202012Validator(schema).is_valid("synthetic-locator")
    for terminator in JSON_LINE_TERMINATORS:
        value = f"synthetic-locator{terminator}"
        with pytest.raises(ValidationError):
            adapter.validate_python(value)
        assert not Draft202012Validator(schema).is_valid(value)


def test_frozen_python_strip_set_matches_nonempty_runtime_and_draft_schema(
    tmp_path: Path,
) -> None:
    observed = tuple(
        codepoint
        for codepoint in range(sys.maxunicode + 1)
        if chr(codepoint).strip() == ""
    )
    assert observed == FROZEN_PYTHON_STRIP_CODEPOINTS

    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "client_reply_output.schema.json").read_text(encoding="utf-8")
    )
    adapter = TypeAdapter(NonEmptyStr)
    blank_values = (*FROZEN_PYTHON_STRIP_CHARS, "".join(FROZEN_PYTHON_STRIP_CHARS))
    valid_values = ("\ufeff", "x", f"{''.join(FROZEN_PYTHON_STRIP_CHARS)}x")

    for value in ("", *blank_values):
        with pytest.raises(ValidationError):
            adapter.validate_python(value)
        with pytest.raises(ValidationError):
            ClientReplyOutput.model_validate_json(json.dumps({"text": value}))
        assert not Draft202012Validator(schema).is_valid({"text": value})
    for value in valid_values:
        assert adapter.validate_python(value) == value
        assert ClientReplyOutput.model_validate_json(json.dumps({"text": value}))
        assert Draft202012Validator(schema).is_valid({"text": value})


def test_nonempty_schema_uses_explicit_python_strip_set_in_node_ecma(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "client_reply_output.schema.json").read_text(encoding="utf-8")
    )
    text_schema = schema["properties"]["text"]
    assert "pattern" not in text_schema
    blank_pattern = text_schema["not"]["pattern"]
    values = (
        "\u0085",
        "\ufeff",
        "".join(FROZEN_PYTHON_STRIP_CHARS),
        f"{''.join(FROZEN_PYTHON_STRIP_CHARS)}x",
    )
    assert _node_regex_matches(blank_pattern, values) == (True, False, True, False)


def test_safe_locator_rejects_every_noncontrol_python_blank_character(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "evidence_locator.schema.json").read_text(encoding="utf-8")
    )["properties"]["display_locator"]
    adapter = TypeAdapter(SafeLocatorText)
    values = (*SAFE_LOCATOR_BLANK_CHARS, "".join(SAFE_LOCATOR_BLANK_CHARS))
    for value in values:
        assert value.strip() == ""
        with pytest.raises(ValidationError):
            adapter.validate_python(value)
        assert not Draft202012Validator(schema).is_valid(value)


def test_all_exported_patterns_are_portable_node_ecma_without_engine_shorthands(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    patterns = tuple(
        sorted(
            {
                node["pattern"]
                for filename in EXPECTED_SCHEMA_FILES
                for node in _walk_json(
                    json.loads((tmp_path / filename).read_text(encoding="utf-8"))
                )
                if isinstance(node, dict) and isinstance(node.get("pattern"), str)
            }
        )
    )
    assert _node_compile_patterns(patterns) == len(patterns)
    for pattern in patterns:
        assert not any(token in pattern for token in (r"\b", r"\s", r"\S")), pattern


def test_published_text_guards_name_unicode_line_separators(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    locator_schema = json.loads(
        (tmp_path / "evidence_locator.schema.json").read_text(encoding="utf-8")
    )["properties"]["display_locator"]
    details_schema = json.loads(
        (tmp_path / "tool_error.schema.json").read_text(encoding="utf-8")
    )["properties"]["safe_details"]

    guarded_nodes = (
        locator_schema,
        details_schema["additionalProperties"]["anyOf"][0],
        details_schema["propertyNames"],
    )
    for node in guarded_nodes:
        assert any(
            isinstance(child, dict)
            and child.get("pattern") == JSON_LINE_SEPARATOR_PATTERN
            for child in _walk_json(node.get("not"))
        )


def test_draft_2020_12_safe_details_constraints_match_runtime(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "tool_error.schema.json").read_text(encoding="utf-8")
    )
    valid = {
        "code": "INVALID",
        "message": "invalid",
        "retryable": False,
        "safe_details": {"a_retry": False, "m_code": "synthetic", "z_count": 2},
    }
    invalid_details = (
        {"Code": "synthetic"},
        {"m_code\n": "synthetic"},
        {"subject": "synthetic"},
        {"m_code": VALID_CLIENT_ID},
        {"m_code": "relative/private"},
        {"m_code": "relative\\private"},
        {"m_code": ".."},
        {"content": "synthetic full consultation body"},
        {"m_code": "synthetic full consultation body"},
        {"m_code": "object case_example exists"},
        {"m_code": "line\nraw"},
        {"m_code": "raw\n"},
        *(
            {f"m_code{terminator}": "synthetic"}
            for terminator in JSON_LINE_TERMINATORS
        ),
        *(
            {"m_code": f"synthetic{terminator}"}
            for terminator in JSON_LINE_TERMINATORS
        ),
    )

    assert ToolError.model_validate_json(json.dumps(valid))
    assert Draft202012Validator(schema).is_valid(valid)
    for details in invalid_details:
        payload = {**valid, "safe_details": details}
        with pytest.raises(ValidationError):
            ToolError.model_validate_json(json.dumps(payload))
        assert not Draft202012Validator(schema).is_valid(payload)


def test_safe_detail_semantic_guards_match_runtime_and_draft_at_boundaries(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "tool_error.schema.json").read_text(encoding="utf-8")
    )
    cases = (
        ("full body", False),
        ("\u4e2dfull body\u6587", False),
        ("full\u0085body", False),
        ("full\ufeffbody", True),
        ("xfull body", True),
        ("full bodyx", True),
        ("_full body", True),
        ("object exists", False),
        ("\u4e2dobject exists\u6587", False),
        (f"object{' ' * 48}exists", False),
        (f"object{' ' * 49}exists", True),
        ("objectx exists", True),
        ("object existsx", True),
    )
    for value, expected in cases:
        payload = {
            "code": "INVALID",
            "message": "invalid",
            "retryable": False,
            "safe_details": {"m_code": value},
        }
        try:
            ToolError.model_validate_json(json.dumps(payload))
            runtime_valid = True
        except ValidationError:
            runtime_valid = False
        schema_valid = Draft202012Validator(schema).is_valid(payload)
        assert runtime_valid is schema_valid is expected, value.encode("unicode_escape")


def test_safe_detail_semantic_guards_match_node_ecma(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "tool_error.schema.json").read_text(encoding="utf-8")
    )
    guards = schema["properties"]["safe_details"]["additionalProperties"]["anyOf"][0][
        "not"
    ]["anyOf"]
    patterns = tuple(item["pattern"] for item in guards)
    body_pattern = next(pattern for pattern in patterns if "[fF][uU]" in pattern)
    existence_pattern = next(pattern for pattern in patterns if "[oO][bB]" in pattern)

    body_values = (
        "full body",
        "\u4e2dfull body\u6587",
        "full\u0085body",
        "full\ufeffbody",
        "xfull body",
        "full bodyx",
    )
    assert _node_regex_matches(body_pattern, body_values) == (
        True,
        True,
        True,
        False,
        False,
        False,
    )
    existence_values = (
        "object exists",
        "\u4e2dobject exists\u6587",
        f"object{' ' * 48}exists",
        f"object{' ' * 49}exists",
        "objectx exists",
        "object existsx",
    )
    assert _node_regex_matches(existence_pattern, existence_values) == (
        True,
        True,
        True,
        False,
        False,
        False,
    )


def test_draft_2020_12_c1_local_state_matrix_matches_runtime(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "c1_applicability_decision.schema.json").read_text(encoding="utf-8")
    )
    applicable = {
        "status": "applicable",
        "revision": VALID_REF,
        "scope_policy_ref": VALID_REF,
        "matched_rule_ids": ["rule_a"],
        "missing_context_fields": [],
        "effective_status": "active",
        "empirical_support": "case_supported",
        "conflict_evidence_ids": [],
    }
    insufficient = {
        **applicable,
        "status": "insufficient_context",
        "matched_rule_ids": [],
        "missing_context_fields": ["relationship_status"],
        "empirical_support": "unassessed",
    }
    unavailable = {
        **applicable,
        "status": "unavailable",
        "revision": None,
        "matched_rule_ids": [],
        "missing_context_fields": [],
        "effective_status": "none",
        "empirical_support": "unassessed",
    }
    cases = (
        (applicable, True),
        ({**applicable, "matched_rule_ids": []}, False),
        ({**applicable, "missing_context_fields": ["unexpected"]}, False),
        ({**applicable, "revision": None}, False),
        ({**applicable, "effective_status": "expired"}, False),
        (insufficient, True),
        ({**insufficient, "missing_context_fields": []}, False),
        ({**insufficient, "revision": None}, False),
        ({**insufficient, "effective_status": "expired"}, False),
        (unavailable, True),
        ({**unavailable, "revision": VALID_REF}, False),
        ({**unavailable, "matched_rule_ids": ["unexpected"]}, False),
        ({**unavailable, "missing_context_fields": ["unexpected"]}, False),
        ({**unavailable, "empirical_support": "case_supported"}, False),
        ({**unavailable, "effective_status": "active", "revision": VALID_REF}, False),
        (
            {
                **unavailable,
                "effective_status": "expired",
                "revision": VALID_REF,
                "empirical_support": "case_supported",
            },
            True,
        ),
        ({**unavailable, "effective_status": "expired"}, False),
        (
            {
                **unavailable,
                "effective_status": "expired",
                "revision": VALID_REF,
                "missing_context_fields": ["unexpected"],
            },
            False,
        ),
    )
    for payload, expected in cases:
        try:
            C1ApplicabilityDecision.model_validate_json(json.dumps(payload))
            runtime_valid = True
        except ValidationError:
            runtime_valid = False
        schema_valid = Draft202012Validator(schema).is_valid(payload)
        assert runtime_valid is schema_valid is expected, payload


def test_draft_2020_12_approval_and_freshness_state_shapes_match_runtime(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    approval_schema = json.loads(
        (tmp_path / "approval_execution.schema.json").read_text(encoding="utf-8")
    )
    freshness_schema = json.loads(
        (tmp_path / "evidence_freshness_snapshot.schema.json").read_text(encoding="utf-8")
    )
    issued = {
        "operation_id": f"operation_{VALID_UUID7}",
        "request_id": f"request_{VALID_UUID7}",
        "descriptor_sha256": VALID_SHA256,
        "target_scope_hash": VALID_SHA256,
        "state": "issued",
        "applied_commit_version": None,
    }
    applied = {**issued, "state": "applied", "applied_commit_version": 1}
    approval_cases = (
        (issued, True),
        ({**issued, "state": "claimed"}, True),
        ({**issued, "applied_commit_version": 1}, False),
        ({**issued, "state": "claimed", "applied_commit_version": 1}, False),
        (applied, True),
        ({**applied, "state": "acknowledged"}, True),
        ({**applied, "applied_commit_version": None}, False),
        ({**applied, "state": "acknowledged", "applied_commit_version": None}, False),
    )
    for payload, expected in approval_cases:
        try:
            ApprovalExecution.model_validate_json(json.dumps(payload))
            runtime_valid = True
        except ValidationError:
            runtime_valid = False
        schema_valid = Draft202012Validator(approval_schema).is_valid(payload)
        assert runtime_valid is schema_valid is expected, payload

    stale = {
        "status": "stale",
        "evaluated_at": "2022-02-22T19:22:22Z",
        "source_observed_at": None,
        "last_reviewed_at": None,
        "review_due_at": "2022-02-22T19:22:22Z",
        "policy_ref": VALID_REF,
    }
    current = {**stale, "status": "current", "review_due_at": None}
    freshness_cases = (
        (stale, True),
        ({**stale, "review_due_at": None}, False),
        (current, True),
    )
    for payload, expected in freshness_cases:
        try:
            EvidenceFreshnessSnapshot.model_validate_json(json.dumps(payload))
            runtime_valid = True
        except ValidationError:
            runtime_valid = False
        schema_valid = Draft202012Validator(freshness_schema).is_valid(payload)
        assert runtime_valid is schema_valid is expected, payload


def test_draft_2020_12_safe_provenance_branch_shapes_match_runtime(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "evidence_provenance_view.schema.json").read_text(encoding="utf-8")
    )
    common = {
        "provenance_ref": VALID_REF,
        "derivation_rule_ref": VALID_REF,
        "passage_count": 1,
    }
    valid_payloads = (
        {
            **common,
            "provenance_scope": "global_source",
            "source_count": 2,
            "case_count": 0,
            "case_contributor_count": 0,
            "independent_source_count": 1,
            "client_exclusion_status": "not_applicable",
        },
        {
            **common,
            "provenance_scope": "client_private",
            "source_count": 0,
            "case_count": 0,
            "case_contributor_count": 0,
            "independent_source_count": 0,
            "client_exclusion_status": "current_subject_private",
        },
        {
            **common,
            "provenance_scope": "case_derived",
            "source_count": 0,
            "case_count": 1,
            "case_contributor_count": 1,
            "independent_source_count": 0,
            "client_exclusion_status": "no_subject_contribution",
        },
        {
            **common,
            "provenance_scope": "mixed",
            "source_count": 1,
            "case_count": 1,
            "case_contributor_count": 1,
            "independent_source_count": 1,
            "client_exclusion_status": "leave_one_subject_out_applied",
        },
    )
    cases = [(payload, True) for payload in valid_payloads]
    cases.extend(
        [
            ({**valid_payloads[0], "source_count": 0}, False),
            ({**valid_payloads[0], "client_exclusion_status": "current_subject_private"}, False),
            ({**valid_payloads[1], "case_count": 1}, False),
            ({**valid_payloads[1], "independent_source_count": 1}, False),
            ({**valid_payloads[2], "case_contributor_count": 0}, False),
            ({**valid_payloads[2], "source_count": 1}, False),
            ({**valid_payloads[3], "case_count": 0}, False),
            ({**valid_payloads[3], "independent_source_count": 0}, False),
        ]
    )
    for payload, expected in cases:
        try:
            EvidenceProvenanceView.model_validate_json(json.dumps(payload))
            runtime_valid = True
        except ValidationError:
            runtime_valid = False
        schema_valid = Draft202012Validator(schema).is_valid(payload)
        assert runtime_valid is schema_valid is expected, payload
    assert schema["x-runtime-only-invariants"] == [
        "independent_source_count_lte_source_count"
    ]


def test_draft_2020_12_full_provenance_presence_matrix_matches_runtime(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "provenance.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    second_client_id = VALID_SECOND_CLIENT_ID
    scopes = ("global_source", "client_private", "case_derived", "mixed")
    mismatches = []
    for scope in scopes:
        for sources, cases, clients, contributors, owner in product(
            (False, True), repeat=5
        ):
            payload = {
                "source_ids": [f"source_{VALID_UUID7}"] if sources else [],
                "passage_ids": [],
                "case_ids": [f"case_{VALID_UUID7}"] if cases else [],
                "client_ids": [VALID_CLIENT_ID] if clients else [],
                "provenance_scope": scope,
                "private_owner_client_id": VALID_CLIENT_ID if owner else None,
                "case_contributor_client_ids": (
                    [VALID_CLIENT_ID] if contributors else []
                ),
                "derivation_rule_ref": VALID_REF,
            }
            expected = {
                "global_source": (
                    sources
                    and not cases
                    and not clients
                    and not contributors
                    and not owner
                ),
                "client_private": (
                    not sources
                    and not cases
                    and clients
                    and not contributors
                    and owner
                ),
                "case_derived": (
                    not sources
                    and cases
                    and clients
                    and contributors
                    and not owner
                ),
                "mixed": sources and cases and clients and contributors and not owner,
            }[scope]
            try:
                Provenance.model_validate_json(json.dumps(payload))
                runtime_valid = True
            except ValidationError:
                runtime_valid = False
            schema_valid = validator.is_valid(payload)
            assert runtime_valid is expected, (scope, payload)
            if schema_valid is not expected:
                mismatches.append((scope, sources, cases, clients, contributors, owner))
    assert mismatches == []

    equality_only_cases = (
        {
            "source_ids": [],
            "passage_ids": [],
            "case_ids": [],
            "client_ids": [VALID_CLIENT_ID],
            "provenance_scope": "client_private",
            "private_owner_client_id": second_client_id,
            "case_contributor_client_ids": [],
            "derivation_rule_ref": VALID_REF,
        },
        {
            "source_ids": [],
            "passage_ids": [],
            "case_ids": [f"case_{VALID_UUID7}"],
            "client_ids": [VALID_CLIENT_ID],
            "provenance_scope": "case_derived",
            "private_owner_client_id": None,
            "case_contributor_client_ids": [second_client_id],
            "derivation_rule_ref": VALID_REF,
        },
        {
            "source_ids": [f"source_{VALID_UUID7}"],
            "passage_ids": [],
            "case_ids": [f"case_{VALID_UUID7}"],
            "client_ids": [VALID_CLIENT_ID],
            "provenance_scope": "mixed",
            "private_owner_client_id": None,
            "case_contributor_client_ids": [second_client_id],
            "derivation_rule_ref": VALID_REF,
        },
    )
    for payload in equality_only_cases:
        with pytest.raises(ValidationError):
            Provenance.model_validate_json(json.dumps(payload))
        assert validator.is_valid(payload)
    assert schema["x-runtime-only-invariants"] == [
        "client_private_client_ids_equal_owner_singleton",
        "case_or_mixed_client_ids_equal_case_contributors",
    ]


def test_draft_2020_12_candidate_channel_matrix_matches_root_and_pack_runtime(
    tmp_path: Path,
) -> None:
    from tests.consultation_kb.unit.test_core_contracts import _candidate, _pack

    export_schemas(tmp_path)
    candidate_schema = json.loads(
        (tmp_path / "evidence_candidate.schema.json").read_text(encoding="utf-8")
    )
    pack_schema = json.loads(
        (tmp_path / "evidence_pack.schema.json").read_text(encoding="utf-8")
    )
    candidate_validator = Draft202012Validator(candidate_schema)
    pack_validator = Draft202012Validator(pack_schema)
    candidate_mismatches = []
    pack_mismatches = []
    for index, (scope, allowed_channels) in enumerate(CHANNELS_BY_SCOPE.items()):
        valid_candidate = _candidate(
            900 + index,
            scope=scope,
            channel=next(
                channel for channel in EVIDENCE_CHANNELS if channel in allowed_channels
            ),
        )
        candidate_base = valid_candidate.model_dump(mode="json")
        pack_base = _pack(supporting=(valid_candidate,)).model_dump(mode="json")
        for channel in EVIDENCE_CHANNELS:
            expected = channel in allowed_channels
            candidate_payload = {**candidate_base, "channel": channel}
            try:
                EvidenceCandidate.model_validate_json(json.dumps(candidate_payload))
                candidate_runtime_valid = True
            except ValidationError:
                candidate_runtime_valid = False
            assert candidate_runtime_valid is expected, (scope, channel)
            if candidate_validator.is_valid(candidate_payload) is not expected:
                candidate_mismatches.append((scope, channel))

            pack_payload = copy.deepcopy(pack_base)
            pack_payload["supporting"][0] = candidate_payload
            try:
                EvidencePack.model_validate_json(json.dumps(pack_payload))
                pack_runtime_valid = True
            except ValidationError:
                pack_runtime_valid = False
            assert pack_runtime_valid is expected, (scope, channel)
            if pack_validator.is_valid(pack_payload) is not expected:
                pack_mismatches.append((scope, channel))
    assert candidate_mismatches == []
    assert pack_mismatches == []


@pytest.mark.parametrize(
    ("kind", "valid_display", "invalid_display"),
    [
        ("source_page_span", "pages:1:2-2:3", "pages:01:2-2:3"),
        ("source_paragraph_span", "paragraphs:1-2", "paragraph:1-2"),
        ("source_line_span", "lines:1-2", "paragraphs:1-2"),
        ("source_table_span", "table:1;rows:1-2;columns:1-3", "table:1;rows:1-2"),
        ("source_sheet_range", "sheet:1;range:A1-B2", "sheet:1;range:a1-B2"),
        ("client_fact", f"fact:{VALID_OBJECT_ID}", "fact:free-narrative"),
        ("session_turn", f"turn:{VALID_UUID7}", f"turn:{VALID_UUID7.upper()}"),
        ("wiki_section", "section:relationship-context", "section:Free Text"),
        ("case_turn", f"case:{VALID_OBJECT_ID};turn:1", "case:free;turn:1"),
        ("graph_path", f"path:{VALID_SHA256}", "path:not-a-hash"),
    ],
)
def test_draft_2020_12_locator_kind_conditions_match_runtime(
    tmp_path: Path,
    kind: str,
    valid_display: str,
    invalid_display: str,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "evidence_locator.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    base = {
        "locator_kind": kind,
        "anchor_refs": [VALID_REF],
        "display_locator": valid_display,
        "locator_policy_ref": VALID_REF,
    }
    assert EvidenceLocator.model_validate_json(json.dumps(base))
    assert validator.is_valid(base)

    controlled_displays = tuple(
        f"{valid_display}{terminator}" for terminator in JSON_LINE_TERMINATORS
    )
    for invalid_value in (invalid_display, *controlled_displays):
        invalid = {**base, "display_locator": invalid_value}
        with pytest.raises(ValidationError):
            EvidenceLocator.model_validate_json(json.dumps(invalid))
        assert not validator.is_valid(invalid)


def test_embedded_object_locator_kind_boundaries_match_runtime(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "evidence_locator.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    kind_64 = "k" * 64
    kind_65 = "k" * 65
    client_canary_kind = f"prefix_{VALID_CLIENT_ID}_suffix"
    long_turn = "1" * 300
    base = {
        "anchor_refs": [VALID_REF],
        "locator_policy_ref": VALID_REF,
    }
    cases = (
        (
            {**base, "locator_kind": "case_turn", "display_locator": f"case:{kind_64}_{VALID_UUID7};turn:1"},
            True,
        ),
        (
            {**base, "locator_kind": "case_turn", "display_locator": f"case:{kind_65}_{VALID_UUID7};turn:1"},
            False,
        ),
        (
            {
                **base,
                "locator_kind": "case_turn",
                "display_locator": f"case:{kind_64}_{VALID_UUID7};turn:{long_turn}",
            },
            True,
        ),
        (
            {
                **base,
                "locator_kind": "case_turn",
                "display_locator": f"case:{client_canary_kind}_{VALID_UUID7};turn:1",
            },
            False,
        ),
        (
            {**base, "locator_kind": "client_fact", "display_locator": f"fact:{kind_64}_{VALID_UUID7}"},
            True,
        ),
        (
            {**base, "locator_kind": "client_fact", "display_locator": f"fact:{kind_65}_{VALID_UUID7}"},
            False,
        ),
    )
    cases += tuple(
        (
            {
                **base,
                "locator_kind": "case_turn",
                "display_locator": f"case:{kind_64}_{VALID_UUID7};turn:1{terminator}",
            },
            False,
        )
        for terminator in JSON_LINE_TERMINATORS
    )
    for payload, expected in cases:
        try:
            EvidenceLocator.model_validate_json(json.dumps(payload))
            runtime_valid = True
        except ValidationError:
            runtime_valid = False
        schema_valid = validator.is_valid(payload)
        assert runtime_valid is schema_valid is expected, payload["display_locator"]

    case_rule = schema["allOf"][8]["then"]["properties"]["display_locator"]
    negative_patterns = {
        node["pattern"]
        for node in _walk_json(case_rule["not"])
        if isinstance(node, dict) and isinstance(node.get("pattern"), str)
    }
    assert JSON_LINE_SEPARATOR_PATTERN in negative_patterns
    assert r"client_[a-z0-9]{12}" in negative_patterns
    assert any("{65,}" in pattern and "-7" in pattern for pattern in negative_patterns)


def test_draft_2020_12_nested_pack_patterns_reject_trailing_controls(
    tmp_path: Path,
) -> None:
    from tests.consultation_kb.unit.test_core_contracts import _pack

    export_schemas(tmp_path)
    schema = json.loads(
        (tmp_path / "evidence_pack.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    valid = _pack().model_dump(mode="json")
    assert validator.is_valid(valid)

    invalid_payloads = []
    for terminator in JSON_LINE_TERMINATORS:
        bad_object = copy.deepcopy(valid)
        bad_object["supporting"][0]["evidence_id"] += terminator
        invalid_payloads.append(bad_object)
        bad_policy = copy.deepcopy(valid)
        bad_policy["c1_applicability"]["matched_rule_ids"][0] += terminator
        invalid_payloads.append(bad_policy)
        bad_locator = copy.deepcopy(valid)
        bad_locator["supporting"][0]["location"]["display_locator"] += terminator
        invalid_payloads.append(bad_locator)

    for payload in invalid_payloads:
        with pytest.raises(ValidationError):
            EvidencePack.model_validate_json(json.dumps(payload))
        assert not validator.is_valid(payload)


def test_schemas_publish_all_representable_tuple_constraints(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    locator = json.loads(
        (tmp_path / "evidence_locator.schema.json").read_text(encoding="utf-8")
    )
    generation = json.loads(
        (tmp_path / "generation_stage_envelope.schema.json").read_text(encoding="utf-8")
    )
    risk = json.loads(
        (tmp_path / "internal_risk_observation.schema.json").read_text(encoding="utf-8")
    )
    candidate = json.loads(
        (tmp_path / "evidence_candidate.schema.json").read_text(encoding="utf-8")
    )
    c1 = json.loads(
        (tmp_path / "c1_applicability_decision.schema.json").read_text(encoding="utf-8")
    )
    pack = json.loads(
        (tmp_path / "evidence_pack.schema.json").read_text(encoding="utf-8")
    )

    unique_nodes = (
        locator["properties"]["anchor_refs"],
        generation["properties"]["parent_sha256s"],
        risk["properties"]["trigger_turn_ids"],
        risk["properties"]["suggested_questions"],
        candidate["properties"]["supports_evidence_ids"],
        candidate["properties"]["contradicts_evidence_ids"],
        c1["properties"]["matched_rule_ids"],
        c1["properties"]["missing_context_fields"],
        c1["properties"]["conflict_evidence_ids"],
        pack["properties"]["temporary_fact_refs"],
        pack["properties"]["supporting"],
        pack["properties"]["contradicting"],
        pack["properties"]["unresolved_conflict_refs"],
    )
    assert all(node.get("uniqueItems") is True for node in unique_nodes)
    assert locator["properties"]["anchor_refs"]["minItems"] == 1
    assert risk["properties"]["trigger_turn_ids"]["minItems"] == 1
    assert risk["properties"]["suggested_questions"]["minItems"] == 1


def test_pack_schema_type_graph_and_client_reply_schema_are_privacy_separated(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    pack_text = (tmp_path / "evidence_pack.schema.json").read_text(encoding="utf-8")
    direct_schema_text = json.dumps(EvidencePack.model_json_schema(), sort_keys=True)
    for text in (pack_text, direct_schema_text):
        assert not CLIENT_ID_RE.search(text)
        for forbidden in (
            "client_id",
            "client_ids",
            "private_owner_client_id",
            "case_contributor_client_ids",
            "allowed_ref_ids",
            VALID_CLIENT_ID,
            VALID_SECOND_CLIENT_ID,
        ):
            assert forbidden not in text

    pack_schema = json.loads(pack_text)
    assert "AuthoritativeFilterSnapshot" not in pack_schema["$defs"]
    assert "Provenance" not in pack_schema["$defs"]

    reply = json.loads((tmp_path / "client_reply_output.schema.json").read_text(encoding="utf-8"))
    assert set(reply["properties"]) == {"schema_version", "text"}
    reply_text = json.dumps(reply, sort_keys=True).lower()
    for forbidden in ("risk", "warning", "client_facing_visibility", "rule_ref"):
        assert forbidden not in reply_text


def test_three_public_roots_have_exact_required_and_default_contract(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    expected = {
        "generation_stage_envelope.schema.json": {
            "schema_version", "stage", "turn_id", "run_id", "parent_sha256s", "created_at"
        },
        "client_reply_output.schema.json": {"schema_version", "text"},
        "internal_risk_observation.schema.json": {
            "schema_version",
            "observation_id",
            "category",
            "level",
            "trigger_turn_ids",
            "rule_ref",
            "detected_at",
            "suggested_questions",
            "client_facing_visibility",
        },
    }
    for filename, fields in expected.items():
        schema = json.loads((tmp_path / filename).read_text(encoding="utf-8"))
        assert set(schema["properties"]) == fields
        assert schema["properties"]["schema_version"]["default"] == "1.0"
        assert set(schema["required"]) == fields - {"schema_version", "client_facing_visibility"}
    risk = json.loads((tmp_path / "internal_risk_observation.schema.json").read_text(encoding="utf-8"))
    assert risk["properties"]["client_facing_visibility"]["default"] == "never"
