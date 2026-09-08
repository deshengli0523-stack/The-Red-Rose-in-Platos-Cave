from __future__ import annotations

from datetime import datetime, timezone

import pytest

from consultation_kb.client.bitemporal import BitemporalFactQuery, FactQuery
from consultation_kb.client.profile import ProfileMaterializer, StaleProfilePreview
from tests.consultation_kb.unit.test_fact_repository import _repository
from tests.consultation_kb.unit.test_fact_schema import _event


UTC = timezone.utc


def test_current_profile_removes_resolved_invalidated_superseded_and_merge_members() -> None:
    repository = _repository()
    active = _event(
        event_id="active",
        fact_id="active",
        predicate="goal",
        object_json='"建立边界"',
        epistemic_status="asserted",
    )
    uncertain = _event(
        event_id="uncertain",
        fact_id="uncertain",
        predicate="attachment_hypothesis",
        object_json='"可能回避冲突"',
        cognitive_type="hypothesis",
        source_kind="session_derived",
        reported_at=datetime(2026, 7, 16, tzinfo=UTC),
    )
    resolved = _event(
        event_id="resolved",
        fact_id="resolved",
        predicate="issue",
        object_json='"旧问题"',
        resolution_status="resolved",
    )
    invalidated = _event(
        event_id="invalidated",
        fact_id="invalidated",
        predicate="preference",
        object_json='"旧偏好"',
        validity_status="invalidated",
    )
    merged_member = _event(
        event_id="member",
        fact_id="member",
        predicate="goal",
        object_json='"建立边界"',
    )
    repository.append_batch(
        base_commit_version=0,
        events=(active, uncertain, resolved, invalidated, merged_member),
    )
    query = FactQuery(
        effective_at=datetime(2026, 7, 17, tzinfo=UTC),
        known_at=datetime(2026, 7, 17, tzinfo=UTC),
        fixed_epoch=1,
    )
    snapshot = BitemporalFactQuery(repository).snapshot(query)
    profile = ProfileMaterializer().build(
        snapshot,
        merge_member_event_ids=frozenset({"member"}),
    )

    assert profile.current_event_ids == ("active", "uncertain")
    assert [section.name for section in profile.sections] == [
        "goals",
        "uncertainty_disputes",
    ]
    uncertain_item = profile.sections[1].items[0]
    assert uncertain_item.epistemic_status == "uncertain"
    assert uncertain_item.source_event_ids == ("uncertain",)


def test_profile_rendering_is_byte_stable_and_stale_prepare_fails() -> None:
    repository = _repository()
    repository.append_batch(base_commit_version=0, events=(_event(),))
    query = FactQuery(
        effective_at=datetime(2026, 7, 17, tzinfo=UTC),
        known_at=datetime(2026, 7, 17, tzinfo=UTC),
        fixed_epoch=1,
    )
    materializer = ProfileMaterializer()
    profile = materializer.build(BitemporalFactQuery(repository).snapshot(query))
    assert materializer.render_json(profile) == materializer.render_json(profile)
    assert materializer.render_markdown(profile) == materializer.render_markdown(profile)

    repository.append_batch(
        base_commit_version=1,
        events=(_event(event_id="later", fact_id="later", commit_version=2),),
    )
    with pytest.raises(StaleProfilePreview, match="STALE_PROFILE_PREVIEW"):
        materializer.prepare_publish(
            profile,
            repository=repository,
            publication_operation_id="profile-operation",
            runtime_epoch=2,
        )


def test_next_session_profile_excludes_session_private_and_disallowed_purpose() -> None:
    repository = _repository()
    allowed = _event(event_id="allowed", fact_id="allowed", object_json='"allowed"')
    session_private = _event(
        event_id="session-private",
        fact_id="session-private",
        object_json='"session-secret"',
        privacy_level="private_session",
    )
    disallowed = _event(
        event_id="case-only",
        fact_id="case-only",
        object_json='"case-secret"',
        allowed_purposes_json='["case_archive"]',
    )
    repository.append_batch(
        base_commit_version=0,
        events=(allowed, session_private, disallowed),
    )
    snapshot = BitemporalFactQuery(repository).snapshot(
        FactQuery(
            effective_at=datetime(2026, 7, 17, tzinfo=UTC),
            known_at=datetime(2026, 7, 17, tzinfo=UTC),
            fixed_epoch=1,
        )
    )
    materializer = ProfileMaterializer()
    profile = materializer.build(snapshot)
    rendered = materializer.render_json(profile) + materializer.render_markdown(profile)
    assert profile.current_event_ids == ("allowed",)
    assert b"session-secret" not in rendered
    assert b"case-secret" not in rendered
