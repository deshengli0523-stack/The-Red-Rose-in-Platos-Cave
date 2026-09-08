"""Build stable JSON/Markdown current profiles from a bitemporal snapshot."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from consultation_kb.client.bitemporal import BitemporalSnapshot
from consultation_kb.models.facts import FactEvent
from consultation_kb.models.profile import (
    ProfileItem,
    ProfileSection,
    ProfileSectionName,
    ProfileSnapshot,
    profile_sha256,
)
from consultation_kb.storage.client_ledger import FactEventRepository


SECTION_ORDER: tuple[ProfileSectionName, ...] = (
    "goals",
    "unresolved_issues",
    "relationships",
    "preferences",
    "constraints",
    "active_facts",
    "uncertainty_disputes",
    "pending_review",
)


class StaleProfilePreview(RuntimeError):
    def __init__(self) -> None:
        super().__init__("STALE_PROFILE_PREVIEW")


@dataclass(frozen=True, slots=True)
class PreparedProfilePublication:
    publication_operation_id: str
    source_client_commit_version: int
    runtime_epoch: int
    json_bytes: bytes
    markdown_bytes: bytes
    json_sha256: str
    markdown_sha256: str


class ProfileMaterializer:
    def build(
        self,
        snapshot: BitemporalSnapshot,
        *,
        merge_member_event_ids: frozenset[str] = frozenset(),
        purpose: str = "next_session_context",
    ) -> ProfileSnapshot:
        if type(purpose) is not str or not purpose:
            raise ValueError("profile purpose must be nonempty")
        grouped: dict[ProfileSectionName, list[ProfileItem]] = {
            name: [] for name in SECTION_ORDER
        }
        for event in snapshot.events:
            if event.event_id in merge_member_event_ids:
                continue
            if event.privacy_level != "private_client" or not event.allows_purpose(
                purpose
            ):
                continue
            if (
                event.review_status != "approved"
                or event.validity_status != "active"
                or event.resolution_status != "open"
            ):
                continue
            section = self._section(event)
            source_ids = (event.event_id,) + tuple(
                item
                for item in sorted(event.source_event_ids)
                if item != event.event_id
            )
            grouped[section].append(
                ProfileItem(
                    fact_id=event.fact_id,
                    event_id=event.event_id,
                    subject=event.subject,
                    predicate=event.predicate,
                    object_json=event.object_json,
                    cognitive_type=event.cognitive_type,
                    review_status=event.review_status,
                    validity_status=event.validity_status,
                    resolution_status=event.resolution_status,
                    epistemic_status=event.epistemic_status,
                    fact_confidence=event.fact_confidence,
                    effective_from=event.effective_from,
                    effective_to=event.effective_to,
                    recorded_at=event.recorded_at,
                    approved_at=event.approved_at,
                    source_session_id=event.source_session_id,
                    source_turn_id=event.source_turn_id,
                    source_event_ids=source_ids,
                )
            )
        sections = tuple(
            ProfileSection(
                name=name,
                items=tuple(
                    sorted(
                        grouped[name],
                        key=lambda item: (
                            item.subject,
                            item.predicate,
                            item.effective_from,
                            item.fact_id,
                        ),
                    )
                ),
            )
            for name in SECTION_ORDER
            if grouped[name]
        )
        current_ids = tuple(item.event_id for section in sections for item in section.items)
        json_base: dict[str, object] = {
            "schema_version": "client_profile.v1",
            "source_snapshot_sha256": snapshot.canonical_sha256,
            "source_client_commit_version": snapshot.client_commit_version,
            "effective_at": snapshot.query.effective_at.isoformat().replace(
                "+00:00", "Z"
            ),
            "known_at": snapshot.query.known_at.isoformat().replace("+00:00", "Z"),
            "fixed_epoch": snapshot.query.fixed_epoch,
            "sections": [section.model_dump(mode="json") for section in sections],
            "current_event_ids": current_ids,
        }
        return ProfileSnapshot(
            schema_version="client_profile.v1",
            source_snapshot_sha256=snapshot.canonical_sha256,
            source_client_commit_version=snapshot.client_commit_version,
            effective_at=snapshot.query.effective_at,
            known_at=snapshot.query.known_at,
            fixed_epoch=snapshot.query.fixed_epoch,
            sections=sections,
            current_event_ids=current_ids,
            canonical_sha256=profile_sha256(json_base),
        )

    def render_json(self, profile: ProfileSnapshot) -> bytes:
        return (
            json.dumps(
                profile.model_dump(mode="json"),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    def render_markdown(self, profile: ProfileSnapshot) -> bytes:
        labels = {
            "goals": "目标",
            "unresolved_issues": "未解决事项",
            "relationships": "关系",
            "preferences": "偏好",
            "constraints": "约束",
            "active_facts": "有效事实",
            "uncertainty_disputes": "不确定或争议",
            "pending_review": "待复核",
        }
        lines = ["# 当前客户资料", ""]
        for section in profile.sections:
            lines.extend((f"## {labels[section.name]}", ""))
            for item in section.items:
                value = json.loads(item.object_json)
                rendered = value if isinstance(value, str) else json.dumps(
                    value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                lines.append(
                    f"- {item.subject} · {item.predicate}: {rendered} "
                    f"[{item.epistemic_status}; confidence={item.fact_confidence:.3f}]"
                )
            lines.append("")
        return ("\n".join(lines).rstrip() + "\n").encode("utf-8")

    def prepare_publish(
        self,
        profile: ProfileSnapshot,
        *,
        repository: FactEventRepository,
        publication_operation_id: str,
        runtime_epoch: int,
    ) -> PreparedProfilePublication:
        if repository.current_commit_version() != profile.source_client_commit_version:
            raise StaleProfilePreview
        if not publication_operation_id or type(runtime_epoch) is not int or runtime_epoch <= 0:
            raise ValueError("profile publication metadata is invalid")
        json_bytes = self.render_json(profile)
        markdown_bytes = self.render_markdown(profile)
        return PreparedProfilePublication(
            publication_operation_id=publication_operation_id,
            source_client_commit_version=profile.source_client_commit_version,
            runtime_epoch=runtime_epoch,
            json_bytes=json_bytes,
            markdown_bytes=markdown_bytes,
            json_sha256=hashlib.sha256(json_bytes).hexdigest(),
            markdown_sha256=hashlib.sha256(markdown_bytes).hexdigest(),
        )

    @staticmethod
    def _section(event: FactEvent) -> ProfileSectionName:
        if event.review_status != "approved":
            return "pending_review"
        if event.epistemic_status in {"uncertain", "disputed"}:
            return "uncertainty_disputes"
        predicate = event.predicate.casefold()
        if "goal" in predicate or "目标" in predicate:
            return "goals"
        if "issue" in predicate or "problem" in predicate or "问题" in predicate:
            return "unresolved_issues"
        if "partner" in predicate or "relationship" in predicate or "关系" in predicate:
            return "relationships"
        if "preference" in predicate or "偏好" in predicate:
            return "preferences"
        if "constraint" in predicate or "约束" in predicate:
            return "constraints"
        return "active_facts"


__all__ = [
    "PreparedProfilePublication",
    "ProfileMaterializer",
    "SECTION_ORDER",
    "StaleProfilePreview",
]
