from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.wiki import WikiGovernanceError, WikiRevisionService
from consultation_kb.models.common import VersionRef
from consultation_kb.models.wiki import (
    WikiDiffKind,
    WikiGraphRelationDeclaration,
    WikiRevisionDraft,
    WikiSection,
)
from tests.consultation_kb.knowledge_support import DirectTestApprovalExecutor


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


def _ids() -> IdFactory:
    counter = iter(range(1, 1000))
    return IdFactory(FixedClock(NOW), lambda: next(counter))


def _draft(
    ids: IdFactory, *, wiki_id: str, base: int, kind: WikiDiffKind
) -> WikiRevisionDraft:
    claim = VersionRef(
        object_id=ids.object_id("claim"), version=1, content_sha256="2" * 64
    )
    passage = VersionRef(
        object_id=ids.object_id("passage"), version=1, content_sha256="3" * 64
    )
    return WikiRevisionDraft(
        wiki_id=wiki_id,
        slug="synthetic-topic",
        title="合成主题",
        base_revision=base,
        diff_kind=kind,
        sections=(
            WikiSection(
                key="definition",
                heading="定义",
                body="合成定义",
                claim_refs=(claim,),
                passage_refs=(passage,),
            ),
        ),
        theory_revision_refs=(),
        review_due_at=None,
    )


def test_wiki_cannot_use_itself_as_evidence() -> None:
    ids = IdFactory(FixedClock(NOW), lambda: 1)
    wiki_id = ids.object_id("wiki")
    wiki_ref = VersionRef(object_id=wiki_id, version=1, content_sha256="1" * 64)

    with pytest.raises(ValidationError, match="Wiki.*evidence"):
        WikiRevisionDraft(
            wiki_id=wiki_id,
            slug="synthetic-topic",
            title="合成主题",
            base_revision=0,
            diff_kind="add",
            sections=(
                WikiSection(
                    key="definition",
                    heading="定义",
                    body="合成定义",
                    claim_refs=(wiki_ref,),
                    passage_refs=(),
                ),
            ),
            theory_revision_refs=(),
            review_due_at=None,
        )


def test_wiki_section_rejects_claim_prefix_subtypes() -> None:
    ids = _ids()
    with pytest.raises(ValidationError, match="Wiki cannot use itself as evidence"):
        WikiRevisionDraft(
            wiki_id=ids.object_id("wiki"),
            slug="synthetic-topic",
            title="Synthetic topic",
            base_revision=0,
            diff_kind="add",
            sections=(
                WikiSection(
                    key="definition",
                    heading="Definition",
                    body="Body",
                    claim_refs=(
                        VersionRef(
                            object_id=ids.object_id("claim_x"),
                            version=1,
                            content_sha256="1" * 64,
                        ),
                    ),
                    passage_refs=(),
                ),
            ),
            theory_revision_refs=(),
            review_due_at=None,
        )


def test_existing_page_requires_structured_non_append_diff() -> None:
    ids = _ids()
    wiki_id = ids.object_id("wiki")
    with pytest.raises(ValidationError, match="structured non-add diff"):
        _draft(ids, wiki_id=wiki_id, base=1, kind="add")


def test_base_revision_change_is_rejected_before_approval() -> None:
    ids = _ids()
    wiki_id = ids.object_id("wiki")
    service = WikiRevisionService(
        claim_resolver=lambda _ref: "approved",
        passage_resolver=lambda ref: ref,
        id_factory=ids,
        clock=FixedClock(NOW),
        approval_executor=DirectTestApprovalExecutor(ids),
    )
    first = service.propose_diff(_draft(ids, wiki_id=wiki_id, base=0, kind="add"))
    service.approve(
        first.proposal_id,
        actor="knowledge_reviewer",
        approval_request_id=ids.object_id("approval_request"),
    )
    stale = service.propose_diff(
        _draft(ids, wiki_id=wiki_id, base=0, kind="add")
    )
    with pytest.raises(WikiGovernanceError, match="WIKI_BASE_VERSION_CONFLICT"):
        service.approve(
            stale.proposal_id,
            actor="knowledge_reviewer",
            approval_request_id=ids.object_id("approval_request"),
        )


def test_model_cannot_approve_wiki() -> None:
    ids = _ids()
    wiki_id = ids.object_id("wiki")
    service = WikiRevisionService(
        id_factory=ids,
        clock=FixedClock(NOW),
        approval_executor=DirectTestApprovalExecutor(ids),
    )
    proposal = service.propose_diff(_draft(ids, wiki_id=wiki_id, base=0, kind="add"))
    with pytest.raises(WikiGovernanceError, match="WIKI_REVIEWER_APPROVAL_REQUIRED"):
        service.approve(
            proposal.proposal_id,
            actor="model",
            approval_request_id=ids.object_id("approval_request"),
        )


def _graph_declaration_payload(ids: IdFactory) -> dict[str, object]:
    return {
        "source_ref": VersionRef(
            object_id=ids.object_id("concept"),
            version=1,
            content_sha256="4" * 64,
        ),
        "target_ref": VersionRef(
            object_id=ids.object_id("theory"),
            version=1,
            content_sha256="5" * 64,
        ),
        "claim_ref": VersionRef(
            object_id=ids.object_id("claim"),
            version=1,
            content_sha256="6" * 64,
        ),
        "relation": "SUPPORTS",
        "scope": ("consultation",),
        "review_status": "approved",
        "effective_from": NOW,
        "effective_to": NOW + timedelta(days=1),
        "confidence_override": 0.75,
    }


@pytest.mark.parametrize("kind", ["claim", "wiki", "client", "session"])
def test_wiki_graph_relation_uses_exact_public_node_allowlist(kind: str) -> None:
    ids = _ids()
    payload = _graph_declaration_payload(ids)
    payload["source_ref"] = VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256="7" * 64,
    )
    with pytest.raises(ValidationError, match="node type is not public-safe"):
        WikiGraphRelationDeclaration.model_validate(payload)


@pytest.mark.parametrize("kind", ["passage", "claim_x"])
def test_wiki_graph_relation_requires_exact_claim_reference_kind(kind: str) -> None:
    ids = _ids()
    payload = _graph_declaration_payload(ids)
    payload["claim_ref"] = VersionRef(
        object_id=ids.object_id(kind),
        version=1,
        content_sha256="7" * 64,
    )
    with pytest.raises(ValidationError, match="must reference a Claim"):
        WikiGraphRelationDeclaration.model_validate(payload)


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), -float("inf"), True])
def test_wiki_graph_relation_rejects_nonfinite_or_boolean_confidence(
    confidence: object,
) -> None:
    payload = _graph_declaration_payload(_ids())
    payload["confidence_override"] = confidence
    with pytest.raises(ValidationError):
        WikiGraphRelationDeclaration.model_validate(payload)


@pytest.mark.parametrize(
    "scope",
    [(), ("consultation", "consultation"), ("planning", "consultation")],
)
def test_wiki_graph_relation_scope_must_be_nonempty_unique_and_sorted(
    scope: tuple[str, ...],
) -> None:
    payload = _graph_declaration_payload(_ids())
    payload["scope"] = scope
    with pytest.raises(ValidationError, match="scope must be canonical"):
        WikiGraphRelationDeclaration.model_validate(payload)


def test_wiki_graph_relation_duplicate_identity_covers_all_canonical_fields() -> None:
    ids = _ids()
    wiki_id = ids.object_id("wiki")
    payload = _graph_declaration_payload(ids)
    first = WikiGraphRelationDeclaration.model_validate(payload)
    second = first.model_copy(update={"confidence_override": 0.5})
    section = WikiSection(
        key="definition",
        heading="definition",
        body="body",
        claim_refs=(first.claim_ref,),
        passage_refs=(),
    )
    WikiRevisionDraft(
        wiki_id=wiki_id,
        slug="graph-declarations",
        title="Graph declarations",
        base_revision=0,
        diff_kind="add",
        sections=(section,),
        theory_revision_refs=(),
        graph_relations=(first, second),
        review_due_at=None,
    )
    with pytest.raises(ValidationError, match="declarations must be unique"):
        WikiRevisionDraft(
            wiki_id=wiki_id,
            slug="graph-declarations",
            title="Graph declarations",
            base_revision=0,
            diff_kind="add",
            sections=(section,),
            theory_revision_refs=(),
            graph_relations=(first, first),
            review_due_at=None,
        )
