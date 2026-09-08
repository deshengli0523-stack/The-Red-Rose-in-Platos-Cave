from __future__ import annotations

from pathlib import Path

import pytest

from tests.consultation_kb.knowledge_integration_support import (
    build_global_knowledge_harness,
    prepare_global_publication,
    prepare_governed_knowledge,
    prepare_successor_knowledge,
)


pytestmark = pytest.mark.golden


def test_new_c1_revision_atomically_supersedes_old_without_regrading_c2(
    tmp_path: Path,
) -> None:
    harness = build_global_knowledge_harness(tmp_path)
    try:
        first = prepare_governed_knowledge(harness)
        first_publication = prepare_global_publication(harness, first)
        first_publication.service.publish_theory_and_wiki(
            first_publication.operation_id,
            theory_id=first.theory.theory_id,
            theory_revision=first.theory.revision,
            wiki_id=first.wiki.wiki_id,
            wiki_revision=first.wiki.revision,
        )
        second = prepare_successor_knowledge(harness, first)
        second_publication = prepare_global_publication(
            harness,
            second,
            authority_base_version=2,
            expected_current_epoch=1,
        )
        second_publication.service.publish_theory_and_wiki(
            second_publication.operation_id,
            theory_id=second.theory.theory_id,
            theory_revision=second.theory.revision,
            wiki_id=second.wiki.wiki_id,
            wiki_revision=second.wiki.revision,
        )

        assert harness.connection.execute(
            """
            SELECT revision, status, empirical_support
              FROM theory_revisions ORDER BY revision
            """
        ).fetchall() == [
            (1, "SUPERSEDED", "unassessed"),
            (2, "ACTIVE", "unassessed"),
        ]
        assert harness.connection.execute(
            """
            SELECT theory_revision, review_status FROM claims
             WHERE source_grade = 'C1' ORDER BY theory_revision
            """
        ).fetchall() == [(1, "REVOKED"), (2, "APPROVED")]
        assert ("C2", "conflicting", "APPROVED") in harness.connection.execute(
            """
            SELECT source_grade, empirical_support, review_status FROM claims
             WHERE source_grade <> 'C1'
            """
        ).fetchall()
        assert second.theory_service.get_active(first.theory.theory_id) is not None
    finally:
        harness.close()
