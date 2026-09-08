"""Deterministic human-readable rendering of governed Wiki revisions."""

from __future__ import annotations

from consultation_kb.models.wiki import WikiRevision


REQUIRED_SECTION_KEYS = frozenset(
    {
        "definition",
        "context",
        "interpretations",
        "applicability",
        "boundaries",
        "contraindications",
        "counterexamples",
        "relationships",
        "support",
        "opposition",
        "anchors",
        "review",
        "unresolved",
    }
)


class WikiRenderError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class WikiRenderer:
    def render(self, revision: WikiRevision) -> str:
        value = WikiRevision.model_validate(revision)
        present = frozenset(section.key for section in value.sections)
        if not REQUIRED_SECTION_KEYS.issubset(present):
            raise WikiRenderError("WIKI_PAGE_CONTRACT_INCOMPLETE")
        lines = [f"# {value.title}", "", f"版本：{value.revision}", ""]
        for section in value.sections:
            lines.extend((f"## {section.heading}", "", section.body, ""))
            if section.claim_refs:
                lines.append(
                    "主张："
                    + "、".join(
                        f"[{item.object_id}@v{item.version}]" for item in section.claim_refs
                    )
                )
            if section.passage_refs:
                lines.append(
                    "原文锚点："
                    + "、".join(
                        f"[{item.object_id}@v{item.version}]"
                        for item in section.passage_refs
                    )
                )
            lines.append("")
        if value.relationships:
            lines.extend(("## 受治理关系", ""))
            for relationship in value.relationships:
                sources = ", ".join(
                    f"{item.object_id}@v{item.version}"
                    for item in relationship.source_refs
                )
                lines.append(
                    f"- {relationship.relationship} → {relationship.target_id}; "
                    f"scope={','.join(relationship.scope)}; sources={sources}"
                )
            lines.append("")
        if value.graph_relations:
            lines.extend(("## Governed graph relations", ""))
            for relation in value.graph_relations:
                lines.append(
                    f"- {relation.relation}: {relation.source_ref.object_id} -> "
                    f"{relation.target_ref.object_id}; "
                    f"claim={relation.claim_ref.object_id}; "
                    f"scope={','.join(relation.scope)}; "
                    f"review={relation.review_status}"
                )
            lines.append("")
        if value.unresolved_questions:
            lines.extend(
                ("## 未解决问题", "", *(f"- {item}" for item in value.unresolved_questions), "")
            )
        return "\n".join(lines).rstrip() + "\n"


__all__ = ["REQUIRED_SECTION_KEYS", "WikiRenderError", "WikiRenderer"]
