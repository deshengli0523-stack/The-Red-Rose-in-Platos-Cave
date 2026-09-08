"""Build abstracted, deidentified shared-case candidates from actual records."""

from __future__ import annotations

from collections.abc import Iterable
import unicodedata

from pydantic import model_validator

from consultation_kb.archive.deidentification import Deidentifier
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge._canonical import canonical_sha256, text_sha256
from consultation_kb.models.archive import ActualTranscript
from consultation_kb.models.cases import (
    CandidateProvenanceSummary,
    DeidentificationScan,
    DeidentificationSummary,
    DeidentificationTransform,
    PrivateActualCaseRecord,
    PrivateCaseSourceItem,
    SharedCaseCandidate,
    SharedCaseSection,
    SharedCaseSectionProposal,
    shared_case_candidate_payload,
    version_ref_key,
)
from consultation_kb.models.common import (
    Sha256Hex,
    StrictModel,
    UtcDateTime,
    VersionRef,
)


_SOURCE_KINDS_BY_SECTION = {
    "factual_context": frozenset({"client_message"}),
    "actual_response": frozenset({"actual_reply"}),
    "model_analysis": frozenset({"model_analysis"}),
    "counselor_reflection": frozenset({"counselor_reflection"}),
}


class SharedCaseCandidateBuild(StrictModel):
    """Shared-safe result; raw private source text is intentionally absent."""

    candidate: SharedCaseCandidate
    scans: tuple[DeidentificationScan, ...]
    transforms: tuple[DeidentificationTransform, ...]

    @model_validator(mode="after")
    def _validate_result(self) -> "SharedCaseCandidateBuild":
        if len(self.scans) != len(self.candidate.sections):
            raise ValueError("candidate build requires one scan per section")
        if len(self.transforms) != len(self.candidate.sections):
            raise ValueError("candidate build requires one transform per section")
        for section, scan, transform in zip(
            self.candidate.sections, self.scans, self.transforms, strict=True
        ):
            if scan.input_sha256 != transform.input_sha256:
                raise ValueError("candidate scan and transform input mismatch")
            if section.text_sha256 != transform.output_sha256:
                raise ValueError("candidate section is not the exact deidentified output")
        return self


def _normalized_overlap_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(
        character
        for character in normalized
        if unicodedata.category(character)[0] in {"L", "M", "N"}
    )


def _contains_verbatim_window(source: str, proposal: str, *, window: int) -> bool:
    source_normalized = _normalized_overlap_text(source)
    proposal_normalized = _normalized_overlap_text(proposal)
    if not source_normalized or not proposal_normalized:
        return False
    if len(proposal_normalized) < window:
        return len(proposal_normalized) >= 6 and proposal_normalized in source_normalized
    return any(
        proposal_normalized[index : index + window] in source_normalized
        for index in range(len(proposal_normalized) - window + 1)
    )


class SharedCaseCandidateBuilder:
    """Build a K1 candidate without copying source-session identifiers or speech."""

    def __init__(
        self,
        *,
        id_factory: IdFactory,
        deidentifier: Deidentifier,
        verbatim_window: int = 8,
    ) -> None:
        if not isinstance(id_factory, IdFactory):
            raise TypeError("shared case builder requires IdFactory")
        if not isinstance(deidentifier, Deidentifier):
            raise TypeError("shared case builder requires Deidentifier")
        if type(verbatim_window) is not int or verbatim_window < 8:
            raise ValueError("verbatim detection window must be an exact integer of at least 8")
        self._ids = id_factory
        self._deidentifier = deidentifier
        self._verbatim_window = verbatim_window

    def build(
        self,
        source: PrivateActualCaseRecord,
        proposals: Iterable[SharedCaseSectionProposal],
        *,
        contributor_client_hash: Sha256Hex,
        provenance_ref: VersionRef,
        derivation_rule_ref: VersionRef,
        requested_allowed_uses: frozenset[str],
        created_at: UtcDateTime,
        actual_transcript: ActualTranscript | None = None,
    ) -> SharedCaseCandidateBuild:
        source_record = PrivateActualCaseRecord.model_validate(source)
        if actual_transcript is None:
            raise ValueError("shared case build requires exact ActualTranscript authority")
        transcript = ActualTranscript.model_validate(actual_transcript)
        self._assert_actual_transcript_authority(source_record, transcript)
        values = tuple(SharedCaseSectionProposal.model_validate(item) for item in proposals)
        if not values:
            raise ValueError("shared case candidate requires section proposals")

        sources_by_key = {
            version_ref_key(item.source_ref): item for item in source_record.items
        }
        sections: list[SharedCaseSection] = []
        scans: list[DeidentificationScan] = []
        transforms: list[DeidentificationTransform] = []
        for proposal in values:
            section_sources = self._resolve_sources(proposal, sources_by_key)
            self._assert_abstraction(proposal, section_sources)
            scan = self._deidentifier.scan(proposal.abstracted_text)
            transform = self._deidentifier.transform(proposal.abstracted_text, scan)
            source_hashes = tuple(
                sorted(
                    self._deidentifier.private_value_hmac(
                        item.source_ref.model_dump_json(), domain="case_source_item"
                    )
                    for item in section_sources
                )
            )
            sections.append(
                SharedCaseSection(
                    section_id=self._ids.object_id("shared_case_section"),
                    section_kind=proposal.section_kind,
                    text=transform.output_text,
                    text_sha256=transform.output_sha256,
                    source_item_hmacs=source_hashes,
                    deidentification_output_sha256=transform.output_sha256,
                )
            )
            scans.append(scan)
            transforms.append(transform)

        report_payload = {
            "scans": [item.model_dump(mode="json") for item in scans],
            "transforms": [
                {
                    "applied_finding_hashes": list(item.applied_finding_hashes),
                    "input_sha256": item.input_sha256,
                    "output_sha256": item.output_sha256,
                    "rule_version": item.rule_version,
                    "unresolved_rare_combination_hashes": list(
                        item.unresolved_rare_combination_hashes
                    ),
                }
                for item in transforms
            ],
        }
        deidentification = DeidentificationSummary(
            report_sha256=canonical_sha256(report_payload),
            scanned_section_count=len(scans),
            transformed_section_count=len(transforms),
            finding_count=sum(len(item.findings) for item in scans),
            unresolved_rare_combination_count=sum(
                len(item.rare_combinations) for item in scans
            ),
            automatic_scan_complete=all(item.complete for item in scans),
        )
        provenance = CandidateProvenanceSummary(
            provenance_ref=provenance_ref,
            contributor_client_hashes=frozenset({contributor_client_hash}),
            independent_source_count=0,
            derivation_rule_ref=derivation_rule_ref,
        )
        candidate_id = self._ids.object_id("shared_case_candidate")
        version = 1
        candidate_sha256 = canonical_sha256(
            shared_case_candidate_payload(
                candidate_id=candidate_id,
                version=version,
                source_record_sha256=source_record.record_ref.content_sha256,
                actual_transcript_sha256=(
                    source_record.actual_transcript_ref.content_sha256
                ),
                sections=tuple(sections),
                deidentification=deidentification,
                provenance=provenance,
                requested_allowed_uses=requested_allowed_uses,
                incomplete_evidence=source_record.incomplete_evidence,
                created_at=created_at,
            )
        )
        candidate = SharedCaseCandidate(
            candidate_ref=VersionRef(
                object_id=candidate_id,
                version=version,
                content_sha256=candidate_sha256,
            ),
            source_record_sha256=source_record.record_ref.content_sha256,
            actual_transcript_sha256=(
                source_record.actual_transcript_ref.content_sha256
            ),
            sections=tuple(sections),
            deidentification=deidentification,
            provenance=provenance,
            requested_allowed_uses=requested_allowed_uses,
            incomplete_evidence=source_record.incomplete_evidence,
            candidate_sha256=candidate_sha256,
            created_at=created_at,
        )
        return SharedCaseCandidateBuild(
            candidate=candidate,
            scans=tuple(scans),
            transforms=tuple(transforms),
        )

    @staticmethod
    def _assert_actual_transcript_authority(
        source: PrivateActualCaseRecord,
        transcript: ActualTranscript,
    ) -> None:
        if source.actual_transcript_ref != transcript.actual_transcript_ref:
            raise ValueError(
                "private actual record does not bind the exact ActualTranscript reference"
            )
        if source.incomplete_evidence != transcript.incomplete_evidence:
            raise ValueError(
                "private actual record incomplete state differs from ActualTranscript"
            )

        expected: dict[tuple[str, int, str], tuple[str, str]] = {}
        for turn in transcript.turns:
            message_key = version_ref_key(turn.client_message_ref)
            if message_key in expected:
                raise ValueError("ActualTranscript repeats an exact message reference")
            expected[message_key] = ("client_message", turn.client_message_text)
            if turn.reply_text is not None:
                if turn.actual_reply_ref is None:
                    raise ValueError("ActualTranscript reply text lacks an exact reference")
                reply_key = version_ref_key(turn.actual_reply_ref)
                if reply_key in expected:
                    raise ValueError("ActualTranscript repeats an exact reply reference")
                expected[reply_key] = ("actual_reply", turn.reply_text)

        actual_items = tuple(
            item
            for item in source.items
            if item.source_kind in {"client_message", "actual_reply"}
        )
        actual_by_key = {
            version_ref_key(item.source_ref): item for item in actual_items
        }
        if set(actual_by_key) != set(expected):
            raise ValueError(
                "private actual record does not exactly match ActualTranscript"
            )
        for key, (expected_kind, expected_text) in expected.items():
            item = actual_by_key[key]
            if item.source_kind != expected_kind or item.content != expected_text:
                raise ValueError(
                    "private actual record does not exactly match ActualTranscript"
                )

    @staticmethod
    def _resolve_sources(
        proposal: SharedCaseSectionProposal,
        sources_by_key: dict[tuple[str, int, str], PrivateCaseSourceItem],
    ) -> tuple[PrivateCaseSourceItem, ...]:
        try:
            sources = tuple(
                sources_by_key[version_ref_key(reference)]
                for reference in proposal.source_item_refs
            )
        except KeyError as exc:
            raise ValueError("shared section references material outside the actual record") from exc
        allowed_kinds = _SOURCE_KINDS_BY_SECTION[proposal.section_kind]
        if any(item.source_kind not in allowed_kinds for item in sources):
            raise ValueError("shared section crosses the actual/analysis/reflection boundary")
        if proposal.section_kind == "actual_response" and any(
            not item.actual_recorded or not item.selected_for_delivery for item in sources
        ):
            raise ValueError("shared actual response must use an adopted or edited reply")
        return sources

    def _assert_abstraction(
        self,
        proposal: SharedCaseSectionProposal,
        sources: tuple[PrivateCaseSourceItem, ...],
    ) -> None:
        for source in sources:
            if _contains_verbatim_window(
                source.content,
                proposal.abstracted_text,
                window=self._verbatim_window,
            ):
                raise ValueError("shared case proposal contains a verbatim source window")
        if text_sha256(proposal.abstracted_text) in {
            item.source_ref.content_sha256 for item in sources
        }:
            raise ValueError("shared case proposal must not copy the source body")


__all__ = ["SharedCaseCandidateBuild", "SharedCaseCandidateBuilder"]
