"""Paired local evaluation runner with strict variant-isolation checks.

This runner never invokes a model or the OpenAI API.  ``prepare`` writes a
body-free queue, a Codex-hosted evaluator (or a local test double) executes the
existing stage contract, and ``submit`` validates an exact ``FinalTurnBundle``
plus its no-body run manifest before persisting only governed references.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Protocol

from consultation_kb.generation.contracts import (
    ClientReplyCandidate,
    CounselorInternalAnalysis,
    EvidenceQualitySummary,
    FinalTurnBundle,
    FollowUpGuidance,
)
from consultation_kb.knowledge._canonical import canonical_sha256
from consultation_kb.models.common import SafePolicyKey, VersionRef
from consultation_kb.models.evaluation import (
    EvaluationCase,
    EvaluationDatasetBundle,
)
from consultation_kb.models.generation import GenerationStageEnvelope
from consultation_kb.observability.runs import (
    EvidenceCandidateClosure,
    EvidencePackClosureV2,
    GovernedObjectRef,
    RunFilterCounts,
    RunLineage,
    RunManifestV2,
    RunRouteSnapshot,
    RunVersionSnapshot,
)

from .variants import (
    ALL_EVIDENCE_CHANNELS,
    ALL_SYSTEM_VARIANTS,
    SystemVariant,
    SystemVariantName,
)
from .work_queue import (
    ChannelUsageCount,
    EvaluationCaseBinding,
    EvaluationExecutionTrace,
    EvaluationFairnessContract,
    EvaluationFinalSummary,
    EvaluationRunPlan,
    EvaluationStageResult,
    EvaluationSubmission,
    EvaluationWorkItem,
    EvaluationWorkQueue,
    MissingEvaluationItem,
    RoutedEvidenceUse,
    VariantCompletion,
    VariantRoutePolicy,
)


class EvaluationValidationError(ValueError):
    """Raised when a submitted result violates the frozen experiment."""


class IncompleteEvaluationError(EvaluationValidationError):
    """Raised when finalize has neither complete results nor exact reasons."""


class StageRunner(Protocol):
    """Optional executor contract; production Codex submission is out-of-process."""

    def run(
        self,
        *,
        case: EvaluationCase,
        item: EvaluationWorkItem,
        variant: SystemVariant,
        fairness: EvaluationFairnessContract,
    ) -> EvaluationStageResult: ...


StageResultFactory = Callable[
    [EvaluationCase, EvaluationWorkItem, SystemVariant, EvaluationFairnessContract],
    EvaluationStageResult,
]


def _ref_key(reference: VersionRef) -> tuple[str, int, str]:
    return reference.object_id, reference.version, reference.content_sha256


def _uuid7_from_key(key: str) -> str:
    raw = bytearray(hashlib.sha256(key.encode("utf-8", errors="strict")).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _derived_ref(
    kind: str, key: str, *, content_sha256: str | None = None
) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_{_uuid7_from_key(f'{kind}:{key}')}",
        version=1,
        content_sha256=content_sha256
        or hashlib.sha256(key.encode("utf-8")).hexdigest(),
    )


def _governed(kind: str, key: str, content_sha256: str) -> GovernedObjectRef:
    return GovernedObjectRef(
        object_id=f"{kind}_{_uuid7_from_key(f'{kind}:{key}')}",
        content_sha256=content_sha256,
    )


def _case_catalog_sha256(case: EvaluationCase) -> str:
    return canonical_sha256(
        [reference.model_dump(mode="json") for reference in case.referenced_objects()]
    )


def _evaluation_scope_sha256(item: EvaluationWorkItem) -> str:
    return canonical_sha256(
        {
            "evaluation_run_id": item.evaluation_run_id,
            "case_id": item.case_id,
        }
    )


class DeterministicFakeStageRunner:
    """Offline deterministic StageRunner used by unit and integration tests.

    A caller may inject a factory for targeted negative cases.  Without one,
    the fake emits a fully valid synthetic ``FinalTurnBundle`` and V2 run
    manifest derived solely from the frozen work item and fairness contract.
    """

    def __init__(self, factory: StageResultFactory | None = None) -> None:
        self._factory = factory
        self.calls: list[str] = []

    def run(
        self,
        *,
        case: EvaluationCase,
        item: EvaluationWorkItem,
        variant: SystemVariant,
        fairness: EvaluationFairnessContract,
    ) -> EvaluationStageResult:
        self.calls.append(item.work_item_id)
        if self._factory is not None:
            return self._factory(case, item, variant, fairness)
        return self._build_result(case, item, variant, fairness)

    @staticmethod
    def _build_result(
        case: EvaluationCase,
        item: EvaluationWorkItem,
        variant: SystemVariant,
        fairness: EvaluationFairnessContract,
    ) -> EvaluationStageResult:
        source_refs = tuple(
            sorted(
                (*case.critical_evidence_refs, *case.alternative_evidence_refs),
                key=_ref_key,
            )
        )
        evidence_uses = tuple(
            RoutedEvidenceUse(
                channel=channel,
                evidence_ref=source_refs[index % len(source_refs)],
            )
            for index, channel in enumerate(variant.features.routes)
        )
        counts = Counter(item.channel for item in evidence_uses)
        c1_refs = (
            (tuple(sorted(case.critical_evidence_refs, key=_ref_key))[:1])
            if variant.features.c1_mode != "disabled"
            else ()
        )
        evidence_ids = tuple(
            sorted(
                {evidence.evidence_ref.object_id for evidence in evidence_uses}
                | {reference.object_id for reference in c1_refs}
            )
        )

        run_id = _uuid7_from_key(f"run:{item.work_item_id}")
        turn_id = _uuid7_from_key(f"turn:{item.work_item_id}")
        evidence_pack_sha256 = canonical_sha256(
            {
                "work_item_id": item.work_item_id,
                "evidence_uses": [
                    evidence.model_dump(mode="json") for evidence in evidence_uses
                ],
                "c1_evidence_refs": [
                    reference.model_dump(mode="json") for reference in c1_refs
                ],
            }
        )
        created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        envelope = GenerationStageEnvelope(
            stage="final_bundle",
            turn_id=turn_id,
            run_id=run_id,
            parent_sha256s=(evidence_pack_sha256,),
            created_at=created_at,
        )
        limited = not evidence_ids
        final_bundle = FinalTurnBundle(
            envelope=envelope,
            evidence_pack_sha256=evidence_pack_sha256,
            counselor_internal=CounselorInternalAnalysis(
                summary="合成评估的内部分析已按固定证据边界生成。",
                key_fact_ids=evidence_ids,
                hypotheses=(),
                conflicts=(),
                uncertainty=("当前输出仅用于合成评估。",) if limited else (),
                evidence_ids=evidence_ids,
                risk_observations=(),
            ),
            client_reply_candidates=(
                ClientReplyCandidate(
                    candidate_id="candidate_primary",
                    label="候选一",
                    strategy="exploratory_guidance",
                    text="我理解这件事让你很为难，我们可以先澄清你最看重的选择。",
                    core_positions=("preserve_agency",),
                    action_directions=("clarify_priority",),
                ),
                ClientReplyCandidate(
                    candidate_id="candidate_secondary",
                    label="候选二",
                    strategy="gentle_empathy",
                    text="你不必立刻得出结论，可以先观察一个具体情境再决定下一步。",
                    core_positions=("preserve_agency",),
                    action_directions=("observe_context",),
                ),
            ),
            follow_up_guidance=FollowUpGuidance(
                suggested_questions=("此刻你最希望先改变哪一点？",),
                optional_actions=("记录一次具体情境。",),
                observation_focus=("自己的感受与边界。",),
                next_steps=("根据新信息再调整建议。",),
            ),
            evidence_quality=EvidenceQualitySummary(
                status="limited" if limited else "sufficient",
                evidence_ids=evidence_ids,
                unresolved_reasons=("该基线不使用知识检索。",) if limited else (),
                retry_count=0,
            ),
        )
        final_sha256 = canonical_sha256(final_bundle.model_dump(mode="json"))
        final_ref = _derived_ref(
            "evaluation_bundle",
            item.work_item_id,
            content_sha256=final_sha256,
        )

        candidates = tuple(
            sorted(
                (
                    EvidenceCandidateClosure(
                        candidate_ref=_derived_ref(
                            "evaluation_candidate",
                            f"{item.work_item_id}:{index}",
                        ),
                        text_ref=_derived_ref(
                            "evaluation_text",
                            f"{item.work_item_id}:{index}",
                        ),
                        locator_ref=_derived_ref(
                            "evaluation_locator",
                            f"{item.work_item_id}:{index}",
                        ),
                        freshness_policy_ref=_derived_ref(
                            "freshness_policy",
                            f"{item.work_item_id}:{index}",
                        ),
                        provenance_ref=_derived_ref(
                            "provenance_record",
                            f"{item.work_item_id}:{index}",
                        ),
                        derivation_ref=_derived_ref(
                            "derivation_record",
                            f"{item.work_item_id}:{index}",
                        ),
                    )
                    for index, _use in enumerate(evidence_uses)
                ),
                key=lambda candidate: _ref_key(candidate.candidate_ref),
            )
        )
        evidence_pack_ref = _derived_ref(
            "evaluation_evidence_pack",
            item.work_item_id,
            content_sha256=evidence_pack_sha256,
        )
        versions = RunVersionSnapshot(
            model_descriptor_ref=fairness.model_descriptor_ref,
            model_parameters_ref=fairness.model_parameters_ref,
            prompt_refs=fairness.prompt_refs,
            skill_refs=fairness.skill_refs,
            client_snapshot_ref=item.client_snapshot_ref,
            wiki_manifest_ref=fairness.wiki_manifest_ref,
            case_manifest_ref=fairness.case_manifest_ref,
            graph_manifest_ref=fairness.graph_manifest_ref,
            lexical_manifest_ref=fairness.lexical_manifest_ref,
            vector_manifest_ref=fairness.vector_manifest_ref,
            reranker_descriptor_ref=fairness.reranker_descriptor_ref,
        )
        manifest = RunManifestV2(
            run_id=run_id,
            run_kind="evaluation",
            scope_sha256=_evaluation_scope_sha256(item),
            started_at=created_at,
            completed_at=created_at,
            lineage=RunLineage(
                root_run_id=run_id,
                parent_run_id=None,
                phase="evaluation",
                sequence=0,
                turn_ref=_governed(
                    "evaluation_turn", item.work_item_id, item.work_item_id
                ),
            ),
            versions=versions,
            evidence=EvidencePackClosureV2(
                evidence_pack_ref=evidence_pack_ref,
                evidence_pack_canonical_sha256=evidence_pack_sha256,
                authority_snapshot_ref=fairness.authority_snapshot_ref,
                authority_policy_ref=fairness.authority_policy_ref,
                client_snapshot_ref=item.client_snapshot_ref,
                temporary_fact_refs=(),
                candidates=candidates,
                c1_revision_ref=(
                    fairness.c1_revision_ref
                    if variant.features.c1_mode != "disabled"
                    else None
                ),
                c1_scope_policy_ref=fairness.c1_scope_policy_ref,
                c1_applicability_ref=fairness.c1_applicability_ref,
                unresolved_conflict_refs=(),
                exclusion_proof_ref=fairness.exclusion_proof_ref,
                wiki_manifest_ref=fairness.wiki_manifest_ref,
                lexical_manifest_ref=fairness.lexical_manifest_ref,
                vector_manifest_ref=fairness.vector_manifest_ref,
                graph_manifest_ref=fairness.graph_manifest_ref,
                reranker_descriptor_ref=fairness.reranker_descriptor_ref,
            ),
            routing=RunRouteSnapshot(
                query_plan_ref=_derived_ref("evaluation_query_plan", item.work_item_id),
                route_policy_ref=item.route_policy_ref,
                routes=variant.features.routes,
                filter_counts=RunFilterCounts(
                    before=len(evidence_uses),
                    after=len(evidence_uses),
                ),
            ),
            runtime=fairness.runtime,
            reproducibility=fairness.reproducibility,
            critique_error_codes=(),
            retry_count=0,
            degraded_components=(),
            generation_candidate_refs=(),
            actual_reply_ref=None,
            consultant_edit_diff_ref=None,
            consultant_review_decision="not_applicable",
            consultant_review_ref=None,
            archive_draft_ref=None,
            archive_decision="not_applicable",
            archive_decision_ref=None,
            result_sha256=final_sha256,
        )
        return EvaluationStageResult(
            final_bundle=final_bundle,
            final_bundle_ref=final_ref,
            run_manifest=manifest,
            evidence_uses=evidence_uses,
            trace=EvaluationExecutionTrace(
                channel_counts=tuple(
                    ChannelUsageCount(channel=channel, count=counts[channel])
                    for channel in ALL_EVIDENCE_CHANNELS
                ),
                c1_mode=variant.features.c1_mode,
                c1_evidence_refs=c1_refs,
                graph_navigation_count=sum(
                    counts[channel] for channel in ("client_history", "global_graph")
                ),
                reranker_application_count=(
                    1 if variant.features.reranker and evidence_uses else 0
                ),
                critique_stage_count=2,
                configured_retry_budget=fairness.retry_budget,
                model_label=fairness.model_label,
                reasoning_effort=fairness.reasoning_effort,
                schema_ref=fairness.schema_ref,
                reply_contract_ref=fairness.reply_contract_ref,
            ),
        )


class EvaluationRunner:
    """Prepare, validate, and finalize one durable paired evaluation queue."""

    def __init__(
        self,
        queue: EvaluationWorkQueue,
        *,
        stage_runner: StageRunner | None = None,
    ) -> None:
        if type(queue) is not EvaluationWorkQueue:
            raise TypeError("evaluation runner requires EvaluationWorkQueue")
        self._queue = queue
        self._stage_runner = stage_runner
        self._cases: dict[str, EvaluationCase] = {}

    def prepare(
        self,
        *,
        bundle: EvaluationDatasetBundle,
        fairness: EvaluationFairnessContract,
        evaluation_run_id: str,
        route_policy_refs: Mapping[SystemVariantName, VersionRef],
        variants: Sequence[SystemVariant] = ALL_SYSTEM_VARIANTS,
        repetition_count: int = 2,
        queue_order_seed: int | None = None,
        case_ids: Sequence[str] | None = None,
        include_canary: bool = False,
    ) -> EvaluationRunPlan:
        """Freeze a paired queue; no case turn or generated text is serialized."""

        selected_variants = tuple(variants)
        selected_names = tuple(variant.name for variant in selected_variants)
        if len(selected_names) != len(set(selected_names)):
            raise EvaluationValidationError("selected variants must be unique")
        if set(route_policy_refs) != set(selected_names):
            raise EvaluationValidationError(
                "route policy refs must exactly cover selected variants"
            )
        seed = (
            fairness.reproducibility.queue_order_seed
            if queue_order_seed is None
            else queue_order_seed
        )
        if seed != fairness.reproducibility.queue_order_seed:
            raise EvaluationValidationError(
                "queue order seed must equal the frozen fairness contract"
            )

        if case_ids is None:
            requested: set[str] | None = None
        else:
            requested = set(case_ids)
            if len(requested) != len(case_ids):
                raise EvaluationValidationError("requested case IDs must be unique")
        datasets_by_id = {
            dataset.manifest.dataset_id: dataset for dataset in bundle.datasets
        }
        selected_cases = tuple(
            case
            for dataset in bundle.datasets
            for case in dataset.cases
            if (include_canary or case.split != "canary")
            and (requested is None or case.case_id in requested)
        )
        if not selected_cases:
            raise EvaluationValidationError("evaluation run has no selected cases")
        selected_case_ids = {case.case_id for case in selected_cases}
        if requested is not None and selected_case_ids != requested:
            raise EvaluationValidationError(
                "requested case ID is absent from the bundle"
            )

        bindings = tuple(
            EvaluationCaseBinding(
                dataset_id=case.dataset_id,
                dataset_file_sha256=datasets_by_id[case.dataset_id].file_sha256,
                dataset_records_sha256=(
                    datasets_by_id[case.dataset_id].manifest.records_sha256
                ),
                case_id=case.case_id,
                split=case.split,
                client_snapshot_ref=case.synthetic_client_snapshot_ref,
                evidence_catalog_sha256=_case_catalog_sha256(case),
            )
            for case in selected_cases
        )
        route_policies = tuple(
            VariantRoutePolicy(
                variant_name=variant.name,
                route_policy_ref=route_policy_refs[variant.name],
            )
            for variant in selected_variants
        )

        rng = random.Random(seed)
        groups = [
            (case, repetition)
            for repetition in range(repetition_count)
            for case in selected_cases
        ]
        rng.shuffle(groups)
        item_inputs: list[tuple[EvaluationCase, int, SystemVariant]] = []
        for case, repetition in groups:
            randomized_variants = list(selected_variants)
            rng.shuffle(randomized_variants)
            item_inputs.extend(
                (case, repetition, variant) for variant in randomized_variants
            )

        fairness_sha256 = fairness.canonical_sha256
        bindings_by_case = {binding.case_id: binding for binding in bindings}
        items: list[EvaluationWorkItem] = []
        for queue_index, (case, repetition, variant) in enumerate(item_inputs):
            binding = bindings_by_case[case.case_id]
            identity = canonical_sha256(
                {
                    "evaluation_run_id": evaluation_run_id,
                    "case_id": case.case_id,
                    "variant_name": variant.name,
                    "repetition_index": repetition,
                    "fairness_sha256": fairness_sha256,
                    "route_policy_ref": route_policy_refs[variant.name].model_dump(
                        mode="json"
                    ),
                }
            )
            items.append(
                EvaluationWorkItem(
                    work_item_id=identity,
                    evaluation_run_id=evaluation_run_id,
                    queue_index=queue_index,
                    dataset_id=binding.dataset_id,
                    dataset_file_sha256=binding.dataset_file_sha256,
                    dataset_records_sha256=binding.dataset_records_sha256,
                    case_id=binding.case_id,
                    split=binding.split,
                    variant_name=variant.name,
                    variant_sha256=variant.canonical_sha256,
                    route_policy_ref=route_policy_refs[variant.name],
                    repetition_index=repetition,
                    client_snapshot_ref=binding.client_snapshot_ref,
                    evidence_catalog_sha256=binding.evidence_catalog_sha256,
                    fairness_sha256=fairness_sha256,
                )
            )
        frozen_items = tuple(items)
        plan = EvaluationRunPlan(
            evaluation_run_id=evaluation_run_id,
            dataset_bundle_sha256=bundle.bundle_sha256,
            cases=bindings,
            variants=selected_variants,
            route_policies=route_policies,
            repetition_count=repetition_count,
            queue_order_seed=seed,
            fairness=fairness,
            expected_item_count=len(frozen_items),
            queue_sha256=canonical_sha256(
                [item.model_dump(mode="json") for item in frozen_items]
            ),
        )
        self._queue.initialize(plan, frozen_items)
        self._cases = {case.case_id: case for case in selected_cases}
        return plan

    def bind_dataset(self, bundle: EvaluationDatasetBundle) -> None:
        """Rebind case bodies after restart while verifying the frozen bundle."""

        plan = self._queue.load_plan()
        if bundle.bundle_sha256 != plan.dataset_bundle_sha256:
            raise EvaluationValidationError(
                "dataset bundle differs from frozen run plan"
            )
        available = {
            case.case_id: case for dataset in bundle.datasets for case in dataset.cases
        }
        bound: dict[str, EvaluationCase] = {}
        for binding in plan.cases:
            case = available.get(binding.case_id)
            if case is None:
                raise EvaluationValidationError("frozen evaluation case is unavailable")
            dataset = next(
                item
                for item in bundle.datasets
                if item.manifest.dataset_id == case.dataset_id
            )
            if (
                case.synthetic_client_snapshot_ref != binding.client_snapshot_ref
                or dataset.file_sha256 != binding.dataset_file_sha256
                or dataset.manifest.records_sha256 != binding.dataset_records_sha256
                or _case_catalog_sha256(case) != binding.evidence_catalog_sha256
            ):
                raise EvaluationValidationError(
                    "evaluation case differs from its frozen queue binding"
                )
            bound[case.case_id] = case
        self._cases = bound

    def run_pending(
        self, *, limit: int | None = None
    ) -> tuple[EvaluationSubmission, ...]:
        """Execute pending work only through the injected local/fake StageRunner."""

        if self._stage_runner is None:
            raise EvaluationValidationError(
                "no local StageRunner is configured; submit Codex results explicitly"
            )
        if not self._cases:
            raise EvaluationValidationError(
                "evaluation dataset must be bound before execution"
            )
        if limit is not None and limit < 1:
            raise EvaluationValidationError("pending-run limit must be positive")
        plan = self._queue.load_plan()
        completed = {
            submission.work_item_id for submission in self._queue.load_submissions()
        }
        variants = {variant.name: variant for variant in plan.variants}
        accepted: list[EvaluationSubmission] = []
        for item in self._queue.load_items():
            if item.work_item_id in completed:
                continue
            result = self._stage_runner.run(
                case=self._cases[item.case_id],
                item=item,
                variant=variants[item.variant_name],
                fairness=plan.fairness,
            )
            accepted.append(self.submit(work_item_id=item.work_item_id, result=result))
            if limit is not None and len(accepted) >= limit:
                break
        return tuple(accepted)

    def submit(
        self,
        *,
        work_item_id: str,
        result: EvaluationStageResult,
    ) -> EvaluationSubmission:
        """Validate one exact bundle and persist its no-body projection."""

        validated = EvaluationStageResult.model_validate(result)
        plan = self._queue.load_plan()
        item = next(
            (
                candidate
                for candidate in self._queue.load_items()
                if candidate.work_item_id == work_item_id
            ),
            None,
        )
        if item is None:
            raise EvaluationValidationError("evaluation work item is unknown")
        case = self._cases.get(item.case_id)
        if case is None:
            raise EvaluationValidationError("evaluation case body is not bound")
        variant = next(
            candidate
            for candidate in plan.variants
            if candidate.name == item.variant_name
        )
        self._validate_result(
            plan=plan,
            item=item,
            case=case,
            variant=variant,
            result=validated,
        )
        final_sha256 = validated.final_bundle_ref.content_sha256
        submission = EvaluationSubmission(
            work_item_id=item.work_item_id,
            evaluation_run_id=item.evaluation_run_id,
            case_id=item.case_id,
            variant_name=item.variant_name,
            repetition_index=item.repetition_index,
            final_bundle_ref=validated.final_bundle_ref,
            final_bundle_sha256=final_sha256,
            run_manifest=validated.run_manifest,
            evidence_uses=validated.evidence_uses,
            trace=validated.trace,
        )
        return self._queue.append_submission(submission)

    def finalize(
        self,
        *,
        missing_reasons: Mapping[str, SafePolicyKey] | None = None,
    ) -> EvaluationFinalSummary:
        """Emit JSON/Markdown only for a complete queue or exact missing reasons."""

        plan = self._queue.load_plan()
        items = self._queue.load_items()
        submissions = self._queue.load_submissions()
        completed_ids = {submission.work_item_id for submission in submissions}
        missing_items = tuple(
            item for item in items if item.work_item_id not in completed_ids
        )
        reasons = dict(missing_reasons or {})
        missing_ids = {item.work_item_id for item in missing_items}
        if missing_ids and set(reasons) != missing_ids:
            raise IncompleteEvaluationError(
                "incomplete queue requires one explicit reason for every missing item"
            )
        if not missing_ids and reasons:
            raise EvaluationValidationError(
                "complete queue must not declare missing-item reasons"
            )
        missing = tuple(
            MissingEvaluationItem(
                work_item_id=work_item_id,
                reason_code=reasons[work_item_id],
            )
            for work_item_id in sorted(missing_ids)
        )
        completed_by_variant = Counter(
            submission.variant_name for submission in submissions
        )
        missing_by_variant = Counter(item.variant_name for item in missing_items)
        expected_per_variant = len(plan.cases) * plan.repetition_count
        variants = tuple(
            VariantCompletion(
                variant_name=variant.name,
                expected_count=expected_per_variant,
                completed_count=completed_by_variant[variant.name],
                missing_count=missing_by_variant[variant.name],
            )
            for variant in plan.variants
        )
        summary = EvaluationFinalSummary(
            evaluation_run_id=plan.evaluation_run_id,
            plan_sha256=plan.canonical_sha256,
            queue_sha256=plan.queue_sha256,
            submissions_sha256=canonical_sha256(
                [submission.model_dump(mode="json") for submission in submissions]
            ),
            status="succeeded" if not missing else "incomplete",
            expected_count=plan.expected_item_count,
            completed_count=len(submissions),
            missing=missing,
            variants=variants,
        )
        self._queue.write_reports(summary)
        return summary

    @staticmethod
    def _validate_result(
        *,
        plan: EvaluationRunPlan,
        item: EvaluationWorkItem,
        case: EvaluationCase,
        variant: SystemVariant,
        result: EvaluationStageResult,
    ) -> None:
        fairness = plan.fairness
        manifest = result.run_manifest
        expected_versions = RunVersionSnapshot(
            model_descriptor_ref=fairness.model_descriptor_ref,
            model_parameters_ref=fairness.model_parameters_ref,
            prompt_refs=fairness.prompt_refs,
            skill_refs=fairness.skill_refs,
            client_snapshot_ref=item.client_snapshot_ref,
            wiki_manifest_ref=fairness.wiki_manifest_ref,
            case_manifest_ref=fairness.case_manifest_ref,
            graph_manifest_ref=fairness.graph_manifest_ref,
            lexical_manifest_ref=fairness.lexical_manifest_ref,
            vector_manifest_ref=fairness.vector_manifest_ref,
            reranker_descriptor_ref=fairness.reranker_descriptor_ref,
        )
        expected_c1_ref = (
            None if variant.features.c1_mode == "disabled" else fairness.c1_revision_ref
        )
        fixed_manifest_fields = (
            manifest.run_kind == "evaluation",
            manifest.lineage.phase == "evaluation",
            manifest.lineage.parent_run_id is None,
            manifest.scope_sha256 == _evaluation_scope_sha256(item),
            manifest.versions == expected_versions,
            manifest.runtime == fairness.runtime,
            manifest.reproducibility == fairness.reproducibility,
            manifest.routing.routes == variant.features.routes,
            manifest.routing.route_policy_ref == item.route_policy_ref,
            manifest.evidence.client_snapshot_ref == item.client_snapshot_ref,
            manifest.evidence.authority_snapshot_ref == fairness.authority_snapshot_ref,
            manifest.evidence.authority_policy_ref == fairness.authority_policy_ref,
            manifest.evidence.c1_revision_ref == expected_c1_ref,
            manifest.evidence.c1_scope_policy_ref == fairness.c1_scope_policy_ref,
            manifest.evidence.c1_applicability_ref == fairness.c1_applicability_ref,
            manifest.evidence.exclusion_proof_ref == fairness.exclusion_proof_ref,
            manifest.retry_count <= fairness.retry_budget,
        )
        if not all(fixed_manifest_fields):
            raise EvaluationValidationError(
                "run manifest violates frozen fairness, snapshot, or variant fields"
            )

        trace = result.trace
        if (
            trace.model_label != fairness.model_label
            or trace.reasoning_effort != fairness.reasoning_effort
            or trace.schema_ref != fairness.schema_ref
            or trace.reply_contract_ref != fairness.reply_contract_ref
            or trace.configured_retry_budget != fairness.retry_budget
            or trace.c1_mode != variant.features.c1_mode
        ):
            raise EvaluationValidationError(
                "execution trace changes a paired fairness field"
            )

        counts = {item.channel: item.count for item in trace.channel_counts}
        observed = Counter(use.channel for use in result.evidence_uses)
        if any(
            counts[channel] != observed[channel] for channel in ALL_EVIDENCE_CHANNELS
        ):
            raise EvaluationValidationError(
                "channel counts do not match routed evidence"
            )
        if any(counts[channel] != 0 for channel in variant.features.prohibited_routes):
            raise EvaluationValidationError(
                "prohibited variant channel carried evidence"
            )
        if len(manifest.evidence.candidates) != len(result.evidence_uses):
            raise EvaluationValidationError(
                "run manifest candidate closure differs from routed evidence"
            )
        if not variant.features.graphify_navigation and trace.graph_navigation_count:
            raise EvaluationValidationError(
                "Graphify navigation occurred in an ablation"
            )
        if trace.graph_navigation_count > (
            counts["client_history"] + counts["global_graph"]
        ):
            raise EvaluationValidationError(
                "Graphify navigation count exceeds graph-routed evidence"
            )
        if not variant.features.reranker and trace.reranker_application_count:
            raise EvaluationValidationError("reranker ran in the reranker ablation")
        if not variant.features.multi_stage_critique and trace.critique_stage_count:
            raise EvaluationValidationError("critique ran when disabled")
        if variant.features.multi_stage_critique and trace.critique_stage_count == 0:
            raise EvaluationValidationError("paired multi-stage critique was omitted")
        if variant.features.c1_mode == "disabled" and trace.c1_evidence_refs:
            raise EvaluationValidationError(
                "C1 evidence leaked into a disabled baseline"
            )

        allowed_refs = {
            _ref_key(reference)
            for reference in (
                *case.critical_evidence_refs,
                *case.alternative_evidence_refs,
            )
        }
        forbidden_refs = {
            _ref_key(reference) for reference in case.forbidden_source_refs
        }
        used_refs = {_ref_key(use.evidence_ref) for use in result.evidence_uses} | {
            _ref_key(reference) for reference in trace.c1_evidence_refs
        }
        if used_refs - allowed_refs or used_refs & forbidden_refs:
            raise EvaluationValidationError(
                "submission used evidence outside the frozen case catalog"
            )
        if _case_catalog_sha256(case) != item.evidence_catalog_sha256:
            raise EvaluationValidationError(
                "case evidence catalog changed after prepare"
            )

        allowed_ids = {reference[0] for reference in used_refs}
        bundle_ids = set(result.final_bundle.counselor_internal.evidence_ids) | set(
            result.final_bundle.evidence_quality.evidence_ids
        )
        if not bundle_ids <= allowed_ids:
            raise EvaluationValidationError(
                "final bundle cites evidence absent from the routed result"
            )


__all__ = [
    "DeterministicFakeStageRunner",
    "EvaluationRunPlan",
    "EvaluationRunner",
    "EvaluationValidationError",
    "IncompleteEvaluationError",
    "StageResultFactory",
    "StageRunner",
]
