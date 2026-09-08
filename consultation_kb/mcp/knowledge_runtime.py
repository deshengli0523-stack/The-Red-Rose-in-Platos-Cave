"""Production adapter for the governed global-knowledge MCP tools.

The adapter deliberately has no caller-selected filesystem API.  Source
handles are minted only for regular files discovered below the one fixed
``<vault>/global/inbox`` directory.  Draft-producing calls delegate to the P3
knowledge services; authority-changing calls consume P1 approval requests.

Passage and Wiki proposal operations delegate to the real P3 services.  Wiki
activation remains separate: a prepared revision is never reported as active
until the complete P4 derived-artifact publication closure has been verified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import tempfile
import threading
from pathlib import Path, PurePosixPath
from typing import Final, Literal, final

from pydantic import BaseModel, ValidationError

from consultation_kb.approvals.models import ApprovalRequest, descriptor_sha256
from consultation_kb.approvals.execution import ApprovalExecutionGuard
from consultation_kb.approvals.provider import ApprovalSigner
from consultation_kb.approvals.review_agent import (
    ReviewAgent,
    VerifiedReviewDiff,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.clock import Clock, SystemClock
from consultation_kb.core.config import AppConfig
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.approval import GovernedWriteExecutor
from consultation_kb.knowledge.anchors import deterministic_object_id
from consultation_kb.knowledge.claims import ClaimProposal, ClaimProposalService
from consultation_kb.knowledge.extractors import DocumentExtractor
from consultation_kb.knowledge.lint import KnowledgeLinter
from consultation_kb.knowledge.passages import PassageCatalog, PassageSegmenter
from consultation_kb.knowledge.proposal_repository import (
    DurableKnowledgeProposal,
    KnowledgeProposalError,
    KnowledgeProposalRepository,
    ProposalKind,
)
from consultation_kb.knowledge.provenance import ProvenancePolicyManifest
from consultation_kb.knowledge.registrar import SourceRegistrar
from consultation_kb.knowledge.review import ClaimReviewResolver
from consultation_kb.knowledge.scope_policy import ScopePolicyRepository
from consultation_kb.knowledge.theory import TheoryRevisionService
from consultation_kb.knowledge.wiki import (
    WikiClaimAuthority,
    WikiGovernanceError,
    WikiProposal,
    WikiRevisionService,
)
from consultation_kb.lifecycle.publish import (
    PreparedArtifactDraft,
    PreparedContentDraft,
    PublicationIntegrityError,
)
from consultation_kb.models.common import StrictModel, VersionRef
from consultation_kb.models.evidence import EvidenceLocator, Provenance
from consultation_kb.models.knowledge import (
    ClaimDraft,
    PassageRecord,
    SourceMetadata,
    SourceRecord,
)
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.models.theory import TheoryProposal
from consultation_kb.models.wiki import WikiRevisionDraft
from consultation_kb.publication.global_knowledge import (
    GlobalKnowledgePublicationPlan,
    GlobalKnowledgePublicationPlanner,
    GlobalPublicationBuilders,
    GlobalPublicationPlanningError,
)
from consultation_kb.security.path_guard import PathGuard, ScopePathDenied
from consultation_kb.storage.connection import transaction
from consultation_kb.vault.content_store import ContentStore, ContentStoreError

from .context import BoundTransport
from .schemas import (
    ApprovalExecutionInput,
    ApproveClaimInput,
    ApprovePassageInput,
    ApproveTheoryRevisionInput,
    ClaimDraftInput,
    ExtractPassagesInput,
    KnowledgeLintInput,
    ListSourceInboxInput,
    PreviewClaimReviewInput,
    PreviewWikiUpdateInput,
    ProposeClaimsInput,
    ProposeTheoryRevisionInput,
    ProposeWikiUpdateInput,
    PublishWikiInput,
    RegisterSourceDraftInput,
    RevokeClaimInput,
    RevokeTheoryRevisionInput,
)


_SUPPORTED_DOCUMENT_TYPES: Final = frozenset(
    {"txt", "md", "pdf", "docx", "xlsx", "csv"}
)
_PUBLICATION_PLAN_SCHEMA_VERSION: Final = 1
_REPARSE_ATTRIBUTE: Final = int(
    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)
_KNOWLEDGE_TOOLS: Final = frozenset(
    {
        "list_source_inbox",
        "register_source_draft",
        "extract_passages",
        "propose_claims",
        "preview_claim_review",
        "propose_wiki_update",
        "preview_wiki_update",
        "knowledge_lint",
        "propose_theory_revision",
    }
)
_WRITE_TOOLS: Final = frozenset(
    {
        "approve_claim",
        "approve_passage",
        "revoke_claim",
        "publish_wiki",
        "approve_theory_revision",
        "revoke_theory_revision",
    }
)
_CLAIM_RULE_BYTES: Final = b"consultation-kb-global-claim-derivation-v1"
_PROVENANCE_MANIFEST_BYTES: Final = (
    b"consultation-kb-global-provenance-policy-v1"
)


class KnowledgeRuntimeError(RuntimeError):
    """Fixed-code failure at the MCP-to-domain adapter boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _is_reparse(status: os.stat_result) -> bool:
    return stat.S_ISLNK(status.st_mode) or bool(
        int(getattr(status, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    )


def _json_bytes(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class _PersistedPreparedContent(StrictModel):
    """Path-free CAS member persisted inside one exact publication review."""

    object_type: str
    object_id: str
    content_sha256: str
    media_type: str
    size_bytes: int
    source_version: int
    source_lineage_hashes: tuple[str, ...]


class _PersistedPreparedArtifact(StrictModel):
    purpose: str
    manifest_id: str
    artifact_key: str
    artifact_kind: str
    source_version: int
    members: tuple[_PersistedPreparedContent, ...]


class _PersistedGlobalPublicationPlan(StrictModel):
    """Durable, auditable representation of an already-built exact closure."""

    schema_version: Literal[1]
    operation_id: str
    descriptor: DraftDescriptor
    authority_base_version: int
    expected_current_epoch: int | None
    target_runtime_epoch: int
    wiki_ref: VersionRef
    theory_ref: VersionRef | None
    artifacts: tuple[_PersistedPreparedArtifact, ...]
    artifact_kinds: tuple[str, ...]


def _publication_plan_payload(
    plan: GlobalKnowledgePublicationPlan,
) -> dict[str, object]:
    """Serialize only stable identities and CAS metadata, never store paths."""

    if not isinstance(plan, GlobalKnowledgePublicationPlan):
        raise TypeError("global publication plan required")
    return {
        "schema_version": _PUBLICATION_PLAN_SCHEMA_VERSION,
        "operation_id": plan.operation_id,
        "descriptor": plan.descriptor.model_dump(mode="json"),
        "authority_base_version": plan.authority_base_version,
        "expected_current_epoch": plan.expected_current_epoch,
        "target_runtime_epoch": plan.target_runtime_epoch,
        "wiki_ref": plan.wiki_ref.model_dump(mode="json"),
        "theory_ref": (
            None
            if plan.theory_ref is None
            else plan.theory_ref.model_dump(mode="json")
        ),
        "artifacts": [
            {
                "purpose": artifact.purpose,
                "manifest_id": artifact.manifest_id,
                "artifact_key": artifact.artifact_key,
                "artifact_kind": artifact.artifact_kind,
                "source_version": artifact.source_version,
                "members": [
                    {
                        "object_type": member.object_type,
                        "object_id": member.object_id,
                        "content_sha256": member.reference.content_sha256,
                        "media_type": member.reference.media_type,
                        "size_bytes": member.reference.size_bytes,
                        "source_version": member.source_version,
                        "source_lineage_hashes": list(
                            member.source_lineage_hashes
                        ),
                    }
                    for member in artifact.members
                ],
            }
            for artifact in plan.artifacts
        ],
        "artifact_kinds": list(plan.artifact_kinds),
    }


def _version_ref(record: SourceRecord | PassageRecord) -> VersionRef:
    if isinstance(record, SourceRecord):
        return VersionRef(
            object_id=record.source_id,
            version=record.version,
            content_sha256=record.content_sha256,
        )
    return VersionRef(
        object_id=record.passage_id,
        version=record.version,
        content_sha256=record.normalized_text_sha256,
    )


def _ref_payload(reference: VersionRef) -> dict[str, object]:
    return {
        "object_id": reference.object_id,
        "version": reference.version,
        "content_sha256": reference.content_sha256,
    }


def _descriptor_payload(descriptor: DraftDescriptor) -> dict[str, object]:
    """Render a global descriptor without the forbidden ``client_id`` key."""

    if descriptor.client_id is not None or descriptor.session_id is not None:
        raise KnowledgeRuntimeError("GLOBAL_DESCRIPTOR_SCOPE_INVALID")
    return {
        "purpose": descriptor.purpose,
        "target_id": descriptor.target_id,
        "base_version": descriptor.base_version,
        "draft_sha256": descriptor.draft_sha256,
    }


def _read_text_content(store: ContentStore, reference: str | None) -> str | None:
    if reference is None:
        return None
    prefix = "sha256:"
    if not reference.startswith(prefix) or len(reference) != len(prefix) + 64:
        raise KnowledgeRuntimeError("PASSAGE_CONTENT_REF_INVALID")
    payload = store.read_hash_verified(reference[len(prefix) :])
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise KnowledgeRuntimeError("PASSAGE_CONTENT_ENCODING_INVALID") from None


def global_claim_derivation_rule_ref() -> VersionRef:
    """Stable code-policy identity shared by production claim services."""

    return VersionRef(
        object_id=deterministic_object_id(
            "derivation_rule",
            "global-claim-v1",
        ),
        version=1,
        content_sha256=hashlib.sha256(_CLAIM_RULE_BYTES).hexdigest(),
    )


def global_provenance_policy_manifest() -> ProvenancePolicyManifest:
    """Return the exact v1 manifest accepted by the production Claim service."""

    return ProvenancePolicyManifest(
        manifest_ref=VersionRef(
            object_id=deterministic_object_id(
                "provenance_manifest",
                "global-v1",
            ),
            version=1,
            content_sha256=hashlib.sha256(
                _PROVENANCE_MANIFEST_BYTES
            ).hexdigest(),
        ),
        rule_members=(global_claim_derivation_rule_ref(),),
    )


@final
class ApprovalDraftIssuer:
    """Persist immutable review bytes and issue/reuse exact P1 requests."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        approval_service: ApprovalService,
        content_store: ContentStore,
        id_factory: IdFactory,
        clock: Clock,
    ) -> None:
        self._connection = connection
        self._approvals = approval_service
        self._store = content_store
        self._ids = id_factory
        self._clock = clock

    def _existing(self, descriptor: DraftDescriptor) -> ApprovalRequest | None:
        digest = descriptor_sha256(descriptor)
        rows = self._connection.execute(
            """
            SELECT request_id FROM approval_requests
             WHERE descriptor_sha256 = ?
             ORDER BY created_at DESC, request_id DESC
            """,
            (digest,),
        ).fetchall()
        for row in rows:
            try:
                request = self._approvals.get(str(row[0]))
            except Exception:
                continue
            if request.descriptor != descriptor:
                continue
            if request.state == "acknowledged":
                return request
            if request.state in {"pending", "confirmed"} and (
                self._clock.now() < request.expires_at
            ):
                return request
        return None

    def issue(
        self,
        descriptor: DraftDescriptor,
        *,
        review_payload: object,
    ) -> ApprovalRequest:
        validated = DraftDescriptor.model_validate(descriptor)
        if validated.client_id is not None or validated.session_id is not None:
            raise KnowledgeRuntimeError("GLOBAL_DESCRIPTOR_SCOPE_INVALID")
        existing = self._existing(validated)
        if existing is not None:
            return existing
        diff = _json_bytes(
            {
                "descriptor": validated.model_dump(mode="json"),
                "review": (
                    review_payload.model_dump(mode="json")
                    if isinstance(review_payload, BaseModel)
                    else review_payload
                ),
            }
        )
        reference = self._store.finalize(
            self._store.stage_bytes(
                diff,
                purpose="approval_diff",
                manifest_id=self._ids.object_id("approval_diff_manifest"),
                media_type="application/json",
            )
        )
        return self._approvals.request(
            validated,
            diff_object_ref=VersionRef(
                object_id=self._ids.object_id("approval_diff"),
                version=1,
                content_sha256=reference.content_sha256,
            ),
        )

    def verified_review_diff(self, reference: VersionRef) -> VerifiedReviewDiff:
        validated = VersionRef.model_validate(reference)
        content = self._store.read_hash_verified(validated.content_sha256)
        if hashlib.sha256(content).hexdigest() != validated.content_sha256:
            raise KnowledgeRuntimeError("APPROVAL_DIFF_HASH_MISMATCH")
        return VerifiedReviewDiff(reference=validated, content=content)


@final
class GlobalKnowledgeToolRuntime:
    """Real P3/P1-backed implementation of the P5 global knowledge tools."""

    def __init__(
        self,
        *,
        config: AppConfig,
        connection: sqlite3.Connection,
        content_store: ContentStore,
        approval_service: ApprovalService,
        approval_executor: GovernedWriteExecutor,
        claim_service: ClaimProposalService,
        wiki_service: WikiRevisionService,
        theory_service: TheoryRevisionService,
        claim_derivation_rule_ref: VersionRef,
        scope_policy_repository: ScopePolicyRepository | None = None,
        id_factory: IdFactory | None = None,
        clock: Clock | None = None,
        handle_key: bytes | None = None,
        publication_planner: GlobalKnowledgePublicationPlanner | None = None,
    ) -> None:
        if type(config) is not AppConfig:
            raise TypeError("knowledge runtime requires AppConfig")
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("knowledge runtime requires sqlite3.Connection")
        if not hasattr(approval_executor, "execute"):
            raise TypeError("knowledge runtime requires governed write executor")
        key = secrets.token_bytes(32) if handle_key is None else handle_key
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("knowledge runtime handle key requires 256 bits")
        self._config = config
        self._connection = connection
        self._store = content_store
        self._approvals = approval_service
        self._ids = id_factory or IdFactory()
        self._clock = clock or SystemClock()
        self._claim_rule = VersionRef.model_validate(claim_derivation_rule_ref)
        self._claims = claim_service
        self._wikis = wiki_service
        self._theories = theory_service
        self._scope_policies = scope_policy_repository
        self._proposal_store = KnowledgeProposalRepository(
            connection,
            content_store=content_store,
            id_factory=self._ids,
            clock=self._clock,
        )
        self._inbox = config.vault_root / "global" / "inbox"
        self._scratch = config.vault_root / "global" / ".mcp-extraction"
        self._ensure_fixed_directory(self._inbox)
        self._ensure_fixed_directory(self._scratch)
        self._registrar = SourceRegistrar(
            connection,
            sources_root=self._inbox,
            content_store=content_store,
            id_factory=self._ids,
            clock=self._clock,
        )
        self._passages = PassageCatalog(
            connection,
            content_store=content_store,
            approval_executor=approval_executor,
            id_factory=self._ids,
            clock=self._clock,
        )
        self._issuer = ApprovalDraftIssuer(
            connection,
            approval_service=approval_service,
            content_store=content_store,
            id_factory=self._ids,
            clock=self._clock,
        )
        self._handle_key = bytes(key)
        self._handles: dict[str, tuple[Path, str]] = {}
        self._passage_approvals: dict[tuple[str, int, str], str] = {}
        self._approval_targets: dict[str, tuple[str, str]] = {}
        self._wiki_drafts: dict[str, WikiRevisionDraft] = {}
        self._formal_results: dict[str, dict[str, object]] = {}
        self._publication_planner = publication_planner
        self._publication_plans: dict[str, GlobalKnowledgePublicationPlan] = {}
        self._lock = threading.RLock()

    @property
    def rollback_wiki_service(self) -> WikiRevisionService:
        """Borrow the canonical global Wiki authority for lifecycle rollback."""

        return self._wikis

    @property
    def rollback_theory_service(self) -> TheoryRevisionService:
        """Borrow the canonical C1 authority without creating a parallel store."""

        return self._theories

    @property
    def rollback_scope_policy_repository(self) -> ScopePolicyRepository:
        """Return the exact scope-policy authority used by C1 revisions."""

        repository = self._scope_policies
        if repository is None:
            raise KnowledgeRuntimeError("SCOPE_POLICY_AUTHORITY_UNAVAILABLE")
        return repository

    @staticmethod
    def _typed_claim(
        durable: DurableKnowledgeProposal,
    ) -> ClaimProposal:
        if not isinstance(durable.proposal, ClaimProposal):
            raise KnowledgeRuntimeError("KNOWLEDGE_PROPOSAL_KIND_MISMATCH")
        return durable.proposal

    @staticmethod
    def _typed_wiki(
        durable: DurableKnowledgeProposal,
    ) -> WikiProposal:
        if not isinstance(durable.proposal, WikiProposal):
            raise KnowledgeRuntimeError("KNOWLEDGE_PROPOSAL_KIND_MISMATCH")
        return durable.proposal

    @staticmethod
    def _typed_theory(
        durable: DurableKnowledgeProposal,
    ) -> TheoryProposal:
        if not isinstance(durable.proposal, TheoryProposal):
            raise KnowledgeRuntimeError("KNOWLEDGE_PROPOSAL_KIND_MISMATCH")
        return durable.proposal

    def _restore_claim(self, proposal_id: str) -> ClaimProposal:
        durable = self._proposal_store.load(
            proposal_id,
            expected_kind="claim",
        )
        return self._claims.restore_proposal(self._typed_claim(durable))

    def _restore_wiki(self, proposal_id: str) -> WikiProposal:
        durable = self._proposal_store.load(
            proposal_id,
            expected_kind="wiki",
        )
        proposal = self._wikis.restore_proposal(self._typed_wiki(durable))
        self._wiki_drafts[proposal.proposal_id] = proposal.draft
        return proposal

    def _restore_theory(self, proposal_id: str) -> TheoryProposal:
        durable = self._proposal_store.load(
            proposal_id,
            expected_kind="theory",
        )
        return self._theories.restore_proposal(self._typed_theory(durable))

    def _restore_for_approval(
        self,
        request_id: str,
        *,
        kind: ProposalKind,
    ) -> str:
        durable = self._proposal_store.load_for_approval(
            request_id,
            expected_kind=kind,
        )
        if kind == "claim":
            proposal_id = self._claims.restore_proposal(
                self._typed_claim(durable)
            ).proposal_id
        elif kind == "wiki":
            proposal = self._wikis.restore_proposal(self._typed_wiki(durable))
            proposal_id = proposal.proposal_id
            self._wiki_drafts[proposal_id] = proposal.draft
        else:
            proposal_id = self._theories.restore_proposal(
                self._typed_theory(durable)
            ).request_id
        self._approval_targets[request_id] = (f"{kind}_proposal", proposal_id)
        return proposal_id

    def _mark_proposal_applied(
        self,
        request_id: str,
        *,
        kind: ProposalKind,
    ) -> None:
        try:
            self._proposal_store.mark_applied(
                request_id,
                expected_kind=kind,
            )
        except KnowledgeProposalError as error:
            # Databases upgraded while a legacy in-memory proposal was pending
            # cannot manufacture the missing body.  Existing catalog recovery
            # remains authoritative for those already-applied legacy writes.
            if error.code != "KNOWLEDGE_PROPOSAL_NOT_FOUND":
                raise

    def _ensure_fixed_directory(self, path: Path) -> None:
        try:
            relative = path.relative_to(self._config.vault_root)
            path.mkdir(parents=True, exist_ok=True)
        except (OSError, ValueError):
            raise KnowledgeRuntimeError("GLOBAL_KNOWLEDGE_DIRECTORY_INVALID") from None
        current = self._config.vault_root
        for component in (None, *relative.parts):
            if component is not None:
                current /= component
            try:
                status = os.lstat(current)
            except OSError:
                raise KnowledgeRuntimeError(
                    "GLOBAL_KNOWLEDGE_DIRECTORY_INVALID"
                ) from None
            if not stat.S_ISDIR(status.st_mode) or _is_reparse(status):
                raise KnowledgeRuntimeError("GLOBAL_KNOWLEDGE_DIRECTORY_INVALID")

    @property
    def inbox_root(self) -> Path:
        """Fixed path for trusted local setup code, never an MCP result."""

        return self._inbox

    def build_review_agent(self, signer: ApprovalSigner) -> ReviewAgent:
        """Build the independent TTY-only review agent over exact CAS bytes."""

        return ReviewAgent(
            service=self._approvals,
            signer=signer,
            render_verified_diff=self._issuer.verified_review_diff,
        )

    def invoke(
        self,
        tool_name: str,
        request: StrictModel,
        *,
        binding: BoundTransport | None,
    ) -> object:
        if binding is not None:
            raise KnowledgeRuntimeError("GLOBAL_TOOL_BINDING_FORBIDDEN")
        if tool_name not in _KNOWLEDGE_TOOLS | _WRITE_TOOLS:
            raise KnowledgeRuntimeError("KNOWLEDGE_TOOL_UNSUPPORTED")
        method = getattr(self, tool_name, None)
        if method is None:
            raise KnowledgeRuntimeError("KNOWLEDGE_TOOL_UNSUPPORTED")
        with self._lock:
            return method(request)

    def _iter_inbox_files(self) -> tuple[Path, ...]:
        files: list[Path] = []

        def visit(directory: Path) -> None:
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name)
            except OSError:
                raise KnowledgeRuntimeError("SOURCE_INBOX_UNAVAILABLE") from None
            for entry in entries:
                try:
                    status = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if _is_reparse(status):
                    continue
                candidate = Path(entry.path)
                if stat.S_ISDIR(status.st_mode):
                    visit(candidate)
                    continue
                try:
                    # On Windows DirEntry.stat may report st_nlink=0 while
                    # os.lstat returns the authoritative hard-link count.
                    status = os.lstat(candidate)
                except OSError:
                    continue
                if (
                    not stat.S_ISREG(status.st_mode)
                    or _is_reparse(status)
                    or int(status.st_nlink) != 1
                    or candidate.suffix.lower().lstrip(".")
                    not in _SUPPORTED_DOCUMENT_TYPES
                ):
                    continue
                files.append(candidate)

        visit(self._inbox)
        return tuple(files)

    def _read_inbox_file(self, relative: Path) -> bytes:
        try:
            with PathGuard(self._inbox).open_scoped(relative, mode="rb") as stream:
                return stream.read()
        except (OSError, ScopePathDenied):
            raise KnowledgeRuntimeError("SOURCE_INBOX_ENTRY_REJECTED") from None

    def _mint_handle(self, relative: Path, digest: str) -> str:
        logical = PurePosixPath(*relative.parts).as_posix().encode("utf-8")
        token = hmac.new(
            self._handle_key,
            b"source-inbox-v1\x00" + logical + b"\x00" + digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        handle = f"source-inbox-{token}"
        for previous, (previous_relative, _previous_digest) in tuple(
            self._handles.items()
        ):
            if previous != handle and previous_relative == relative:
                del self._handles[previous]
        self._handles[handle] = (relative, digest)
        return handle

    def list_source_inbox(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, ListSourceInboxInput):
            raise TypeError("list_source_inbox request mismatch")
        items: list[dict[str, object]] = []
        for path in self._iter_inbox_files():
            relative = path.relative_to(self._inbox)
            payload = self._read_inbox_file(relative)
            digest = hashlib.sha256(payload).hexdigest()
            kind = (
                "consultant_theory"
                if relative.parts and relative.parts[0].casefold() == "consultant-theory"
                else "general_knowledge"
            )
            items.append(
                {
                    "source_handle": self._mint_handle(relative, digest),
                    "document_type": path.suffix.lower().lstrip("."),
                    "source_kind": kind,
                    "size_bytes": len(payload),
                    "content_sha256": digest,
                }
            )
        return {"status": "ready", "items": items}

    def register_source_draft(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, RegisterSourceDraftInput):
            raise TypeError("register_source_draft request mismatch")
        resolved = self._handles.get(request.source_handle)
        if resolved is None:
            raise KnowledgeRuntimeError("SOURCE_HANDLE_UNAVAILABLE")
        relative, expected_digest = resolved
        current = self._read_inbox_file(relative)
        if not hmac.compare_digest(
            hashlib.sha256(current).hexdigest(), expected_digest
        ):
            raise KnowledgeRuntimeError("SOURCE_HANDLE_STALE")
        metadata = SourceMetadata.model_validate(request.metadata.model_dump())
        with transaction(self._connection):
            record = self._registrar.register_local_file(
                self._inbox / relative,
                metadata,
            )
            if not hmac.compare_digest(
                record.content_sha256,
                expected_digest,
            ):
                # SourceRegistrar joins this outer transaction, so a file swap
                # cannot leave mismatched catalog authority behind.
                raise KnowledgeRuntimeError("SOURCE_HANDLE_STALE")
        return {
            "status": "draft_registered",
            "source_ref": _ref_payload(_version_ref(record)),
            "document_type": record.metadata.document_type,
            "review_status": record.status,
        }

    def _existing_passages(self, source_ref: VersionRef) -> tuple[PassageRecord, ...]:
        rows = self._connection.execute(
            """
            SELECT passage_id, version FROM passages
             WHERE source_id = ? AND source_version = ?
             ORDER BY structural_path, passage_id, version
            """,
            (source_ref.object_id, source_ref.version),
        ).fetchall()
        return tuple(self._passages.get(str(row[0]), int(row[1])) for row in rows)

    def _passage_approval(self, passage: PassageRecord) -> ApprovalRequest | None:
        if passage.review_status == "approved":
            return None
        descriptor = self._passages.preview_approval(
            passage.passage_id,
            passage.version,
        )
        request = self._issuer.issue(
            descriptor,
            review_payload={
                "passage_ref": _ref_payload(_version_ref(passage)),
                "source_ref": _ref_payload(passage.source_ref),
                "structural_path": passage.structural_path,
                "locator": passage.locator.model_dump(mode="json"),
                "text": _read_text_content(
                    self._store,
                    passage.retrieval_content_ref,
                ),
                "context_before": _read_text_content(
                    self._store,
                    passage.context_before_ref,
                ),
                "context_after": _read_text_content(
                    self._store,
                    passage.context_after_ref,
                ),
            },
        )
        key = (
            passage.passage_id,
            passage.version,
            passage.normalized_text_sha256,
        )
        self._passage_approvals[key] = request.request_id
        return request

    def _extract_source(self, record: SourceRecord) -> tuple[PassageRecord, ...]:
        existing = self._existing_passages(_version_ref(record))
        if existing:
            if any(
                item.extractor_version != DocumentExtractor.VERSION
                for item in existing
            ):
                raise KnowledgeRuntimeError("PASSAGE_EXTRACTOR_VERSION_CONFLICT")
            return existing
        payload = self._store.read_hash_verified(record.content_sha256)
        if hashlib.sha256(payload).hexdigest() != record.content_sha256:
            raise KnowledgeRuntimeError("SOURCE_CONTENT_HASH_MISMATCH")
        suffix = f".{record.metadata.document_type}"
        with tempfile.TemporaryDirectory(dir=self._scratch) as directory:
            extraction_path = Path(directory) / f"source{suffix}"
            extraction_path.write_bytes(payload)
            extraction = DocumentExtractor().extract(extraction_path)
        if extraction.status != "ok":
            raise KnowledgeRuntimeError("SOURCE_EXTRACTION_QUARANTINED")
        drafts = PassageSegmenter(
            logical_source_id=record.source_id,
            source_ref=_version_ref(record),
            content_store=self._store,
            id_factory=self._ids,
        ).segment(
            record.metadata.document_type,
            extraction.blocks,
            review_status="draft",
            created_at=self._clock.now(),
        )
        return self._passages.persist_drafts(drafts)

    def extract_passages(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, ExtractPassagesInput):
            raise TypeError("extract_passages request mismatch")
        if request.extractor_version != DocumentExtractor.VERSION:
            raise KnowledgeRuntimeError("EXTRACTOR_VERSION_UNSUPPORTED")
        source = self._registrar.get(
            request.source_ref.object_id,
            request.source_ref.version,
        )
        if source.content_sha256 != request.source_ref.content_sha256:
            raise KnowledgeRuntimeError("SOURCE_REFERENCE_MISMATCH")
        passages = self._extract_source(source)
        values: list[dict[str, object]] = []
        has_pending = False
        for passage in passages:
            approval = self._passage_approval(passage)
            has_pending = has_pending or approval is not None
            item: dict[str, object] = {
                "passage_ref": _ref_payload(_version_ref(passage)),
                "review_status": passage.review_status,
            }
            if approval is not None:
                item.update(
                    {
                        "approval_request_id": approval.request_id,
                        "approval_state": approval.state,
                    }
                )
            values.append(item)
        return {
            "status": (
                "pending_passage_approval" if has_pending else "passages_approved"
            ),
            "source_ref": _ref_payload(_version_ref(source)),
            "passages": values,
            "blocking_code": (
                "PASSAGE_APPROVAL_REQUIRED" if has_pending else None
            ),
        }

    def _claim_draft(self, value: object) -> ClaimDraft:
        # ``ClaimDraftInput`` is intentionally transport-only; the authoritative
        # global provenance is reconstructed from catalogued Passage rows.
        model = ClaimDraftInput.model_validate(value)
        evidence_values = model.evidence
        passage_records = tuple(
            self._passages.get(
                evidence.passage_ref.object_id,
                evidence.passage_ref.version,
            )
            for evidence in evidence_values
        )
        for evidence, passage in zip(evidence_values, passage_records, strict=True):
            if (
                passage.normalized_text_sha256
                != evidence.passage_ref.content_sha256
                or passage.privacy_scope != "global"
            ):
                raise KnowledgeRuntimeError("CLAIM_PASSAGE_AUTHORITY_INVALID")
        source_ids = frozenset(
            source_id
            for passage in passage_records
            for source_id in passage.provenance.source_ids
        )
        passage_ids = frozenset(item.passage_id for item in passage_records)
        provenance = Provenance(
            source_ids=source_ids,
            passage_ids=passage_ids,
            provenance_scope="global_source",
            derivation_rule_ref=self._claim_rule,
        )
        return ClaimDraft(
            text=model.text,
            cognitive_type=model.cognitive_type,
            source_grade=model.source_grade,
            empirical_support=model.empirical_support,
            model_confidence=model.model_confidence,
            applicability=model.applicability,
            privacy_scope="global",
            allowed_uses=model.allowed_uses,
            evidence=evidence_values,
            provenance=provenance,
        )

    def propose_claims(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, ProposeClaimsInput):
            raise TypeError("propose_claims request mismatch")
        references = tuple(
            evidence.passage_ref
            for claim in request.claims
            for evidence in claim.evidence
        )
        blockers = self._passage_blockers_for_references(references)
        if blockers:
            return {
                "status": "pending_passage_approval",
                "proposals": [],
                "passage_blockers": blockers,
                "blocking_code": "PASSAGE_APPROVAL_REQUIRED",
            }
        drafts = tuple(self._claim_draft(item) for item in request.claims)
        proposals: list[ClaimProposal] = []
        for draft in drafts:
            generated = self._claims.propose(draft)
            descriptor = self._claims.preview(generated.proposal_id).descriptor
            durable = self._proposal_store.save_claim(generated, descriptor)
            proposals.append(
                self._claims.restore_proposal(self._typed_claim(durable))
            )
        return {
            "status": "claim_drafts_proposed",
            "proposals": [
                {
                    "proposal_id": proposal.proposal_id,
                    "draft_sha256": proposal.draft_sha256,
                    "catalog_base_version": proposal.catalog_base_version,
                }
                for proposal in proposals
            ],
        }

    def _passage_blockers_for_references(
        self,
        references: tuple[VersionRef, ...],
    ) -> list[dict[str, object]]:
        blockers: list[dict[str, object]] = []
        seen: set[tuple[str, int, str]] = set()
        for reference in references:
            key = (reference.object_id, reference.version, reference.content_sha256)
            if key in seen:
                continue
            seen.add(key)
            passage = self._passages.get(reference.object_id, reference.version)
            if passage.normalized_text_sha256 != reference.content_sha256:
                raise KnowledgeRuntimeError("CLAIM_PASSAGE_AUTHORITY_INVALID")
            if passage.review_status == "approved":
                continue
            item: dict[str, object] = {
                "passage_ref": _ref_payload(reference),
                "review_status": passage.review_status,
            }
            approval_id = self._passage_approvals.get(key)
            if approval_id is not None:
                item["approval_request_id"] = approval_id
                item["approval_state"] = self._approvals.get(approval_id).state
            blockers.append(item)
        return blockers

    def _claim_blockers(self, proposal_id: str) -> list[dict[str, object]]:
        preview = self._claims.preview(proposal_id)
        return self._passage_blockers_for_references(
            tuple(item.passage_ref for item in preview.review.evidence)
        )

    def preview_claim_review(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, PreviewClaimReviewInput):
            raise TypeError("preview_claim_review request mismatch")
        self._restore_claim(request.proposal_id)
        preview = self._claims.preview(request.proposal_id)
        approval = self._issuer.issue(
            preview.descriptor,
            review_payload=preview.review,
        )
        self._proposal_store.bind_approval(
            preview.proposal_id,
            expected_kind="claim",
            approval=approval,
        )
        self._approval_targets[approval.request_id] = (
            "claim_proposal",
            preview.proposal_id,
        )
        blockers = self._claim_blockers(preview.proposal_id)
        return {
            "status": (
                "pending_passage_approval" if blockers else "pending_local_review"
            ),
            "proposal_id": preview.proposal_id,
            "descriptor": _descriptor_payload(preview.descriptor),
            "review": preview.review.model_dump(mode="json"),
            "approval_request_id": approval.request_id,
            "approval_state": approval.state,
            "passage_blockers": blockers,
            "blocking_code": (
                "PASSAGE_APPROVAL_REQUIRED" if blockers else None
            ),
        }

    def propose_wiki_update(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, ProposeWikiUpdateInput):
            raise TypeError("propose_wiki_update request mismatch")
        generated = self._wikis.propose_diff(request.draft)
        descriptor = self._wikis.preview(generated.proposal_id)
        durable = self._proposal_store.save_wiki(generated, descriptor)
        proposal = self._wikis.restore_proposal(self._typed_wiki(durable))
        self._wiki_drafts[proposal.proposal_id] = proposal.draft
        return {
            "status": "wiki_update_proposed",
            "wiki_draft_id": proposal.proposal_id,
            "draft_sha256": proposal.draft_sha256,
            "wiki_id": proposal.draft.wiki_id,
            "base_revision": proposal.draft.base_revision,
        }

    def preview_wiki_update(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, PreviewWikiUpdateInput):
            raise TypeError("preview_wiki_update request mismatch")
        try:
            self._restore_wiki(request.wiki_draft_id)
            descriptor = self._wikis.preview(request.wiki_draft_id)
        except (KnowledgeProposalError, WikiGovernanceError) as error:
            code = getattr(error, "code", str(error))
            if code not in {
                "KNOWLEDGE_PROPOSAL_NOT_FOUND",
                "WIKI_PROPOSAL_NOT_FOUND",
            }:
                raise
            return {
                "status": "wiki_draft_not_found",
                "wiki_draft_id": request.wiki_draft_id,
                "blocking_code": "WIKI_PROPOSAL_NOT_FOUND",
            }
        approval = self._issuer.issue(
            descriptor,
            review_payload=(
                self._wiki_drafts[request.wiki_draft_id]
                if request.wiki_draft_id in self._wiki_drafts
                else {"wiki_proposal_id": request.wiki_draft_id}
            ),
        )
        self._proposal_store.bind_approval(
            request.wiki_draft_id,
            expected_kind="wiki",
            approval=approval,
        )
        self._approval_targets[approval.request_id] = (
            "wiki_proposal",
            request.wiki_draft_id,
        )
        return {
            "status": "pending_local_review",
            "wiki_draft_id": request.wiki_draft_id,
            "descriptor": _descriptor_payload(descriptor),
            "approval_request_id": approval.request_id,
            "approval_state": approval.state,
        }

    def knowledge_lint(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, KnowledgeLintInput):
            raise TypeError("knowledge_lint request mismatch")
        report = KnowledgeLinter(
            self._connection,
            now=self._clock.now(),
        ).run(request.catalog_version)
        return {"status": "complete", "report": report.model_dump(mode="json")}

    def propose_theory_revision(self, request: StrictModel) -> dict[str, object]:
        if not isinstance(request, ProposeTheoryRevisionInput):
            raise TypeError("propose_theory_revision request mismatch")
        generated = self._theories.propose(request.draft, actor="codex_curator")
        descriptor = self._theories.preview(generated.request_id)
        durable = self._proposal_store.save_theory(generated, descriptor)
        proposal = self._theories.restore_proposal(self._typed_theory(durable))
        descriptor = self._theories.preview(proposal.request_id)
        approval = self._issuer.issue(
            descriptor,
            review_payload=proposal.draft,
        )
        self._proposal_store.bind_approval(
            proposal.request_id,
            expected_kind="theory",
            approval=approval,
        )
        self._approval_targets[approval.request_id] = (
            "theory_proposal",
            proposal.request_id,
        )
        return {
            "status": "pending_primary_counselor_review",
            "theory_proposal_id": proposal.request_id,
            "draft_sha256": proposal.draft_sha256,
            "descriptor": _descriptor_payload(descriptor),
            "approval_request_id": approval.request_id,
            "approval_state": approval.state,
        }

    def _formal_request(
        self,
        request: StrictModel,
        *,
        expected_type: type[ApprovalExecutionInput],
        purpose: str,
    ) -> tuple[str, ApprovalRequest]:
        if not isinstance(request, expected_type):
            raise TypeError("formal knowledge request mismatch")
        request_id = request.approval_request_id
        approval = self._approvals.get(request_id)
        if approval.descriptor.purpose != purpose:
            raise KnowledgeRuntimeError("APPROVAL_PURPOSE_MISMATCH")
        if approval.descriptor.client_id is not None:
            raise KnowledgeRuntimeError("GLOBAL_DESCRIPTOR_SCOPE_INVALID")
        return request_id, approval

    @staticmethod
    def _pending_review(approval: ApprovalRequest) -> dict[str, object]:
        return {
            "status": "pending_local_review",
            "approval_request_id": approval.request_id,
            "approval_state": approval.state,
            "mutation_applied": False,
        }

    def _restore_publication_plan(
        self,
        approval: ApprovalRequest,
    ) -> GlobalKnowledgePublicationPlan:
        """Recover only the immutable closure that the reviewer confirmed.

        The CAS review object is the durable handoff.  Recovery never invokes
        the planner, so a restart cannot substitute newer authority rows,
        another model, or a newly generated operation identifier.
        """

        invalid = "WIKI_PUBLICATION_PLAN_INVALID"
        try:
            if (
                approval.descriptor.purpose != "wiki_publish"
                or approval.descriptor.target_id != "global-knowledge"
                or approval.descriptor.client_id is not None
                or approval.descriptor.session_id is not None
            ):
                raise KnowledgeRuntimeError(invalid)
            encoded = self._store.read_hash_verified(
                approval.diff_object_ref.content_sha256
            )
            if hashlib.sha256(encoded).hexdigest() != (
                approval.diff_object_ref.content_sha256
            ):
                raise KnowledgeRuntimeError(invalid)
            envelope = json.loads(encoded)
            if (
                type(envelope) is not dict
                or set(envelope) != {"descriptor", "review"}
                or _json_bytes(envelope) != encoded
            ):
                raise KnowledgeRuntimeError(invalid)
            descriptor = DraftDescriptor.model_validate(envelope["descriptor"])
            if descriptor != approval.descriptor:
                raise KnowledgeRuntimeError(invalid)
            review = envelope["review"]
            if type(review) is not dict or set(review) != {
                "artifact_kinds",
                "publication_plan",
                "source_approval_request_id",
                "target_runtime_epoch",
                "wiki_ref",
            }:
                raise KnowledgeRuntimeError(invalid)
            if type(review["source_approval_request_id"]) is not str:
                raise KnowledgeRuntimeError(invalid)
            persisted = _PersistedGlobalPublicationPlan.model_validate_json(
                _json_bytes(review["publication_plan"])
            )
            if (
                review["artifact_kinds"] != list(persisted.artifact_kinds)
                or review["target_runtime_epoch"]
                != persisted.target_runtime_epoch
                or review["wiki_ref"]
                != persisted.wiki_ref.model_dump(mode="json")
                or persisted.descriptor != approval.descriptor
            ):
                raise KnowledgeRuntimeError(invalid)
            artifacts: list[PreparedArtifactDraft] = []
            for artifact in persisted.artifacts:
                members: list[PreparedContentDraft] = []
                for member in artifact.members:
                    reference = self._store.reference(
                        content_sha256=member.content_sha256,
                        media_type=member.media_type,
                        size_bytes=member.size_bytes,
                    )
                    self._store.read_verified(reference)
                    members.append(
                        PreparedContentDraft(
                            object_type=member.object_type,
                            object_id=member.object_id,
                            reference=reference,
                            source_version=member.source_version,
                            source_lineage_hashes=member.source_lineage_hashes,
                        )
                    )
                artifacts.append(
                    PreparedArtifactDraft(
                        purpose=artifact.purpose,
                        manifest_id=artifact.manifest_id,
                        artifact_key=artifact.artifact_key,
                        artifact_kind=artifact.artifact_kind,
                        source_version=artifact.source_version,
                        members=tuple(members),
                    )
                )
            plan = GlobalKnowledgePublicationPlan(
                operation_id=persisted.operation_id,
                descriptor=persisted.descriptor,
                authority_base_version=persisted.authority_base_version,
                expected_current_epoch=persisted.expected_current_epoch,
                target_runtime_epoch=persisted.target_runtime_epoch,
                wiki_ref=persisted.wiki_ref,
                theory_ref=persisted.theory_ref,
                artifacts=tuple(artifacts),
                artifact_kinds=persisted.artifact_kinds,
            )
            if plan.descriptor != approval.descriptor:
                raise KnowledgeRuntimeError(invalid)
            return plan
        except KnowledgeRuntimeError:
            raise
        except (
            ContentStoreError,
            GlobalPublicationPlanningError,
            PublicationIntegrityError,
            ValidationError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise KnowledgeRuntimeError(invalid) from None

    def _claim_result_from_decision(
        self,
        request_id: str,
        *,
        decision: str,
    ) -> dict[str, object] | None:
        row = self._connection.execute(
            """
            SELECT object_id, object_version FROM review_decisions
             WHERE approval_request_id = ? AND object_type = 'claim'
               AND decision = ?
             ORDER BY decided_at DESC, decision_id DESC
             LIMIT 1
            """,
            (request_id, decision),
        ).fetchone()
        if row is None:
            return None
        record = self._claims.get(str(row[0]), int(row[1]))
        requested_status = "approved" if decision == "APPROVE" else "revoked"
        return {
            "status": (
                "claim_approved"
                if record.review_status == "approved"
                else "claim_revoked"
                if record.review_status == "revoked"
                else "claim_not_active"
            ),
            "approval_request_id": request_id,
            "mutation_applied": True,
            "requested_status": requested_status,
            "current_review_status": record.review_status,
            "claim_ref": _ref_payload(
                VersionRef(
                    object_id=record.claim_id,
                    version=record.version,
                    content_sha256=record.text_sha256,
                )
            ),
        }

    def _passage_result_from_decision(
        self,
        request_id: str,
    ) -> dict[str, object] | None:
        row = self._connection.execute(
            """
            SELECT object_id, object_version FROM review_decisions
             WHERE approval_request_id = ? AND object_type = 'passage'
               AND decision = 'APPROVE'
             ORDER BY decided_at DESC, decision_id DESC
             LIMIT 1
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        passage = self._passages.get(str(row[0]), int(row[1]))
        if passage.review_status != "approved":
            raise KnowledgeRuntimeError("PASSAGE_APPROVAL_RECOVERY_INVALID")
        return {
            "status": "passage_approved",
            "approval_request_id": request_id,
            "mutation_applied": True,
            "passage_ref": _ref_payload(_version_ref(passage)),
        }

    def _wiki_result_from_catalog(
        self,
        request_id: str,
    ) -> dict[str, object] | None:
        row = self._connection.execute(
            """
            SELECT wiki_id, revision, body_sha256, review_status
              FROM wiki_revisions WHERE approval_request_id = ?
             ORDER BY revision DESC LIMIT 1
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        review_status = str(row[3]).lower()
        return {
            "status": (
                "wiki_active"
                if review_status == "active"
                else "prepared_pending_artifact_publication"
                if review_status == "prepared"
                else "wiki_not_active"
            ),
            "approval_request_id": request_id,
            "mutation_applied": True,
            "wiki_ref": _ref_payload(
                VersionRef(
                    object_id=str(row[0]),
                    version=int(row[1]),
                    content_sha256=str(row[2]),
                )
            ),
            "authority_active": review_status == "active",
            "current_review_status": review_status,
            "blocking_code": (
                None
                if review_status == "active"
                else "WIKI_DERIVED_ARTIFACT_PUBLICATION_UNAVAILABLE"
                if review_status == "prepared"
                else "WIKI_AUTHORITY_NOT_ACTIVE"
            ),
            "blocking_stage": (
                "derived_artifact_build_and_publication"
                if review_status == "prepared"
                else None
            ),
        }

    def _theory_result_from_catalog(
        self,
        request_id: str,
        *,
        decision: str,
    ) -> dict[str, object] | None:
        if decision == "APPROVE":
            row = self._connection.execute(
                """
                SELECT theory_id, revision, status FROM theory_revisions
                 WHERE approval_request_id = ?
                 ORDER BY revision DESC LIMIT 1
                """,
                (request_id,),
            ).fetchone()
        else:
            descriptor = self._approvals.get(request_id).descriptor
            row = self._connection.execute(
                """
                SELECT theory_id, revision, status FROM theory_revisions
                 WHERE theory_id = ? AND revision = ? AND status = 'REVOKED'
                """,
                (descriptor.target_id, descriptor.base_version),
            ).fetchone()
        if row is None:
            return None
        status = str(row[2]).lower()
        return {
            "status": (
                "theory_revoked"
                if status == "revoked"
                else "theory_active"
                if status == "active"
                else "prepared_pending_combined_publication"
                if status == "prepared"
                else "theory_not_active"
            ),
            "approval_request_id": request_id,
            "mutation_applied": True,
            "theory_ref": _ref_payload(
                self._theories.version_ref(str(row[0]), int(row[1]))
            ),
            "authority_active": status == "active",
            "current_status": status,
            "blocking_code": (
                None
                if status in {"active", "revoked"}
                else "THEORY_WIKI_COMBINED_PUBLICATION_UNAVAILABLE"
                if status == "prepared"
                else "THEORY_AUTHORITY_NOT_ACTIVE"
            ),
        }

    def approve_passage(self, request: StrictModel) -> dict[str, object]:
        request_id, approval = self._formal_request(
            request,
            expected_type=ApprovePassageInput,
            purpose="passage_approve",
        )
        cached = self._formal_results.get(request_id)
        if cached is not None:
            return cached
        if approval.state == "acknowledged":
            recovered = self._passage_result_from_decision(request_id)
            if recovered is not None:
                return recovered
        if approval.state == "pending":
            return self._pending_review(approval)
        passage = self._passages.approve(
            approval.descriptor.target_id,
            approval.descriptor.base_version,
            approval_request_id=request_id,
        )
        result: dict[str, object] = {
            "status": "passage_approved",
            "approval_request_id": request_id,
            "mutation_applied": True,
            "passage_ref": _ref_payload(_version_ref(passage)),
        }
        self._formal_results[request_id] = result
        return result

    def approve_claim(self, request: StrictModel) -> dict[str, object]:
        request_id, approval = self._formal_request(
            request,
            expected_type=ApproveClaimInput,
            purpose="claim_approve",
        )
        cached = self._formal_results.get(request_id)
        if cached is not None:
            return cached
        if approval.state == "acknowledged":
            recovered = self._claim_result_from_decision(
                request_id,
                decision="APPROVE",
            )
            if recovered is not None:
                self._mark_proposal_applied(request_id, kind="claim")
                return recovered
        if approval.state == "pending":
            return self._pending_review(approval)
        proposal_id = self._restore_for_approval(request_id, kind="claim")
        blockers = self._claim_blockers(proposal_id)
        if blockers:
            return {
                "status": "pending_passage_approval",
                "approval_request_id": request_id,
                "mutation_applied": False,
                "passage_blockers": blockers,
                "blocking_code": "PASSAGE_APPROVAL_REQUIRED",
            }
        preview = self._claims.preview(proposal_id)
        if preview.descriptor != approval.descriptor:
            raise KnowledgeRuntimeError("CLAIM_APPROVAL_DESCRIPTOR_MISMATCH")
        record = self._claims.commit(
            proposal_id,
            descriptor=approval.descriptor,
            approval_request_id=request_id,
        )
        self._mark_proposal_applied(request_id, kind="claim")
        result: dict[str, object] = {
            "status": "claim_approved",
            "approval_request_id": request_id,
            "mutation_applied": True,
            "claim_ref": _ref_payload(
                VersionRef(
                    object_id=record.claim_id,
                    version=record.version,
                    content_sha256=record.text_sha256,
                )
            ),
        }
        self._formal_results[request_id] = result
        return result

    def revoke_claim(self, request: StrictModel) -> dict[str, object]:
        request_id, approval = self._formal_request(
            request,
            expected_type=RevokeClaimInput,
            purpose="claim_revoke",
        )
        cached = self._formal_results.get(request_id)
        if cached is not None:
            return cached
        if approval.state == "acknowledged":
            recovered = self._claim_result_from_decision(
                request_id,
                decision="REVOKE",
            )
            if recovered is not None:
                return recovered
        if approval.state == "pending":
            return self._pending_review(approval)
        record = self._claims.revoke(
            approval.descriptor.target_id,
            approval.descriptor.base_version,
            approval_request_id=request_id,
        )
        result = {
            "status": "claim_revoked",
            "approval_request_id": request_id,
            "mutation_applied": True,
            "claim_ref": _ref_payload(
                VersionRef(
                    object_id=record.claim_id,
                    version=record.version,
                    content_sha256=record.text_sha256,
                )
            ),
        }
        self._formal_results[request_id] = result
        return result

    def publish_wiki(self, request: StrictModel) -> dict[str, object]:
        request_id, approval = self._formal_request(
            request,
            expected_type=PublishWikiInput,
            purpose="wiki_publish",
        )
        publication_plan = self._publication_plans.get(request_id)
        if (
            publication_plan is None
            and approval.descriptor.target_id == "global-knowledge"
        ):
            if self._publication_planner is None:
                raise KnowledgeRuntimeError(
                    "WIKI_PUBLICATION_PLANNER_UNAVAILABLE"
                )
            publication_plan = self._restore_publication_plan(approval)
            self._publication_plans[request_id] = publication_plan
        if publication_plan is not None:
            if approval.state == "pending":
                return self._pending_review(approval)
            if self._publication_planner is None:
                raise KnowledgeRuntimeError("WIKI_PUBLICATION_PLANNER_UNAVAILABLE")
            operation = self._publication_planner.execute(
                publication_plan,
                approval_request_id=request_id,
            )
            result = {
                "status": "wiki_active",
                "approval_request_id": request_id,
                "mutation_applied": True,
                "wiki_ref": _ref_payload(publication_plan.wiki_ref),
                "authority_active": True,
                "runtime_epoch": operation.runtime_epoch,
                "publication_operation_id": operation.operation_id,
                "blocking_code": None,
            }
            self._formal_results[request_id] = result
            return result
        cached = self._formal_results.get(request_id)
        if cached is not None:
            return cached
        if approval.state == "acknowledged":
            recovered = self._wiki_result_from_catalog(request_id)
            if recovered is not None:
                self._mark_proposal_applied(request_id, kind="wiki")
                if (
                    recovered.get("current_review_status") == "prepared"
                    and self._publication_planner is not None
                ):
                    wiki_ref = VersionRef.model_validate(recovered["wiki_ref"])
                    revision = self._wikis.get(
                        wiki_ref.object_id,
                        wiki_ref.version,
                    )
                    return self.prepare_wiki_publication(
                        revision,
                        source_approval_request_id=request_id,
                    )
                return recovered
        if approval.state == "pending":
            return self._pending_review(approval)
        proposal_id = self._restore_for_approval(request_id, kind="wiki")
        revision = self._wikis.approve(
            proposal_id,
            actor="knowledge_reviewer",
            approval_request_id=request_id,
        )
        self._mark_proposal_applied(request_id, kind="wiki")
        if self._publication_planner is not None:
            return self.prepare_wiki_publication(
                revision,
                source_approval_request_id=request_id,
            )
        result = {
            "status": "prepared_pending_artifact_publication",
            "approval_request_id": request_id,
            "mutation_applied": True,
            "wiki_ref": _ref_payload(
                VersionRef(
                    object_id=revision.wiki_id,
                    version=revision.revision,
                    content_sha256=revision.body_sha256,
                )
            ),
            "authority_active": False,
            "blocking_code": "WIKI_DERIVED_ARTIFACT_PUBLICATION_UNAVAILABLE",
            "blocking_stage": "derived_artifact_build_and_publication",
        }
        self._formal_results[request_id] = result
        return result

    def prepare_wiki_publication(
        self,
        revision: object,
        *,
        source_approval_request_id: str,
    ) -> dict[str, object]:
        if self._publication_planner is None:
            raise KnowledgeRuntimeError("WIKI_PUBLICATION_PLANNER_UNAVAILABLE")
        wiki_id = getattr(revision, "wiki_id", None)
        wiki_revision = getattr(revision, "revision", None)
        if type(wiki_id) is not str or type(wiki_revision) is not int:
            raise KnowledgeRuntimeError("WIKI_PUBLICATION_TARGET_INVALID")
        plan = self._publication_planner.plan_wiki(
            wiki_id=wiki_id,
            wiki_revision=wiki_revision,
        )
        publication_approval = self._issuer.issue(
            plan.descriptor,
            review_payload={
                "artifact_kinds": list(plan.artifact_kinds),
                "source_approval_request_id": source_approval_request_id,
                "target_runtime_epoch": plan.target_runtime_epoch,
                "wiki_ref": plan.wiki_ref.model_dump(mode="json"),
                "publication_plan": _publication_plan_payload(plan),
            },
        )
        self._publication_plans[publication_approval.request_id] = plan
        return {
            "status": "prepared_pending_artifact_publication_approval",
            "approval_request_id": source_approval_request_id,
            "publication_approval_request_id": publication_approval.request_id,
            "publication_approval_state": publication_approval.state,
            "mutation_applied": True,
            "wiki_ref": _ref_payload(plan.wiki_ref),
            "authority_active": False,
            "target_runtime_epoch": plan.target_runtime_epoch,
            "publication_operation_id": plan.operation_id,
            "blocking_code": "WIKI_ARTIFACT_PUBLICATION_APPROVAL_REQUIRED",
            "blocking_stage": "exact_derived_artifact_publication_review",
        }

    def approve_theory_revision(self, request: StrictModel) -> dict[str, object]:
        request_id, approval = self._formal_request(
            request,
            expected_type=ApproveTheoryRevisionInput,
            purpose="theory_approve",
        )
        cached = self._formal_results.get(request_id)
        if cached is not None:
            return cached
        if approval.state == "acknowledged":
            recovered = self._theory_result_from_catalog(
                request_id,
                decision="APPROVE",
            )
            if recovered is not None:
                self._mark_proposal_applied(request_id, kind="theory")
                return recovered
        if approval.state == "pending":
            return self._pending_review(approval)
        proposal_id = self._restore_for_approval(request_id, kind="theory")
        revision = self._theories.approve(
            proposal_id,
            actor="primary_counselor",
            approval_request_id=request_id,
        )
        self._mark_proposal_applied(request_id, kind="theory")
        result = {
            "status": "prepared_pending_combined_publication",
            "approval_request_id": request_id,
            "mutation_applied": True,
            "theory_ref": _ref_payload(
                self._theories.version_ref(revision.theory_id, revision.revision)
            ),
            "authority_active": False,
            "blocking_code": "THEORY_WIKI_COMBINED_PUBLICATION_UNAVAILABLE",
        }
        self._formal_results[request_id] = result
        return result

    def revoke_theory_revision(self, request: StrictModel) -> dict[str, object]:
        request_id, approval = self._formal_request(
            request,
            expected_type=RevokeTheoryRevisionInput,
            purpose="theory_revoke",
        )
        cached = self._formal_results.get(request_id)
        if cached is not None:
            return cached
        if approval.state == "acknowledged":
            recovered = self._theory_result_from_catalog(
                request_id,
                decision="REVOKE",
            )
            if recovered is not None:
                return recovered
        if approval.state == "pending":
            return self._pending_review(approval)
        revision = self._theories.revoke(
            approval.descriptor.target_id,
            approval.descriptor.base_version,
            actor="primary_counselor",
            approval_request_id=request_id,
        )
        result = {
            "status": "theory_revoked",
            "approval_request_id": request_id,
            "mutation_applied": True,
            "theory_ref": _ref_payload(
                self._theories.version_ref(revision.theory_id, revision.revision)
            ),
            "authority_active": False,
        }
        self._formal_results[request_id] = result
        return result


def build_global_knowledge_runtime(
    *,
    config: AppConfig,
    connection: sqlite3.Connection,
    content_store: ContentStore,
    approval_service: ApprovalService,
    approval_executor: GovernedWriteExecutor,
    id_factory: IdFactory | None = None,
    clock: Clock | None = None,
    handle_key: bytes | None = None,
    publication_builders: GlobalPublicationBuilders | None = None,
    publication_execution_guard: ApprovalExecutionGuard | None = None,
) -> GlobalKnowledgeToolRuntime:
    """Compose all P3 global services around one explicit v1 policy.

    The returned runtime borrows every injected resource.  In particular it
    does not close ``connection``; the owning MCP lifespan must do that once.
    """

    ids = id_factory or IdFactory()
    runtime_clock = clock or SystemClock()
    passages = PassageCatalog(
        connection,
        content_store=content_store,
        approval_executor=approval_executor,
        id_factory=ids,
        clock=runtime_clock,
    )

    def resolve_evidence(
        reference: VersionRef,
    ) -> tuple[str, str | None, str | None, EvidenceLocator]:
        passage = passages.get(reference.object_id, reference.version)
        if passage.normalized_text_sha256 != reference.content_sha256:
            raise KnowledgeRuntimeError("PASSAGE_REFERENCE_MISMATCH")
        text = _read_text_content(content_store, passage.retrieval_content_ref)
        if text is None:
            raise KnowledgeRuntimeError("PASSAGE_CONTENT_REF_INVALID")
        return (
            text,
            _read_text_content(content_store, passage.context_before_ref),
            _read_text_content(content_store, passage.context_after_ref),
            passage.locator,
        )

    claims = ClaimProposalService(
        review_resolver=ClaimReviewResolver(resolve_evidence),
        id_factory=ids,
        clock=runtime_clock,
        connection=connection,
        approval_executor=approval_executor,
        content_store=content_store,
        provenance_policy=global_provenance_policy_manifest(),
    )
    scope_policies = ScopePolicyRepository(
        connection,
        content_store=content_store,
        approval_executor=approval_executor,
        clock=runtime_clock,
    )
    theories = TheoryRevisionService(
        id_factory=ids,
        clock=runtime_clock,
        connection=connection,
        approval_executor=approval_executor,
        content_store=content_store,
        scope_policy_repository=scope_policies,
    )

    def claim_authority(reference: VersionRef) -> WikiClaimAuthority:
        try:
            claim = claims.get(reference.object_id, reference.version)
        except Exception:
            return WikiClaimAuthority(status="unavailable", source_grade="C2")
        if claim.text_sha256 != reference.content_sha256:
            return WikiClaimAuthority(status="unavailable", source_grade="C2")
        return WikiClaimAuthority(
            status=(
                "approved"
                if claim.review_status == "approved"
                else "prepared"
                if claim.review_status == "reviewed"
                else "unavailable"
            ),
            source_grade=claim.source_grade,
            theory_revision_ref=claim.theory_revision_ref,
        )

    def resolve_passage(reference: VersionRef) -> object:
        passage = passages.get(reference.object_id, reference.version)
        if passage.normalized_text_sha256 != reference.content_sha256:
            raise KnowledgeRuntimeError("PASSAGE_REFERENCE_MISMATCH")
        return passage.locator

    wikis = WikiRevisionService(
        claim_resolver=claim_authority,
        passage_resolver=resolve_passage,
        theory_resolver=lambda reference: theories.get_by_ref(reference).status,
        id_factory=ids,
        clock=runtime_clock,
        connection=connection,
        approval_executor=approval_executor,
        content_store=content_store,
    )
    planner: GlobalKnowledgePublicationPlanner | None = None
    if publication_builders is not None:
        if publication_execution_guard is None:
            raise KnowledgeRuntimeError("KNOWLEDGE_PUBLICATION_GUARD_REQUIRED")
        planner = GlobalKnowledgePublicationPlanner(
            connection=connection,
            content_store=content_store,
            approval_service=approval_service,
            execution_guard=publication_execution_guard,
            claim_service=claims,
            passage_reader=passages,
            theory_service=theories,
            wiki_service=wikis,
            builders=publication_builders,
            build_root=(
                config.vault_root / "global" / ".publication-builds"
            ).resolve(),
            id_factory=ids,
            clock=runtime_clock,
            lint_error_count=lambda: int(
                KnowledgeLinter(connection, now=runtime_clock.now()).run().has_errors
            ),
        )
    return GlobalKnowledgeToolRuntime(
        config=config,
        connection=connection,
        content_store=content_store,
        approval_service=approval_service,
        approval_executor=approval_executor,
        claim_service=claims,
        wiki_service=wikis,
        theory_service=theories,
        scope_policy_repository=scope_policies,
        claim_derivation_rule_ref=global_claim_derivation_rule_ref(),
        id_factory=ids,
        clock=runtime_clock,
        handle_key=handle_key,
        publication_planner=planner,
    )


__all__ = [
    "ApprovalDraftIssuer",
    "GlobalKnowledgeToolRuntime",
    "KnowledgeRuntimeError",
    "build_global_knowledge_runtime",
    "global_claim_derivation_rule_ref",
    "global_provenance_policy_manifest",
]
