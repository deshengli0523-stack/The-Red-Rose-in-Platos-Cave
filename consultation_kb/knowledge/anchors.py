"""Stable, source-addressed Passage anchors."""

from __future__ import annotations

import hashlib
import uuid

from pydantic import model_validator

from consultation_kb.models.common import NonEmptyStr, ObjectId, StrictModel, VersionRef
from consultation_kb.models.evidence import EvidenceLocator
from consultation_kb.models.knowledge import DocumentType


def deterministic_object_id(kind: str, *parts: str) -> str:
    """Build a valid deterministic UUIDv7-shaped object ID from stable inputs."""

    payload = "\x00".join((kind, *parts)).encode("utf-8", errors="strict")
    value = int.from_bytes(hashlib.sha256(payload).digest()[:16], "big")
    value = (value & ~(0xF << 76)) | (0x7 << 76)
    value = (value & ~(0b11 << 62)) | (0b10 << 62)
    return f"{kind}_{uuid.UUID(int=value)}"


class PassageAnchor(StrictModel):
    passage_id: ObjectId
    logical_source_id: ObjectId
    document_type: DocumentType
    structural_path: NonEmptyStr
    locator: EvidenceLocator

    @model_validator(mode="after")
    def _validate_id(self) -> "PassageAnchor":
        expected = deterministic_object_id(
            "passage",
            self.logical_source_id,
            self.document_type,
            self.structural_path,
        )
        if self.passage_id != expected:
            raise ValueError("Passage ID does not match its stable anchor")
        return self


def locator_policy_ref() -> VersionRef:
    return VersionRef(
        object_id=deterministic_object_id("locator_policy", "knowledge-v1"),
        version=1,
        content_sha256=hashlib.sha256(b"consultation-kb-locator-policy-v1").hexdigest(),
    )


__all__ = ["PassageAnchor", "deterministic_object_id", "locator_policy_ref"]
