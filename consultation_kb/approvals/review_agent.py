"""Interactive local review boundary; no silent or piped approval path exists."""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import TextIO

from consultation_kb.models.common import VersionRef

from .provider import ApprovalSigner
from .store import ApprovalError, ApprovalService


class InteractiveApprovalRequired(ApprovalError):
    pass


class ReviewRejected(ApprovalError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedReviewDiff:
    """Exact bytes loaded for one immutable, hash-addressed review object."""

    reference: VersionRef
    content: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.reference, VersionRef)
            or type(self.content) is not bytes
        ):
            raise TypeError("verified review diff requires a VersionRef and bytes")


def _terminal_safe_text(content: bytes) -> str:
    try:
        decoded = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ApprovalError("verified review diff is not UTF-8") from None
    if not decoded:
        raise ApprovalError("verified review diff is unavailable")
    rendered: list[str] = []
    for character in decoded:
        codepoint = ord(character)
        if character == "\n":
            rendered.append(character)
        elif character.isprintable() and not (0x7F <= codepoint <= 0x9F):
            rendered.append(character)
        elif codepoint <= 0xFFFF:
            rendered.append(f"\\u{codepoint:04x}")
        else:
            rendered.append(f"\\U{codepoint:08x}")
    return "".join(rendered)


class ReviewAgent:
    """Display a verified diff locally and consume one explicit TTY confirmation."""

    def __init__(
        self,
        *,
        service: ApprovalService,
        signer: ApprovalSigner,
        render_verified_diff: Callable[[VersionRef], VerifiedReviewDiff],
    ) -> None:
        self._service = service
        self._signer = signer
        self._render_verified_diff = render_verified_diff

    def review(
        self,
        request_id: str,
        *,
        stdin: TextIO,
        stdout: TextIO,
    ) -> None:
        if not stdin.isatty():
            raise InteractiveApprovalRequired("interactive local review is required")
        challenge = self._service.challenge_for_review(request_id)
        request = challenge.request
        try:
            rendered = self._render_verified_diff(request.diff_object_ref)
        except Exception:
            raise ApprovalError("verified review diff is unavailable") from None
        if type(rendered) is not VerifiedReviewDiff:
            raise ApprovalError("verified review diff is unavailable")
        if rendered.reference != request.diff_object_ref:
            raise ApprovalError("verified review diff reference mismatch")
        actual_hash = hashlib.sha256(rendered.content).hexdigest()
        if actual_hash != request.diff_object_ref.content_sha256:
            raise ApprovalError("verified review diff hash mismatch")
        verified_diff = _terminal_safe_text(rendered.content)
        phrase = f"APPROVE {request.descriptor_sha256[:16]}"
        stdout.write("Local consultation-kb approval review\n")
        stdout.write(
            f"purpose={request.descriptor.purpose} "
            f"base_version={request.descriptor.base_version}\n"
        )
        stdout.write(
            f"diff_object={request.diff_object_ref.object_id} "
            f"version={request.diff_object_ref.version} "
            f"sha256={request.diff_object_ref.content_sha256}\n"
        )
        stdout.write("--- BEGIN VERIFIED DIFF ---\n")
        stdout.write(verified_diff)
        if not verified_diff.endswith("\n"):
            stdout.write("\n")
        stdout.write("--- END VERIFIED DIFF ---\n")
        stdout.write(f"Type exactly: {phrase}\n> ")
        stdout.flush()
        answer = stdin.readline()
        if answer.rstrip("\r\n") != phrase:
            raise ReviewRejected("approval was not confirmed")
        event = self._signer.confirm(challenge)
        self._service.confirm(event)


def run_review_agent(
    agent: ReviewAgent,
    request_id: str,
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        agent.review(request_id, stdin=stdin, stdout=stdout)
    except InteractiveApprovalRequired:
        stderr.write("consultation-kb review: INTERACTIVE_REVIEW_REQUIRED\n")
        return 2
    except ReviewRejected:
        stderr.write("consultation-kb review: REVIEW_REJECTED\n")
        return 2
    except ApprovalError:
        stderr.write("consultation-kb review: REVIEW_FAILED\n")
        return 2
    return 0


__all__ = [
    "InteractiveApprovalRequired",
    "ReviewAgent",
    "ReviewRejected",
    "VerifiedReviewDiff",
    "run_review_agent",
]
