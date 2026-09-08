from __future__ import annotations

import hashlib
import io
import sys
from pathlib import Path

import pytest

from consultation_kb import cli
from consultation_kb.approvals.provider import ProtectedProviderSecretStore
from consultation_kb.approvals.review_agent import (
    ReviewAgent,
    VerifiedReviewDiff,
    run_review_agent,
)
from consultation_kb.approvals.store import ApprovalService
from consultation_kb.core.clock import SystemClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.models.common import VersionRef
from consultation_kb.models.manifests import DraftDescriptor
from consultation_kb.security.dpapi import WindowsDpapiProtector
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore
from tests.consultation_kb.approval_support import DIFF_BYTES, build_approval_harness


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_review_cli_has_no_silent_approval_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "review",
                "--request",
                "approval_request_018f22e2-79b0-7cc3-98c4-dc0c0c07398f",
                "--approve",
                "yes",
            ]
        )
    assert raised.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "win32", reason="production review uses DPAPI")
def test_review_cli_loads_the_hash_bound_diff_and_confirms_in_a_tty(
    synthetic_workspace: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, vault = synthetic_workspace
    global_root = vault / "global"
    global_root.mkdir()
    database = global_root / "catalog.sqlite3"
    connection = connect_database(database, mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    clock = SystemClock()
    ids = IdFactory(clock)
    protector = WindowsDpapiProtector()
    vault_id = cli._vault_security_id(vault.resolve())
    secret_store = ProtectedProviderSecretStore(
        vault / "security" / "review-agent-secret.dpapi",
        protector=protector,
        vault_id=vault_id,
    )
    secret_store.initialize()
    diff_bytes = b"verified production review diff\n"
    content_store = ContentStore(global_root)
    content_reference = content_store.finalize(
        content_store.stage_bytes(
            diff_bytes,
            purpose="approval_diff",
            manifest_id=ids.object_id("approval_diff_manifest"),
            media_type="text/plain",
        )
    )
    diff_ref = VersionRef(
        object_id=ids.object_id("approval_diff"),
        version=1,
        content_sha256=content_reference.content_sha256,
    )
    service = ApprovalService(
        connection,
        provider=secret_store.load_verifier(),
        protector=protector,
        clock=clock,
        id_factory=ids,
        target_scope_hash="a" * 64,
        vault_id=vault_id,
        execution_secret=secret_store.load_execution_secret(),
        execution_proof_verifier=(secret_store.load_target_execution_proof_verifier()),
    )
    request = service.request(
        DraftDescriptor(
            purpose="profile_update",
            target_id="synthetic-profile",
            client_id="client_" + "a" * 12,
            base_version=0,
            draft_sha256="b" * 64,
            session_id=None,
        ),
        diff_object_ref=diff_ref,
    )
    connection.close()

    monkeypatch.setattr(
        sys,
        "stdin",
        TtyInput(f"APPROVE {request.descriptor_sha256[:16]}\n"),
    )
    assert (
        cli.main(
            [
                "review",
                "--request",
                request.request_id,
                "--repo-root",
                str(repo),
                "--vault-root",
                str(vault),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "verified production review diff" in captured.out
    assert captured.err == ""

    verified = connect_database(database, mode="reader")
    try:
        assert verified.execute(
            "SELECT state FROM approval_requests WHERE request_id = ?",
            (request.request_id,),
        ).fetchone() == ("CONFIRMED",)
    finally:
        verified.close()


def test_review_agent_rejects_piped_input_and_accepts_exact_tty_phrase(
    tmp_path: Path,
) -> None:
    harness = build_approval_harness(tmp_path)
    try:
        draft = harness.draft()
        request = harness.service.request(
            draft,
            diff_object_ref=harness.diff_object_ref(),
        )
        agent = ReviewAgent(
            service=harness.service,
            signer=harness.signer,
            render_verified_diff=lambda reference: VerifiedReviewDiff(
                reference=reference,
                content=DIFF_BYTES,
            ),
        )
        stderr = io.StringIO()
        assert (
            run_review_agent(
                agent,
                request.request_id,
                stdin=io.StringIO("APPROVE\n"),
                stdout=io.StringIO(),
                stderr=stderr,
            )
            == 2
        )
        assert stderr.getvalue() == (
            "consultation-kb review: INTERACTIVE_REVIEW_REQUIRED\n"
        )
        assert harness.service.get(request.request_id).state == "pending"

        phrase = f"APPROVE {request.descriptor_sha256[:16]}\n"
        output = io.StringIO()
        assert (
            run_review_agent(
                agent,
                request.request_id,
                stdin=TtyInput(phrase),
                stdout=output,
                stderr=io.StringIO(),
            )
            == 0
        )
        assert "verified synthetic diff" in output.getvalue()
        assert harness.service.get(request.request_id).state == "confirmed"
    finally:
        harness.close()


def test_review_agent_rejects_wrong_diff_and_escapes_terminal_controls(
    tmp_path: Path,
) -> None:
    harness = build_approval_harness(tmp_path)
    try:
        draft = harness.draft()
        hostile = b"line\x1b[2J\rnext\n"
        reference = harness.diff_object_ref().model_copy(
            update={"content_sha256": hashlib.sha256(hostile).hexdigest()}
        )
        request = harness.service.request(draft, diff_object_ref=reference)
        wrong_agent = ReviewAgent(
            service=harness.service,
            signer=harness.signer,
            render_verified_diff=lambda returned_reference: VerifiedReviewDiff(
                reference=returned_reference,
                content=b"different",
            ),
        )
        assert (
            run_review_agent(
                wrong_agent,
                request.request_id,
                stdin=TtyInput(f"APPROVE {request.descriptor_sha256[:16]}\n"),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )
            == 2
        )
        assert harness.service.get(request.request_id).state == "pending"

        output = io.StringIO()
        safe_agent = ReviewAgent(
            service=harness.service,
            signer=harness.signer,
            render_verified_diff=lambda returned_reference: VerifiedReviewDiff(
                reference=returned_reference,
                content=hostile,
            ),
        )
        assert (
            run_review_agent(
                safe_agent,
                request.request_id,
                stdin=TtyInput(f"APPROVE {request.descriptor_sha256[:16]}\n"),
                stdout=output,
                stderr=io.StringIO(),
            )
            == 0
        )
        assert "\\u001b[2J\\u000d" in output.getvalue()
        assert "\x1b" not in output.getvalue()
    finally:
        harness.close()
