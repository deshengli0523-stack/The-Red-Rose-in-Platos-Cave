from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from consultation_kb.core.ids import IdFactory
from consultation_kb.vault.content_store import (
    ContentHashMismatch,
    ContentObjectRef,
    ContentScopeMismatch,
    ContentStore,
    InvalidContentReference,
)


def _manifest_id() -> str:
    return IdFactory().object_id("manifest")


def _put(store: ContentStore, data: bytes = b'{"a":1}\n') -> ContentObjectRef:
    return store.finalize(
        store.stage_bytes(
            data,
            purpose="test",
            manifest_id=_manifest_id(),
            media_type="application/json",
        )
    )


def _make_directory_reparse(link: Path, target: Path) -> None:
    if os.name == "nt":
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.fail(f"unable to create test junction: {result.stderr}")
        return
    link.symlink_to(target, target_is_directory=True)


def test_content_store_deduplicates_only_inside_one_scope(tmp_path: Path) -> None:
    store = ContentStore(tmp_path)
    first = _put(store)
    second = _put(store)

    assert first.path == second.path
    assert first.content_sha256 == second.content_sha256
    assert store.read_verified(second) == b'{"a":1}\n'


def test_content_store_detects_tampering(tmp_path: Path) -> None:
    store = ContentStore(tmp_path)
    reference = _put(store)
    reference.path.write_bytes(b'{"a":2}\n')

    with pytest.raises(ContentHashMismatch, match="^CONTENT_HASH_MISMATCH$"):
        store.read_verified(reference)


def test_finalize_rehashes_staged_payload(tmp_path: Path) -> None:
    store = ContentStore(tmp_path)
    staged = store.stage_bytes(
        b"original",
        purpose="test",
        manifest_id=_manifest_id(),
        media_type="application/octet-stream",
    )
    staged._path.write_bytes(b"changed")

    with pytest.raises(ContentHashMismatch):
        store.finalize(staged)


def test_reference_is_bound_to_its_physical_scope(tmp_path: Path) -> None:
    left = ContentStore(tmp_path / "left")
    right = ContentStore(tmp_path / "right")
    left_ref = _put(left)
    right_ref = _put(right)
    assert left_ref.content_sha256 == right_ref.content_sha256
    assert left_ref.path != right_ref.path

    with pytest.raises(ContentScopeMismatch, match="^CONTENT_SCOPE_MISMATCH$"):
        left.read_verified(right_ref)


def test_staged_reference_cannot_be_finalized_in_another_scope(tmp_path: Path) -> None:
    left = ContentStore(tmp_path / "left")
    right = ContentStore(tmp_path / "right")
    staged = right.stage_bytes(
        b"same",
        purpose="test",
        manifest_id=_manifest_id(),
        media_type="text/plain",
    )

    with pytest.raises(ContentScopeMismatch):
        left.finalize(staged)


@pytest.mark.parametrize(
    ("purpose", "media_type"),
    [
        ("../escape", "text/plain"),
        ("escape/path", "text/plain"),
        ("valid", "text/plain\nunsafe"),
    ],
)
def test_staging_rejects_path_capable_components(
    tmp_path: Path,
    purpose: str,
    media_type: str,
) -> None:
    with pytest.raises(InvalidContentReference):
        ContentStore(tmp_path).stage_bytes(
            b"safe",
            purpose=purpose,
            manifest_id=_manifest_id(),
            media_type=media_type,
        )


def test_internal_reference_has_no_automatic_serialization_surface(
    tmp_path: Path,
) -> None:
    reference = _put(ContentStore(tmp_path))
    assert str(tmp_path) not in repr(reference)
    assert not hasattr(reference, "model_dump")
    assert not hasattr(reference, "__dict__")
    with pytest.raises(TypeError):
        json.dumps(reference)


def test_content_store_rejects_a_hardlinked_cas_object(tmp_path: Path) -> None:
    store = ContentStore(tmp_path / "scope")
    reference = _put(store)
    os.link(reference.path, tmp_path / "outside-alias")

    with pytest.raises(ContentHashMismatch, match="^CONTENT_HASH_MISMATCH$"):
        store.read_hash_verified(reference.content_sha256)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory sharing contract")
def test_content_store_pins_every_write_ancestor_against_rename(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "scope"
    observed_phases: list[str] = []

    def attempt_ancestor_swap(phase: str, directory: Path) -> None:
        ancestors = []
        ancestor = directory
        while True:
            ancestors.append(ancestor)
            if ancestor == scope:
                break
            ancestor = ancestor.parent
        for index, ancestor in enumerate(ancestors):
            replacement = tmp_path / f"replacement-{phase}-{index}"
            with pytest.raises(OSError):
                ancestor.rename(replacement)
        observed_phases.append(phase)

    store = ContentStore(scope, write_hook=attempt_ancestor_swap)
    reference = _put(store, b"directory-pins")

    assert observed_phases == ["stage", "finalize"]
    assert store.read_verified(reference) == b"directory-pins"
    assert not any(tmp_path.glob("replacement-*"))


def test_stage_rejects_preexisting_reparse_without_writing_through_it(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "scope"
    outside = tmp_path / "outside"
    scope.mkdir()
    outside.mkdir()
    _make_directory_reparse(scope / ".staging", outside)

    with pytest.raises(InvalidContentReference):
        ContentStore(scope).stage_bytes(
            b"must-not-escape",
            purpose="test",
            manifest_id=_manifest_id(),
            media_type="application/octet-stream",
        )
    assert list(outside.iterdir()) == []


def test_finalize_rejects_preexisting_reparse_without_writing_through_it(
    tmp_path: Path,
) -> None:
    scope = tmp_path / "scope"
    outside = tmp_path / "outside"
    outside.mkdir()
    store = ContentStore(scope)
    staged = store.stage_bytes(
        b"must-not-escape",
        purpose="test",
        manifest_id=_manifest_id(),
        media_type="application/octet-stream",
    )
    _make_directory_reparse(scope / "objects", outside)

    with pytest.raises(InvalidContentReference):
        store.finalize(staged)
    assert list(outside.iterdir()) == []
