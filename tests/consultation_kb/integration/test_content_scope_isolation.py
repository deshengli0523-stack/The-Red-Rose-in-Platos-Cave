from __future__ import annotations

from pathlib import Path

import pytest

from consultation_kb.core.ids import IdFactory
from consultation_kb.vault.content_store import ContentScopeMismatch, ContentStore


def test_equal_bytes_are_three_scope_local_physical_objects(tmp_path: Path) -> None:
    stores = {
        name: ContentStore(tmp_path / name)
        for name in ("global", "client_a", "client_b")
    }
    payload = b'{"canonical":true}\n'
    references = {}
    for name, store in stores.items():
        staged = store.stage_bytes(
            payload,
            purpose="knowledge",
            manifest_id=IdFactory().object_id("manifest"),
            media_type="application/json",
        )
        references[name] = store.finalize(staged)

    assert len({ref.content_sha256 for ref in references.values()}) == 1
    assert len({ref.path for ref in references.values()}) == 3
    assert all(ref.path.is_file() for ref in references.values())

    for own_name, store in stores.items():
        for foreign_name, reference in references.items():
            if own_name == foreign_name:
                assert store.read_verified(reference) == payload
            else:
                with pytest.raises(ContentScopeMismatch):
                    store.read_verified(reference)
