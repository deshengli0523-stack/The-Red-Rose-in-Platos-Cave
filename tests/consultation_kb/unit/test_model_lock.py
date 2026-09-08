from __future__ import annotations

import json
from pathlib import Path

import pytest

from consultation_kb.models.model_lock import (
    ModelLockError,
    hash_model_tree,
    load_tracked_model_spec,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TRACKED_MODELS = REPOSITORY_ROOT / "models" / "consultation-models.json"


def _tracked_payload() -> dict[str, object]:
    return json.loads(TRACKED_MODELS.read_text(encoding="utf-8"))


def _write_payload(tmp_path: Path, payload: dict[str, object]) -> Path:
    target = tmp_path / "consultation-models.json"
    target.write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
    return target


def test_tracked_candidate_file_is_complete_portable_and_offline() -> None:
    raw = TRACKED_MODELS.read_text(encoding="utf-8")
    tracked = load_tracked_model_spec(TRACKED_MODELS)

    assert "revision" not in raw
    assert {(item.role, item.repo) for item in tracked.candidates} == {
        ("embedding", "BAAI/bge-m3"),
        ("embedding", "BAAI/bge-small-zh-v1.5"),
        ("reranker", "BAAI/bge-reranker-v2-m3"),
        ("reranker", "BAAI/bge-reranker-base"),
    }
    assert len(tracked.canonical_sha256) == 64
    for item in tracked.candidates:
        assert not Path(item.artifact_relpath).is_absolute()
        assert "\\" not in item.artifact_relpath
        assert ":" not in item.artifact_relpath
        assert item.load_policy.local_files_only is True
        assert item.load_policy.trust_remote_code is False
        assert item.load_policy.hf_hub_offline == "1"
        assert item.load_policy.transformers_offline == "1"


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "C:/models/bge-m3",
        "\\\\server\\share\\bge-m3",
        "/srv/models/bge-m3",
        "~/models/bge-m3",
        "../models/bge-m3",
        "embedding//bge-m3",
    ),
)
def test_tracked_candidate_rejects_machine_local_and_traversing_paths(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    payload = _tracked_payload()
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    candidates[0]["artifact_relpath"] = unsafe_path

    with pytest.raises(ModelLockError) as caught:
        load_tracked_model_spec(_write_payload(tmp_path, payload))

    assert caught.value.code == "MODEL_CANDIDATE_SPEC_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("api_key", "not-allowed"),
        ("notes", "https://huggingface.co/BAAI/bge-m3?token=not-allowed"),
        ("notes", "https://operator:not-allowed@huggingface.co/BAAI/bge-m3"),
    ),
)
def test_tracked_candidate_rejects_credentials_and_url_tokens(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    payload = _tracked_payload()
    payload[field] = value

    with pytest.raises(ModelLockError) as caught:
        load_tracked_model_spec(_write_payload(tmp_path, payload))

    assert caught.value.code == "MODEL_CANDIDATE_SPEC_INVALID"


def test_tracked_candidate_requires_explicit_offline_policy(tmp_path: Path) -> None:
    payload = _tracked_payload()
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    del candidates[0]["load_policy"]["local_files_only"]

    with pytest.raises(ModelLockError) as caught:
        load_tracked_model_spec(_write_payload(tmp_path, payload))

    assert caught.value.code == "MODEL_CANDIDATE_SPEC_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("model_id", "renamed_model"),
        ("artifact_relpath", "embedding/renamed-model"),
    ),
)
def test_tracked_candidate_rejects_logical_binding_drift(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    payload = _tracked_payload()
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    candidates[0][field] = value

    with pytest.raises(ModelLockError) as caught:
        load_tracked_model_spec(_write_payload(tmp_path, payload))

    assert caught.value.code == "MODEL_CANDIDATE_SPEC_INVALID"


def test_tracked_candidate_rejects_unregistered_adapter(tmp_path: Path) -> None:
    payload = _tracked_payload()
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    candidates[0]["encoding"]["adapter_class"] = "malicious.DynamicLoader"

    with pytest.raises(ModelLockError) as caught:
        load_tracked_model_spec(_write_payload(tmp_path, payload))

    assert caught.value.code == "MODEL_CANDIDATE_SPEC_INVALID"


def test_model_tree_hashes_every_regular_file_in_canonical_order(
    tmp_path: Path,
) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "nested" / "weights.bin").write_bytes(b"weights")
    (tmp_path / "tokenizer.json").write_text("{}", encoding="utf-8")

    files = hash_model_tree(tmp_path)

    assert [item.relative_path for item in files] == [
        "config.json",
        "nested/weights.bin",
        "tokenizer.json",
    ]
    assert all(len(item.sha256) == 64 for item in files)
