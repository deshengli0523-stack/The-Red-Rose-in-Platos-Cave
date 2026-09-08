from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from tests.consultation_kb.retrieval_support import candidate


def test_candidate_ref_is_body_free_and_forbids_extra_text() -> None:
    value = candidate(1)
    payload = value.model_dump(mode="json")

    serialized = json.dumps(payload, sort_keys=True)
    assert "text" not in payload
    assert "body" not in payload
    assert "raw_content" not in serialized

    with pytest.raises(ValidationError):
        type(value).model_validate({**payload, "text": "forbidden"})


def test_retrieval_candidate_requires_exact_version_and_hash() -> None:
    payload = candidate(2).model_dump(mode="json")
    payload["reference"].pop("content_sha256")

    with pytest.raises(ValidationError):
        type(candidate(2)).model_validate(payload)
