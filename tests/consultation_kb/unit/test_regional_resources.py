from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal, cast

import pytest

from consultation_kb.models.common import VersionRef
from consultation_kb.risk.resources import (
    RegionalResource,
    RegionalResourceCatalog,
    ResourceReviewRequired,
)


NOW = datetime(2026, 7, 19, 10, 0, tzinfo=timezone.utc)


def _ref(kind: str, suffix: int) -> VersionRef:
    return VersionRef(
        object_id=f"{kind}_018f0000-0000-7000-8000-{suffix:012x}",
        version=1,
        content_sha256=f"{suffix % 16:x}" * 64,
    )


def _resource(
    suffix: int,
    *,
    status: Literal["draft", "approved", "revoked"] = "approved",
    region: str = "cn_shanghai",
    expires_delta: int = 30,
) -> RegionalResource:
    return RegionalResource(
        resource_id=f"regional_resource_018f0000-0000-7000-8000-{suffix:012x}",
        status=status,
        regions=(region,),
        public_text_ref=_ref("public_resource_text", suffix),
        source_ref=_ref("public_resource_source", suffix + 100),
        reviewed_at=NOW - timedelta(days=30),
        review_expires_at=NOW + timedelta(days=expires_delta),
    )


def test_only_approved_region_matched_unexpired_resources_are_projected() -> None:
    approved = _resource(1)
    other_region = _resource(2, region="cn_beijing")
    catalog = RegionalResourceCatalog((approved, other_region))
    selected = catalog.approved_for("cn_shanghai", as_of=NOW)
    assert len(selected) == 1
    assert selected[0].public_text_ref == approved.public_text_ref
    assert set(selected[0].model_dump()) == {"resource_id", "public_text_ref"}


@pytest.mark.parametrize("status", ["draft", "revoked"])
def test_unapproved_resource_requires_review(status: str) -> None:
    catalog = RegionalResourceCatalog(
        (
            _resource(
                3,
                status=cast(Literal["draft", "approved", "revoked"], status),
            ),
        )
    )
    with pytest.raises(ResourceReviewRequired, match="RESOURCE_REVIEW_REQUIRED"):
        catalog.approved_for("cn_shanghai", as_of=NOW)


def test_expired_contact_is_never_returned_and_requires_review() -> None:
    catalog = RegionalResourceCatalog((_resource(4, expires_delta=-1),))
    with pytest.raises(ResourceReviewRequired, match="RESOURCE_REVIEW_REQUIRED"):
        catalog.approved_for("cn_shanghai", as_of=NOW)


def test_resource_expiring_exactly_at_lookup_time_is_not_unexpired() -> None:
    catalog = RegionalResourceCatalog((_resource(40, expires_delta=0),))
    with pytest.raises(ResourceReviewRequired, match="RESOURCE_REVIEW_REQUIRED"):
        catalog.approved_for("cn_shanghai", as_of=NOW)


def test_unknown_region_has_no_automatic_fallback() -> None:
    catalog = RegionalResourceCatalog((_resource(5),))
    assert catalog.approved_for("cn_guangdong", as_of=NOW) == ()


def test_future_dated_review_is_not_treated_as_current() -> None:
    future = _resource(6).model_copy(
        update={
            "reviewed_at": NOW + timedelta(days=1),
            "review_expires_at": NOW + timedelta(days=31),
        }
    )
    with pytest.raises(ResourceReviewRequired, match="RESOURCE_REVIEW_REQUIRED"):
        RegionalResourceCatalog((future,)).approved_for("cn_shanghai", as_of=NOW)
