"""Reviewed, region-scoped public resources safe for optional projection."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, ValidationError, field_validator, model_validator

from consultation_kb.models.common import (
    ObjectId,
    SafePolicyKey,
    StrictModel,
    UtcDateTime,
    VersionRef,
)


_REGION_ADAPTER: TypeAdapter[str] = TypeAdapter(SafePolicyKey)
_UTC_ADAPTER: TypeAdapter[datetime] = TypeAdapter(UtcDateTime)


class ResourceReviewRequired(RuntimeError):
    def __init__(self) -> None:
        super().__init__("RESOURCE_REVIEW_REQUIRED")


class RegionalResource(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    resource_id: ObjectId
    status: Literal["draft", "approved", "revoked"]
    regions: Annotated[
        tuple[SafePolicyKey, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]
    public_text_ref: VersionRef
    source_ref: VersionRef
    reviewed_at: UtcDateTime
    review_expires_at: UtcDateTime

    @field_validator("regions")
    @classmethod
    def _canonical_regions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("resource regions must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _review_interval(self) -> "RegionalResource":
        if self.review_expires_at < self.reviewed_at:
            raise ValueError("resource review expiry cannot predate review")
        return self


class ApprovedRegionalResource(StrictModel):
    """Narrow projection type: no phone, URL, or unreviewed prose."""

    resource_id: ObjectId
    public_text_ref: VersionRef


class RegionalResourceCatalog:
    def __init__(self, resources: tuple[RegionalResource, ...]) -> None:
        exact = tuple(RegionalResource.model_validate(value) for value in resources)
        if len({value.resource_id for value in exact}) != len(exact):
            raise ValueError("regional resource IDs must be unique")
        self._resources = exact

    def approved_for(
        self,
        region: SafePolicyKey,
        *,
        as_of: UtcDateTime,
    ) -> tuple[ApprovedRegionalResource, ...]:
        try:
            exact_region = _REGION_ADAPTER.validate_python(region, strict=True)
            exact_as_of = _UTC_ADAPTER.validate_python(as_of, strict=True)
        except ValidationError:
            raise ValueError("resource lookup requires canonical region and UTC time") from None
        matching = tuple(
            resource for resource in self._resources if exact_region in resource.regions
        )
        current = tuple(
            resource
            for resource in matching
            if resource.status == "approved"
            and resource.reviewed_at <= exact_as_of
            and resource.review_expires_at > exact_as_of
        )
        if current:
            return tuple(
                ApprovedRegionalResource(
                    resource_id=resource.resource_id,
                    public_text_ref=resource.public_text_ref,
                )
                for resource in sorted(current, key=lambda item: item.resource_id)
            )
        if matching:
            raise ResourceReviewRequired
        return ()


__all__ = [
    "ApprovedRegionalResource",
    "RegionalResource",
    "RegionalResourceCatalog",
    "ResourceReviewRequired",
]
