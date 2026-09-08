"""Client fact-state and bitemporal value objects."""

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from .common import StrictModel, UtcDateTime


class FactState(StrictModel):
    review_status: Literal["proposed", "reviewed", "approved", "rejected"]
    validity_status: Literal["active", "superseded", "invalidated", "historical"]
    resolution_status: Literal["open", "resolved", "not_applicable"]
    epistemic_status: Literal["asserted", "uncertain", "disputed"]


class BitemporalWindow(StrictModel):
    effective_from: UtcDateTime
    effective_to: UtcDateTime | None
    recorded_at: UtcDateTime
    superseded_at: UtcDateTime | None

    @model_validator(mode="after")
    def _validate_endpoints(self) -> "BitemporalWindow":
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("effective_to must be later than effective_from")
        if self.superseded_at is not None and self.superseded_at < self.recorded_at:
            raise ValueError("superseded_at must not be earlier than recorded_at")
        return self
