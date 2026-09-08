"""Fixed, redacted paths derived from a validated application config."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn, SupportsIndex, cast, final

from consultation_kb.core.config import AppConfig


_VALIDATED_CONFIG_ERROR = "VAULT_VALIDATED_CONFIG_REQUIRED"
_SERIALIZATION_ERROR = "VAULT_SERIALIZATION_FORBIDDEN"
_FROZEN_ERROR = "VAULT_LAYOUT_FROZEN"


@final
class VaultLayout:
    """An immutable value object containing only fixed vault paths."""

    __slots__ = ("_vault_root",)

    _vault_root: Path

    def __new__(cls, *_args: object, **_kwargs: object) -> NoReturn:
        del cls, _args, _kwargs
        raise TypeError(_VALIDATED_CONFIG_ERROR)

    @classmethod
    def from_config(cls, config: AppConfig) -> VaultLayout:
        """Derive the fixed layout from one exact validated config."""
        if type(config) is not AppConfig:
            raise TypeError(_VALIDATED_CONFIG_ERROR)
        instance = object.__new__(cls)
        object.__setattr__(instance, "_vault_root", config.vault_root)
        return instance

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del self, name, value
        raise AttributeError(_FROZEN_ERROR)

    def __delattr__(self, name: str) -> NoReturn:
        del self, name
        raise AttributeError(_FROZEN_ERROR)

    def __repr__(self) -> str:
        return "<VaultLayout redacted>"

    def __eq__(self, other: object) -> bool:
        if type(other) is not VaultLayout:
            return False
        other_layout = cast(VaultLayout, other)
        return self._vault_root == other_layout._vault_root

    def __hash__(self) -> int:
        return hash(self._vault_root)

    def __copy__(self) -> NoReturn:
        raise TypeError(_SERIALIZATION_ERROR)

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise TypeError(_SERIALIZATION_ERROR)

    def __reduce__(self) -> NoReturn:
        raise TypeError(_SERIALIZATION_ERROR)

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError(_SERIALIZATION_ERROR)

    @property
    def identity_map(self) -> Path:
        return self._vault_root / "identity" / "identity-map.enc"

    @property
    def sources(self) -> Path:
        return self._vault_root / "sources"

    @property
    def wiki_draft(self) -> Path:
        return self._vault_root / "wiki" / "draft"

    @property
    def wiki_approved(self) -> Path:
        return self._vault_root / "wiki" / "approved"

    @property
    def wiki_history(self) -> Path:
        return self._vault_root / "wiki" / "history"

    @property
    def global_db(self) -> Path:
        return self._vault_root / "global" / "catalog.sqlite3"

    @property
    def global_graph(self) -> Path:
        return self._vault_root / "global" / "graph" / "graph.json"

    @property
    def lexical_indexes(self) -> Path:
        return self._vault_root / "global" / "indexes" / "bm25"

    @property
    def vector_indexes(self) -> Path:
        return self._vault_root / "global" / "indexes" / "vector"

    @property
    def cases_draft(self) -> Path:
        return self._vault_root / "cases" / "draft"

    @property
    def cases_approved(self) -> Path:
        return self._vault_root / "cases" / "approved"

    @property
    def cases_quarantine(self) -> Path:
        return self._vault_root / "cases" / "quarantine"

    @property
    def clients_root(self) -> Path:
        return self._vault_root / "clients"

    @property
    def global_objects_root(self) -> Path:
        return self._vault_root / "global" / "objects"

    @property
    def global_staging_root(self) -> Path:
        return self._vault_root / "global" / ".staging"

    @property
    def review_queue(self) -> Path:
        return self._vault_root / "review-queue"

    @property
    def audit_root(self) -> Path:
        return self._vault_root / "audit"

    @property
    def quarantine(self) -> Path:
        return self._vault_root / "quarantine"
