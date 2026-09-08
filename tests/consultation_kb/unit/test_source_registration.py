from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from consultation_kb.core.clock import FixedClock
from consultation_kb.core.ids import IdFactory
from consultation_kb.knowledge.registrar import SourceRegistrar, SourceRegistrationError
from consultation_kb.models.knowledge import SourceMetadata
from consultation_kb.storage.connection import connect_database
from consultation_kb.storage.migrate import MigrationRunner
from consultation_kb.vault.content_store import ContentStore


NOW = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)


@pytest.fixture
def registrar(
    tmp_path: Path,
) -> Iterator[tuple[SourceRegistrar, Path, sqlite3.Connection]]:
    root = tmp_path / "knowledge-vault"
    sources = root / "sources"
    sources.mkdir(parents=True)
    connection = connect_database(root / "global.sqlite3", mode="writer")
    MigrationRunner.for_scope(connection, "global").apply()
    counter = iter(range(1, 1000))
    value = SourceRegistrar(
        connection,
        sources_root=sources,
        content_store=ContentStore(root / "global-content"),
        id_factory=IdFactory(FixedClock(NOW), lambda: next(counter)),
        clock=FixedClock(NOW),
    )
    yield value, sources, connection
    connection.close()


def _metadata(**updates: object) -> SourceMetadata:
    values: dict[str, object] = {
        "license": "user_authorized",
        "domain": "traditional_culture",
        "language": "zh-CN",
        "sensitivity": "internal",
        "source_grade": "T1",
        "document_type": "md",
    }
    values.update(updates)
    return SourceMetadata.model_validate(values)


def test_changed_source_creates_new_version(
    registrar: tuple[SourceRegistrar, Path, sqlite3.Connection],
) -> None:
    service, sources, _ = registrar
    source_file = sources / "classic.md"
    source_file.write_text("第一个明确合成版本", encoding="utf-8")
    first = service.register_local_file(source_file, _metadata())
    same = service.register_local_file(source_file, _metadata())
    source_file.write_text("第二个明确合成版本", encoding="utf-8")
    second = service.register_local_file(source_file, _metadata())

    assert same == first
    assert second.source_id == first.source_id
    assert second.version == first.version + 1
    assert second.content_sha256 != first.content_sha256
    assert service.get(first.source_id, first.version).content_sha256 == first.content_sha256


def test_metadata_only_change_creates_governed_revision_and_invalidation(
    registrar: tuple[SourceRegistrar, Path, sqlite3.Connection],
) -> None:
    service, sources, connection = registrar
    source_file = sources / "classic.md"
    source_file.write_text("相同正文", encoding="utf-8")
    first = service.register_local_file(source_file, _metadata())
    second = service.register_local_file(
        source_file,
        _metadata(sensitivity="restricted"),
    )

    assert second.source_id == first.source_id
    assert second.version == 2
    assert second.content_sha256 == first.content_sha256
    assert connection.execute(
        """
        SELECT catalog_version, authorization_epoch
          FROM knowledge_catalog_state WHERE singleton = 1
        """
    ).fetchone() == (2, 1)
    assert connection.execute(
        "SELECT count(*) FROM rebuild_queue"
    ).fetchone() == (1,)


def test_rollback_to_historical_content_creates_monotonic_revision(
    registrar: tuple[SourceRegistrar, Path, sqlite3.Connection],
) -> None:
    service, sources, _ = registrar
    source_file = sources / "classic.md"
    source_file.write_text("版本 A", encoding="utf-8")
    first = service.register_local_file(source_file, _metadata())
    source_file.write_text("版本 B", encoding="utf-8")
    second = service.register_local_file(source_file, _metadata())
    source_file.write_text("版本 A", encoding="utf-8")
    third = service.register_local_file(source_file, _metadata())

    assert (first.version, second.version, third.version) == (1, 2, 3)
    assert third.content_sha256 == first.content_sha256


def test_windows_case_variants_resolve_to_one_logical_source(
    registrar: tuple[SourceRegistrar, Path, sqlite3.Connection],
) -> None:
    service, sources, connection = registrar
    lower = sources / "classic.md"
    lower.write_text("同一文件", encoding="utf-8")
    first = service.register_local_file(lower, _metadata())
    upper = sources / "CLASSIC.md"
    second = service.register_local_file(upper, _metadata())

    assert second == first
    assert connection.execute(
        "SELECT count(*) FROM sources"
    ).fetchone() == (1,)


def test_source_must_be_inside_sources_root(
    registrar: tuple[SourceRegistrar, Path, sqlite3.Connection], tmp_path: Path
) -> None:
    service, _, _ = registrar
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    with pytest.raises(SourceRegistrationError, match="SOURCE_OUTSIDE_ROOT"):
        service.register_local_file(outside, _metadata())


def test_c1_requires_consultant_theory_directory(
    registrar: tuple[SourceRegistrar, Path, sqlite3.Connection],
) -> None:
    service, sources, _ = registrar
    wrong = sources / "ordinary.md"
    wrong.write_text("咨询师理论", encoding="utf-8")
    with pytest.raises(SourceRegistrationError, match="C1_SOURCE_DIRECTORY_REQUIRED"):
        service.register_local_file(wrong, _metadata(source_grade="C1"))

    directory = sources / "consultant-theory"
    directory.mkdir()
    correct = directory / "formal.md"
    correct.write_text("咨询师理论", encoding="utf-8")
    record = service.register_local_file(correct, _metadata(source_grade="C1"))
    assert record.metadata.source_grade == "C1"


@pytest.mark.parametrize("missing", ["license", "domain", "language", "sensitivity"])
def test_required_source_metadata_cannot_be_omitted(missing: str) -> None:
    values = _metadata().model_dump()
    del values[missing]
    with pytest.raises(ValidationError):
        SourceMetadata(**values)
