"""Pure-local document extraction with canonical source coordinates."""

from __future__ import annotations

import csv
import hashlib
import importlib
import io
import re
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import model_validator

from consultation_kb.models.common import NonEmptyStr, StrictModel, VersionRef
from consultation_kb.models.evidence import EvidenceLocator, LocatorKind
from consultation_kb.models.knowledge import DocumentType

from .anchors import deterministic_object_id, locator_policy_ref


class ExtractionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ExtractedBlock(StrictModel):
    text: NonEmptyStr
    document_type: DocumentType
    extractor_version: NonEmptyStr
    structural_path: NonEmptyStr
    locator: EvidenceLocator
    metadata: dict[str, str | int] = {}


class ExtractionResult(StrictModel):
    status: Literal["ok", "quarantined"]
    document_type: DocumentType
    blocks: tuple[ExtractedBlock, ...]
    quarantine_reason: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _validate_state(self) -> "ExtractionResult":
        if self.status == "ok" and (not self.blocks or self.quarantine_reason is not None):
            raise ValueError("successful extraction requires blocks and no quarantine reason")
        if self.status == "quarantined" and (
            self.blocks or self.quarantine_reason is None
        ):
            raise ValueError("quarantine requires an explicit reason and no blocks")
        return self


def _anchor_ref(seed: bytes, locator: str) -> VersionRef:
    digest = hashlib.sha256(seed + b"\x00" + locator.encode("ascii")).hexdigest()
    return VersionRef(
        object_id=deterministic_object_id("source_anchor", digest),
        version=1,
        content_sha256=digest,
    )


def _locator(
    *,
    kind: LocatorKind,
    display: str,
    source_bytes: bytes,
) -> EvidenceLocator:
    return EvidenceLocator(
        locator_kind=kind,
        anchor_refs=(_anchor_ref(source_bytes, display),),
        display_locator=display,
        locator_policy_ref=locator_policy_ref(),
    )


def _nonblank(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if normalized:
        return normalized[:80]
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


class DocumentExtractor:
    """Dispatch extraction exclusively by local file suffix."""

    VERSION = "local-layout-v1"

    def extract(self, path: Path) -> ExtractionResult:
        if type(path) is not Path:
            path = Path(path)
        try:
            source_bytes = path.read_bytes()
        except OSError as exc:
            raise ExtractionError("SOURCE_READ_FAILED") from exc
        suffix = path.suffix.lower().lstrip(".")
        if suffix not in {"txt", "md", "pdf", "docx", "xlsx", "csv"}:
            raise ExtractionError("DOCUMENT_TYPE_UNSUPPORTED")
        document_type = cast(DocumentType, suffix)
        method = getattr(self, f"_extract_{suffix}")
        blocks = method(source_bytes)
        if document_type == "pdf" and not blocks:
            return ExtractionResult(
                status="quarantined",
                document_type="pdf",
                blocks=(),
                quarantine_reason="SCANNED_PDF_OCR_REQUIRED",
            )
        if not blocks:
            raise ExtractionError("DOCUMENT_EMPTY")
        return ExtractionResult(
            status="ok",
            document_type=document_type,
            blocks=tuple(blocks),
        )

    def _extract_txt(self, source_bytes: bytes) -> list[ExtractedBlock]:
        return self._extract_lines(source_bytes, "txt")

    def _extract_md(self, source_bytes: bytes) -> list[ExtractedBlock]:
        return self._extract_lines(source_bytes, "md")

    def _extract_lines(
        self,
        source_bytes: bytes,
        document_type: Literal["txt", "md"],
    ) -> list[ExtractedBlock]:
        try:
            lines = source_bytes.decode("utf-8-sig", errors="strict").splitlines()
        except UnicodeDecodeError as exc:
            raise ExtractionError("SOURCE_ENCODING_UNSUPPORTED") from exc
        heading_path: list[str] = []
        result: list[ExtractedBlock] = []
        for ordinal, raw in enumerate(lines, 1):
            text = raw.strip()
            if not text:
                continue
            if document_type == "md" and text.startswith("#"):
                level = len(text) - len(text.lstrip("#"))
                title = text[level:].strip()
                if title:
                    heading_path = heading_path[: max(level - 1, 0)] + [_slug(title)]
            prefix = "/".join(heading_path) if heading_path else "document"
            structural_path = f"{prefix}/line-{ordinal}"
            display = f"lines:{ordinal}-{ordinal}"
            result.append(
                ExtractedBlock(
                    text=text,
                    document_type=document_type,
                    extractor_version=self.VERSION,
                    structural_path=structural_path,
                    locator=_locator(
                        kind="source_line_span",
                        display=display,
                        source_bytes=source_bytes,
                    ),
                    metadata={"line": ordinal},
                )
            )
        return result

    def _extract_csv(self, source_bytes: bytes) -> list[ExtractedBlock]:
        try:
            text = source_bytes.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise ExtractionError("SOURCE_ENCODING_UNSUPPORTED") from exc
        result: list[ExtractedBlock] = []
        for row_number, row in enumerate(csv.reader(io.StringIO(text)), 1):
            values = [value.strip() for value in row]
            if not any(values):
                continue
            end_column = max(len(values), 1)
            display = (
                f"table:1;rows:{row_number}-{row_number};"
                f"columns:1-{end_column}"
            )
            result.append(
                ExtractedBlock(
                    text=" | ".join(values),
                    document_type="csv",
                    extractor_version=self.VERSION,
                    structural_path=f"table-1/row-{row_number}",
                    locator=_locator(
                        kind="source_table_span",
                        display=display,
                        source_bytes=source_bytes,
                    ),
                    metadata={"table": 1, "row": row_number},
                )
            )
        return result

    def _extract_pdf(self, source_bytes: bytes) -> list[ExtractedBlock]:
        try:
            pypdf: Any = importlib.import_module("pypdf")
        except ImportError as exc:
            raise ExtractionError("OPTIONAL_EXTRACTOR_MISSING") from exc
        try:
            reader = pypdf.PdfReader(io.BytesIO(source_bytes))
            result: list[ExtractedBlock] = []
            for page_number, page in enumerate(reader.pages, 1):
                extracted = page.extract_text() or ""
                fragments = [item.strip() for item in extracted.splitlines() if item.strip()]
                for block_number, text in enumerate(fragments, 1):
                    display = (
                        f"pages:{page_number}:{block_number}-"
                        f"{page_number}:{block_number}"
                    )
                    result.append(
                        ExtractedBlock(
                            text=text,
                            document_type="pdf",
                            extractor_version=self.VERSION,
                            structural_path=f"page-{page_number}/block-{block_number}",
                            locator=_locator(
                                kind="source_page_span",
                                display=display,
                                source_bytes=source_bytes,
                            ),
                            metadata={"page": page_number, "block": block_number},
                        )
                    )
            return result
        except ExtractionError:
            raise
        except Exception as exc:
            raise ExtractionError("DOCUMENT_PARSE_FAILED") from exc

    def _extract_docx(self, source_bytes: bytes) -> list[ExtractedBlock]:
        try:
            docx: Any = importlib.import_module("docx")
        except ImportError as exc:
            raise ExtractionError("OPTIONAL_EXTRACTOR_MISSING") from exc
        try:
            document = docx.Document(io.BytesIO(source_bytes))
            result: list[ExtractedBlock] = []
            for paragraph_number, paragraph in enumerate(document.paragraphs, 1):
                text = paragraph.text.strip()
                if not text:
                    continue
                display = f"paragraphs:{paragraph_number}-{paragraph_number}"
                result.append(
                    ExtractedBlock(
                        text=text,
                        document_type="docx",
                        extractor_version=self.VERSION,
                        structural_path=f"paragraph-{paragraph_number}",
                        locator=_locator(
                            kind="source_paragraph_span",
                            display=display,
                            source_bytes=source_bytes,
                        ),
                        metadata={"paragraph": paragraph_number},
                    )
                )
            for table_number, table in enumerate(document.tables, 1):
                for row_number, row in enumerate(table.rows, 1):
                    values = [cell.text.strip() for cell in row.cells]
                    if not any(values):
                        continue
                    display = (
                        f"table:{table_number};rows:{row_number}-{row_number};"
                        f"columns:1-{max(len(values), 1)}"
                    )
                    result.append(
                        ExtractedBlock(
                            text=" | ".join(values),
                            document_type="docx",
                            extractor_version=self.VERSION,
                            structural_path=f"table-{table_number}/row-{row_number}",
                            locator=_locator(
                                kind="source_table_span",
                                display=display,
                                source_bytes=source_bytes,
                            ),
                            metadata={"table": table_number, "row": row_number},
                        )
                    )
            return result
        except ExtractionError:
            raise
        except Exception as exc:
            raise ExtractionError("DOCUMENT_PARSE_FAILED") from exc

    def _extract_xlsx(self, source_bytes: bytes) -> list[ExtractedBlock]:
        try:
            openpyxl: Any = importlib.import_module("openpyxl")
        except ImportError as exc:
            raise ExtractionError("OPTIONAL_EXTRACTOR_MISSING") from exc
        try:
            workbook = openpyxl.load_workbook(
                io.BytesIO(source_bytes), read_only=True, data_only=True
            )
            result: list[ExtractedBlock] = []
            for sheet_number, sheet in enumerate(workbook.worksheets, 1):
                for row_number, row in enumerate(sheet.iter_rows(), 1):
                    cells = [cell for cell in row if _nonblank(cell.value) is not None]
                    if not cells:
                        continue
                    first, last = cells[0], cells[-1]
                    values = [str(cell.value).strip() for cell in cells]
                    display = (
                        f"sheet:{sheet_number};range:{first.column_letter}{row_number}-"
                        f"{last.column_letter}{row_number}"
                    )
                    result.append(
                        ExtractedBlock(
                            text=" | ".join(values),
                            document_type="xlsx",
                            extractor_version=self.VERSION,
                            structural_path=f"sheet-{sheet_number}/row-{row_number}",
                            locator=_locator(
                                kind="source_sheet_range",
                                display=display,
                                source_bytes=source_bytes,
                            ),
                            metadata={"sheet": sheet_number, "row": row_number},
                        )
                    )
            workbook.close()
            return result
        except ExtractionError:
            raise
        except Exception as exc:
            raise ExtractionError("DOCUMENT_PARSE_FAILED") from exc


__all__ = [
    "DocumentExtractor",
    "ExtractedBlock",
    "ExtractionError",
    "ExtractionResult",
]
