"""Generate and inspect bounded synthetic resume evidence.

Untrusted PDF parsing runs in a fresh ``spawn`` worker for every document.  The
parent supplies the worker only a bounded temporary input file, waits for a
bounded wall-clock interval, and accepts only a strictly decoded JSON result.
On Unix the worker also attempts to lower CPU, address-space, file-size, and
open-file limits.  Those kernel limits are defence in depth: they are not
available on every platform, so the parent deadline and byte bounds remain the
portable enforcement boundary.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import multiprocessing
import os
import tempfile
import textwrap
import time
from collections.abc import Callable, Mapping
from contextlib import redirect_stderr, redirect_stdout, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, cast

import pdfplumber
from pypdf import PdfReader
from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
from reportlab.pdfgen import canvas  # type: ignore[import-untyped]

from cv_trust_agent.dataset import HiddenPlacement

MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PDF_PAGES = 10
MAX_EXTRACTED_CHARACTERS = 100_000
MAX_PDF_LINES = 2_048
MAX_PDF_METADATA_ITEMS = 64
MAX_PDF_RESULT_BYTES = 8 * 1024 * 1024
PDF_DOCUMENT_TIMEOUT_SECONDS = 2.0
PDF_BATCH_TIMEOUT_SECONDS = 20.0
MICROTEXT_MAX_FONT_SIZE = 4.0
_MAX_CHARACTER_RECORDS = 100_000
_WORKER_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
_WORKER_FILE_SIZE_BYTES = MAX_PDF_RESULT_BYTES + 4_096
_WORKER_OPEN_FILES = 64


class _WorkerFailureCode(StrEnum):
    BYTE_LIMIT = "byte_limit"
    PAGE_LIMIT = "page_limit"
    TEXT_LIMIT = "text_limit"
    LINE_LIMIT = "line_limit"
    METADATA_LIMIT = "metadata_limit"
    RESULT_LIMIT = "result_limit"
    PARSING_FAILED = "parsing_failed"


class PdfEvidenceError(ValueError):
    """A PDF cannot safely cross the isolated evidence boundary."""


class PdfEvidenceLimitError(PdfEvidenceError):
    """A PDF exceeds the bounded evidence-processing contract."""

    def __init__(self, message: str, *, code: _WorkerFailureCode) -> None:
        super().__init__(message)
        self.code = code


class PdfEvidenceTimeoutError(PdfEvidenceError):
    """An isolated parser missed its portable parent wall deadline."""


class PdfEvidenceWorkerError(PdfEvidenceError):
    """An isolated parser failed without exposing worker or document text."""


class PdfBatchBudget:
    """One monotonic wall-clock budget shared by a batch of PDF parses.

    The object is intentionally tiny and run-local.  Callers pass the same
    instance to every :func:`extract_pdf_evidence` call in a batch; the parent
    then caps each two-second document deadline by the remaining batch time.
    """

    __slots__ = ("_clock", "_deadline")

    def __init__(
        self,
        timeout_seconds: float = PDF_BATCH_TIMEOUT_SECONDS,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("PDF batch timeout must be a positive finite value")
        self._clock = clock
        self._deadline = clock() + timeout_seconds

    @property
    def remaining_seconds(self) -> float:
        """Return the non-negative time left in this batch."""

        return max(0.0, self._deadline - self._clock())

    @property
    def expired(self) -> bool:
        """Return whether the batch deadline has elapsed."""

        return self.remaining_seconds <= 0.0


@dataclass(frozen=True)
class _PdfWorkerLimits:
    max_pages: int
    max_characters: int
    max_lines: int
    max_metadata_items: int
    max_result_bytes: int
    cpu_seconds: int


class EvidenceVisibility(StrEnum):
    """How a PDF token is presented to a human reader."""

    VISIBLE = "visible"
    LOW_CONTRAST = "low_contrast"
    OFF_PAGE = "off_page"
    METADATA = "metadata"
    MICROTEXT = "microtext"


@dataclass(frozen=True)
class PdfCharacter:
    """One machine-extracted PDF character with its presentation classification."""

    evidence_id: str
    text: str
    page_number: int
    document_page_count: int
    page_width: float
    page_height: float
    x0: float
    x1: float
    top: float
    bottom: float
    font_size: float
    fill_color: tuple[float, ...] | None
    contrast_ratio: float
    visibility: EvidenceVisibility


@dataclass(frozen=True)
class PdfMetadataItem:
    """One PDF document-information value."""

    evidence_id: str
    key: str
    value: str
    visibility: EvidenceVisibility = EvidenceVisibility.METADATA


@dataclass(frozen=True)
class PdfExtraction:
    """Character geometry and metadata extracted from one resume PDF."""

    sha256: str
    page_count: int
    characters: tuple[PdfCharacter, ...]
    metadata: tuple[PdfMetadataItem, ...]

    def text_for(self, visibility: EvidenceVisibility | str) -> str:
        """Concatenate text in extraction order for one presentation class."""

        selected = EvidenceVisibility(visibility)
        if selected is EvidenceVisibility.METADATA:
            return "\n".join(item.value for item in self.metadata)
        return "".join(
            character.text for character in self.characters if character.visibility is selected
        )

    @property
    def visible_text(self) -> str:
        """Return only normally visible page text."""

        return self.text_for(EvidenceVisibility.VISIBLE)


def generate_resume_pdf(
    output_path: Path | str,
    *,
    candidate_id: str,
    ap_years: float,
    invoice_processing: bool,
    reconciliation: bool,
    spreadsheet: str | None,
    accounting_platform: str | None,
    monthly_invoice_volume: int | None,
    qualification: str | None,
    note: str,
    employment_start: str | None,
    employment_end: str | None,
    hidden_claim: str | None = None,
    hidden_placement: HiddenPlacement | str | None = None,
) -> Path:
    """Render a deterministic one-page resume with optional machine-only evidence."""

    if invoice_processing and (employment_start is None or employment_end is None):
        raise ValueError("invoice-processing evidence requires AP employment dates")
    placement = HiddenPlacement(hidden_placement) if hidden_placement is not None else None
    if (hidden_claim is None) != (placement is None):
        raise ValueError("hidden_claim and hidden_placement must be provided together")

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    width, height = A4
    document = canvas.Canvas(
        str(target),
        pagesize=A4,
        invariant=1,
        pageCompression=0,
    )
    document.setAuthor("CV-Trust-Agent synthetic source")
    document.setCreator("CV-Trust-Agent deterministic fixture generator")
    document.setTitle(f"Accounts payable evidence for {candidate_id}")
    document.setSubject(
        hidden_claim
        if hidden_claim is not None and placement is HiddenPlacement.METADATA
        else "Synthetic accounts payable resume evidence"
    )

    document.setFillColorRGB(0.08, 0.08, 0.08)
    document.setFont("Helvetica-Bold", 16)
    document.drawString(54, height - 62, "Accounts Payable Candidate Evidence")
    document.setFont("Helvetica", 10)

    lines = [
        f"Candidate ID: {candidate_id}",
        f"AP years: {ap_years:.1f}",
        f"Invoice processing: {_display_bool(invoice_processing)}",
        f"Reconciliation: {_display_bool(reconciliation)}",
        f"Spreadsheet: {_display_optional(spreadsheet)}",
        f"Accounting platform: {_display_optional(accounting_platform)}",
        f"Monthly invoice volume: {_display_optional(monthly_invoice_volume)}",
        f"Qualification: {_display_optional(qualification)}",
    ]
    if invoice_processing:
        lines.extend(
            (
                f"AP employment start: {employment_start}",
                f"AP employment end: {employment_end}",
            )
        )
    else:
        lines.append("AP employment dates: Not applicable")
    wrapped_note = textwrap.wrap(note, width=82, break_long_words=False) or [""]
    lines.extend(
        f"Note: {part}" if index == 0 else f"      {part}"
        for index, part in enumerate(wrapped_note)
    )

    y = height - 94
    for line in lines:
        document.drawString(54, y, line)
        y -= 20

    document.setFont("Helvetica-Oblique", 8)
    document.setFillColorRGB(0.35, 0.35, 0.35)
    document.drawString(54, 36, "Synthetic evidence for a security demonstration; no real person.")

    if hidden_claim is not None and placement is HiddenPlacement.LOW_CONTRAST:
        document.setFont("Helvetica", 9)
        document.setFillColorRGB(0.97, 0.97, 0.97)
        document.drawString(54, 66, hidden_claim)
    elif hidden_claim is not None and placement is HiddenPlacement.OFF_PAGE:
        document.setFont("Helvetica", 9)
        document.setFillColorRGB(0.08, 0.08, 0.08)
        document.drawString(width + 36, 66, hidden_claim)
    elif hidden_claim is not None and placement is HiddenPlacement.MICROTEXT:
        document.setFont("Helvetica", 3)
        document.setFillColorRGB(0.08, 0.08, 0.08)
        document.drawString(54, 66, hidden_claim)

    document.showPage()
    document.save()
    return target


def extract_pdf_evidence(
    source: Path | str | bytes | bytearray,
    *,
    batch_budget: PdfBatchBudget | None = None,
) -> PdfExtraction:
    """Parse one PDF in a fresh, bounded worker with no retry.

    ``batch_budget`` should be shared across all candidates in one run.  A
    timeout, crash, malformed result, or resource violation becomes a fixed
    exception message; document bytes and third-party exception text never
    cross this API as diagnostics.
    """

    started = time.monotonic()
    batch_remaining = (
        PDF_BATCH_TIMEOUT_SECONDS if batch_budget is None else batch_budget.remaining_seconds
    )
    if batch_remaining <= 0:
        raise PdfEvidenceTimeoutError("resume PDF batch deadline exceeded")
    deadline = started + min(PDF_DOCUMENT_TIMEOUT_SECONDS, batch_remaining)

    data = _read_pdf_bytes(source)
    expected_digest = hashlib.sha256(data).hexdigest()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _deadline_error(batch_budget)

    limits = _PdfWorkerLimits(
        max_pages=MAX_PDF_PAGES,
        max_characters=MAX_EXTRACTED_CHARACTERS,
        max_lines=MAX_PDF_LINES,
        max_metadata_items=MAX_PDF_METADATA_ITEMS,
        max_result_bytes=MAX_PDF_RESULT_BYTES,
        cpu_seconds=max(1, math.ceil(PDF_DOCUMENT_TIMEOUT_SECONDS)),
    )
    try:
        with tempfile.TemporaryDirectory(prefix="cv-trust-pdf-") as spool:
            spool_path = Path(spool)
            input_path = spool_path / "input.pdf"
            result_path = spool_path / "result.json"
            with input_path.open("xb") as stream:
                stream.write(data)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _deadline_error(batch_budget)
            payload = _run_worker(
                input_path=input_path,
                result_path=result_path,
                limits=limits,
                timeout_seconds=remaining,
                batch_budget=batch_budget,
            )
    except PdfEvidenceError:
        raise
    except Exception as exc:
        raise PdfEvidenceWorkerError("resume PDF isolation failed") from exc

    return _decode_worker_payload(
        payload,
        expected_digest=expected_digest,
        limits=limits,
    )


def _extract_pdf_evidence_in_worker(data: bytes, limits: _PdfWorkerLimits) -> PdfExtraction:
    """Worker-only parser.  Never call this on the trusted orchestration path."""

    digest = hashlib.sha256(data).hexdigest()
    characters: list[PdfCharacter] = []
    line_keys: set[tuple[int, EvidenceVisibility, float]] = set()

    with pdfplumber.open(io.BytesIO(data)) as pdf:
        page_count = len(pdf.pages)
        if page_count > limits.max_pages:
            raise PdfEvidenceLimitError(
                "resume PDF exceeds page limit",
                code=_WorkerFailureCode.PAGE_LIMIT,
            )
        extracted_character_count = 0
        for page_number, page in enumerate(pdf.pages, start=1):
            page_width = float(page.width)
            page_height = float(page.height)
            if (
                not math.isfinite(page_width)
                or not math.isfinite(page_height)
                or page_width <= 0
                or page_height <= 0
            ):
                raise PdfEvidenceWorkerError("resume PDF parsing failed")
            for character_index, raw_character in enumerate(page.chars):
                text = str(raw_character.get("text", ""))
                x0 = float(raw_character.get("x0", 0.0))
                x1 = float(raw_character.get("x1", x0))
                top = float(raw_character.get("top", 0.0))
                bottom = float(raw_character.get("bottom", top))
                raw_font_size = raw_character.get("size")
                font_size = (
                    float(raw_font_size)
                    if isinstance(raw_font_size, int | float)
                    else max(0.0, bottom - top)
                )
                fill_color = _normalize_color(raw_character.get("non_stroking_color"))
                contrast_ratio = _contrast_against_white(fill_color)
                visibility = _classify_character(
                    x0=x0,
                    x1=x1,
                    top=top,
                    bottom=bottom,
                    page_width=page_width,
                    page_height=page_height,
                    font_size=font_size,
                    contrast_ratio=contrast_ratio,
                )
                extracted_character_count += len(text)
                if extracted_character_count > limits.max_characters:
                    raise PdfEvidenceLimitError(
                        "resume PDF exceeds extracted text limit",
                        code=_WorkerFailureCode.TEXT_LIMIT,
                    )
                if len(characters) >= _MAX_CHARACTER_RECORDS:
                    raise PdfEvidenceLimitError(
                        "resume PDF exceeds extracted text limit",
                        code=_WorkerFailureCode.TEXT_LIMIT,
                    )
                characters.append(
                    PdfCharacter(
                        evidence_id=f"pdf:{digest}:p{page_number}:c{character_index}",
                        text=text,
                        page_number=page_number,
                        document_page_count=page_count,
                        page_width=page_width,
                        page_height=page_height,
                        x0=x0,
                        x1=x1,
                        top=top,
                        bottom=bottom,
                        font_size=font_size,
                        fill_color=fill_color,
                        contrast_ratio=contrast_ratio,
                        visibility=visibility,
                    )
                )
                if text.strip():
                    line_keys.add((page_number, visibility, round(top, 1)))
                    if len(line_keys) > limits.max_lines:
                        raise PdfEvidenceLimitError(
                            "resume PDF exceeds line limit",
                            code=_WorkerFailureCode.LINE_LIMIT,
                        )

    reader = PdfReader(io.BytesIO(data))
    metadata_items: list[PdfMetadataItem] = []
    if reader.metadata is not None:
        for key, value in sorted(reader.metadata.items(), key=lambda item: str(item[0])):
            if value is None:
                continue
            if len(metadata_items) >= limits.max_metadata_items:
                raise PdfEvidenceLimitError(
                    "resume PDF exceeds metadata item limit",
                    code=_WorkerFailureCode.METADATA_LIMIT,
                )
            normalized_key = str(key).removeprefix("/")
            normalized_value = str(value)
            extracted_character_count += len(normalized_key) + len(normalized_value)
            if extracted_character_count > limits.max_characters:
                raise PdfEvidenceLimitError(
                    "resume PDF exceeds extracted text limit",
                    code=_WorkerFailureCode.TEXT_LIMIT,
                )
            metadata_items.append(
                PdfMetadataItem(
                    evidence_id=_metadata_evidence_id(digest, normalized_key),
                    key=normalized_key,
                    value=normalized_value,
                )
            )

    return PdfExtraction(
        sha256=digest,
        page_count=page_count,
        characters=tuple(characters),
        metadata=tuple(metadata_items),
    )


def _read_pdf_bytes(source: Path | str | bytes | bytearray) -> bytes:
    if isinstance(source, bytes):
        data = source
    elif isinstance(source, bytearray):
        data = bytes(source)
    else:
        path = Path(source)
        if path.stat().st_size > MAX_PDF_BYTES:
            raise PdfEvidenceLimitError(
                "resume PDF exceeds byte limit",
                code=_WorkerFailureCode.BYTE_LIMIT,
            )
        with path.open("rb") as stream:
            data = stream.read(MAX_PDF_BYTES + 1)
    if len(data) > MAX_PDF_BYTES:
        raise PdfEvidenceLimitError(
            "resume PDF exceeds byte limit",
            code=_WorkerFailureCode.BYTE_LIMIT,
        )
    return data


def _run_worker(
    *,
    input_path: Path,
    result_path: Path,
    limits: _PdfWorkerLimits,
    timeout_seconds: float,
    batch_budget: PdfBatchBudget | None,
) -> bytes:
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_pdf_worker_main,
        args=(str(input_path), str(result_path), limits),
        name="cv-trust-pdf-parser",
        daemon=False,
    )
    started = False
    try:
        process.start()
        started = True
        process.join(timeout_seconds)
        if process.is_alive():
            _terminate_worker(process)
            raise _deadline_error(batch_budget)
        if process.exitcode != 0:
            raise PdfEvidenceWorkerError("resume PDF parsing failed")
        return _read_bounded_result(result_path, limits.max_result_bytes)
    finally:
        if started and process.is_alive():
            _terminate_worker(process)
        if started:
            with suppress(ValueError):
                process.close()


def _terminate_worker(process: multiprocessing.process.BaseProcess) -> None:
    process.terminate()
    process.join(0.25)
    if process.is_alive():
        kill = getattr(process, "kill", None)
        if callable(kill):
            kill()
            process.join(0.25)


def _deadline_error(batch_budget: PdfBatchBudget | None) -> PdfEvidenceTimeoutError:
    if batch_budget is not None and batch_budget.expired:
        return PdfEvidenceTimeoutError("resume PDF batch deadline exceeded")
    return PdfEvidenceTimeoutError("resume PDF parsing timed out")


def _pdf_worker_main(
    input_path: str,
    result_path: str,
    limits: _PdfWorkerLimits,
) -> None:
    """Isolated process entry point; always writes a bounded fixed-shape result."""

    _apply_unix_worker_limits(limits)
    try:
        with (
            open(os.devnull, "w", encoding="utf-8") as sink,
            redirect_stdout(sink),
            redirect_stderr(sink),
        ):
            data = _read_worker_input(Path(input_path))
            extraction = _extract_pdf_evidence_in_worker(data, limits)
        envelope: Mapping[str, object] = {
            "status": "ok",
            "extraction": _extraction_to_wire(extraction),
        }
        payload = json.dumps(
            envelope,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > limits.max_result_bytes:
            payload = _failure_payload(_WorkerFailureCode.RESULT_LIMIT)
    except PdfEvidenceLimitError as exc:
        payload = _failure_payload(exc.code)
    except Exception:
        payload = _failure_payload(_WorkerFailureCode.PARSING_FAILED)

    if len(payload) > limits.max_result_bytes:
        payload = _failure_payload(_WorkerFailureCode.RESULT_LIMIT)
    try:
        with Path(result_path).open("xb") as stream:
            stream.write(payload)
    except OSError:
        return


def _read_worker_input(path: Path) -> bytes:
    if path.stat().st_size > MAX_PDF_BYTES:
        raise PdfEvidenceLimitError(
            "resume PDF exceeds byte limit",
            code=_WorkerFailureCode.BYTE_LIMIT,
        )
    with path.open("rb") as stream:
        data = stream.read(MAX_PDF_BYTES + 1)
    if len(data) > MAX_PDF_BYTES:
        raise PdfEvidenceLimitError(
            "resume PDF exceeds byte limit",
            code=_WorkerFailureCode.BYTE_LIMIT,
        )
    return data


def _read_bounded_result(path: Path, max_bytes: int) -> bytes:
    try:
        if path.stat().st_size > max_bytes:
            raise PdfEvidenceLimitError(
                "resume PDF exceeds isolated result limit",
                code=_WorkerFailureCode.RESULT_LIMIT,
            )
        with path.open("rb") as stream:
            payload = stream.read(max_bytes + 1)
    except PdfEvidenceError:
        raise
    except OSError as exc:
        raise PdfEvidenceWorkerError("resume PDF parsing failed") from exc
    if len(payload) > max_bytes:
        raise PdfEvidenceLimitError(
            "resume PDF exceeds isolated result limit",
            code=_WorkerFailureCode.RESULT_LIMIT,
        )
    return payload


def _failure_payload(code: _WorkerFailureCode) -> bytes:
    return json.dumps(
        {"status": "failure", "code": code.value},
        separators=(",", ":"),
    ).encode("ascii")


def _extraction_to_wire(extraction: PdfExtraction) -> dict[str, object]:
    return {
        "sha256": extraction.sha256,
        "page_count": extraction.page_count,
        "characters": [
            {
                "evidence_id": item.evidence_id,
                "text": item.text,
                "page_number": item.page_number,
                "document_page_count": item.document_page_count,
                "page_width": item.page_width,
                "page_height": item.page_height,
                "x0": item.x0,
                "x1": item.x1,
                "top": item.top,
                "bottom": item.bottom,
                "font_size": item.font_size,
                "fill_color": None if item.fill_color is None else list(item.fill_color),
                "contrast_ratio": item.contrast_ratio,
                "visibility": item.visibility.value,
            }
            for item in extraction.characters
        ],
        "metadata": [
            {
                "evidence_id": item.evidence_id,
                "key": item.key,
                "value": item.value,
                "visibility": item.visibility.value,
            }
            for item in extraction.metadata
        ],
    }


def _decode_worker_payload(
    payload: bytes,
    *,
    expected_digest: str,
    limits: _PdfWorkerLimits,
) -> PdfExtraction:
    try:
        raw = cast(object, json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result") from exc
    envelope = _strict_mapping(raw, keys=None)
    status = _strict_string(envelope.get("status"))
    if status == "failure":
        if set(envelope) != {"status", "code"}:
            raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
        _raise_worker_failure(_strict_string(envelope.get("code")))
    if status != "ok" or set(envelope) != {"status", "extraction"}:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")

    extraction = _strict_mapping(
        envelope.get("extraction"),
        keys={"sha256", "page_count", "characters", "metadata"},
    )
    digest = _strict_string(extraction.get("sha256"))
    if digest != expected_digest:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    page_count = _strict_integer(extraction.get("page_count"))
    if not 0 <= page_count <= limits.max_pages:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")

    raw_characters = _strict_list(extraction.get("characters"))
    if len(raw_characters) > _MAX_CHARACTER_RECORDS:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    characters = tuple(_character_from_wire(item) for item in raw_characters)
    raw_metadata = _strict_list(extraction.get("metadata"))
    if len(raw_metadata) > limits.max_metadata_items:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    metadata = tuple(_metadata_from_wire(item) for item in raw_metadata)
    if any(item.evidence_id != _metadata_evidence_id(digest, item.key) for item in metadata):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    _revalidate_extraction_bounds(characters, metadata, page_count, limits)
    return PdfExtraction(
        sha256=digest,
        page_count=page_count,
        characters=characters,
        metadata=metadata,
    )


def _character_from_wire(raw: object) -> PdfCharacter:
    item = _strict_mapping(
        raw,
        keys={
            "evidence_id",
            "text",
            "page_number",
            "document_page_count",
            "page_width",
            "page_height",
            "x0",
            "x1",
            "top",
            "bottom",
            "font_size",
            "fill_color",
            "contrast_ratio",
            "visibility",
        },
    )
    raw_color = item.get("fill_color")
    fill_color: tuple[float, ...] | None
    if raw_color is None:
        fill_color = None
    else:
        components = _strict_list(raw_color)
        if len(components) not in {1, 3, 4}:
            raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
        fill_color = tuple(_strict_float(component) for component in components)
    try:
        visibility = EvidenceVisibility(_strict_string(item.get("visibility")))
    except ValueError as exc:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result") from exc
    return PdfCharacter(
        evidence_id=_strict_string(item.get("evidence_id")),
        text=_strict_string(item.get("text")),
        page_number=_strict_integer(item.get("page_number")),
        document_page_count=_strict_integer(item.get("document_page_count")),
        page_width=_strict_float(item.get("page_width")),
        page_height=_strict_float(item.get("page_height")),
        x0=_strict_float(item.get("x0")),
        x1=_strict_float(item.get("x1")),
        top=_strict_float(item.get("top")),
        bottom=_strict_float(item.get("bottom")),
        font_size=_strict_float(item.get("font_size")),
        fill_color=fill_color,
        contrast_ratio=_strict_float(item.get("contrast_ratio")),
        visibility=visibility,
    )


def _metadata_from_wire(raw: object) -> PdfMetadataItem:
    item = _strict_mapping(
        raw,
        keys={"evidence_id", "key", "value", "visibility"},
    )
    if _strict_string(item.get("visibility")) != EvidenceVisibility.METADATA.value:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    return PdfMetadataItem(
        evidence_id=_strict_string(item.get("evidence_id")),
        key=_strict_string(item.get("key")),
        value=_strict_string(item.get("value")),
    )


def _metadata_evidence_id(document_digest: str, key: str) -> str:
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"pdf:{document_digest}:metadata:{key_digest}"


def _revalidate_extraction_bounds(
    characters: tuple[PdfCharacter, ...],
    metadata: tuple[PdfMetadataItem, ...],
    document_page_count: int,
    limits: _PdfWorkerLimits,
) -> None:
    for item in characters:
        geometry = (item.x0, item.x1, item.top, item.bottom)
        if (
            any(
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or not math.isfinite(value)
                for value in geometry
            )
            or item.x1 < item.x0
            or item.bottom < item.top
            or isinstance(item.font_size, bool)
            or not isinstance(item.font_size, int | float)
            or not math.isfinite(item.font_size)
            or item.font_size < 0
            or isinstance(item.contrast_ratio, bool)
            or not isinstance(item.contrast_ratio, int | float)
            or not math.isfinite(item.contrast_ratio)
            or (
                item.fill_color is not None
                and (
                    len(item.fill_color) not in {1, 3, 4}
                    or any(
                        isinstance(component, bool)
                        or not isinstance(component, int | float)
                        or not math.isfinite(component)
                        for component in item.fill_color
                    )
                )
            )
        ):
            raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
        expected_contrast = _contrast_against_white(item.fill_color)
        expected_visibility = _classify_character(
            x0=item.x0,
            x1=item.x1,
            top=item.top,
            bottom=item.bottom,
            page_width=item.page_width,
            page_height=item.page_height,
            font_size=item.font_size,
            contrast_ratio=expected_contrast,
        )
        if (
            not math.isclose(
                item.contrast_ratio,
                expected_contrast,
                rel_tol=1e-12,
                abs_tol=1e-12,
            )
            or item.visibility is not expected_visibility
        ):
            raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")

    character_count = sum(len(item.text) for item in characters)
    character_count += sum(len(item.key) + len(item.value) for item in metadata)
    line_keys = {
        (item.page_number, item.visibility, round(item.top, 1))
        for item in characters
        if item.text.strip()
    }
    if character_count > limits.max_characters or len(line_keys) > limits.max_lines:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    if any(
        item.document_page_count != document_page_count
        or item.page_number < 1
        or item.page_number > document_page_count
        or item.page_number > limits.max_pages
        or not math.isfinite(item.page_width)
        or not math.isfinite(item.page_height)
        or item.page_width <= 0
        or item.page_height <= 0
        for item in characters
    ):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")


def _strict_mapping(value: object, *, keys: set[str] | None) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    result = cast(dict[str, object], value)
    if keys is not None and set(result) != keys:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    return result


def _strict_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    return cast(list[object], value)


def _strict_string(value: object) -> str:
    if not isinstance(value, str):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    return value


def _strict_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    return value


def _strict_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    result = float(value)
    if not math.isfinite(result):
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result")
    return result


def _raise_worker_failure(raw_code: str) -> None:
    try:
        code = _WorkerFailureCode(raw_code)
    except ValueError as exc:
        raise PdfEvidenceWorkerError("resume PDF parser returned an invalid result") from exc
    failures: Final[dict[_WorkerFailureCode, tuple[type[PdfEvidenceError], str]]] = {
        _WorkerFailureCode.BYTE_LIMIT: (
            PdfEvidenceLimitError,
            "resume PDF exceeds byte limit",
        ),
        _WorkerFailureCode.PAGE_LIMIT: (
            PdfEvidenceLimitError,
            "resume PDF exceeds page limit",
        ),
        _WorkerFailureCode.TEXT_LIMIT: (
            PdfEvidenceLimitError,
            "resume PDF exceeds extracted text limit",
        ),
        _WorkerFailureCode.LINE_LIMIT: (
            PdfEvidenceLimitError,
            "resume PDF exceeds line limit",
        ),
        _WorkerFailureCode.METADATA_LIMIT: (
            PdfEvidenceLimitError,
            "resume PDF exceeds metadata item limit",
        ),
        _WorkerFailureCode.RESULT_LIMIT: (
            PdfEvidenceLimitError,
            "resume PDF exceeds isolated result limit",
        ),
        _WorkerFailureCode.PARSING_FAILED: (
            PdfEvidenceWorkerError,
            "resume PDF parsing failed",
        ),
    }
    error_type, message = failures[code]
    if error_type is PdfEvidenceLimitError:
        raise PdfEvidenceLimitError(message, code=code)
    raise PdfEvidenceWorkerError(message)


def _apply_unix_worker_limits(limits: _PdfWorkerLimits) -> None:
    """Best-effort defence in depth; parent-enforced bounds stay authoritative."""

    try:
        import resource
    except ImportError:  # pragma: no cover - Windows has no resource module
        return

    requested = (
        ("RLIMIT_CPU", limits.cpu_seconds),
        ("RLIMIT_AS", _WORKER_ADDRESS_SPACE_BYTES),
        ("RLIMIT_FSIZE", _WORKER_FILE_SIZE_BYTES),
        ("RLIMIT_NOFILE", _WORKER_OPEN_FILES),
        ("RLIMIT_CORE", 0),
    )
    for name, desired in requested:
        resource_kind = getattr(resource, name, None)
        if resource_kind is None:
            continue
        try:
            _soft, hard = resource.getrlimit(resource_kind)
            bounded = desired
            if hard != resource.RLIM_INFINITY:
                bounded = min(bounded, hard)
            resource.setrlimit(resource_kind, (bounded, bounded))
        except (OSError, ValueError):
            continue


def _classify_character(
    *,
    x0: float,
    x1: float,
    top: float,
    bottom: float,
    page_width: float,
    page_height: float,
    font_size: float,
    contrast_ratio: float,
) -> EvidenceVisibility:
    if x0 < 0 or x1 > page_width or top < 0 or bottom > page_height:
        return EvidenceVisibility.OFF_PAGE
    if contrast_ratio < 3.0:
        return EvidenceVisibility.LOW_CONTRAST
    if font_size < MICROTEXT_MAX_FONT_SIZE:
        return EvidenceVisibility.MICROTEXT
    return EvidenceVisibility.VISIBLE


def _normalize_color(value: Any) -> tuple[float, ...] | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        return (float(value),)
    if isinstance(value, list | tuple):
        normalized: list[float] = []
        for component in value:
            if not isinstance(component, int | float):
                return None
            normalized.append(float(component))
        return tuple(normalized)
    return None


def _contrast_against_white(color: tuple[float, ...] | None) -> float:
    red, green, blue = _to_rgb(color)
    luminance = (
        0.2126 * _linear_channel(red)
        + 0.7152 * _linear_channel(green)
        + 0.0722 * _linear_channel(blue)
    )
    return 1.05 / (luminance + 0.05)


def _to_rgb(color: tuple[float, ...] | None) -> tuple[float, float, float]:
    if color is None:
        return (0.0, 0.0, 0.0)
    if len(color) == 1:
        gray = _clamp(color[0])
        return (gray, gray, gray)
    if len(color) == 3:
        red, green, blue = color
        return (_clamp(red), _clamp(green), _clamp(blue))
    if len(color) == 4:
        cyan, magenta, yellow, black = (_clamp(component) for component in color)
        return (
            1.0 - min(1.0, cyan + black),
            1.0 - min(1.0, magenta + black),
            1.0 - min(1.0, yellow + black),
        )
    return (0.0, 0.0, 0.0)


def _linear_channel(value: float) -> float:
    normalized = _clamp(value)
    if normalized <= 0.04045:
        return normalized / 12.92
    return float(((normalized + 0.055) / 1.055) ** 2.4)


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, value))


def _display_bool(value: bool) -> str:
    return "Yes" if value else "No"


def _display_optional(value: object | None) -> str:
    return "Not stated" if value is None else str(value)
