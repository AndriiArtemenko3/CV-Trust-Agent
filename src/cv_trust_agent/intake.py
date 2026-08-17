"""Quarantine and normalize indexed candidate JSON/PDF evidence.

The batch index is prepared before any candidate component is fetched. Each
candidate is then prepared independently so one malformed detail or resume can
be represented as locally unavailable without discarding healthy candidates.
Raw record notes and visible PDF text remain confined to mapper requests;
evidence references carry only identifiers, geometry, and hashes.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from typing import Final, TypeAlias

from pydantic import ValidationError

from cv_trust_agent.models import (
    BatchIndex,
    CandidateIndexEntry,
    CandidateRecord,
    ClaimKind,
    EvidenceRef,
    MappedClaim,
    MapperOutput,
    MapperRequest,
    ReasonCode,
    SourceKind,
    TrustStage,
)
from cv_trust_agent.pdf_evidence import (
    EvidenceVisibility,
    PdfBatchBudget,
    PdfCharacter,
    extract_pdf_evidence,
)
from cv_trust_agent.retrieval import (
    RetrievedCandidateDetail,
    RetrievedResume,
)

JsonScalar: TypeAlias = bool | int | float | str | None

_DECISION_FIELDS: Final[tuple[str, ...]] = (
    "ap_years",
    "invoice_processing",
    "reconciliation",
    "spreadsheet",
    "accounting_platform",
    "monthly_invoice_volume",
    "qualification",
)
_CLAIM_PATHS: Final[tuple[str, ...]] = tuple(f"resume.{field}" for field in _DECISION_FIELDS)
_TAGGED_LINE = re.compile(
    r'^<evidence id="(?P<evidence_id>[A-Za-z0-9][A-Za-z0-9_.:/-]*)">'
    r"(?P<text>.*)</evidence>$"
)
_SAFE_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
_SAFE_FIELD_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,159}$")


class IntakeError(RuntimeError):
    """Retrieved content could not be converted to the strict intake contract."""

    def __init__(
        self,
        message: str,
        *,
        stage: TrustStage = TrustStage.PARSING,
        reason: ReasonCode = ReasonCode.PARSING_FAILED,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.reason = reason


@dataclass(frozen=True)
class PreparedCandidateDetail:
    """One strict structured detail, prepared before its resume is parsed."""

    record: CandidateRecord


@dataclass(frozen=True)
class PreparedCandidate:
    """One independently prepared detail/resume pair."""

    record: CandidateRecord
    mapper_request: MapperRequest


@dataclass(frozen=True)
class _PdfLine:
    page: int
    document_page_count: int
    page_width: float
    page_height: float
    ordinal: int
    text: str
    bbox: tuple[float, float, float, float]
    visibility: EvidenceVisibility


@dataclass(frozen=True)
class _LineMeaning:
    field_path: str | None
    value: JsonScalar
    canonical_scalar: bool
    decision_field: bool


def prepare_candidate_detail(
    entry: CandidateIndexEntry,
    detail: RetrievedCandidateDetail,
) -> PreparedCandidateDetail:
    """Strictly validate one detail before requesting its resume."""

    if detail.candidate_id != entry.candidate_id:
        raise IntakeError(
            "candidate detail identity mismatch",
            stage=TrustStage.SCHEMA,
            reason=ReasonCode.SCHEMA_INVALID,
        )
    try:
        record = CandidateRecord.model_validate(detail.payload)
    except ValidationError as exc:
        raise IntakeError(
            "candidate detail failed strict schema validation",
            stage=TrustStage.SCHEMA,
            reason=ReasonCode.SCHEMA_INVALID,
        ) from exc
    if record.candidate_id != entry.candidate_id:
        raise IntakeError(
            "candidate detail identity mismatch",
            stage=TrustStage.SCHEMA,
            reason=ReasonCode.SCHEMA_INVALID,
        )
    return PreparedCandidateDetail(record=record)


def prepare_candidate_resume(
    index: BatchIndex,
    entry: CandidateIndexEntry,
    detail: PreparedCandidateDetail,
    resume: RetrievedResume,
    *,
    batch_budget: PdfBatchBudget | None = None,
) -> PreparedCandidate:
    """Parse one resume and bind it to an already strict candidate detail."""

    record = detail.record
    if resume.candidate_id != entry.candidate_id or record.candidate_id != entry.candidate_id:
        raise IntakeError(
            "candidate component identity mismatch",
            stage=TrustStage.SCHEMA,
            reason=ReasonCode.SCHEMA_INVALID,
        )
    try:
        extraction = extract_pdf_evidence(resume.content, batch_budget=batch_budget)
    except Exception as exc:
        raise IntakeError(
            "resume evidence extraction failed",
            stage=TrustStage.PARSING,
            reason=ReasonCode.PARSING_FAILED,
        ) from exc

    json_refs = _json_evidence_refs(index, record)
    lines = _group_pdf_lines(extraction.characters)
    pdf_refs = tuple(
        _pdf_line_ref(
            line,
            candidate_id=record.candidate_id,
            snapshot_id=index.index_id,
        )
        for line in lines
    )
    metadata_refs = tuple(
        EvidenceRef(
            evidence_id=_bounded_id(
                "pdfmeta",
                extraction.sha256,
                _metadata_key_digest(item.key),
            ),
            candidate_id=record.candidate_id,
            snapshot_id=index.index_id,
            source_kind=SourceKind.PDF_METADATA,
            field_path=f"metadata.key_{_metadata_key_digest(item.key)}",
            visible=False,
            admissible=False,
            semantic_hash=_hash_text(item.value),
        )
        for item in extraction.metadata
    )
    catalog = (*json_refs, *pdf_refs, *metadata_refs)
    evidence_ids = [evidence.evidence_id for evidence in catalog]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise IntakeError("evidence catalog contains duplicate identifiers")

    identity_values = tuple(
        (meaning.value, evidence.evidence_id)
        for line, evidence in zip(lines, pdf_refs, strict=True)
        if (meaning := _line_meaning(line.text)).field_path == "resume.candidate_id"
        and meaning.canonical_scalar
        and line.visibility is EvidenceVisibility.VISIBLE
    )
    document_candidate_id = str(identity_values[0][0]) if len(identity_values) == 1 else None
    identity_evidence_ids = tuple(item[1] for item in identity_values)

    try:
        request = MapperRequest(
            candidate_id=record.candidate_id,
            snapshot_id=index.index_id,
            fetched_at=index.fetched_at,
            record=record,
            tagged_visible_text=_tag_visible_lines(lines, pdf_refs),
            evidence_catalog=catalog,
            document_hash=extraction.sha256,
            document_candidate_id=document_candidate_id,
            document_identity_evidence_ids=identity_evidence_ids,
        )
    except ValidationError as exc:
        raise IntakeError("mapper request failed strict validation") from exc

    return PreparedCandidate(
        record=record,
        mapper_request=request,
    )


def build_deterministic_mapper_output(request: MapperRequest) -> MapperOutput:
    """Map admissible visible atoms without fixture specifications or gold labels.

    Values are parsed only from correctly delimited visible lines whose canonical
    scalar hash matches their catalog entry. Each emitted mapper claim cites its
    admissible visible-PDF atoms; trusted validation later binds those atoms to
    the independently fetched JSON evidence. Conflicting duplicate visible values
    are omitted for the trusted engine to restrict.
    """

    tagged_lines = _parse_tagged_lines(request.tagged_visible_text)
    parsed: dict[str, list[tuple[JsonScalar, str, str]]] = {}
    for evidence in request.evidence_catalog:
        if (
            evidence.source_kind is not SourceKind.RESUME_VISIBLE
            or not evidence.visible
            or not evidence.admissible
            or evidence.field_path not in _CLAIM_PATHS
        ):
            continue
        line_text = tagged_lines.get(evidence.evidence_id)
        if line_text is None:
            continue
        meaning = _line_meaning(line_text)
        if (
            meaning.field_path != evidence.field_path
            or not meaning.canonical_scalar
            or _hash_scalar(meaning.value) != evidence.semantic_hash
        ):
            continue
        parsed.setdefault(evidence.field_path, []).append(
            (meaning.value, evidence.semantic_hash, evidence.evidence_id)
        )

    claims: list[MappedClaim] = []
    scalar_values = {path: _single_value(entries) for path, entries in parsed.items()}

    ap_years = scalar_values.get("resume.ap_years")
    if isinstance(ap_years, int | float) and not isinstance(ap_years, bool):
        claim = _validated_claim(
            claim_id=_claim_id(request, ClaimKind.AP_YEARS),
            candidate_id=request.candidate_id,
            snapshot_id=request.snapshot_id,
            kind=ClaimKind.AP_YEARS,
            number_value=float(ap_years),
            evidence_ids=_supporting_ids(request, "ap_years", _hash_scalar(ap_years)),
        )
        if claim is not None:
            claims.append(claim)

    for field_path, kind in (
        ("resume.invoice_processing", ClaimKind.INVOICE_PROCESSING),
        ("resume.reconciliation", ClaimKind.RECONCILIATION),
    ):
        value = scalar_values.get(field_path)
        if isinstance(value, bool):
            claim = _validated_claim(
                claim_id=_claim_id(request, kind),
                candidate_id=request.candidate_id,
                snapshot_id=request.snapshot_id,
                kind=kind,
                bool_value=value,
                evidence_ids=_supporting_ids(
                    request,
                    field_path.removeprefix("resume."),
                    _hash_scalar(value),
                ),
            )
            if claim is not None:
                claims.append(claim)

    for field_path, kind in (
        ("resume.spreadsheet", ClaimKind.SPREADSHEET),
        ("resume.accounting_platform", ClaimKind.ACCOUNTING_PLATFORM),
        ("resume.qualification", ClaimKind.QUALIFICATION),
    ):
        value = scalar_values.get(field_path)
        if isinstance(value, str):
            claim = _validated_claim(
                claim_id=_claim_id(request, kind),
                candidate_id=request.candidate_id,
                snapshot_id=request.snapshot_id,
                kind=kind,
                text_value=value,
                evidence_ids=_supporting_ids(
                    request,
                    field_path.removeprefix("resume."),
                    _hash_scalar(value),
                ),
            )
            if claim is not None:
                claims.append(claim)

    monthly_volume = scalar_values.get("resume.monthly_invoice_volume")
    if isinstance(monthly_volume, int) and not isinstance(monthly_volume, bool):
        claim = _validated_claim(
            claim_id=_claim_id(request, ClaimKind.MONTHLY_INVOICE_VOLUME),
            candidate_id=request.candidate_id,
            snapshot_id=request.snapshot_id,
            kind=ClaimKind.MONTHLY_INVOICE_VOLUME,
            number_value=float(monthly_volume),
            evidence_ids=_supporting_ids(
                request,
                "monthly_invoice_volume",
                _hash_scalar(monthly_volume),
            ),
        )
        if claim is not None:
            claims.append(claim)

    start_value = _single_visible_value(request, tagged_lines, "resume.employment_start")
    end_value = _single_visible_value(request, tagged_lines, "resume.employment_end")
    if isinstance(start_value, str) and isinstance(end_value, str):
        try:
            start_date = date.fromisoformat(start_value)
            end_date = date.fromisoformat(end_value)
        except ValueError:
            pass
        else:
            interval_ids = (
                *_supporting_ids(request, "employment_start", _hash_scalar(start_value)),
                *_supporting_ids(request, "employment_end", _hash_scalar(end_value)),
            )
            claim = _validated_claim(
                claim_id=_claim_id(request, ClaimKind.EMPLOYMENT_INTERVAL),
                candidate_id=request.candidate_id,
                snapshot_id=request.snapshot_id,
                kind=ClaimKind.EMPLOYMENT_INTERVAL,
                start_date=start_date,
                end_date=end_date,
                evidence_ids=tuple(dict.fromkeys(interval_ids))[:16],
            )
            if claim is not None:
                claims.append(claim)

    return MapperOutput(
        candidate_id=request.candidate_id,
        snapshot_id=request.snapshot_id,
        claims=tuple(claims),
    )


class CatalogDeterministicMapper:
    """No-key mapper that derives typed claims from each request's catalog."""

    @property
    def name(self) -> str:
        return "deterministic_mapper"

    def map_claims(self, request: MapperRequest) -> MapperOutput:
        return build_deterministic_mapper_output(request)


def _json_evidence_refs(
    index: BatchIndex,
    record: CandidateRecord,
) -> tuple[EvidenceRef, ...]:
    candidate_id = record.candidate_id
    values = record.model_dump(mode="python")
    fields = ("candidate_id", *_DECISION_FIELDS)
    references: list[EvidenceRef] = []
    for field in fields:
        semantic_hash = _hash_scalar(values[field])
        references.append(
            EvidenceRef(
                evidence_id=_bounded_id(
                    "json",
                    index.index_id,
                    candidate_id,
                    semantic_hash,
                    field,
                ),
                candidate_id=candidate_id,
                snapshot_id=index.index_id,
                source_kind=SourceKind.APPLICATION_JSON,
                field_path=_json_field_path(candidate_id, field),
                visible=True,
                admissible=True,
                semantic_hash=semantic_hash,
            )
        )
    return tuple(references)


def _group_pdf_lines(characters: Sequence[PdfCharacter]) -> tuple[_PdfLine, ...]:
    grouped: dict[tuple[int, EvidenceVisibility, float], list[PdfCharacter]] = {}
    for character in characters:
        key = (
            character.page_number,
            character.visibility,
            round(character.top, 1),
        )
        grouped.setdefault(key, []).append(character)

    ordered_groups = sorted(
        grouped.values(),
        key=lambda group: (
            group[0].page_number,
            min(character.top for character in group),
            min(character.x0 for character in group),
            group[0].visibility.value,
        ),
    )
    page_ordinals: dict[int, int] = {}
    result: list[_PdfLine] = []
    for group in ordered_groups:
        ordered_characters = sorted(group, key=lambda character: (character.x0, character.x1))
        text = "".join(character.text for character in ordered_characters)
        text = text.replace("\r", " ").replace("\n", " ")
        if not text.strip():
            continue
        page = group[0].page_number
        ordinal = page_ordinals.get(page, 0)
        page_ordinals[page] = ordinal + 1
        result.append(
            _PdfLine(
                page=page,
                document_page_count=group[0].document_page_count,
                page_width=group[0].page_width,
                page_height=group[0].page_height,
                ordinal=ordinal,
                text=text,
                bbox=(
                    min(character.x0 for character in group),
                    min(character.top for character in group),
                    max(character.x1 for character in group),
                    max(character.bottom for character in group),
                ),
                visibility=group[0].visibility,
            )
        )
    return tuple(result)


def _pdf_line_ref(
    line: _PdfLine,
    *,
    candidate_id: str,
    snapshot_id: str,
) -> EvidenceRef:
    meaning = _line_meaning(line.text)
    field_path = meaning.field_path or f"resume.lines[{line.page}.{line.ordinal}]"
    semantic_hash = (
        _hash_scalar(meaning.value) if meaning.canonical_scalar else _hash_text(line.text)
    )
    visible = line.visibility is EvidenceVisibility.VISIBLE
    source_kind = SourceKind.RESUME_VISIBLE if visible else SourceKind.RESUME_NON_VISIBLE
    return EvidenceRef(
        evidence_id=_bounded_id(
            "pdfline",
            snapshot_id,
            candidate_id,
            f"p{line.page}",
            line.visibility.value,
            f"l{line.ordinal}",
            semantic_hash[:16],
        ),
        candidate_id=candidate_id,
        snapshot_id=snapshot_id,
        source_kind=source_kind,
        field_path=field_path,
        page=line.page,
        document_page_count=line.document_page_count,
        page_width=line.page_width,
        page_height=line.page_height,
        bbox=line.bbox,
        visible=visible,
        admissible=visible
        and meaning.canonical_scalar
        and (meaning.decision_field or meaning.field_path == "resume.candidate_id"),
        semantic_hash=semantic_hash,
    )


def _tag_visible_lines(
    lines: Sequence[_PdfLine],
    refs: Sequence[EvidenceRef],
) -> str:
    tagged: list[str] = []
    for line, evidence in zip(lines, refs, strict=True):
        if line.visibility is not EvidenceVisibility.VISIBLE:
            continue
        escaped = html.escape(line.text, quote=True)
        tagged.append(f'<evidence id="{evidence.evidence_id}">{escaped}</evidence>')
    return "\n".join(tagged)


def _parse_tagged_lines(tagged_text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for tagged_line in tagged_text.splitlines():
        match = _TAGGED_LINE.fullmatch(tagged_line)
        if match is None:
            continue
        evidence_id = match.group("evidence_id")
        if evidence_id in result:
            continue
        result[evidence_id] = html.unescape(match.group("text"))
    return result


def _line_meaning(text: str) -> _LineMeaning:
    stripped = text.strip()
    simple_fields = (
        ("AP years:", "resume.ap_years", _parse_float),
        ("Invoice processing:", "resume.invoice_processing", _parse_bool),
        ("Reconciliation:", "resume.reconciliation", _parse_bool),
        ("Spreadsheet:", "resume.spreadsheet", _parse_optional_text),
        ("Accounting platform:", "resume.accounting_platform", _parse_optional_text),
        (
            "Monthly invoice volume:",
            "resume.monthly_invoice_volume",
            _parse_optional_int,
        ),
        ("Qualification:", "resume.qualification", _parse_optional_text),
        ("AP employment start:", "resume.employment_start", _parse_iso_date),
        ("AP employment end:", "resume.employment_end", _parse_iso_date),
    )
    for prefix, field_path, parser in simple_fields:
        if not stripped.startswith(prefix):
            continue
        raw_value = stripped.removeprefix(prefix).strip()
        try:
            value = parser(raw_value)
        except ValueError:
            return _LineMeaning(field_path, stripped, False, True)
        return _LineMeaning(field_path, value, True, True)

    if stripped.startswith("Candidate ID:"):
        value = stripped.removeprefix("Candidate ID:").strip()
        return _LineMeaning("resume.candidate_id", value, True, False)
    if stripped.startswith("AP employment dates:"):
        return _LineMeaning("resume.employment_dates", stripped, False, False)
    if stripped.startswith("Note:"):
        return _LineMeaning("resume.note", stripped, False, False)
    return _LineMeaning(None, stripped, False, False)


def _single_value(entries: Sequence[tuple[JsonScalar, str, str]]) -> JsonScalar:
    by_hash = {semantic_hash: value for value, semantic_hash, _ in entries}
    if len(by_hash) != 1:
        return None
    return next(iter(by_hash.values()))


def _single_visible_value(
    request: MapperRequest,
    tagged_lines: dict[str, str],
    field_path: str,
) -> JsonScalar:
    entries: list[tuple[JsonScalar, str, str]] = []
    for evidence in request.evidence_catalog:
        if (
            evidence.source_kind is not SourceKind.RESUME_VISIBLE
            or not evidence.admissible
            or evidence.field_path != field_path
        ):
            continue
        text = tagged_lines.get(evidence.evidence_id)
        if text is None:
            continue
        meaning = _line_meaning(text)
        if (
            meaning.field_path == field_path
            and meaning.canonical_scalar
            and _hash_scalar(meaning.value) == evidence.semantic_hash
        ):
            entries.append((meaning.value, evidence.semantic_hash, evidence.evidence_id))
    return _single_value(entries)


def _supporting_ids(
    request: MapperRequest,
    logical_field: str,
    semantic_hash: str,
) -> tuple[str, ...]:
    evidence_ids = tuple(
        evidence.evidence_id
        for evidence in request.evidence_catalog
        if evidence.admissible
        and evidence.visible
        and evidence.source_kind is SourceKind.RESUME_VISIBLE
        and evidence.semantic_hash == semantic_hash
        and _logical_field(evidence.field_path) == logical_field
    )
    return tuple(dict.fromkeys(evidence_ids))[:16]


def _logical_field(field_path: str | None) -> str | None:
    if field_path is None:
        return None
    return field_path.rsplit(".", maxsplit=1)[-1]


def _validated_claim(**values: object) -> MappedClaim | None:
    try:
        return MappedClaim.model_validate(values)
    except ValidationError:
        return None


def _claim_id(request: MapperRequest, kind: ClaimKind) -> str:
    return _bounded_id("claim", request.snapshot_id, request.candidate_id, kind.value)


def _parse_float(value: str) -> float:
    parsed = float(value)
    if parsed != parsed or parsed in {float("inf"), float("-inf")}:
        raise ValueError("non-finite number")
    return parsed


def _parse_bool(value: str) -> bool:
    normalized = value.casefold()
    if normalized == "yes":
        return True
    if normalized == "no":
        return False
    raise ValueError("expected Yes or No")


def _parse_optional_text(value: str) -> str | None:
    return None if value.casefold() == "not stated" else value


def _parse_optional_int(value: str) -> int | None:
    if value.casefold() == "not stated":
        return None
    return int(value.replace(",", ""))


def _parse_iso_date(value: str) -> str:
    return date.fromisoformat(value).isoformat()


def _hash_scalar(value: JsonScalar) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bounded_id(prefix: str, *parts: str) -> str:
    readable = ":".join((prefix, *parts))
    if _SAFE_EVIDENCE_ID.fullmatch(readable) is not None:
        return readable
    digest = hashlib.sha256(readable.encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"


def _json_field_path(candidate_id: str, field: str) -> str:
    detailed = f"records[{candidate_id}].{field}"
    return detailed if _SAFE_FIELD_PATH.fullmatch(detailed) is not None else f"record.{field}"


def _metadata_key_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
