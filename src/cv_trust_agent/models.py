"""Strict contracts for evidence-strength ranking over one source snapshot.

Raw source text is confined to :class:`MapperRequest`. The trusted ranking
controller accepts only normalized :class:`ValidatedBatchEvidence`, making it
impossible for notes, PDF spans, or mapper prose to become ranking policy.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

SafeId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    ),
]
SourceId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    ),
]
SafeHash = Annotated[
    str,
    StringConstraints(strip_whitespace=True, to_lower=True, pattern=r"^[0-9a-f]{64}$"),
]
SafeLabel = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 .+#&/_()-]*$",
    ),
]
FieldPath = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]*$",
    ),
]
SourceUrl = Annotated[str, Field(min_length=1, max_length=512)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


class TrustState(StrEnum):
    USABLE = "USABLE"
    DEGRADED = "DEGRADED"
    QUARANTINED = "QUARANTINED"
    UNAVAILABLE = "UNAVAILABLE"


class TrustOutcome(StrEnum):
    ALLOW = "ALLOW"
    RESTRICT = "RESTRICT"
    QUARANTINE = "QUARANTINE"
    UNAVAILABLE = "UNAVAILABLE"
    HOLD = "HOLD"


class TrustStage(StrEnum):
    RETRIEVAL = "retrieval"
    SCHEMA = "schema"
    MANIFEST = "manifest"
    REVISION = "revision"
    PARSING = "parsing"
    IDENTITY = "identity"
    MAPPING = "mapping"
    PROVENANCE = "provenance"
    CROSS_SOURCE = "cross_source"
    TIMELINE = "timeline"
    CANDIDATE_VALIDATION = "candidate_validation"
    PLANNING = "planning"
    RANKING = "ranking"
    PRE_RELEASE = "pre_release"
    RELEASE = "release"


class ExecutionMode(StrEnum):
    """Whether the trusted workflow completed normally or failed closed."""

    EXECUTED = "EXECUTED"
    FAILED_CLOSED = "FAILED_CLOSED"


class TrustScope(StrEnum):
    RECORD = "record"
    BATCH = "batch"


class Strategy(StrEnum):
    FULL_EVIDENCE_RANKING = "FULL_EVIDENCE_RANKING"
    SUPPORTED_ONLY_RANKING = "SUPPORTED_ONLY_RANKING"
    PARTIAL_SAFE_RANKING = "PARTIAL_SAFE_RANKING"
    BATCH_INTEGRITY_HOLD = "BATCH_INTEGRITY_HOLD"


class RankingScope(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    NONE = "NONE"


class SourceKind(StrEnum):
    APPLICATION_JSON = "application_json"
    RESUME_VISIBLE = "resume_visible"
    RESUME_NON_VISIBLE = "resume_non_visible"
    PDF_METADATA = "pdf_metadata"


class ClaimKind(StrEnum):
    CANDIDATE_ID = "candidate_id"
    AP_YEARS = "ap_years"
    INVOICE_PROCESSING = "invoice_processing"
    RECONCILIATION = "reconciliation"
    SPREADSHEET = "spreadsheet"
    ACCOUNTING_PLATFORM = "accounting_platform"
    MONTHLY_INVOICE_VOLUME = "monthly_invoice_volume"
    QUALIFICATION = "qualification"
    EMPLOYMENT_INTERVAL = "employment_interval"


STRUCTURED_FIELD_KINDS: tuple[ClaimKind, ...] = (
    ClaimKind.ACCOUNTING_PLATFORM,
    ClaimKind.AP_YEARS,
    ClaimKind.INVOICE_PROCESSING,
    ClaimKind.MONTHLY_INVOICE_VOLUME,
    ClaimKind.QUALIFICATION,
    ClaimKind.RECONCILIATION,
    ClaimKind.SPREADSHEET,
)


class NormalizationMode(StrEnum):
    BOUNDED_ALLOW_LIST_V1 = "bounded_allow_list_v1"


class EvidenceDispositionState(StrEnum):
    """Bounded lifecycle state for one mapper-consumed evidence reference."""

    CONSUMED = "consumed"
    RELEASED = "released"
    DROPPED_UNSUPPORTED_CATEGORY = "dropped_unsupported_category"
    DROPPED_TIMELINE_POLICY = "dropped_timeline_policy"
    DROPPED_CROSS_SOURCE = "dropped_cross_source"


class PlanObjective(StrEnum):
    RANK_FULL_CORROBORATED_EVIDENCE = "rank_full_corroborated_evidence"
    RANK_SUPPORTED_EVIDENCE_ONLY = "rank_supported_evidence_only"
    RANK_AVAILABLE_EVIDENCE_SAFELY = "rank_available_evidence_safely"
    HOLD_BATCH_FOR_INTEGRITY_REVIEW = "hold_batch_for_integrity_review"


class ProhibitedAction(StrEnum):
    AUTOMATED_HIRE = "automated_hire"
    AUTOMATED_REJECT = "automated_reject"
    EXECUTE_SOURCE_INSTRUCTIONS = "execute_source_instructions"
    USE_RAW_SOURCE_TEXT = "use_raw_source_text"
    USE_PROTECTED_ATTRIBUTES = "use_protected_attributes"
    RANK_QUARANTINED_EVIDENCE = "rank_quarantined_evidence"
    RANK_UNAVAILABLE_CANDIDATE = "rank_unavailable_candidate"
    RELEASE_FINAL_QUALIFICATION_DECISION = "release_final_qualification_decision"


class PlanStep(StrEnum):
    FETCH_CANDIDATE_DETAILS = "fetch_candidate_details"
    VALIDATE_CANDIDATE_DETAILS = "validate_candidate_details"
    FETCH_CANDIDATE_RESUMES = "fetch_candidate_resumes"
    PARSE_CANDIDATE_RESUMES = "parse_candidate_resumes"
    VALIDATE_CANDIDATE_BINDINGS = "validate_candidate_bindings"
    MAP_CANDIDATE_CLAIMS = "map_candidate_claims"
    VALIDATE_CANDIDATE_EVIDENCE = "validate_candidate_evidence"
    VALIDATE_INDEX_COMMITMENTS = "validate_index_commitments"
    RANK_FULL_EVIDENCE = "rank_full_evidence"
    QUARANTINE_UNSUPPORTED = "quarantine_unsupported"
    MARK_EVIDENCE_PENDING = "mark_evidence_pending"
    RANK_SUPPORTED_EVIDENCE = "rank_supported_evidence"
    RANK_PARTIAL_EVIDENCE = "rank_partial_evidence"
    ISOLATE_BATCH = "isolate_batch"
    REQUEST_CORROBORATION = "request_corroboration"
    PRE_RELEASE_AUDIT = "pre_release_audit"
    RELEASE_OUTPUT = "release_output"


class StepStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    RESTRICTED = "restricted"
    FAILED = "failed"


class ReasonCode(StrEnum):
    FETCH_SUCCEEDED = "fetch_succeeded"
    RETRIEVAL_FAILED = "retrieval_failed"
    SCHEMA_VALID = "schema_valid"
    SCHEMA_INVALID = "schema_invalid"
    PARSING_FAILED = "parsing_failed"
    INDEX_VALID = "index_valid"
    INDEX_CONFLICT = "index_conflict"
    MANIFEST_VALID = "manifest_valid"
    MANIFEST_CONFLICT = "manifest_conflict"
    REVISION_VALID = "revision_valid"
    REVISION_CONFLICT = "revision_conflict"
    SEMANTIC_HASH_VALID = "semantic_hash_valid"
    SEMANTIC_HASH_CONFLICT = "semantic_hash_conflict"
    RESUME_HASH_VALID = "resume_hash_valid"
    RESUME_HASH_CONFLICT = "resume_hash_conflict"
    CANDIDATE_UNAVAILABLE = "candidate_unavailable"
    MAPPER_OUTPUT_VALID = "mapper_output_valid"
    MAPPER_UNAVAILABLE = "mapper_unavailable"
    MAPPER_DISAGREEMENT = "mapper_disagreement"
    EVIDENCE_ADMISSIBLE = "evidence_admissible"
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_UNKNOWN = "evidence_unknown"
    EVIDENCE_INADMISSIBLE = "evidence_inadmissible"
    EVIDENCE_VALUE_CONFLICT = "evidence_value_conflict"
    CROSS_SOURCE_MATCH = "cross_source_match"
    CROSS_SOURCE_CONFLICT = "cross_source_conflict"
    TIMELINE_VALID = "timeline_valid"
    TIMELINE_UNAVAILABLE = "timeline_unavailable"
    TIMELINE_CONFLICT = "timeline_conflict"
    TIMELINE_DRIFT = "timeline_drift"
    DOMAIN_INVARIANT_CONFLICT = "domain_invariant_conflict"
    RECORD_QUARANTINED = "record_quarantined"
    BATCH_HOLD_REQUIRED = "batch_hold_required"
    PLAN_SELECTED = "plan_selected"
    PLAN_REVISED = "plan_revised"
    RANKING_ALLOWED = "ranking_allowed"
    RANKING_RESTRICTED = "ranking_restricted"
    RANKING_PARTIAL = "ranking_partial"
    RANKING_HELD = "ranking_held"
    PRE_RELEASE_VALID = "pre_release_valid"
    PRE_RELEASE_BLOCKED = "pre_release_blocked"
    DOCUMENT_IDENTITY_VALID = "document_identity_valid"
    DOCUMENT_IDENTITY_MISSING = "document_identity_missing"
    DOCUMENT_IDENTITY_CONFLICT = "document_identity_conflict"
    SUPPORT_GRAPH_VALID = "support_graph_valid"
    SUPPORT_GRAPH_INCOMPLETE = "support_graph_incomplete"
    COMMAND_STARTED = "command_started"
    COMMAND_COMPLETED = "command_completed"
    COMMAND_RESTRICTED = "command_restricted"
    COMMAND_FAILED = "command_failed"
    RELEASE_AUTHORIZED = "release_authorized"
    RELEASE_BLOCKED = "release_blocked"
    CORROBORATION_REQUIRED = "corroboration_required"
    CATEGORY_NOT_SUPPORTED = "category_not_supported"


class ReviewBand(StrEnum):
    STRONG_EVIDENCE_MATCH = "STRONG_EVIDENCE_MATCH"
    POTENTIAL_EVIDENCE_MATCH = "POTENTIAL_EVIDENCE_MATCH"
    INSUFFICIENT_SUPPORTED_EVIDENCE = "INSUFFICIENT_SUPPORTED_EVIDENCE"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    INTEGRITY_HOLD = "INTEGRITY_HOLD"


class ReviewQueue(StrEnum):
    PRIORITY_HUMAN_REVIEW = "PRIORITY_HUMAN_REVIEW"
    STANDARD_HUMAN_REVIEW = "STANDARD_HUMAN_REVIEW"
    EVIDENCE_CHECK = "EVIDENCE_CHECK"
    EVIDENCE_PENDING = "EVIDENCE_PENDING"
    INTEGRITY_REVIEW = "INTEGRITY_REVIEW"
    BATCH_INTEGRITY_HOLD = "BATCH_INTEGRITY_HOLD"


class ExplanationTemplate(StrEnum):
    RECORD_DEGRADED = "record_degraded"
    RECORD_QUARANTINED = "record_quarantined"
    CANDIDATE_UNAVAILABLE = "candidate_unavailable"
    BATCH_HELD = "batch_held"
    STRATEGY_SELECTED = "strategy_selected"


class UnavailableComponent(StrEnum):
    DETAIL = "DETAIL"
    RESUME = "RESUME"
    INTAKE = "INTAKE"


class CandidateIndexEntry(StrictModel):
    candidate_id: SourceId
    record_revision: SourceId
    detail_url: SourceUrl
    resume_url: SourceUrl
    semantic_hash: SafeHash
    resume_sha256: SafeHash


class BatchIndex(StrictModel):
    batch_id: SourceId
    batch_revision: SourceId
    index_id: SourceId
    fetched_at: datetime
    manifest_hash: SafeHash
    candidates: tuple[CandidateIndexEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_candidates(self) -> BatchIndex:
        candidate_ids = [entry.candidate_id for entry in self.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate_id values must be unique within an index")
        return self


class CandidateRecord(StrictModel):
    """Untrusted structured detail fetched once for one index entry."""

    candidate_id: SourceId
    record_revision: SourceId
    ap_years: Annotated[float, Field(strict=True, ge=0, le=80)]
    invoice_processing: Annotated[bool, Field(strict=True)]
    reconciliation: Annotated[bool, Field(strict=True)]
    spreadsheet: SafeLabel | None = None
    accounting_platform: SafeLabel | None = None
    monthly_invoice_volume: Annotated[int, Field(strict=True, ge=0, le=100_000_000)] | None = None
    qualification: SafeLabel | None = None
    note: Annotated[str, Field(max_length=8_000)]
    resume_url: SourceUrl
    semantic_hash: SafeHash

    @field_validator("ap_years")
    @classmethod
    def normalize_zero_years(cls, value: float) -> float:
        return 0.0 if value == 0.0 else value


class EvidenceRef(StrictModel):
    evidence_id: SafeId
    candidate_id: SourceId
    snapshot_id: SourceId
    source_kind: SourceKind
    field_path: FieldPath | None = None
    page: Annotated[int, Field(strict=True, ge=1)] | None = None
    document_page_count: Annotated[int, Field(strict=True, ge=1, le=10)] | None = None
    page_width: Annotated[float, Field(strict=True, gt=0)] | None = None
    page_height: Annotated[float, Field(strict=True, gt=0)] | None = None
    bbox: (
        tuple[
            Annotated[float, Field(strict=True)],
            Annotated[float, Field(strict=True)],
            Annotated[float, Field(strict=True)],
            Annotated[float, Field(strict=True)],
        ]
        | None
    ) = None
    visible: Annotated[bool, Field(strict=True)]
    admissible: Annotated[bool, Field(strict=True)]
    semantic_hash: SafeHash

    @model_validator(mode="after")
    def visibility_is_required_for_resume_evidence(self) -> EvidenceRef:
        if self.source_kind is SourceKind.RESUME_VISIBLE and not self.visible:
            raise ValueError("resume_visible evidence must be visible")
        if self.source_kind in {SourceKind.RESUME_NON_VISIBLE, SourceKind.PDF_METADATA} and (
            self.visible or self.admissible
        ):
            raise ValueError("non-visible or metadata evidence cannot be admissible")
        if self.source_kind is SourceKind.RESUME_VISIBLE:
            if (
                self.page is None
                or self.document_page_count is None
                or self.page_width is None
                or self.page_height is None
                or self.bbox is None
            ):
                raise ValueError("visible resume evidence requires document and page geometry")
            if self.page > self.document_page_count:
                raise ValueError("visible resume evidence page exceeds document page count")
            if (
                not math.isfinite(self.page_width)
                or not math.isfinite(self.page_height)
                or self.page_width <= 0
                or self.page_height <= 0
            ):
                raise ValueError("visible resume evidence requires finite positive page dimensions")
            x0, top, x1, bottom = self.bbox
            if (
                not all(math.isfinite(item) for item in self.bbox)
                or not 0 <= x0 <= x1 <= self.page_width
                or not 0 <= top <= bottom <= self.page_height
            ):
                raise ValueError("visible resume evidence requires an in-page bounding box")
        return self


class MappedClaim(StrictModel):
    claim_id: SafeId
    candidate_id: SourceId
    snapshot_id: SourceId
    kind: ClaimKind
    bool_value: Annotated[bool, Field(strict=True)] | None = None
    number_value: Annotated[float, Field(strict=True)] | None = None
    text_value: SafeLabel | None = None
    start_date: date | None = None
    end_date: date | None = None
    evidence_ids: tuple[SafeId, ...] = Field(min_length=1, max_length=16)

    @field_validator("number_value")
    @classmethod
    def finite_number(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("number_value must be finite")
        return 0.0 if value == 0.0 else value

    @model_validator(mode="after")
    def typed_value_matches_kind(self) -> MappedClaim:
        value_count = sum(
            value is not None for value in (self.bool_value, self.number_value, self.text_value)
        )
        if self.kind is ClaimKind.EMPLOYMENT_INTERVAL:
            if value_count or self.start_date is None or self.end_date is None:
                raise ValueError("employment intervals require dates and no scalar value")
            if self.end_date < self.start_date:
                raise ValueError("employment interval end_date precedes start_date")
            return self
        if self.start_date is not None or self.end_date is not None or value_count != 1:
            raise ValueError("non-interval claims require exactly one scalar value")
        if self.kind in {ClaimKind.INVOICE_PROCESSING, ClaimKind.RECONCILIATION}:
            if self.bool_value is None:
                raise ValueError("boolean claim kind requires bool_value")
        elif self.kind in {ClaimKind.AP_YEARS, ClaimKind.MONTHLY_INVOICE_VOLUME}:
            if self.number_value is None:
                raise ValueError("numeric claim kind requires number_value")
        elif self.text_value is None:
            raise ValueError("text claim kind requires text_value")
        return self


class MapperOutput(StrictModel):
    candidate_id: SourceId
    snapshot_id: SourceId
    claims: tuple[MappedClaim, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def claims_belong_to_request(self) -> MapperOutput:
        for claim in self.claims:
            if claim.candidate_id != self.candidate_id:
                raise ValueError("claim candidate_id differs from mapper output")
            if claim.snapshot_id != self.snapshot_id:
                raise ValueError("claim snapshot_id differs from mapper output")
        return self


class MapperRequest(StrictModel):
    """The only boundary model allowed to contain raw source text."""

    candidate_id: SourceId
    snapshot_id: SourceId
    fetched_at: datetime
    record: CandidateRecord
    tagged_visible_text: Annotated[str, Field(max_length=60_000)]
    evidence_catalog: tuple[EvidenceRef, ...]
    document_hash: SafeHash
    document_candidate_id: SourceId | None = None
    document_identity_evidence_ids: tuple[SafeId, ...] = Field(max_length=16, default=())

    @model_validator(mode="after")
    def request_components_match(self) -> MapperRequest:
        if self.record.candidate_id != self.candidate_id:
            raise ValueError("record candidate_id differs from mapper request")
        for evidence in self.evidence_catalog:
            if evidence.candidate_id != self.candidate_id:
                raise ValueError("evidence candidate_id differs from mapper request")
            if evidence.snapshot_id != self.snapshot_id:
                raise ValueError("evidence snapshot_id differs from mapper request")
        catalog_ids = {evidence.evidence_id for evidence in self.evidence_catalog}
        if not set(self.document_identity_evidence_ids).issubset(catalog_ids):
            raise ValueError("document identity evidence is absent from the catalog")
        return self


def _structured_value_matches_kind(
    kind: ClaimKind,
    value: object,
    *,
    allow_null: bool,
) -> bool:
    optional_kinds = {
        ClaimKind.ACCOUNTING_PLATFORM,
        ClaimKind.MONTHLY_INVOICE_VOLUME,
        ClaimKind.QUALIFICATION,
        ClaimKind.SPREADSHEET,
    }
    if value is None:
        return allow_null and kind in optional_kinds
    if kind is ClaimKind.AP_YEARS:
        return (
            type(value) is float
            and math.isfinite(value)
            and 0 <= value <= 80
            and not (value == 0.0 and math.copysign(1.0, value) < 0)
        )
    if kind in {ClaimKind.INVOICE_PROCESSING, ClaimKind.RECONCILIATION}:
        return type(value) is bool
    if kind is ClaimKind.MONTHLY_INVOICE_VOLUME:
        return type(value) is int and 0 <= value <= 100_000_000
    if kind in {
        ClaimKind.ACCOUNTING_PLATFORM,
        ClaimKind.QUALIFICATION,
        ClaimKind.SPREADSHEET,
    }:
        return type(value) is str
    return False


def _bounded_structured_evidence_id(
    snapshot_id: str,
    candidate_id: str,
    semantic_hash: str,
    role: str,
) -> str:
    readable = ":".join(("json", snapshot_id, candidate_id, semantic_hash, role))
    if len(readable) <= 128:
        return readable
    return f"json:{hashlib.sha256(readable.encode('utf-8')).hexdigest()}"


def _structured_field_path(candidate_id: str, role: str) -> str:
    detailed = f"records[{candidate_id}].{role}"
    return detailed if len(detailed) <= 160 else f"record.{role}"


class EvidenceDispositionEntry(StrictModel):
    """One sanitized claim-to-evidence edge and its bounded disposition.

    The reference contains no source text.  Retaining its typed provenance lets
    an independent release authorizer distinguish a real consumed citation from
    an arbitrary identifier inserted into a later trust gate.
    """

    claim_kind: ClaimKind
    reference: EvidenceRef
    state: EvidenceDispositionState
    date_value: Annotated[date, Field(strict=True)] | None = None
    mapped_value: bool | int | float | SafeLabel | None = None

    @model_validator(mode="after")
    def claim_matches_reference_role(self) -> EvidenceDispositionEntry:
        if self.claim_kind is ClaimKind.CANDIDATE_ID:
            raise ValueError("identity proposals are never consumable evidence")
        if (
            self.reference.source_kind is not SourceKind.RESUME_VISIBLE
            or not self.reference.visible
            or not self.reference.admissible
            or self.reference.field_path is None
        ):
            raise ValueError("disposition inventory accepts visible admissible resume evidence")
        role = self.reference.field_path.rsplit(".", maxsplit=1)[-1]
        if self.claim_kind is ClaimKind.EMPLOYMENT_INTERVAL:
            if self.date_value is None or self.mapped_value is not None:
                raise ValueError("employment disposition requires a typed endpoint date")
            if role not in {"employment_start", "employment_end"}:
                raise ValueError("employment disposition requires one dated endpoint")
            canonical = json.dumps(
                self.date_value.isoformat(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            if hashlib.sha256(canonical).hexdigest() != self.reference.semantic_hash:
                raise ValueError("employment endpoint date differs from its evidence hash")
        else:
            if self.date_value is not None:
                raise ValueError("only employment dispositions may carry endpoint dates")
            if role != self.claim_kind.value or not _structured_value_matches_kind(
                self.claim_kind,
                self.mapped_value,
                allow_null=False,
            ):
                raise ValueError("disposition claim kind differs from its evidence field")
            canonical = json.dumps(
                self.mapped_value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            if hashlib.sha256(canonical).hexdigest() != self.reference.semantic_hash:
                raise ValueError("mapped value differs from its visible evidence hash")
        return self


class StructuredFieldAnchor(StrictModel):
    """One typed structured value and its canonical application-JSON reference."""

    claim_kind: ClaimKind
    value: bool | int | float | SafeLabel | None
    reference: EvidenceRef

    @model_validator(mode="after")
    def value_and_reference_are_typed(self) -> StructuredFieldAnchor:
        if self.claim_kind not in STRUCTURED_FIELD_KINDS or not _structured_value_matches_kind(
            self.claim_kind,
            self.value,
            allow_null=True,
        ):
            raise ValueError("structured field anchor has an invalid typed value")
        reference = self.reference
        canonical = json.dumps(
            self.value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if (
            reference.source_kind is not SourceKind.APPLICATION_JSON
            or reference.visible is not True
            or reference.admissible is not True
            or reference.field_path is None
            or reference.field_path.rsplit(".", maxsplit=1)[-1] != self.claim_kind.value
            or any(
                item is not None
                for item in (
                    reference.page,
                    reference.document_page_count,
                    reference.page_width,
                    reference.page_height,
                    reference.bbox,
                )
            )
            or hashlib.sha256(canonical).hexdigest() != reference.semantic_hash
        ):
            raise ValueError("structured field anchor reference is inconsistent")
        return self


class EvidenceDispositionInventory(StrictModel):
    """Stage-local consumed/released/dropped evidence accounting.

    The complete typed structured-anchor set lets an independent authorizer
    rederive every cross-source comparison.  The two legacy scalar fields are
    exact aliases retained for the separate timeline derivation.
    """

    candidate_id: SourceId
    snapshot_id: SourceId
    record_ap_years: Annotated[float, Field(strict=True, ge=0, le=80)]
    record_invoice_processing: Annotated[bool, Field(strict=True)]
    record_ap_years_reference: EvidenceRef
    record_invoice_processing_reference: EvidenceRef
    structured_anchors: tuple[StructuredFieldAnchor, ...] = Field(min_length=7, max_length=7)
    entries: tuple[EvidenceDispositionEntry, ...] = Field(max_length=1_024)

    @field_validator("record_ap_years")
    @classmethod
    def normalize_record_zero_years(cls, value: float) -> float:
        return 0.0 if value == 0.0 else value

    @model_validator(mode="after")
    def entries_are_unique_and_owned(self) -> EvidenceDispositionInventory:
        evidence_ids = [item.reference.evidence_id for item in self.entries]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence disposition identifiers must be unique")
        if any(
            item.reference.candidate_id != self.candidate_id
            or item.reference.snapshot_id != self.snapshot_id
            for item in self.entries
        ):
            raise ValueError("evidence disposition belongs to another candidate or snapshot")
        if tuple(anchor.claim_kind for anchor in self.structured_anchors) != (
            STRUCTURED_FIELD_KINDS
        ):
            raise ValueError("structured field anchors must contain the exact ordered field set")
        anchor_ids: set[str] = set()
        anchors_by_kind = {anchor.claim_kind: anchor for anchor in self.structured_anchors}
        for anchor in self.structured_anchors:
            reference = anchor.reference
            expected_id = _bounded_structured_evidence_id(
                self.snapshot_id,
                self.candidate_id,
                reference.semantic_hash,
                anchor.claim_kind.value,
            )
            expected_path = _structured_field_path(
                self.candidate_id,
                anchor.claim_kind.value,
            )
            if (
                reference.evidence_id in anchor_ids
                or reference.evidence_id in evidence_ids
                or reference.candidate_id != self.candidate_id
                or reference.snapshot_id != self.snapshot_id
                or reference.evidence_id != expected_id
                or reference.field_path != expected_path
            ):
                raise ValueError("structured field anchor ownership or identifier is inconsistent")
            anchor_ids.add(reference.evidence_id)
        anchors = (
            (
                self.record_ap_years_reference,
                "ap_years",
                self.record_ap_years,
                anchors_by_kind[ClaimKind.AP_YEARS],
            ),
            (
                self.record_invoice_processing_reference,
                "invoice_processing",
                self.record_invoice_processing,
                anchors_by_kind[ClaimKind.INVOICE_PROCESSING],
            ),
        )
        for reference, role, value, structured_anchor in anchors:
            canonical = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            if (
                reference.candidate_id != self.candidate_id
                or reference.snapshot_id != self.snapshot_id
                or reference.source_kind is not SourceKind.APPLICATION_JSON
                or reference.visible is not True
                or reference.admissible is not True
                or reference.field_path is None
                or reference.field_path.rsplit(".", maxsplit=1)[-1] != role
                or any(
                    item is not None
                    for item in (
                        reference.page,
                        reference.document_page_count,
                        reference.page_width,
                        reference.page_height,
                        reference.bbox,
                    )
                )
                or hashlib.sha256(canonical).hexdigest() != reference.semantic_hash
                or reference != structured_anchor.reference
                or value != structured_anchor.value
                or type(value) is not type(structured_anchor.value)
            ):
                raise ValueError("record scalar anchor is inconsistent with its typed value")
        if self.record_ap_years_reference.evidence_id == (
            self.record_invoice_processing_reference.evidence_id
        ):
            raise ValueError("record scalar anchors must be distinct")
        return self


class UnavailableCandidate(StrictModel):
    candidate_id: SourceId
    component: UnavailableComponent
    reason: ReasonCode

    @model_validator(mode="after")
    def reason_is_structural_failure(self) -> UnavailableCandidate:
        if self.reason not in {
            ReasonCode.RETRIEVAL_FAILED,
            ReasonCode.SCHEMA_INVALID,
            ReasonCode.PARSING_FAILED,
        }:
            raise ValueError("unavailable candidate requires a structural failure reason")
        return self


class TrustDecision(StrictModel):
    decision_id: SafeId
    stage: TrustStage
    scope: TrustScope
    state: TrustState
    outcome: TrustOutcome
    reason_codes: tuple[ReasonCode, ...] = Field(min_length=1)
    candidate_id: SourceId | None = None
    snapshot_id: SourceId | None = None
    evidence_ids: tuple[SafeId, ...] = ()
    input_gate_ids: tuple[SafeId, ...] = ()
    evidence_inventory: EvidenceDispositionInventory | None = None

    @model_validator(mode="after")
    def state_and_scope_are_consistent(self) -> TrustDecision:
        if self.scope is TrustScope.RECORD and self.candidate_id is None:
            raise ValueError("record trust decisions require candidate_id")
        if self.scope is TrustScope.BATCH and self.candidate_id is not None:
            raise ValueError("batch trust decisions cannot carry candidate_id")
        valid_outcomes = {
            TrustState.USABLE: {TrustOutcome.ALLOW},
            TrustState.DEGRADED: {TrustOutcome.RESTRICT},
            TrustState.QUARANTINED: {TrustOutcome.QUARANTINE, TrustOutcome.HOLD},
            TrustState.UNAVAILABLE: {TrustOutcome.UNAVAILABLE, TrustOutcome.HOLD},
        }
        if self.outcome not in valid_outcomes[self.state]:
            raise ValueError("trust outcome is inconsistent with trust state")
        if self.decision_id in self.input_gate_ids:
            raise ValueError("trust decisions cannot consume themselves")
        if len(self.input_gate_ids) != len(set(self.input_gate_ids)):
            raise ValueError("trust decision input gates must be unique")
        if self.evidence_inventory is not None:
            inventory = self.evidence_inventory
            if (
                self.scope is not TrustScope.RECORD
                or self.candidate_id != inventory.candidate_id
                or self.snapshot_id != inventory.snapshot_id
                or self.stage
                not in {
                    TrustStage.MAPPING,
                    TrustStage.PROVENANCE,
                    TrustStage.CANDIDATE_VALIDATION,
                }
            ):
                raise ValueError("evidence inventory is attached to the wrong trust boundary")
            inventory_ids = tuple(sorted(item.reference.evidence_id for item in inventory.entries))
            if self.stage in {TrustStage.MAPPING, TrustStage.PROVENANCE}:
                if any(
                    item.state is not EvidenceDispositionState.CONSUMED
                    for item in inventory.entries
                ):
                    raise ValueError("provenance inventory may contain only consumed entries")
                if inventory_ids != tuple(sorted(self.evidence_ids)):
                    raise ValueError("provenance inventory must equal gate evidence")
            elif any(item.state is EvidenceDispositionState.CONSUMED for item in inventory.entries):
                raise ValueError("terminal inventory requires final evidence dispositions")
        return self


class StageHandle(StrictModel):
    """Opaque, run-bound reference to a value held privately by ``StageVault``."""

    handle_id: SafeId
    run_id: SafeId
    provenance_ids: tuple[SafeId, ...] = ()
    decision: TrustDecision
    consumable: bool

    @model_validator(mode="after")
    def handle_matches_gate(self) -> StageHandle:
        may_consume = self.decision.outcome in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
        if self.consumable is not may_consume:
            raise ValueError("only ALLOW/RESTRICT decisions may create consumable handles")
        if self.handle_id != self.decision.decision_id:
            raise ValueError("stage handle must be bound to its trust decision")
        return self


class PlanCommand(StrictModel):
    command_id: SafeId
    kind: PlanStep
    scope: TrustScope = TrustScope.BATCH
    candidate_id: SourceId | None = None
    dependency_ids: tuple[SafeId, ...] = ()

    @model_validator(mode="after")
    def scope_matches_candidate(self) -> PlanCommand:
        if self.scope is TrustScope.RECORD and self.candidate_id is None:
            raise ValueError("record commands require candidate_id")
        if self.scope is TrustScope.BATCH and self.candidate_id is not None:
            raise ValueError("batch commands cannot carry candidate_id")
        if self.command_id in self.dependency_ids:
            raise ValueError("commands cannot depend on themselves")
        return self


class StepReceipt(StrictModel):
    receipt_id: SafeId
    sequence: Annotated[int, Field(ge=1)]
    plan_version: Annotated[int, Field(ge=1)]
    command_id: SafeId
    command_kind: PlanStep
    status: StepStatus
    reason_codes: tuple[ReasonCode, ...] = Field(min_length=1)
    candidate_id: SourceId | None = None
    evidence_ids: tuple[SafeId, ...] = ()
    produced_gate_id: SafeId | None = None
    consumed_gate_ids: tuple[SafeId, ...] = ()

    @model_validator(mode="after")
    def status_marker_matches_terminal_state(self) -> StepReceipt:
        markers = {
            StepStatus.STARTED: ReasonCode.COMMAND_STARTED,
            StepStatus.COMPLETED: ReasonCode.COMMAND_COMPLETED,
            StepStatus.RESTRICTED: ReasonCode.COMMAND_RESTRICTED,
            StepStatus.FAILED: ReasonCode.COMMAND_FAILED,
        }
        expected = markers[self.status]
        status_codes = frozenset(markers.values())
        present = status_codes.intersection(self.reason_codes)
        if self.status is StepStatus.STARTED:
            if self.reason_codes != (expected,):
                raise ValueError("started receipts require only command_started")
        elif expected not in present or present != {expected}:
            raise ValueError("terminal receipt marker does not match status")
        return self


class CorroborationRequest(StrictModel):
    request_id: SafeId
    candidate_ids: tuple[SourceId, ...]
    reason_codes: tuple[ReasonCode, ...] = Field(min_length=1)
    requested_evidence_kinds: tuple[ClaimKind, ...] = ()


class ExecutionPlan(StrictModel):
    version: Annotated[int, Field(ge=1)]
    objective: PlanObjective
    strategy: Strategy
    commands: tuple[PlanCommand, ...] = Field(min_length=1)
    trigger_codes: tuple[ReasonCode, ...] = ()
    allowed_evidence_ids: tuple[SafeId, ...] = ()
    prohibited_actions: tuple[ProhibitedAction, ...] = (
        ProhibitedAction.AUTOMATED_HIRE,
        ProhibitedAction.AUTOMATED_REJECT,
        ProhibitedAction.EXECUTE_SOURCE_INSTRUCTIONS,
        ProhibitedAction.USE_RAW_SOURCE_TEXT,
        ProhibitedAction.USE_PROTECTED_ATTRIBUTES,
        ProhibitedAction.RANK_QUARANTINED_EVIDENCE,
        ProhibitedAction.RANK_UNAVAILABLE_CANDIDATE,
    )

    @model_validator(mode="after")
    def command_graph_is_closed(self) -> ExecutionPlan:
        command_ids = [command.command_id for command in self.commands]
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("plan command IDs must be unique")
        available: set[str] = set()
        for command in self.commands:
            if not set(command.dependency_ids).issubset(available):
                raise ValueError("plan command dependencies must reference earlier commands")
            available.add(command.command_id)
        return self


class PlanDiff(StrictModel):
    from_version: Annotated[int, Field(ge=1)]
    to_version: Annotated[int, Field(ge=2)]
    strategy_before: Strategy
    strategy_after: Strategy
    objective_before: PlanObjective
    objective_after: PlanObjective
    trigger_codes: tuple[ReasonCode, ...] = Field(min_length=1)
    removed_command_ids: tuple[SafeId, ...]
    added_commands: tuple[PlanCommand, ...]
    revoked_evidence_ids: tuple[SafeId, ...] = ()
    granted_evidence_ids: tuple[SafeId, ...] = ()
    added_prohibitions: tuple[ProhibitedAction, ...] = ()

    @model_validator(mode="after")
    def is_material_change(self) -> PlanDiff:
        if self.to_version <= self.from_version:
            raise ValueError("plan diff must advance the plan version")
        policy_unchanged = (
            self.strategy_before is self.strategy_after
            and self.objective_before is self.objective_after
        )
        material_change = bool(
            self.revoked_evidence_ids
            or self.granted_evidence_ids
            or self.removed_command_ids
            or self.added_commands
        )
        if policy_unchanged and not material_change:
            raise ValueError("unchanged policy requires a command or evidence change")
        return self


class SupportedEmploymentInterval(StrictModel):
    """One bounded dated interval and the exact visible evidence for each endpoint."""

    start_date: date
    end_date: date
    start_evidence_id: SafeId
    end_evidence_id: SafeId

    @model_validator(mode="after")
    def interval_is_ordered_and_distinct(self) -> SupportedEmploymentInterval:
        if self.end_date < self.start_date:
            raise ValueError("supported employment interval end precedes start")
        if self.start_evidence_id == self.end_evidence_id:
            raise ValueError("employment interval endpoints require distinct evidence")
        return self


class SupportedFact(StrictModel):
    fact_id: SafeId
    candidate_id: SourceId
    snapshot_id: SourceId
    kind: ClaimKind
    normalized_value: bool | int | float | SafeLabel | None = None
    source_value: SafeLabel | None = None
    canonical_value: SafeLabel | None = None
    normalization_mode: NormalizationMode | None = None
    canonical_value_sha256: SafeHash | None = None
    employment_intervals: tuple[SupportedEmploymentInterval, ...] = ()
    source_roles: tuple[SourceKind, ...] = ()
    evidence_ids: tuple[SafeId, ...] = Field(min_length=1)

    @field_validator("normalized_value")
    @classmethod
    def normalized_numeric_value_is_finite(
        cls, value: bool | int | float | str | None
    ) -> bool | int | float | str | None:
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("supported numeric facts must be finite")
            return 0.0 if value == 0.0 else value
        return value

    @model_validator(mode="after")
    def categorical_normalization_is_atomic(self) -> SupportedFact:
        categorical = self.kind in {
            ClaimKind.SPREADSHEET,
            ClaimKind.ACCOUNTING_PLATFORM,
            ClaimKind.QUALIFICATION,
        }
        values = (
            self.source_value,
            self.canonical_value,
            self.normalization_mode,
            self.canonical_value_sha256,
        )
        if categorical and any(value is None for value in values):
            raise ValueError("categorical facts require complete canonicalization metadata")
        if not categorical and any(value is not None for value in values):
            raise ValueError("non-categorical facts cannot carry canonicalization metadata")
        if categorical and self.normalized_value != self.canonical_value:
            raise ValueError("categorical normalized value must equal its canonical value")
        interval_fact = self.kind is ClaimKind.EMPLOYMENT_INTERVAL
        if interval_fact:
            if not self.employment_intervals:
                raise ValueError("employment interval facts require dated interval evidence")
            if not isinstance(self.normalized_value, (int, float)) or isinstance(
                self.normalized_value, bool
            ):
                raise ValueError("employment interval facts require a numeric duration")
            endpoint_ids = tuple(
                evidence_id
                for interval in self.employment_intervals
                for evidence_id in (
                    interval.start_evidence_id,
                    interval.end_evidence_id,
                )
            )
            if len(endpoint_ids) != len(set(endpoint_ids)):
                raise ValueError("employment interval endpoint evidence must be unique")
            if set(endpoint_ids) != set(self.evidence_ids):
                raise ValueError("employment interval endpoints must equal fact evidence")
        elif self.employment_intervals:
            raise ValueError("only employment interval facts may carry dated intervals")
        return self


class DerivedFeature(StrictModel):
    feature_id: SafeId
    candidate_id: SourceId
    snapshot_id: SourceId
    name: SafeId
    normalized_value: bool | int | float | SafeLabel | None = None
    dependency_fact_ids: tuple[SafeId, ...] = ()
    dependency_feature_ids: tuple[SafeId, ...] = ()

    @field_validator("normalized_value")
    @classmethod
    def derived_numeric_value_is_finite(
        cls, value: bool | int | float | str | None
    ) -> bool | int | float | str | None:
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("derived numeric features must be finite")
            return 0.0 if value == 0.0 else value
        return value

    @model_validator(mode="after")
    def has_a_dependency(self) -> DerivedFeature:
        if not self.dependency_fact_ids and not self.dependency_feature_ids:
            raise ValueError("derived features require a fact or feature dependency")
        return self


class DecisionSupportGraph(StrictModel):
    candidate_id: SourceId
    snapshot_id: SourceId
    evidence_ids: tuple[SafeId, ...]
    evidence_manifest: tuple[EvidenceRef, ...] = ()
    facts: tuple[SupportedFact, ...]
    features: tuple[DerivedFeature, ...]
    route_support_ids: tuple[SafeId, ...]

    @model_validator(mode="after")
    def graph_is_closed(self) -> DecisionSupportGraph:
        facts = {fact.fact_id: fact for fact in self.facts}
        features = {feature.feature_id: feature for feature in self.features}
        if len(facts) != len(self.facts) or len(features) != len(self.features):
            raise ValueError("support graph node IDs must be unique")
        evidence = set(self.evidence_ids)
        if any(fact.candidate_id != self.candidate_id for fact in self.facts):
            raise ValueError("support facts must belong to graph candidate")
        if any(fact.snapshot_id != self.snapshot_id for fact in self.facts):
            raise ValueError("support facts must belong to graph snapshot")
        if any(not set(fact.evidence_ids).issubset(evidence) for fact in self.facts):
            raise ValueError("support fact references evidence outside graph closure")
        manifest = {item.evidence_id: item for item in self.evidence_manifest}
        if len(manifest) != len(self.evidence_manifest):
            raise ValueError("support evidence manifest IDs must be unique")
        if manifest and set(manifest) != evidence:
            raise ValueError("support evidence manifest must equal graph evidence closure")
        if any(item.candidate_id != self.candidate_id for item in self.evidence_manifest):
            raise ValueError("support evidence must belong to graph candidate")
        if any(item.snapshot_id != self.snapshot_id for item in self.evidence_manifest):
            raise ValueError("support evidence must belong to graph snapshot")
        if any(feature.candidate_id != self.candidate_id for feature in self.features):
            raise ValueError("derived features must belong to graph candidate")
        if any(feature.snapshot_id != self.snapshot_id for feature in self.features):
            raise ValueError("derived features must belong to graph snapshot")
        if any(not set(feature.dependency_fact_ids).issubset(facts) for feature in self.features):
            raise ValueError("derived feature references an unknown fact")
        if any(
            not set(feature.dependency_feature_ids).issubset(features) for feature in self.features
        ):
            raise ValueError("derived feature references an unknown derived feature")
        if not set(self.route_support_ids).issubset(set(features)):
            raise ValueError("route support references an unknown feature")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(feature_id: str) -> None:
            if feature_id in visiting:
                raise ValueError("derived feature graph must be acyclic")
            if feature_id in visited:
                return
            visiting.add(feature_id)
            for dependency_id in features[feature_id].dependency_feature_ids:
                visit(dependency_id)
            visiting.remove(feature_id)
            visited.add(feature_id)

        for feature_id in features:
            visit(feature_id)
        return self


class ValidatedCandidateEvidence(StrictModel):
    """The only candidate type accepted by the ranking controller."""

    candidate_id: SourceId
    snapshot_id: SourceId
    trust_state: TrustState
    ap_years: Annotated[float, Field(strict=True, ge=0, le=80)] | None = None
    invoice_processing: Annotated[bool, Field(strict=True)] | None = None
    reconciliation: Annotated[bool, Field(strict=True)] | None = None
    spreadsheet_supported: Annotated[bool, Field(strict=True)] = False
    accounting_platform_supported: Annotated[bool, Field(strict=True)] = False
    monthly_invoice_volume: Annotated[int, Field(strict=True, ge=0, le=100_000_000)] | None = None
    qualification_supported: Annotated[bool, Field(strict=True)] = False
    corroborated_claim_kinds: tuple[ClaimKind, ...] = ()
    evidence_ids: tuple[SafeId, ...] = ()
    support_graph: DecisionSupportGraph | None = None
    reason_codes: tuple[ReasonCode, ...] = ()

    @field_validator("ap_years")
    @classmethod
    def normalize_zero_years(cls, value: float | None) -> float | None:
        return 0.0 if value == 0.0 else value

    @model_validator(mode="after")
    def claim_kinds_are_unique(self) -> ValidatedCandidateEvidence:
        if len(self.corroborated_claim_kinds) != len(set(self.corroborated_claim_kinds)):
            raise ValueError("corroborated claim kinds must be unique")
        if self.support_graph is not None:
            if self.support_graph.candidate_id != self.candidate_id:
                raise ValueError("support graph belongs to another candidate")
            if self.support_graph.snapshot_id != self.snapshot_id:
                raise ValueError("support graph belongs to another snapshot")
            if set(self.evidence_ids) != set(self.support_graph.evidence_ids):
                raise ValueError("candidate evidence must equal support graph evidence closure")
        return self


class ValidatedBatchEvidence(StrictModel):
    batch_id: SourceId
    snapshot_id: SourceId
    candidates: tuple[ValidatedCandidateEvidence, ...]
    unavailable_candidate_ids: tuple[SourceId, ...] = ()

    @model_validator(mode="after")
    def candidates_belong_to_snapshot(self) -> ValidatedBatchEvidence:
        if any(candidate.snapshot_id != self.snapshot_id for candidate in self.candidates):
            raise ValueError("validated candidates must belong to the batch snapshot")
        return self

    batch_integrity_valid: Annotated[bool, Field(strict=True)]
    mapper_disagreement: Annotated[bool, Field(strict=True)]


class EvidenceRankKey(StrictModel):
    band_priority: Annotated[int, Field(strict=True, ge=0, le=2)]
    essentials_count: Annotated[int, Field(strict=True, ge=0, le=4)]
    preferred_count: Annotated[int, Field(strict=True, ge=0, le=3)]
    corroborated_claim_count: Annotated[int, Field(strict=True, ge=0, le=len(ClaimKind))]

    def as_tuple(self) -> tuple[int, int, int, int]:
        return (
            self.band_priority,
            self.essentials_count,
            self.preferred_count,
            self.corroborated_claim_count,
        )


class CandidateRoute(StrictModel):
    candidate_id: SourceId
    snapshot_id: SourceId
    band: ReviewBand
    queue: ReviewQueue
    evidence_rank: Annotated[int, Field(strict=True, ge=1)] | None = None
    display_position: Annotated[int, Field(strict=True, ge=1)] | None = None
    rank_key: EvidenceRankKey | None = None
    reason_codes: tuple[ReasonCode, ...]
    evidence_ids: tuple[SafeId, ...] = ()
    support_graph: DecisionSupportGraph | None = None

    @model_validator(mode="after")
    def rank_and_key_are_atomic(self) -> CandidateRoute:
        ranked_fields = (self.evidence_rank, self.display_position, self.rank_key)
        if any(value is None for value in ranked_fields) and not all(
            value is None for value in ranked_fields
        ):
            raise ValueError("evidence rank, display position, and rank key are atomic")
        excluded = self.band in {ReviewBand.EVIDENCE_UNAVAILABLE, ReviewBand.INTEGRITY_HOLD}
        if excluded and self.evidence_rank is not None:
            raise ValueError("unavailable or quarantined candidates cannot be ranked")
        if self.support_graph is not None:
            if self.support_graph.candidate_id != self.candidate_id:
                raise ValueError("route support graph belongs to another candidate")
            if self.support_graph.snapshot_id != self.snapshot_id:
                raise ValueError("route support graph belongs to another snapshot")
            if set(self.evidence_ids) != set(self.support_graph.evidence_ids):
                raise ValueError("route evidence must equal support graph evidence closure")
        return self


class DecisionExplanation(StrictModel):
    template: ExplanationTemplate
    message: Annotated[str, Field(min_length=1, max_length=320)]
    candidate_id: SourceId | None = None
    reason_codes: tuple[ReasonCode, ...] = ()


class RunDecision(StrictModel):
    run_id: SafeId
    batch_id: SourceId
    snapshot_id: SourceId
    strategy: Strategy
    ranking_scope: RankingScope
    plans: tuple[ExecutionPlan, ...] = Field(min_length=1, max_length=3)
    plan: ExecutionPlan
    plan_diff: PlanDiff | None = None
    execution_mode: ExecutionMode
    step_receipts: tuple[StepReceipt, ...]
    corroboration_requests: tuple[CorroborationRequest, ...] = ()
    support_graph_hash: SafeHash
    batch_state: TrustState
    routes: tuple[CandidateRoute, ...]
    trust_ledger: tuple[TrustDecision, ...]
    explanations: tuple[DecisionExplanation, ...]

    @model_validator(mode="after")
    def plan_and_ranking_match_decision(self) -> RunDecision:
        if self.plans[-1] != self.plan or self.plans[0].version != 1:
            raise ValueError("plan history must start at v1 and end at the final plan")
        if len(self.plans) != self.plan.version:
            raise ValueError("plan history length must match final plan version")
        if self.plan.strategy is not self.strategy:
            raise ValueError("run strategy must match final plan strategy")
        if (self.plan.version == 1) is not (self.plan_diff is None):
            raise ValueError("only revised plans carry a plan diff")
        if self.strategy is Strategy.BATCH_INTEGRITY_HOLD:
            if self.ranking_scope is not RankingScope.NONE or any(
                route.evidence_rank is not None for route in self.routes
            ):
                raise ValueError("batch hold cannot release rankings")
        elif self.strategy is Strategy.FULL_EVIDENCE_RANKING:
            if self.ranking_scope is not RankingScope.COMPLETE:
                raise ValueError("full ranking requires complete scope")
        elif self.ranking_scope is not RankingScope.PARTIAL:
            raise ValueError("restricted ranking strategies require partial scope")
        terminal = {StepStatus.COMPLETED, StepStatus.RESTRICTED, StepStatus.FAILED}
        plan_versions = {plan.version for plan in self.plans}
        if any(receipt.plan_version not in plan_versions for receipt in self.step_receipts):
            raise ValueError("step receipt references a plan outside the plan history")
        known_commands = {
            (plan.version, command.command_id): command
            for plan in self.plans
            for command in plan.commands
        }
        if any(
            (command := known_commands.get((receipt.plan_version, receipt.command_id))) is None
            or receipt.command_kind is not command.kind
            for receipt in self.step_receipts
        ):
            raise ValueError("every receipt must belong to its exact planned command")
        sequences = [receipt.sequence for receipt in self.step_receipts]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("step receipt sequences must be globally contiguous and ordered")
        if len({receipt.receipt_id for receipt in self.step_receipts}) != len(self.step_receipts):
            raise ValueError("step receipt IDs must be globally unique")
        for plan in self.plans:
            for command in plan.commands:
                matching = [
                    receipt
                    for receipt in self.step_receipts
                    if receipt.plan_version == plan.version
                    and receipt.command_id == command.command_id
                ]
                removed_command = (
                    self.plan_diff is not None
                    and command.command_id in self.plan_diff.removed_command_ids
                )
                if removed_command:
                    if matching:
                        raise ValueError("removed commands must never start or complete")
                    continue
                if not matching or matching[0].status is not StepStatus.STARTED:
                    raise ValueError("every command requires a started receipt")
                if len(matching) != 2 or matching[-1].status not in terminal:
                    raise ValueError("every command requires exactly one terminal receipt")
                if any(receipt.command_kind is not command.kind for receipt in matching):
                    raise ValueError("receipt command kind differs from its plan")
        if self.execution_mode is ExecutionMode.EXECUTED and any(
            receipt.status is not StepStatus.COMPLETED
            for receipt in self.step_receipts
            if receipt.status is not StepStatus.STARTED
        ):
            raise ValueError("executed runs cannot contain restricted or failed commands")
        return self


SafeTraceScalar = bool | int | float | str


class TraceEvent(StrictModel):
    event_type: SafeId
    run_id: SafeId
    emitted_at: datetime
    stage: TrustStage | None = None
    candidate_id: SourceId | None = None
    snapshot_id: SourceId | None = None
    gate_id: SafeId | None = None
    state: TrustState | None = None
    reason_codes: tuple[ReasonCode, ...] = ()
    attributes: dict[SafeId, SafeTraceScalar] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def trace_attributes_are_scalar(cls, value: dict[str, Any]) -> dict[str, SafeTraceScalar]:
        if any(not isinstance(item, (bool, int, float, str)) for item in value.values()):
            raise ValueError("trace attributes must be sanitized scalar values")
        return value
