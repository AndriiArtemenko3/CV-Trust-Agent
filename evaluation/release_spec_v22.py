"""Independent V2.2 release projection and canonical digest.

This module is deliberately dependency-light and does not import the runtime,
capture runners, or the V1 evaluator.  It is the common structural contract
used by the V2.2 semantic release validators.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated, Literal, TypeAlias, cast

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

JsonObject: TypeAlias = dict[str, object]
JsonScalar: TypeAlias = bool | int | float | str | None

SCHEMA_VERSION_V22 = 3
PROTOCOL_VERSION_V22 = "2.2"
DECISION_DIGEST_DOMAIN = b"cv-trust-agent/decision-projection/v3\0"
ACTION_SEMANTICS_DOMAIN = b"cv-trust-agent/decision-action-semantics/v3\0"
CANONICAL_VALUE_DOMAIN = b"cv-trust-agent/canonical-value/v2\0"
IMPLEMENTATION_TREE_DOMAIN = b"cv-trust-agent/implementation-tree/v2\0"

_SOURCE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_INTERNAL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$"
_TOKEN_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{0,79}$"
_FIELD_PATH_PATTERN = r"^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,159}$"
_CANONICAL_EVIDENCE_ID_PATTERN_V22 = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")

SourceId = Annotated[str, StringConstraints(pattern=_SOURCE_ID_PATTERN)]
InternalId = Annotated[str, StringConstraints(pattern=_INTERNAL_ID_PATTERN)]
Token = Annotated[str, StringConstraints(pattern=_TOKEN_PATTERN)]
FieldPath = Annotated[str, StringConstraints(pattern=_FIELD_PATH_PATTERN)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


def _metadata_label_is_safe(value: str) -> str:
    folded = value.casefold()
    forbidden_prefixes = (
        "api-key",
        "api_key",
        "apikey",
        "bearer",
        "data:",
        "file:",
        "http:",
        "https:",
        "secret",
        "sk-",
        "www.",
    )
    if folded.startswith(forbidden_prefixes):
        raise ValueError("metadata labels cannot carry URLs or credential-shaped values")
    return value


SafeMetadataLabel = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,79}$"),
    AfterValidator(_metadata_label_is_safe),
]
SafeCategoricalLabel = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9 ]{0,78}[A-Za-z0-9])?$"),
]

CATEGORICAL_ALLOW_LISTS_V22: Mapping[str, frozenset[str]] = {
    "spreadsheet": frozenset({"excel", "google sheets"}),
    "accounting_platform": frozenset({"xero", "sage", "quickbooks", "netsuite", "sap"}),
    "qualification": frozenset({"aat level 2", "aat level 3", "aat level 4", "acca"}),
}
_DISPOSITION_CLAIM_KINDS_V22 = frozenset(
    {
        "ap_years",
        "employment_interval",
        "invoice_processing",
        "reconciliation",
        "spreadsheet",
        "accounting_platform",
        "monthly_invoice_volume",
        "qualification",
    }
)
_STRUCTURED_CLAIM_KINDS_V22 = (
    "accounting_platform",
    "ap_years",
    "invoice_processing",
    "monthly_invoice_volume",
    "qualification",
    "reconciliation",
    "spreadsheet",
)
_NULLABLE_STRUCTURED_CLAIM_KINDS_V22 = frozenset(
    {
        "accounting_platform",
        "monthly_invoice_volume",
        "qualification",
        "spreadsheet",
    }
)
_STRUCTURED_LABEL_PATTERN_V22 = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .+#&/_()-]{0,79}$")


def _structured_category_value_valid_v22(claim_kind: str, value: object) -> bool:
    """Validate one bounded category without assigning another field's token."""

    if (
        claim_kind not in CATEGORICAL_ALLOW_LISTS_V22
        or type(value) is not str
        or value != value.strip()
        or _STRUCTURED_LABEL_PATTERN_V22.fullmatch(value) is None
    ):
        return False
    normalized = " ".join(value.split()).casefold()
    known_values = frozenset().union(*CATEGORICAL_ALLOW_LISTS_V22.values())
    return normalized not in known_values or normalized in CATEGORICAL_ALLOW_LISTS_V22[claim_kind]


_RANK_COMMANDS = frozenset(
    {"rank_full_evidence", "rank_supported_evidence", "rank_partial_evidence"}
)
_EVIDENCE_CONSUMING_COMMANDS = frozenset(
    {
        *_RANK_COMMANDS,
        "quarantine_unsupported",
        "mark_evidence_pending",
        "isolate_batch",
        "pre_release_audit",
        "release_output",
    }
)
_UNRANKED_BANDS = frozenset({"INTEGRITY_HOLD", "EVIDENCE_UNAVAILABLE"})
_ALLOWED_BAND_QUEUE = frozenset(
    {
        ("STRONG_EVIDENCE_MATCH", "PRIORITY_HUMAN_REVIEW"),
        ("POTENTIAL_EVIDENCE_MATCH", "STANDARD_HUMAN_REVIEW"),
        ("INSUFFICIENT_SUPPORTED_EVIDENCE", "EVIDENCE_CHECK"),
        ("INTEGRITY_HOLD", "INTEGRITY_REVIEW"),
        ("INTEGRITY_HOLD", "BATCH_INTEGRITY_HOLD"),
        ("EVIDENCE_UNAVAILABLE", "EVIDENCE_PENDING"),
    }
)
_FACT_KINDS_V22 = frozenset(
    {
        "candidate_id",
        "ap_years",
        "employment_interval",
        "invoice_processing",
        "reconciliation",
        "spreadsheet",
        "accounting_platform",
        "monthly_invoice_volume",
        "qualification",
    }
)
_STRATEGIES_V22 = frozenset(
    {
        "FULL_EVIDENCE_RANKING",
        "SUPPORTED_ONLY_RANKING",
        "PARTIAL_SAFE_RANKING",
        "BATCH_INTEGRITY_HOLD",
    }
)
_OBJECTIVES_V22 = frozenset(
    {
        "rank_full_corroborated_evidence",
        "rank_supported_evidence_only",
        "rank_available_evidence_safely",
        "hold_batch_for_integrity_review",
    }
)
_PLAN_STEPS_V22 = frozenset(
    {
        "fetch_candidate_details",
        "validate_candidate_details",
        "fetch_candidate_resumes",
        "parse_candidate_resumes",
        "validate_candidate_bindings",
        "map_candidate_claims",
        "validate_candidate_evidence",
        "validate_index_commitments",
        "rank_full_evidence",
        "quarantine_unsupported",
        "mark_evidence_pending",
        "rank_supported_evidence",
        "rank_partial_evidence",
        "isolate_batch",
        "request_corroboration",
        "pre_release_audit",
        "release_output",
    }
)
_PROVISIONAL_PLAN_STEPS_V22 = frozenset(
    {
        "rank_full_evidence",
        "quarantine_unsupported",
        "mark_evidence_pending",
        "rank_supported_evidence",
        "rank_partial_evidence",
        "isolate_batch",
        "request_corroboration",
        "pre_release_audit",
        "release_output",
    }
)
_PROHIBITIONS_V22 = frozenset(
    {
        "automated_hire",
        "automated_reject",
        "execute_source_instructions",
        "use_raw_source_text",
        "use_protected_attributes",
        "rank_quarantined_evidence",
        "rank_unavailable_candidate",
        "release_final_qualification_decision",
    }
)
_BASE_PROHIBITIONS_V22 = frozenset(_PROHIBITIONS_V22 - {"release_final_qualification_decision"})
_TRUST_STAGES_V22 = frozenset(
    {
        "retrieval",
        "schema",
        "manifest",
        "revision",
        "parsing",
        "identity",
        "mapping",
        "provenance",
        "cross_source",
        "timeline",
        "candidate_validation",
        "planning",
        "ranking",
        "pre_release",
        "release",
    }
)
_REASON_CODES_V22 = frozenset(
    {
        "fetch_succeeded",
        "retrieval_failed",
        "schema_valid",
        "schema_invalid",
        "parsing_failed",
        "index_valid",
        "index_conflict",
        "manifest_valid",
        "manifest_conflict",
        "revision_valid",
        "revision_conflict",
        "semantic_hash_valid",
        "semantic_hash_conflict",
        "resume_hash_valid",
        "resume_hash_conflict",
        "candidate_unavailable",
        "mapper_output_valid",
        "mapper_unavailable",
        "mapper_disagreement",
        "evidence_admissible",
        "evidence_missing",
        "evidence_unknown",
        "evidence_inadmissible",
        "evidence_value_conflict",
        "cross_source_match",
        "cross_source_conflict",
        "category_not_supported",
        "timeline_valid",
        "timeline_unavailable",
        "timeline_conflict",
        "timeline_drift",
        "domain_invariant_conflict",
        "record_quarantined",
        "batch_hold_required",
        "plan_selected",
        "plan_revised",
        "ranking_allowed",
        "ranking_restricted",
        "ranking_partial",
        "ranking_held",
        "pre_release_valid",
        "pre_release_blocked",
        "document_identity_valid",
        "document_identity_missing",
        "document_identity_conflict",
        "support_graph_valid",
        "support_graph_incomplete",
        "command_started",
        "command_completed",
        "command_restricted",
        "command_failed",
        "release_authorized",
        "release_blocked",
        "corroboration_required",
    }
)
_FEATURE_NAMES_V22 = frozenset(
    {
        "essential_invoice_processing",
        "essential_reconciliation",
        "essential_spreadsheet",
        "essential_accounting_platform",
        "preferred_ap_years",
        "preferred_volume",
        "preferred_qualification",
        "essentials_count",
        "preferred_count",
        "corroborated_count",
        "band",
        "rank_band_priority",
        "rank_essentials",
        "rank_preferred",
        "rank_corroborated",
        "rank_key",
        "queue",
        "route",
    }
)
_STAGE_REASON_CODES_V22: Mapping[str, frozenset[str]] = {
    "retrieval": frozenset(
        {
            "fetch_succeeded",
            "retrieval_failed",
            "candidate_unavailable",
            "command_completed",
        }
    ),
    "schema": frozenset({"schema_valid", "schema_invalid", "command_completed"}),
    "manifest": frozenset(
        {
            "manifest_valid",
            "manifest_conflict",
            "semantic_hash_valid",
            "semantic_hash_conflict",
            "resume_hash_valid",
            "resume_hash_conflict",
        }
    ),
    "revision": frozenset({"revision_valid", "revision_conflict"}),
    "parsing": frozenset(
        {
            "command_completed",
            "parsing_failed",
            "candidate_unavailable",
            "evidence_admissible",
            "evidence_inadmissible",
        }
    ),
    "identity": frozenset(
        {
            "command_completed",
            "document_identity_valid",
            "document_identity_missing",
            "document_identity_conflict",
        }
    ),
    "mapping": frozenset(
        {"command_completed", "mapper_output_valid", "mapper_unavailable", "mapper_disagreement"}
    ),
    "provenance": frozenset(
        {
            "command_completed",
            "evidence_admissible",
            "evidence_missing",
            "evidence_unknown",
            "evidence_inadmissible",
            "evidence_value_conflict",
            "mapper_disagreement",
            "record_quarantined",
        }
    ),
    "timeline": frozenset(
        {"timeline_valid", "timeline_unavailable", "timeline_conflict", "timeline_drift"}
    ),
    "cross_source": frozenset(
        {
            "cross_source_match",
            "cross_source_conflict",
            "category_not_supported",
            "evidence_value_conflict",
            "domain_invariant_conflict",
            "mapper_disagreement",
        }
    ),
    "candidate_validation": frozenset(
        _REASON_CODES_V22
        - {
            "command_started",
            "command_completed",
            "command_restricted",
            "command_failed",
            "plan_selected",
            "plan_revised",
            "ranking_allowed",
            "ranking_restricted",
            "ranking_partial",
            "ranking_held",
            "pre_release_valid",
            "pre_release_blocked",
            "release_authorized",
            "release_blocked",
            "corroboration_required",
        }
    ),
    "planning": frozenset(
        {
            "plan_selected",
            "plan_revised",
            "record_quarantined",
            "candidate_unavailable",
            "corroboration_required",
            "pre_release_blocked",
        }
    ),
    "ranking": frozenset(
        {
            "ranking_allowed",
            "ranking_restricted",
            "ranking_partial",
            "ranking_held",
            "batch_hold_required",
        }
    ),
    "pre_release": frozenset(
        {
            "support_graph_valid",
            "support_graph_incomplete",
            "pre_release_valid",
            "pre_release_blocked",
            "release_authorized",
            "release_blocked",
        }
    ),
    "release": frozenset({"release_authorized", "release_blocked"}),
}


class ReleaseSpecV22Error(ValueError):
    """A V2.2 observation or release projection is structurally invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CommandV22(_StrictModel):
    command_id: InternalId
    kind: Token
    scope: Literal["record", "batch"]
    candidate_id: SourceId | None = None
    dependency_ids: tuple[InternalId, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def scope_matches_identity(self) -> CommandV22:
        if self.kind not in _PLAN_STEPS_V22:
            raise ValueError("command kind is outside the closed workflow vocabulary")
        if (self.scope == "record") is not (self.candidate_id is not None):
            raise ValueError("record commands alone carry a candidate ID")
        if self.command_id in self.dependency_ids:
            raise ValueError("a command cannot depend on itself")
        if len(self.dependency_ids) != len(set(self.dependency_ids)):
            raise ValueError("command dependencies must be unique")
        return self


class PlanV22(_StrictModel):
    version: int = Field(ge=1, le=3)
    objective: Token
    strategy: Token
    commands: tuple[CommandV22, ...] = Field(min_length=1, max_length=64)
    trigger_codes: tuple[Token, ...] = Field(max_length=64)
    allowed_evidence_ids: tuple[InternalId, ...] = Field(max_length=3_200)
    prohibited_actions: tuple[Token, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def command_graph_is_closed(self) -> PlanV22:
        if self.objective not in _OBJECTIVES_V22 or self.strategy not in _STRATEGIES_V22:
            raise ValueError("plan policy is outside the closed workflow vocabulary")
        if not set(self.trigger_codes).issubset(_REASON_CODES_V22):
            raise ValueError("plan trigger uses an unknown reason code")
        if not set(self.prohibited_actions).issubset(_PROHIBITIONS_V22):
            raise ValueError("plan contains an unknown prohibition")
        command_ids = [command.command_id for command in self.commands]
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("plan command IDs must be unique")
        available: set[str] = set()
        for command in self.commands:
            if not set(command.dependency_ids).issubset(available):
                raise ValueError("plan dependencies must reference earlier commands")
            available.add(command.command_id)
        if len(self.allowed_evidence_ids) != len(set(self.allowed_evidence_ids)):
            raise ValueError("plan evidence IDs must be unique")
        if len(self.prohibited_actions) != len(set(self.prohibited_actions)):
            raise ValueError("plan prohibitions must be unique")
        return self


class PlanDiffV22(_StrictModel):
    from_version: int = Field(ge=1, le=2)
    to_version: int = Field(ge=2, le=3)
    strategy_before: Token
    strategy_after: Token
    objective_before: Token
    objective_after: Token
    trigger_codes: tuple[Token, ...] = Field(min_length=1, max_length=64)
    removed_command_ids: tuple[InternalId, ...] = Field(max_length=64)
    added_commands: tuple[CommandV22, ...] = Field(max_length=64)
    revoked_evidence_ids: tuple[InternalId, ...] = Field(max_length=3_200)
    granted_evidence_ids: tuple[InternalId, ...] = Field(max_length=3_200)
    added_prohibitions: tuple[Token, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def advances_once(self) -> PlanDiffV22:
        if self.strategy_before not in _STRATEGIES_V22 or self.strategy_after not in (
            _STRATEGIES_V22
        ):
            raise ValueError("plan diff contains an unknown strategy")
        if self.objective_before not in _OBJECTIVES_V22 or self.objective_after not in (
            _OBJECTIVES_V22
        ):
            raise ValueError("plan diff contains an unknown objective")
        if not set(self.trigger_codes).issubset(_REASON_CODES_V22) or not set(
            self.added_prohibitions
        ).issubset(_PROHIBITIONS_V22):
            raise ValueError("plan diff contains an unknown bounded value")
        if self.to_version != self.from_version + 1:
            raise ValueError("a release plan diff must advance exactly one version")
        return self


class ReceiptV22(_StrictModel):
    receipt_id: InternalId
    sequence: int = Field(ge=1, le=512)
    plan_version: int = Field(ge=1, le=3)
    command_id: InternalId
    command_kind: Token
    status: Literal["started", "completed", "restricted", "failed"]
    candidate_id: SourceId | None = None
    reason_codes: tuple[Token, ...] = Field(min_length=1, max_length=64)
    evidence_ids: tuple[InternalId, ...] = Field(max_length=3_200)
    produced_gate_id: InternalId | None = None
    consumed_gate_ids: tuple[InternalId, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def vocabulary_is_closed(self) -> ReceiptV22:
        if self.command_kind not in _PLAN_STEPS_V22 or not set(self.reason_codes).issubset(
            _REASON_CODES_V22
        ):
            raise ValueError("receipt contains an unknown command or reason")
        status_markers = {
            "command_started",
            "command_completed",
            "command_restricted",
            "command_failed",
        }
        expected_marker = {
            "started": "command_started",
            "completed": "command_completed",
            "restricted": "command_restricted",
            "failed": "command_failed",
        }[self.status]
        observed_markers = set(self.reason_codes) & status_markers
        if observed_markers != {expected_marker}:
            raise ValueError("receipt status marker is missing, duplicated, or inconsistent")
        if self.status != "completed" and set(self.reason_codes) != {expected_marker}:
            raise ValueError("non-completed receipts cannot carry domain outcome reasons")
        return self


class TrustGateV22(_StrictModel):
    gate_id: InternalId
    stage: Token
    scope: Literal["record", "batch"]
    state: Literal["USABLE", "DEGRADED", "QUARANTINED", "UNAVAILABLE"]
    outcome: Literal["ALLOW", "RESTRICT", "QUARANTINE", "UNAVAILABLE", "HOLD"]
    candidate_id: SourceId | None = None
    snapshot_id: SourceId | None = None
    reason_codes: tuple[Token, ...] = Field(min_length=1, max_length=64)
    evidence_ids: tuple[InternalId, ...] = Field(max_length=3_200)
    input_gate_ids: tuple[InternalId, ...] = Field(max_length=64)
    evidence_inventory: EvidenceDispositionInventoryV22 | None = None

    @model_validator(mode="after")
    def decision_is_coherent(self) -> TrustGateV22:
        if self.stage not in _TRUST_STAGES_V22 or not set(self.reason_codes).issubset(
            _REASON_CODES_V22
        ):
            raise ValueError("trust gate contains an unknown stage or reason")
        if not set(self.reason_codes).issubset(_STAGE_REASON_CODES_V22[self.stage]):
            raise ValueError("trust gate reason is incompatible with its stage")
        if (self.scope == "record") is not (self.candidate_id is not None):
            raise ValueError("record trust gates alone carry a candidate ID")
        valid = {
            "USABLE": {"ALLOW"},
            "DEGRADED": {"RESTRICT"},
            "QUARANTINED": {"QUARANTINE", "HOLD"},
            "UNAVAILABLE": {"UNAVAILABLE", "HOLD"},
        }
        if self.outcome not in valid[self.state]:
            raise ValueError("trust state and outcome disagree")
        if self.gate_id in self.input_gate_ids:
            raise ValueError("a trust gate cannot consume itself")
        if len(self.input_gate_ids) != len(set(self.input_gate_ids)):
            raise ValueError("trust gate inputs must be unique")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("trust gate evidence must be unique")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("trust gate reasons must be unique")
        inventory = self.evidence_inventory
        if inventory is not None:
            if (
                self.scope != "record"
                or self.stage not in {"mapping", "provenance", "candidate_validation"}
                or self.candidate_id != inventory.candidate_id
                or self.snapshot_id != inventory.snapshot_id
            ):
                raise ValueError("evidence inventory is attached to the wrong trust boundary")
            inventory_ids = tuple(sorted(item.reference.evidence_id for item in inventory.entries))
            if self.stage in {"mapping", "provenance"}:
                if any(item.state != "consumed" for item in inventory.entries):
                    raise ValueError("pre-consumption inventory may contain only consumed entries")
                if inventory_ids != tuple(sorted(self.evidence_ids)):
                    raise ValueError("pre-consumption inventory must equal gate evidence")
            elif any(item.state == "consumed" for item in inventory.entries):
                raise ValueError("terminal inventory requires final evidence dispositions")
        return self


class EvidenceRefV22(_StrictModel):
    evidence_id: InternalId
    candidate_id: SourceId
    snapshot_id: SourceId
    source_kind: Literal["application_json", "resume_visible", "resume_non_visible", "pdf_metadata"]
    field_path: FieldPath | None = None
    page: int | None = Field(default=None, ge=1, le=10)
    document_page_count: int | None = Field(default=None, ge=1, le=10)
    page_width: float | None = Field(default=None, gt=0)
    page_height: float | None = Field(default=None, gt=0)
    bbox: tuple[float, float, float, float] | None = None
    visible: bool
    admissible: bool
    semantic_hash: Digest

    @field_validator("bbox")
    @classmethod
    def finite_bbox(
        cls, value: tuple[float, float, float, float] | None
    ) -> tuple[float, float, float, float] | None:
        if value is not None and any(not math.isfinite(item) for item in value):
            raise ValueError("evidence bounds must be finite")
        return value

    @field_validator("page_width", "page_height")
    @classmethod
    def finite_page_dimension(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("evidence page dimensions must be finite")
        return value

    @model_validator(mode="after")
    def visibility_is_coherent(self) -> EvidenceRefV22:
        geometry = (
            self.page,
            self.document_page_count,
            self.page_width,
            self.page_height,
            self.bbox,
        )
        if self.source_kind == "resume_visible":
            if not self.visible or any(value is None for value in geometry):
                raise ValueError("visible résumé evidence requires bounded page geometry")
            assert self.page is not None
            assert self.document_page_count is not None
            assert self.page_width is not None
            assert self.page_height is not None
            assert self.bbox is not None
            x0, top, x1, bottom = self.bbox
            if self.page > self.document_page_count or not (
                0 <= x0 <= x1 <= self.page_width and 0 <= top <= bottom <= self.page_height
            ):
                raise ValueError("visible résumé evidence escapes its committed page")
        elif any(value is not None for value in geometry):
            raise ValueError("non-visible or structured evidence cannot carry page geometry")
        if self.source_kind in {"resume_non_visible", "pdf_metadata"} and (
            self.visible or self.admissible
        ):
            raise ValueError("non-visible evidence cannot be admissible")
        return self


class EvidenceDispositionEntryV22(_StrictModel):
    """One sanitized mapper-consumed citation and its bounded lifecycle state."""

    claim_kind: Token
    reference: EvidenceRefV22
    state: Literal[
        "consumed",
        "released",
        "dropped_unsupported_category",
        "dropped_timeline_policy",
        "dropped_cross_source",
    ]
    date_value: Annotated[date, Field(strict=True)] | None = None
    mapped_value: JsonScalar = None

    @model_validator(mode="after")
    def reference_is_a_consumable_claim_edge(self) -> EvidenceDispositionEntryV22:
        if self.claim_kind not in _DISPOSITION_CLAIM_KINDS_V22:
            raise ValueError("disposition claim is outside the consumable evidence contract")
        reference = self.reference
        if (
            reference.source_kind != "resume_visible"
            or not reference.visible
            or not reference.admissible
            or reference.field_path is None
        ):
            raise ValueError("disposition requires visible admissible résumé evidence")
        role = reference.field_path.rsplit(".", maxsplit=1)[-1]
        if self.claim_kind == "employment_interval":
            if (
                self.date_value is None
                or self.mapped_value is not None
                or role not in {"employment_start", "employment_end"}
            ):
                raise ValueError("employment disposition requires one dated endpoint")
            if reference.semantic_hash != _evidence_value_sha256(self.date_value.isoformat()):
                raise ValueError("employment endpoint date differs from its evidence hash")
        else:
            if self.date_value is not None:
                raise ValueError("only employment dispositions may carry endpoint dates")
            if role != self.claim_kind:
                raise ValueError("disposition claim kind differs from its evidence field")
            value = self.mapped_value
            if self.claim_kind == "ap_years":
                valid_value = (
                    type(value) is float
                    and math.isfinite(value)
                    and 0 <= value <= 80
                    and not (value == 0.0 and math.copysign(1.0, value) < 0)
                )
                hash_value: object = value
            elif self.claim_kind == "monthly_invoice_volume":
                valid_value = type(value) is int and 0 <= value <= 100_000_000
                hash_value = value
            elif self.claim_kind in {"invoice_processing", "reconciliation"}:
                valid_value = type(value) is bool
                hash_value = value
            else:
                valid_value = _structured_category_value_valid_v22(
                    self.claim_kind,
                    value,
                )
                hash_value = value
            if not valid_value or reference.semantic_hash != _evidence_value_sha256(hash_value):
                raise ValueError("mapped scalar differs from its typed evidence hash")
        return self


class StructuredFieldAnchorV22(_StrictModel):
    """One typed application-side value used for independent comparison."""

    claim_kind: Token
    value: JsonScalar = None
    reference: EvidenceRefV22

    @model_validator(mode="after")
    def value_and_reference_are_exact(self) -> StructuredFieldAnchorV22:
        value = self.value
        if self.claim_kind not in _STRUCTURED_CLAIM_KINDS_V22:
            raise ValueError("structured anchor kind is outside the comparison contract")
        if self.claim_kind == "ap_years":
            valid_value = (
                type(value) is float
                and math.isfinite(value)
                and 0 <= value <= 80
                and not (value == 0.0 and math.copysign(1.0, value) < 0)
            )
        elif self.claim_kind in {"invoice_processing", "reconciliation"}:
            valid_value = type(value) is bool
        elif self.claim_kind == "monthly_invoice_volume":
            valid_value = value is None or (type(value) is int and 0 <= value <= 100_000_000)
        else:
            valid_value = value is None or _structured_category_value_valid_v22(
                self.claim_kind,
                value,
            )
        reference = self.reference
        if (
            not valid_value
            or (value is None and self.claim_kind not in _NULLABLE_STRUCTURED_CLAIM_KINDS_V22)
            or reference.source_kind != "application_json"
            or reference.visible is not True
            or reference.admissible is not True
            or _field_role(reference.field_path) != self.claim_kind
            or reference.semantic_hash != _evidence_value_sha256(value)
        ):
            raise ValueError("structured anchor differs from its typed application value")
        return self


class EvidenceDispositionInventoryV22(_StrictModel):
    """Exact pre-consumption or terminal accounting for one record lineage."""

    candidate_id: SourceId
    snapshot_id: SourceId
    record_ap_years: float = Field(strict=True, ge=0, le=80)
    record_invoice_processing: bool = Field(strict=True)
    record_ap_years_reference: EvidenceRefV22
    record_invoice_processing_reference: EvidenceRefV22
    structured_anchors: tuple[StructuredFieldAnchorV22, ...] = Field(
        min_length=7,
        max_length=7,
    )
    entries: tuple[EvidenceDispositionEntryV22, ...] = Field(max_length=1_024)

    @field_validator("record_ap_years", mode="before")
    @classmethod
    def require_runtime_float(cls, value: object) -> object:
        if type(value) is not float:
            raise ValueError("record AP years must be a JSON float")
        return value

    @field_validator("record_ap_years")
    @classmethod
    def normalize_record_zero_years(cls, value: float) -> float:
        return 0.0 if value == 0.0 else value

    @model_validator(mode="after")
    def entries_are_unique_and_owned(self) -> EvidenceDispositionInventoryV22:
        evidence_ids = [item.reference.evidence_id for item in self.entries]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence disposition identifiers must be unique")
        if any(
            item.reference.candidate_id != self.candidate_id
            or item.reference.snapshot_id != self.snapshot_id
            for item in self.entries
        ):
            raise ValueError("evidence disposition belongs to another candidate or snapshot")
        if tuple(item.claim_kind for item in self.structured_anchors) != (
            _STRUCTURED_CLAIM_KINDS_V22
        ):
            raise ValueError("structured anchors are not the exact ordered field set")
        anchor_ids: list[str] = []
        for anchor in self.structured_anchors:
            reference = anchor.reference
            anchor_ids.append(reference.evidence_id)
            if (
                reference.candidate_id != self.candidate_id
                or reference.snapshot_id != self.snapshot_id
                or reference.evidence_id
                != _canonical_evidence_id_v22(
                    "json",
                    self.snapshot_id,
                    self.candidate_id,
                    reference.semantic_hash,
                    anchor.claim_kind,
                )
                or reference.field_path
                != _canonical_structured_field_path_v22(
                    self.candidate_id,
                    anchor.claim_kind,
                )
            ):
                raise ValueError("structured anchor escapes its canonical record field")
        anchors_by_kind = {item.claim_kind: item for item in self.structured_anchors}
        if (
            anchors_by_kind["ap_years"].value != self.record_ap_years
            or anchors_by_kind["ap_years"].reference != self.record_ap_years_reference
            or anchors_by_kind["invoice_processing"].value is not self.record_invoice_processing
            or anchors_by_kind["invoice_processing"].reference
            != self.record_invoice_processing_reference
        ):
            raise ValueError("compatibility scalar aliases differ from structured anchors")
        if len(set(anchor_ids)) != 7 or set(anchor_ids).intersection(evidence_ids):
            raise ValueError("structured record anchors must be distinct from consumed evidence")
        return self


class SupportedEmploymentIntervalV22(_StrictModel):
    start_date: date
    end_date: date
    start_evidence_id: InternalId
    end_evidence_id: InternalId

    @model_validator(mode="after")
    def interval_is_ordered(self) -> SupportedEmploymentIntervalV22:
        if self.end_date < self.start_date:
            raise ValueError("employment interval end precedes its start")
        if self.start_evidence_id == self.end_evidence_id:
            raise ValueError("employment interval endpoints require distinct evidence")
        return self


class SupportedFactV22(_StrictModel):
    fact_id: InternalId
    candidate_id: SourceId
    snapshot_id: SourceId
    kind: Token
    normalized_value: JsonScalar = None
    source_roles: tuple[Token, ...] = Field(max_length=8)
    evidence_ids: tuple[InternalId, ...] = Field(min_length=1, max_length=32)
    source_value: SafeCategoricalLabel | None = None
    canonical_value: SafeCategoricalLabel | None = None
    normalization_mode: Literal["bounded_allow_list_v1"] | None = None
    canonical_value_sha256: Digest | None = None
    employment_intervals: tuple[SupportedEmploymentIntervalV22, ...] = Field(max_length=32)

    @field_validator("normalized_value")
    @classmethod
    def finite_value(cls, value: JsonScalar) -> JsonScalar:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("fact values must be finite")
        return value

    @model_validator(mode="after")
    def categorical_value_is_independently_checkable(self) -> SupportedFactV22:
        if self.kind not in _FACT_KINDS_V22:
            raise ValueError("fact kind is outside the bounded evidence contract")
        categorical = self.kind in CATEGORICAL_ALLOW_LISTS_V22
        categorical_fields = (
            self.source_value,
            self.canonical_value,
            self.normalization_mode,
            self.canonical_value_sha256,
        )
        if categorical:
            if any(value is None for value in categorical_fields):
                raise ValueError("categorical facts require complete normalization evidence")
            assert self.source_value is not None
            assert self.canonical_value is not None
            assert self.canonical_value_sha256 is not None
            canonical = canonicalize_category(self.source_value)
            if canonical != self.canonical_value:
                raise ValueError("categorical canonical value was not independently reproducible")
            if canonical not in CATEGORICAL_ALLOW_LISTS_V22[self.kind]:
                raise ValueError("categorical canonical value is outside the bounded allow-list")
            if canonical_value_sha256(canonical) != self.canonical_value_sha256:
                raise ValueError("categorical canonical value hash is invalid")
            if not isinstance(self.normalized_value, str) or (
                canonicalize_category(self.normalized_value) != canonical
            ):
                raise ValueError("categorical normalized fact value disagrees")
        elif any(value is not None for value in categorical_fields):
            raise ValueError("non-categorical facts cannot carry normalization metadata")
        if self.kind == "employment_interval":
            if not self.employment_intervals:
                raise ValueError("employment interval facts require endpoint bindings")
            endpoint_ids = tuple(
                evidence_id
                for interval in self.employment_intervals
                for evidence_id in (
                    interval.start_evidence_id,
                    interval.end_evidence_id,
                )
            )
            if len(endpoint_ids) != len(set(endpoint_ids)) or not set(endpoint_ids).issubset(
                self.evidence_ids
            ):
                raise ValueError("employment interval endpoint evidence is incomplete")
        elif self.employment_intervals:
            raise ValueError("only employment interval facts may carry endpoint bindings")
        return self


class DerivedFeatureV22(_StrictModel):
    feature_id: InternalId
    candidate_id: SourceId
    snapshot_id: SourceId
    name: InternalId
    normalized_value: JsonScalar = None
    dependency_fact_ids: tuple[InternalId, ...] = Field(max_length=64)
    dependency_feature_ids: tuple[InternalId, ...] = Field(max_length=64)

    @field_validator("normalized_value")
    @classmethod
    def finite_value(cls, value: JsonScalar) -> JsonScalar:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("feature values must be finite")
        return value

    @model_validator(mode="after")
    def has_dependency(self) -> DerivedFeatureV22:
        if self.name not in _FEATURE_NAMES_V22:
            raise ValueError("feature name is outside the bounded reducer vocabulary")
        if not self.dependency_fact_ids and not self.dependency_feature_ids:
            raise ValueError("derived features require a dependency")
        return self


class SupportGraphV22(_StrictModel):
    candidate_id: SourceId
    snapshot_id: SourceId
    evidence_ids: tuple[InternalId, ...] = Field(max_length=512)
    evidence_manifest: tuple[EvidenceRefV22, ...] = Field(max_length=512)
    facts: tuple[SupportedFactV22, ...] = Field(max_length=64)
    features: tuple[DerivedFeatureV22, ...] = Field(max_length=128)
    route_support_ids: tuple[InternalId, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def graph_is_closed(self) -> SupportGraphV22:
        evidence = {item.evidence_id: item for item in self.evidence_manifest}
        facts = {item.fact_id: item for item in self.facts}
        features = {item.feature_id: item for item in self.features}
        if len(evidence) != len(self.evidence_manifest):
            raise ValueError("support evidence IDs must be unique")
        if len(facts) != len(self.facts) or len(features) != len(self.features):
            raise ValueError("support graph node IDs must be unique")
        if self.evidence_ids != tuple(sorted(evidence)):
            raise ValueError("support evidence manifest must equal the evidence closure")
        evidence_ownership_valid = all(
            item.candidate_id == self.candidate_id and item.snapshot_id == self.snapshot_id
            for item in self.evidence_manifest
        )
        fact_ownership_valid = all(
            item.candidate_id == self.candidate_id and item.snapshot_id == self.snapshot_id
            for item in self.facts
        )
        feature_ownership_valid = all(
            item.candidate_id == self.candidate_id and item.snapshot_id == self.snapshot_id
            for item in self.features
        )
        if not (evidence_ownership_valid and fact_ownership_valid and feature_ownership_valid):
            raise ValueError("support graph contains mixed candidate or snapshot ownership")
        if any(not item.admissible for item in self.evidence_manifest):
            raise ValueError("released support graphs may contain only admissible evidence")
        for reference in self.evidence_manifest:
            if reference.source_kind != "application_json":
                continue
            role = _field_role(reference.field_path)
            if (
                role is None
                or reference.evidence_id
                != _canonical_evidence_id_v22(
                    "json",
                    self.snapshot_id,
                    self.candidate_id,
                    reference.semantic_hash,
                    role,
                )
                or reference.field_path
                != _canonical_structured_field_path_v22(
                    self.candidate_id,
                    role,
                )
            ):
                raise ValueError(
                    "structured support reference lacks its content-addressed identity"
                )
        if any(not set(item.evidence_ids).issubset(evidence) for item in self.facts):
            raise ValueError("a fact references evidence outside the graph closure")
        if any(not set(item.dependency_fact_ids).issubset(facts) for item in self.features):
            raise ValueError("a feature references an unknown fact")
        if any(not set(item.dependency_feature_ids).issubset(features) for item in self.features):
            raise ValueError("a feature references an unknown feature")
        if not set(self.route_support_ids).issubset(features):
            raise ValueError("route support references an unknown feature")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(feature_id: str) -> None:
            if feature_id in visiting:
                raise ValueError("support feature graph must be acyclic")
            if feature_id in visited:
                return
            visiting.add(feature_id)
            for dependency in features[feature_id].dependency_feature_ids:
                visit(dependency)
            visiting.remove(feature_id)
            visited.add(feature_id)

        for feature_id in features:
            visit(feature_id)
        return self


class RankKeyV22(_StrictModel):
    band_priority: int = Field(ge=0, le=2)
    essentials_count: int = Field(ge=0, le=4)
    preferred_count: int = Field(ge=0, le=3)
    corroborated_claim_count: int = Field(ge=0, le=64)

    def tuple(self) -> tuple[int, int, int, int]:
        return (
            self.band_priority,
            self.essentials_count,
            self.preferred_count,
            self.corroborated_claim_count,
        )


class RouteV22(_StrictModel):
    candidate_id: SourceId
    snapshot_id: SourceId
    band: Token
    queue: Token
    evidence_rank: int | None = Field(default=None, ge=1, le=50)
    display_position: int | None = Field(default=None, ge=1, le=50)
    rank_key: RankKeyV22 | None = None
    reason_codes: tuple[Token, ...] = Field(max_length=64)
    evidence_ids: tuple[InternalId, ...] = Field(max_length=512)
    support_graph: SupportGraphV22 | None = None

    @model_validator(mode="after")
    def route_is_atomic(self) -> RouteV22:
        if (self.band, self.queue) not in _ALLOWED_BAND_QUEUE:
            raise ValueError("route band and queue disagree")
        if not set(self.reason_codes).issubset(_REASON_CODES_V22) or len(self.reason_codes) != len(
            set(self.reason_codes)
        ):
            raise ValueError("route reasons must use the unique closed vocabulary")
        ranking_fields = (self.evidence_rank, self.display_position, self.rank_key)
        if any(value is None for value in ranking_fields) and not all(
            value is None for value in ranking_fields
        ):
            raise ValueError("rank fields are atomic")
        if self.band in _UNRANKED_BANDS:
            if any(value is not None for value in ranking_fields):
                raise ValueError("held or unavailable evidence cannot be ranked")
            if self.evidence_ids or self.support_graph is not None:
                raise ValueError("unranked routes cannot release evidence")
        else:
            if self.support_graph is None or not self.evidence_ids:
                raise ValueError("ranked routes require a complete support graph")
            if self.support_graph.candidate_id != self.candidate_id:
                raise ValueError("route and support graph candidate IDs disagree")
            if self.support_graph.snapshot_id != self.snapshot_id:
                raise ValueError("route and support graph snapshots disagree")
            if self.evidence_ids != tuple(sorted(self.support_graph.evidence_ids)):
                raise ValueError("route evidence differs from its support closure")
        return self


class CorroborationRequestV22(_StrictModel):
    candidate_ids: tuple[SourceId, ...] = Field(max_length=50)
    reason_codes: tuple[Token, ...] = Field(min_length=1, max_length=64)
    requested_evidence_kinds: tuple[Token, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def request_is_bounded(self) -> CorroborationRequestV22:
        if not set(self.reason_codes).issubset(_REASON_CODES_V22) or not set(
            self.requested_evidence_kinds
        ).issubset(_FACT_KINDS_V22):
            raise ValueError("corroboration request uses an unknown bounded value")
        if len(self.candidate_ids) != len(set(self.candidate_ids)):
            raise ValueError("corroboration request candidate IDs must be unique")
        return self


class ExplanationV22(_StrictModel):
    template: Literal[
        "record_degraded",
        "record_quarantined",
        "candidate_unavailable",
        "batch_held",
        "strategy_selected",
    ]
    candidate_id: SourceId | None = None
    reason_codes: tuple[Token, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def template_scope_is_closed(self) -> ExplanationV22:
        if not set(self.reason_codes).issubset(_REASON_CODES_V22):
            raise ValueError("explanation contains an unknown reason code")
        record_template = self.template in {
            "record_degraded",
            "record_quarantined",
            "candidate_unavailable",
        }
        if record_template is not (self.candidate_id is not None):
            raise ValueError("explanation template and candidate scope disagree")
        if self.template == "strategy_selected" and self.candidate_id is not None:
            raise ValueError("explanation template and candidate scope disagree")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("explanation reason codes must be unique")
        return self


class DecisionProjectionV22(_StrictModel):
    """The complete, bounded semantics independently reconstructed at release."""

    schema_version: Literal[3]
    protocol_version: Literal["2.2"]
    batch_id: SourceId
    snapshot_id: SourceId
    strategy: Token
    ranking_scope: Literal["COMPLETE", "PARTIAL", "NONE"]
    execution_mode: Literal["EXECUTED", "FAILED_CLOSED"]
    batch_state: Literal["USABLE", "DEGRADED", "QUARANTINED", "UNAVAILABLE"]
    plans: tuple[PlanV22, ...] = Field(min_length=1, max_length=3)
    plan_diff: PlanDiffV22 | None = None
    receipts: tuple[ReceiptV22, ...] = Field(max_length=512)
    trust_gates: tuple[TrustGateV22, ...] = Field(max_length=1_024)
    routes: tuple[RouteV22, ...] = Field(min_length=1, max_length=50)
    corroboration_requests: tuple[CorroborationRequestV22, ...] = Field(max_length=50)
    explanations: tuple[ExplanationV22, ...] = Field(max_length=50)
    prohibited_actions: tuple[Token, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def release_semantics_are_closed(self) -> DecisionProjectionV22:
        if self.strategy not in _STRATEGIES_V22:
            raise ValueError("release strategy is outside the closed vocabulary")
        versions = [plan.version for plan in self.plans]
        if versions != list(range(1, len(self.plans) + 1)):
            raise ValueError("plan history must be contiguous from version one")
        for plan in self.plans:
            _validate_plan_policy(plan)
        final_plan = self.plans[-1]
        if final_plan.strategy != self.strategy:
            raise ValueError("final plan strategy differs from the decision")
        expected_batch_state = {
            "FULL_EVIDENCE_RANKING": "USABLE",
            "SUPPORTED_ONLY_RANKING": "DEGRADED",
            "PARTIAL_SAFE_RANKING": "DEGRADED",
            "BATCH_INTEGRITY_HOLD": "QUARANTINED",
        }[self.strategy]
        failed_closed_hold = (
            self.execution_mode == "FAILED_CLOSED" and self.strategy == "BATCH_INTEGRITY_HOLD"
        )
        if self.batch_state != expected_batch_state or (
            self.execution_mode != "EXECUTED" and not failed_closed_hold
        ):
            raise ValueError("release execution or batch state disagrees with its strategy")
        if set(final_plan.prohibited_actions) != set(self.prohibited_actions):
            raise ValueError("projection prohibitions differ from the active plan")
        if (len(self.plans) == 1) is not (self.plan_diff is None):
            raise ValueError("only revised plans carry a plan diff")
        if self.plan_diff is not None and (
            self.plan_diff.from_version != self.plans[-2].version
            or self.plan_diff.to_version != final_plan.version
            or self.plan_diff.strategy_before != self.plans[-2].strategy
            or self.plan_diff.strategy_after != final_plan.strategy
        ):
            raise ValueError("plan diff does not bind the final transition")
        if self.plan_diff is not None:
            previous_plan = self.plans[-2]
            if (
                tuple(self.plan_diff.added_commands) != tuple(final_plan.commands)
                or set(self.plan_diff.trigger_codes) != set(final_plan.trigger_codes)
                or set(self.plan_diff.revoked_evidence_ids)
                != set(previous_plan.allowed_evidence_ids) - set(final_plan.allowed_evidence_ids)
                or set(self.plan_diff.granted_evidence_ids)
                != set(final_plan.allowed_evidence_ids) - set(previous_plan.allowed_evidence_ids)
                or set(self.plan_diff.added_prohibitions)
                != set(final_plan.prohibited_actions) - set(previous_plan.prohibited_actions)
            ):
                raise ValueError("plan diff does not exactly reconcile the active plans")

        routes = {route.candidate_id: route for route in self.routes}
        if len(routes) != len(self.routes):
            raise ValueError("route candidate IDs must be unique")
        if any(route.snapshot_id != self.snapshot_id for route in self.routes):
            raise ValueError("released routes must share the decision snapshot")
        explanation_keys = [(item.template, item.candidate_id) for item in self.explanations]
        if len(explanation_keys) != len(set(explanation_keys)):
            raise ValueError("semantic explanations must be unique")
        if any(
            item.candidate_id is not None and item.candidate_id not in routes
            for item in self.explanations
        ):
            raise ValueError("explanation references a candidate outside the released cohort")
        batch_explanations = [item for item in self.explanations if item.template == "batch_held"]
        if (self.strategy == "BATCH_INTEGRITY_HOLD") is not (len(batch_explanations) == 1):
            raise ValueError("batch-hold explanation does not match release strategy")
        for explanation in self.explanations:
            if explanation.candidate_id is None:
                continue
            route = routes[explanation.candidate_id]
            if self.strategy != "BATCH_INTEGRITY_HOLD" and (
                (
                    explanation.template == "candidate_unavailable"
                    and route.band != "EVIDENCE_UNAVAILABLE"
                )
                or (explanation.template == "record_quarantined" and route.band != "INTEGRITY_HOLD")
                or (explanation.template == "record_degraded" and route.band in _UNRANKED_BANDS)
            ):
                raise ValueError("explanation template is inconsistent with its route")
        ranked = [route for route in self.routes if route.rank_key is not None]
        positions = sorted(cast(int, route.display_position) for route in ranked)
        if positions != list(range(1, len(ranked) + 1)):
            raise ValueError("display positions must be unique and contiguous")
        ordered = sorted(
            ranked,
            key=lambda route: (
                -cast(RankKeyV22, route.rank_key).band_priority,
                -cast(RankKeyV22, route.rank_key).essentials_count,
                -cast(RankKeyV22, route.rank_key).preferred_count,
                -cast(RankKeyV22, route.rank_key).corroborated_claim_count,
                route.candidate_id,
            ),
        )
        if [route.display_position for route in ordered] != list(range(1, len(ranked) + 1)):
            raise ValueError("display order does not follow evidence keys and the tie breaker")
        dense_rank = 0
        previous: tuple[int, int, int, int] | None = None
        for route in ordered:
            key = cast(RankKeyV22, route.rank_key).tuple()
            if key != previous:
                dense_rank += 1
                previous = key
            if route.evidence_rank != dense_rank:
                raise ValueError("evidence ranks are not dense over equal rank keys")
            _validate_ranked_route_semantics(route)

        if self.strategy == "BATCH_INTEGRITY_HOLD":
            if self.ranking_scope != "NONE" or ranked:
                raise ValueError("a batch hold cannot release a ranking")
        elif self.strategy == "FULL_EVIDENCE_RANKING":
            if self.ranking_scope != "COMPLETE" or len(ranked) != len(self.routes):
                raise ValueError("full ranking requires a complete ranked cohort")
        elif self.ranking_scope != "PARTIAL":
            raise ValueError("restricted strategies require partial ranking scope")

        command_by_key = {
            (plan.version, command.command_id): command
            for plan in self.plans
            for command in plan.commands
        }
        if len(command_by_key) != sum(len(plan.commands) for plan in self.plans):
            raise ValueError("commands collide within a plan version")
        sequences = [receipt.sequence for receipt in self.receipts]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("receipt sequence must be globally contiguous")
        receipt_ids = [receipt.receipt_id for receipt in self.receipts]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("receipt IDs must be unique")
        terminal: dict[tuple[int, str], str] = {}
        terminal_sequence: dict[tuple[int, str], int] = {}
        receipt_pairs: dict[tuple[int, str], list[ReceiptV22]] = {}
        for receipt in self.receipts:
            receipt_key = (receipt.plan_version, receipt.command_id)
            command = command_by_key.get(receipt_key)
            if command is None or command.kind != receipt.command_kind:
                raise ValueError("receipt does not belong to its exact planned command")
            if receipt.candidate_id != command.candidate_id:
                raise ValueError("receipt candidate differs from its planned command")
            if command.kind in _EVIDENCE_CONSUMING_COMMANDS and not set(
                receipt.evidence_ids
            ).issubset(set(self.plans[receipt.plan_version - 1].allowed_evidence_ids)):
                raise ValueError("receipt evidence falls outside its active plan")
            pair = receipt_pairs.setdefault(receipt_key, [])
            pair.append(receipt)
            if receipt.status == "started":
                if (
                    len(pair) != 1
                    or receipt.evidence_ids
                    or receipt.produced_gate_id is not None
                    or receipt.consumed_gate_ids
                ):
                    raise ValueError("STARTED receipt contains terminal semantics")
                if receipt_key in terminal:
                    raise ValueError("command was restarted after a terminal receipt")
            else:
                if len(pair) != 2 or pair[0].status != "started":
                    raise ValueError("terminal receipt must immediately follow one STARTED receipt")
                if receipt.sequence != pair[0].sequence + 1:
                    raise ValueError("a command receipt pair must be contiguous")
                if receipt_key in terminal:
                    raise ValueError("command has multiple terminal receipts")
                if (receipt.status == "completed") is not (receipt.produced_gate_id is not None):
                    raise ValueError("only completed commands produce a trust gate")
                terminal[receipt_key] = receipt.status
                terminal_sequence[receipt_key] = receipt.sequence
        if any(len(pair) != 2 for pair in receipt_pairs.values()):
            raise ValueError(
                "every attempted command requires one STARTED and one terminal receipt"
            )

        produced_by_command = {
            key: pair[1].produced_gate_id
            for key, pair in receipt_pairs.items()
            if pair[1].status == "completed"
        }
        produced_gate_ids = [cast(str, gate_id) for gate_id in produced_by_command.values()]
        if len(produced_gate_ids) != len(set(produced_gate_ids)):
            raise ValueError("completed commands cannot share a produced trust gate")
        gate_lookup = {gate.gate_id: gate for gate in self.trust_gates}
        first_attempt_by_plan: dict[int, tuple[int, str]] = {}
        for receipt in self.receipts:
            if receipt.status == "started":
                first_attempt_by_plan.setdefault(
                    receipt.plan_version, (receipt.plan_version, receipt.command_id)
                )
        for receipt_key, pair in receipt_pairs.items():
            terminal_receipt = pair[1]
            command = command_by_key[receipt_key]
            dependency_keys = tuple(
                (terminal_receipt.plan_version, dependency_id)
                for dependency_id in command.dependency_ids
            )
            if (
                terminal_receipt.status == "completed"
                and receipt_key != first_attempt_by_plan[terminal_receipt.plan_version]
                and any(
                    terminal.get(dependency) != "completed"
                    or terminal_sequence[dependency] >= terminal_receipt.sequence
                    for dependency in dependency_keys
                )
            ):
                raise ValueError("completed command lacks earlier completed dependencies")
            expected_dependency_gates = tuple(
                cast(str, produced_by_command[dependency])
                for dependency in dependency_keys
                if dependency in produced_by_command
            )
            external_root = (
                receipt_key == first_attempt_by_plan[terminal_receipt.plan_version]
                and len(terminal_receipt.consumed_gate_ids) == 1
                and terminal_receipt.consumed_gate_ids[0]
                not in {item for item in produced_by_command.values() if item is not None}
            )
            candidate_fan_in = (
                terminal_receipt.command_kind
                in {"validate_candidate_bindings", "validate_candidate_evidence"}
                and set(expected_dependency_gates).issubset(terminal_receipt.consumed_gate_ids)
                and len(terminal_receipt.consumed_gate_ids) > len(expected_dependency_gates)
            )
            planning_bridge = (
                len(terminal_receipt.consumed_gate_ids) == 1
                and terminal_receipt.consumed_gate_ids[0] in gate_lookup
                and gate_lookup[terminal_receipt.consumed_gate_ids[0]].stage == "planning"
                and set(expected_dependency_gates).issubset(
                    gate_lookup[terminal_receipt.consumed_gate_ids[0]].input_gate_ids
                )
            )
            if terminal_receipt.status == "completed" and not (
                external_root
                or candidate_fan_in
                or planning_bridge
                or set(terminal_receipt.consumed_gate_ids) == set(expected_dependency_gates)
            ):
                raise ValueError("command did not consume its dependency-produced gates")
        if self.plan_diff is not None:
            removed = set(self.plan_diff.removed_command_ids)
            attempted = {
                (receipt.plan_version, receipt.command_id)
                for receipt in self.receipts
                if receipt.status == "started"
            }
            expected_removed = {
                command.command_id
                for plan in self.plans[:-1]
                for command in plan.commands
                if command.kind in _PROVISIONAL_PLAN_STEPS_V22
                and (plan.version, command.command_id) not in attempted
            }
            if removed != expected_removed:
                raise ValueError("plan diff removed set does not match unattempted commands")
            if any(
                version == self.plan_diff.from_version
                and command_id in removed
                and status == "completed"
                for (version, command_id), status in terminal.items()
            ):
                raise ValueError("a command removed by replanning was completed")
        if self.strategy == "BATCH_INTEGRITY_HOLD" and any(
            command_by_key[key].kind in _RANK_COMMANDS and status == "completed"
            for key, status in terminal.items()
        ):
            raise ValueError("a batch hold completed a ranking command")

        gates = {gate.gate_id: gate for gate in self.trust_gates}
        if len(gates) != len(self.trust_gates):
            raise ValueError("trust gate IDs must be unique")
        seen_gates: set[str] = set()
        for gate_index, gate in enumerate(self.trust_gates):
            if not set(gate.input_gate_ids).issubset(seen_gates):
                raise ValueError("trust gates must consume only preceding gates")
            if gate.snapshot_id is None and gate_index != 0:
                raise ValueError("only the first raw-index gate may omit a snapshot")
            if gate.snapshot_id is not None and gate.snapshot_id != self.snapshot_id:
                raise ValueError("trust ledger contains a stale or mixed snapshot")
            seen_gates.add(gate.gate_id)
        consumed: list[str] = []
        for receipt in self.receipts:
            referenced = [*receipt.consumed_gate_ids]
            if receipt.produced_gate_id is not None:
                referenced.append(receipt.produced_gate_id)
            if not set(referenced).issubset(gates):
                raise ValueError("receipt references a missing trust gate")
            consumed.extend(receipt.consumed_gate_ids)
        if len(consumed) != len(set(consumed)):
            raise ValueError("a trust gate was consumed more than once")
        for receipt in self.receipts:
            if receipt.status != "completed":
                continue
            for gate_id in receipt.consumed_gate_ids:
                gate = gates[gate_id]
                if gate.outcome in {"ALLOW", "RESTRICT"}:
                    continue
                terminal_observation = (
                    receipt.command_kind == "validate_candidate_bindings"
                    and gate.scope == "record"
                    and gate.stage
                    in {"retrieval", "schema", "identity", "manifest", "revision", "parsing"}
                ) or (
                    receipt.command_kind == "validate_candidate_evidence"
                    and gate.scope == "record"
                    and gate.stage == "candidate_validation"
                )
                if not terminal_observation:
                    raise ValueError("a blocked trust gate was consumed outside a terminal fan-in")
        for _receipt_key, pair in receipt_pairs.items():
            terminal_receipt = pair[1]
            if terminal_receipt.status != "completed":
                continue
            assert terminal_receipt.produced_gate_id is not None
            produced_gate = gates[terminal_receipt.produced_gate_id]
            consumed_ids = terminal_receipt.consumed_gate_ids
            if terminal_receipt.command_kind == "validate_candidate_bindings":
                if set(produced_gate.input_gate_ids) != set(consumed_ids):
                    raise ValueError("binding validation gate has invalid causal fan-in")
            elif set(produced_gate.input_gate_ids) != set(consumed_ids):
                raise ValueError("produced trust gate is not bound to consumed dependencies")
        _validate_trust_causality(
            self,
            gates=gates,
            receipt_pairs=receipt_pairs,
        )
        _validate_release_evidence_closure(
            self,
            final_plan=final_plan,
            gates=gates,
            receipt_pairs=receipt_pairs,
        )
        _validate_route_reason_semantics(self, gates=gates)
        _validate_plan_triggers(self)
        _validate_corroboration_semantics(
            self,
            terminal=terminal,
            gates=gates,
        )
        _validate_stage_local_closure(self)
        if self.execution_mode == "FAILED_CLOSED":
            _validate_failed_closed_drift_hold(
                self,
                gates=gates,
                receipt_pairs=receipt_pairs,
                terminal=terminal,
            )
        return self

    def canonical_object(self) -> JsonObject:
        """Return the deterministic semantic object used for release hashing."""

        raw = cast(JsonObject, self.model_dump(mode="json", exclude_none=False))
        raw["prohibited_actions"] = sorted(cast(list[str], raw["prohibited_actions"]))
        raw["routes"] = sorted(
            (
                _canonical_route(cast(JsonObject, item))
                for item in cast(list[object], raw["routes"])
            ),
            key=lambda item: cast(str, item["candidate_id"]),
        )
        raw["corroboration_requests"] = sorted(
            (
                _canonical_corroboration(cast(JsonObject, item))
                for item in cast(list[object], raw["corroboration_requests"])
            ),
            key=_canonical_sort_key,
        )
        raw["explanations"] = sorted(
            (
                _canonical_explanation(cast(JsonObject, item))
                for item in cast(list[object], raw["explanations"])
            ),
            key=_canonical_sort_key,
        )
        raw["plans"] = [
            _canonical_plan(cast(JsonObject, item)) for item in cast(list[object], raw["plans"])
        ]
        if raw["plan_diff"] is not None:
            raw["plan_diff"] = _canonical_plan_diff(cast(JsonObject, raw["plan_diff"]))
        raw["receipts"] = [
            _canonical_receipt(cast(JsonObject, item))
            for item in cast(list[object], raw["receipts"])
        ]
        raw["trust_gates"] = [
            _canonical_gate(cast(JsonObject, item))
            for item in cast(list[object], raw["trust_gates"])
        ]
        return raw

    def canonical_json(self) -> bytes:
        return canonical_json_bytes(self.canonical_object())

    def digest(self) -> str:
        return hashlib.sha256(DECISION_DIGEST_DOMAIN + self.canonical_json()).hexdigest()

    def audit_digest(self) -> str:
        """Digest of the complete auditable projection (alias of ``digest``)."""

        return self.digest()

    def action_semantic_digest(self) -> str:
        """Hash action semantics only: the released decision and its support.

        Action semantics cover facts, support graphs, strategy, ranks, queues,
        final-plan effects, corroboration requests, explanations, and
        prohibitions.  Plan history, receipts, and trust gates are audit
        semantics: they are bound by :meth:`audit_digest` and validated by the
        exact causal stage-local closure rules, so validated non-action
        proposal variation can never move an action digest.
        """

        canonical = deepcopy(self.canonical_object())
        plans = cast(list[JsonObject], canonical["plans"])
        action: JsonObject = {
            "schema_version": canonical["schema_version"],
            "protocol_version": canonical["protocol_version"],
            "batch_id": canonical["batch_id"],
            "snapshot_id": canonical["snapshot_id"],
            "strategy": canonical["strategy"],
            "ranking_scope": canonical["ranking_scope"],
            "execution_mode": canonical["execution_mode"],
            "batch_state": canonical["batch_state"],
            "final_plan": plans[-1],
            "routes": canonical["routes"],
            "corroboration_requests": canonical["corroboration_requests"],
            "explanations": canonical["explanations"],
            "prohibited_actions": canonical["prohibited_actions"],
        }
        return hashlib.sha256(ACTION_SEMANTICS_DOMAIN + canonical_json_bytes(action)).hexdigest()

    @classmethod
    def from_observation(cls, observation: Mapping[str, object]) -> DecisionProjectionV22:
        """Project a full public runtime payload, discarding producer summaries.

        Opaque run-specific gate, receipt, and command identifiers are replaced
        with structural aliases while every cross-reference is retained.
        """

        projected = _project_runtime_observation(observation)
        try:
            return cls.model_validate_json(canonical_json_bytes(projected))
        except Exception as exc:
            raise ReleaseSpecV22Error("runtime observation is not a valid V2.2 decision") from exc

    @classmethod
    def from_canonical(cls, value: object) -> DecisionProjectionV22:
        try:
            projection = cls.model_validate_json(canonical_json_bytes(value))
        except Exception as exc:
            raise ReleaseSpecV22Error("stored V2.2 decision projection is invalid") from exc
        if projection.canonical_object() != value:
            raise ReleaseSpecV22Error("stored V2.2 decision projection is not canonical")
        return projection


def canonicalize_category(value: str) -> str:
    return " ".join(value.casefold().split())


def canonical_value_sha256(canonical_value: str) -> str:
    return hashlib.sha256(CANONICAL_VALUE_DOMAIN + canonical_value.encode("utf-8")).hexdigest()


def _validate_plan_policy(plan: PlanV22) -> None:
    acquisition = (
        "fetch_candidate_details",
        "validate_candidate_details",
        "fetch_candidate_resumes",
        "parse_candidate_resumes",
        "validate_candidate_bindings",
        "map_candidate_claims",
        "validate_candidate_evidence",
    )
    policy: Mapping[str, tuple[str, tuple[str, ...], frozenset[str]]] = {
        "FULL_EVIDENCE_RANKING": (
            "rank_full_corroborated_evidence",
            ("rank_full_evidence", "pre_release_audit", "release_output"),
            _BASE_PROHIBITIONS_V22,
        ),
        "SUPPORTED_ONLY_RANKING": (
            "rank_supported_evidence_only",
            (
                "quarantine_unsupported",
                "rank_supported_evidence",
                "pre_release_audit",
                "release_output",
            ),
            _BASE_PROHIBITIONS_V22,
        ),
        "PARTIAL_SAFE_RANKING": (
            "rank_available_evidence_safely",
            (
                "mark_evidence_pending",
                "rank_partial_evidence",
                "request_corroboration",
                "pre_release_audit",
                "release_output",
            ),
            _BASE_PROHIBITIONS_V22,
        ),
        "BATCH_INTEGRITY_HOLD": (
            "hold_batch_for_integrity_review",
            (
                "isolate_batch",
                "request_corroboration",
                "pre_release_audit",
                "release_output",
            ),
            frozenset(_PROHIBITIONS_V22),
        ),
    }
    objective, suffix, prohibitions = policy[plan.strategy]
    initial_index_hold = (
        plan.version == 1
        and plan.strategy == "BATCH_INTEGRITY_HOLD"
        and tuple(command.kind for command in plan.commands) == ("validate_index_commitments",)
    )
    expected_kinds = (
        (*acquisition, *suffix)
        if plan.version == 1 and plan.strategy == "FULL_EVIDENCE_RANKING"
        else ("validate_index_commitments",)
        if initial_index_hold
        else suffix
    )
    if plan.version == 1 and plan.strategy not in {
        "FULL_EVIDENCE_RANKING",
        "BATCH_INTEGRITY_HOLD",
    }:
        raise ValueError("initial plan uses an impossible strategy")
    if plan.version == 3 and plan.strategy != "BATCH_INTEGRITY_HOLD":
        raise ValueError("terminal third plan must be a batch hold")
    if (
        plan.objective != objective
        or tuple(command.kind for command in plan.commands) != expected_kinds
        or set(plan.prohibited_actions) != prohibitions
    ):
        raise ValueError("plan does not match the evaluator-owned strategy policy")
    for index, command in enumerate(plan.commands):
        expected_dependencies = () if index == 0 else (plan.commands[index - 1].command_id,)
        if (
            command.scope != "batch"
            or command.candidate_id is not None
            or command.dependency_ids != expected_dependencies
        ):
            raise ValueError("plan command graph is not the closed linear workflow")


def _validate_release_evidence_closure(
    projection: DecisionProjectionV22,
    *,
    final_plan: PlanV22,
    gates: Mapping[str, TrustGateV22],
    receipt_pairs: Mapping[tuple[int, str], list[ReceiptV22]],
) -> None:
    """Bind released support to the active plan and consequential command chain."""

    released_ids = tuple(
        sorted(
            evidence_id
            for route in projection.routes
            if route.rank_key is not None
            for evidence_id in route.evidence_ids
        )
    )
    if len(released_ids) != len(set(released_ids)):
        raise ValueError("released routes contain duplicate evidence ownership")
    if final_plan.allowed_evidence_ids != released_ids:
        raise ValueError("active plan evidence differs from the released support closure")

    active_terminal_kinds = {
        "FULL_EVIDENCE_RANKING": "rank_full_evidence",
        "SUPPORTED_ONLY_RANKING": "rank_supported_evidence",
        "PARTIAL_SAFE_RANKING": "rank_partial_evidence",
        "BATCH_INTEGRITY_HOLD": "isolate_batch",
    }
    consequential_kinds = {
        active_terminal_kinds[projection.strategy],
        "pre_release_audit",
        "release_output",
    }
    consequential_receipts = [
        pair[1]
        for pair in receipt_pairs.values()
        if pair[1].status == "completed" and pair[1].command_kind in consequential_kinds
    ]
    if {receipt.command_kind for receipt in consequential_receipts} != consequential_kinds or len(
        consequential_receipts
    ) != len(consequential_kinds):
        raise ValueError("release evidence chain is incomplete or duplicated")
    for receipt in consequential_receipts:
        if receipt.evidence_ids != released_ids:
            raise ValueError("consequential receipt evidence differs from the active plan")
        assert receipt.produced_gate_id is not None
        if gates[receipt.produced_gate_id].evidence_ids != released_ids:
            raise ValueError("consequential trust gate evidence differs from the active plan")

    validation_receipts = [
        pair[1]
        for pair in receipt_pairs.values()
        if pair[1].status == "completed" and pair[1].command_kind == "validate_candidate_evidence"
    ]
    if len(validation_receipts) > 1 or (released_ids and not validation_receipts):
        raise ValueError("released support lacks one completed evidence-validation boundary")
    if validation_receipts:
        validation_receipt = validation_receipts[0]
        assert validation_receipt.produced_gate_id is not None
        validation_gate = gates[validation_receipt.produced_gate_id]
        if not set(released_ids).issubset(validation_receipt.evidence_ids) or not set(
            released_ids
        ).issubset(validation_gate.evidence_ids):
            raise ValueError("released support exceeds validated provenance")


def _validate_ordinary_record_inventories(projection: DecisionProjectionV22) -> None:
    """Validate mapped record evidence even when no support graph is released.

    A local quarantine is still a consequential evidence decision.  The
    evaluator therefore validates its typed mapping commitment, the identical
    usable provenance boundary, and whichever deterministic stage terminated
    the record.  Candidates which failed before a typed mapping commitment was
    created remain representable as bounded unavailable/identity failures.
    """

    mapping_receipts = tuple(
        receipt
        for receipt in projection.receipts
        if receipt.command_kind == "map_candidate_claims" and receipt.status == "completed"
    )
    parsing_receipts = tuple(
        receipt
        for receipt in projection.receipts
        if receipt.command_kind == "parse_candidate_resumes" and receipt.status == "completed"
    )
    catalog_ids: set[str] | None = None
    mapping_receipt: ReceiptV22 | None = None
    if mapping_receipts:
        if len(mapping_receipts) != 1 or len(mapping_receipts[0].evidence_ids) != len(
            set(mapping_receipts[0].evidence_ids)
        ):
            raise ValueError("mapped records require one exact mapping commitment")
        if len(parsing_receipts) != 1 or len(parsing_receipts[0].evidence_ids) != len(
            set(parsing_receipts[0].evidence_ids)
        ):
            raise ValueError("mapped records require one bounded parsed evidence catalog")
        mapping_receipt = mapping_receipts[0]
        catalog_ids = set(parsing_receipts[0].evidence_ids)

    expected_mapping_ids: set[str] = set()

    for route in projection.routes:
        stages: dict[str, TrustGateV22 | None] = {}
        for stage in (
            "mapping",
            "provenance",
            "timeline",
            "cross_source",
            "candidate_validation",
        ):
            matching = tuple(
                gate
                for gate in projection.trust_gates
                if gate.scope == "record"
                and gate.stage == stage
                and gate.candidate_id == route.candidate_id
            )
            if len(matching) > 1:
                raise ValueError("record contains duplicate disposition-stage decisions")
            stages[stage] = matching[0] if matching else None

        mapping = stages["mapping"]
        provenance = stages["provenance"]
        mapping_inventory = mapping.evidence_inventory if mapping is not None else None
        provenance_inventory = provenance.evidence_inventory if provenance is not None else None
        if mapping_inventory is None:
            if provenance_inventory is not None:
                raise ValueError("provenance inventory lacks its typed mapping commitment")
            _validate_inventory_free_record_path_v22(
                projection,
                route=route,
                stages=stages,
                catalog_ids=catalog_ids,
            )
            continue
        if provenance_inventory is None or catalog_ids is None:
            raise ValueError("typed mapping inventory lacks a usable provenance boundary")
        if mapping_inventory != provenance_inventory:
            raise ValueError("mapping and provenance inventories are not exactly equal")
        assert mapping is not None
        assert provenance is not None
        if (
            mapping.state != "USABLE"
            or mapping.outcome != "ALLOW"
            or mapping.reason_codes != ("mapper_output_valid",)
            or provenance.state != "USABLE"
            or provenance.outcome != "ALLOW"
            or provenance.reason_codes != ("evidence_admissible",)
            or provenance.input_gate_ids != (mapping.gate_id,)
            or mapping.snapshot_id != route.snapshot_id
            or provenance.snapshot_id != route.snapshot_id
            or mapping.evidence_ids != provenance.evidence_ids
        ):
            raise ValueError("typed mapping and provenance gates do not form one usable lineage")

        consumed_by_id, intervals = _validate_preconsumption_inventory_v22(
            mapping_inventory,
            candidate_id=route.candidate_id,
            snapshot_id=route.snapshot_id,
            gate_evidence_ids=provenance.evidence_ids,
            catalog_ids=catalog_ids,
        )
        expected_mapping_ids.update(consumed_by_id)
        expected_mapping_ids.update(
            anchor.reference.evidence_id for anchor in mapping_inventory.structured_anchors
        )
        timeline = stages["timeline"]
        terminal_gate = stages["candidate_validation"]
        if timeline is None or terminal_gate is None:
            raise ValueError("usable mapped record lacks timeline and terminal decisions")
        expected_timeline = _expected_timeline_reason_v22(
            intervals,
            record_ap_years=mapping_inventory.record_ap_years,
            record_invoice_processing=mapping_inventory.record_invoice_processing,
        )
        interval_ids = tuple(
            sorted(
                item.reference.evidence_id
                for item in consumed_by_id.values()
                if item.claim_kind == "employment_interval"
            )
        )
        expected_timeline_state = {
            "timeline_valid": "USABLE",
            "timeline_unavailable": "DEGRADED",
            "timeline_conflict": "QUARANTINED",
            "timeline_drift": "DEGRADED",
        }[expected_timeline]
        expected_timeline_outcome = {
            "USABLE": "ALLOW",
            "DEGRADED": "RESTRICT",
            "QUARANTINED": "QUARANTINE",
        }[expected_timeline_state]
        if (
            timeline.input_gate_ids != (provenance.gate_id,)
            or timeline.reason_codes != (expected_timeline,)
            or timeline.state != expected_timeline_state
            or timeline.outcome != expected_timeline_outcome
            or timeline.evidence_ids != interval_ids
        ):
            raise ValueError("mapped record timeline was not independently derived")

        cross_source = stages["cross_source"]
        if expected_timeline == "timeline_conflict":
            if (
                cross_source is not None
                or route.rank_key is not None
                or route.support_graph is not None
                or terminal_gate.input_gate_ids != (timeline.gate_id,)
                or terminal_gate.state != "QUARANTINED"
                or terminal_gate.outcome != "QUARANTINE"
                or set(terminal_gate.reason_codes)
                != {"evidence_admissible", "mapper_disagreement", "timeline_conflict"}
                or terminal_gate.evidence_ids
                or terminal_gate.evidence_inventory is not None
            ):
                raise ValueError("timeline-conflict quarantine has inexact terminal semantics")
            continue

        if cross_source is None or cross_source.input_gate_ids != (timeline.gate_id,):
            raise ValueError("consumable timeline lacks its cross-source decision")
        final_inventory = terminal_gate.evidence_inventory
        if final_inventory is not None and (
            final_inventory.structured_anchors != mapping_inventory.structured_anchors
            or final_inventory.record_ap_years_reference
            != mapping_inventory.record_ap_years_reference
            or final_inventory.record_invoice_processing_reference
            != mapping_inventory.record_invoice_processing_reference
            or final_inventory.record_ap_years != mapping_inventory.record_ap_years
            or final_inventory.record_invoice_processing
            is not mapping_inventory.record_invoice_processing
        ):
            raise ValueError("terminal disposition rewrites its structured record anchors")
        cross_derivation = _validate_cross_source_evidence_closure_v22(
            mapping_inventory,
            cross_source=cross_source,
            catalog_ids=catalog_ids,
            terminal_inventory=final_inventory,
        )
        if final_inventory is not None:
            # Ranked records are validated against their support graph below.
            # Graph-free batch holds use the same independently derived
            # disposition validator as the exact drift-hold path.
            if route.support_graph is None:
                _validate_unreleased_record_inventory(
                    projection,
                    candidate_id=route.candidate_id,
                    gates={gate.gate_id: gate for gate in projection.trust_gates},
                    catalog_ids=catalog_ids,
                )
            continue

        # A cross-source quarantine consumes no released evidence and carries
        # no terminal disposition inventory, but its gate/route result is still
        # derived from the exact mapped inventory and causal chain.
        expected_terminal_reasons = {
            "evidence_admissible",
            expected_timeline,
            *cross_derivation.terminal_reason_codes,
        }
        if (
            cross_derivation.state != "QUARANTINED"
            or "mapper_disagreement" not in cross_derivation.terminal_reason_codes
            or not set(cross_derivation.terminal_reason_codes).intersection(
                {"cross_source_conflict", "domain_invariant_conflict"}
            )
            or terminal_gate.input_gate_ids != (cross_source.gate_id,)
            or terminal_gate.state != "QUARANTINED"
            or terminal_gate.outcome != "QUARANTINE"
            or set(terminal_gate.reason_codes) != expected_terminal_reasons
            or terminal_gate.evidence_ids
            or route.rank_key is not None
            or route.support_graph is not None
        ):
            raise ValueError("cross-source quarantine has inexact terminal semantics")

    if mapping_receipt is not None:
        expected_ids = tuple(sorted(expected_mapping_ids))
        if mapping_receipt.evidence_ids != expected_ids:
            raise ValueError("mapping receipt differs from the exact typed record commitments")
        if mapping_receipt.produced_gate_id is None:
            raise ValueError("mapping receipt lacks its produced batch commitment")
        batch_mapping = next(
            (
                gate
                for gate in projection.trust_gates
                if gate.gate_id == mapping_receipt.produced_gate_id
            ),
            None,
        )
        if (
            batch_mapping is None
            or batch_mapping.scope != "batch"
            or batch_mapping.stage != "mapping"
            or batch_mapping.evidence_ids != expected_ids
        ):
            raise ValueError("batch mapping gate differs from the exact typed commitments")


def _validate_inventory_free_record_path_v22(
    projection: DecisionProjectionV22,
    *,
    route: RouteV22,
    stages: Mapping[str, TrustGateV22 | None],
    catalog_ids: set[str] | None,
) -> None:
    """Admit only an independently bounded path which stopped before evidence use.

    A producer cannot turn an ordinary usable-provenance decision into an
    apparent early failure by erasing both inventories and coherently shrinking
    the batch mapping receipt.  Inventory-free records are limited to either a
    batch-level hold before any record stage, an exact pre-mapping local
    failure, or the frozen mapper-disagreement path which terminates at the
    rejecting provenance gate before timeline or cross-source evaluation.
    """

    mapping = stages["mapping"]
    provenance = stages["provenance"]
    timeline = stages["timeline"]
    cross_source = stages["cross_source"]
    terminal = stages["candidate_validation"]

    if all(item is None for item in stages.values()):
        if (
            projection.strategy != "BATCH_INTEGRITY_HOLD"
            or projection.ranking_scope != "NONE"
            or route.rank_key is not None
            or route.support_graph is not None
            or route.evidence_ids
        ):
            raise ValueError("inventory-free record lacks a proven batch-level stop")
        return

    if (
        timeline is not None
        or cross_source is not None
        or terminal is None
        or terminal.evidence_inventory is not None
        or terminal.evidence_ids
        or route.rank_key is not None
        or route.support_graph is not None
        or route.evidence_ids
    ):
        raise ValueError("downstream evidence decision lacks its typed mapping inventory")

    # A mapper result can be structurally accepted while its cited values are
    # rejected at the immediately following provenance boundary.  This is the
    # sole inventory-free post-mapping shape: no timeline or cross-source stage
    # ran, and the terminal decision preserves the exact rejecting gate.
    if mapping is not None or provenance is not None:
        if (
            mapping is None
            or provenance is None
            or catalog_ids is None
            or mapping.state != "USABLE"
            or mapping.outcome != "ALLOW"
            or mapping.reason_codes != ("mapper_output_valid",)
            or mapping.evidence_ids
            or provenance.input_gate_ids != (mapping.gate_id,)
            or provenance.state != "QUARANTINED"
            or provenance.outcome != "QUARANTINE"
            or provenance.reason_codes != ("evidence_value_conflict", "mapper_disagreement")
            or not provenance.evidence_ids
            or not set(provenance.evidence_ids).issubset(catalog_ids)
            or terminal.input_gate_ids != (provenance.gate_id,)
            or terminal.state != provenance.state
            or terminal.outcome != provenance.outcome
            or terminal.reason_codes != provenance.reason_codes
        ):
            raise ValueError("inventory-free provenance rejection is not the exact early stop")
        return

    # Local retrieval/schema/identity/revision/manifest/parsing failures stop
    # before the mapper.  The terminal gate must be a lossless consequence of
    # that one non-usable record gate; a usable predecessor is not an early
    # failure and therefore cannot justify missing inventories.
    if len(terminal.input_gate_ids) != 1:
        raise ValueError("inventory-free terminal decision lacks one early-failure parent")
    parent = next(
        (gate for gate in projection.trust_gates if gate.gate_id == terminal.input_gate_ids[0]),
        None,
    )
    unavailable_transition = (
        parent is not None
        and "candidate_unavailable" in parent.reason_codes
        and terminal.state == "UNAVAILABLE"
        and terminal.outcome == "UNAVAILABLE"
    )
    preserved_transition = (
        parent is not None and terminal.state == parent.state and terminal.outcome == parent.outcome
    )
    if (
        parent is None
        or parent.scope != "record"
        or parent.candidate_id != route.candidate_id
        or parent.stage
        not in {"retrieval", "schema", "identity", "revision", "manifest", "parsing"}
        or parent.state == "USABLE"
        or parent.outcome == "ALLOW"
        or not (unavailable_transition or preserved_transition)
        or set(terminal.reason_codes) != set(parent.reason_codes)
    ):
        raise ValueError("inventory-free record is not an exact pre-mapping failure")


def _validate_preconsumption_inventory_v22(
    inventory: EvidenceDispositionInventoryV22,
    *,
    candidate_id: str,
    snapshot_id: str,
    gate_evidence_ids: tuple[str, ...],
    catalog_ids: set[str],
) -> tuple[
    dict[str, EvidenceDispositionEntryV22],
    tuple[SupportedEmploymentIntervalV22, ...],
]:
    """Validate one exact typed mapper-consumed record commitment."""

    if inventory.candidate_id != candidate_id or inventory.snapshot_id != snapshot_id:
        raise ValueError("pre-consumption inventory escapes its record lineage")
    consumed_by_id = {item.reference.evidence_id: item for item in inventory.entries}
    if (
        len(consumed_by_id) != len(inventory.entries)
        or gate_evidence_ids != tuple(sorted(consumed_by_id))
        or not {
            *consumed_by_id,
            *(anchor.reference.evidence_id for anchor in inventory.structured_anchors),
        }.issubset(catalog_ids)
        or any(item.state != "consumed" for item in inventory.entries)
    ):
        raise ValueError("pre-consumption inventory is not its exact mapped evidence closure")

    scalar_items: dict[str, list[EvidenceDispositionEntryV22]] = {}
    for item in inventory.entries:
        if item.claim_kind != "employment_interval":
            scalar_items.setdefault(item.claim_kind, []).append(item)
    if {"ap_years", "invoice_processing"}.difference(scalar_items):
        raise ValueError("mapped inventory lacks its mandatory scalar claim edges")

    if any(
        item.reference.semantic_hash
        not in {_evidence_value_sha256(False), _evidence_value_sha256(True)}
        for item in scalar_items["invoice_processing"]
    ):
        raise ValueError("mapped invoice claim is not a typed boolean")
    return consumed_by_id, _disposition_intervals_v22(inventory)


def _canonical_evidence_id_v22(prefix: str, *parts: str) -> str:
    """Independently reproduce the canonical adapter's bounded evidence ID."""

    readable = ":".join((prefix, *parts))
    if _CANONICAL_EVIDENCE_ID_PATTERN_V22.fullmatch(readable) is not None:
        return readable
    return f"{prefix}:{hashlib.sha256(readable.encode('utf-8')).hexdigest()}"


def _canonical_structured_field_path_v22(candidate_id: str, role: str) -> str:
    """Independently reproduce the bounded canonical adapter field path."""

    detailed = f"records[{candidate_id}].{role}"
    return detailed if len(detailed) <= 160 else f"record.{role}"


@dataclass(frozen=True, slots=True)
class _CrossSourceDerivationV22:
    """Evaluator-owned result of the bounded visible/structured comparison."""

    state: Literal["USABLE", "DEGRADED", "QUARANTINED"]
    outcome: Literal["ALLOW", "RESTRICT", "QUARANTINE"]
    gate_reason_codes: tuple[str, ...]
    terminal_reason_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    matched_kinds: frozenset[str]
    conflicting_kinds: frozenset[str]
    missing_kinds: frozenset[str]
    unsupported_category_kinds: frozenset[str]


def _structured_values_equal_v22(
    claim_kind: str,
    expected: JsonScalar,
    observed: JsonScalar,
) -> bool:
    """Mirror only the frozen, typed cross-source equivalence relation."""

    if expected is None:
        return False
    if claim_kind in {"ap_years", "monthly_invoice_volume"}:
        return abs(float(cast(int | float, expected)) - float(cast(int | float, observed))) <= 0.01
    if claim_kind in {"invoice_processing", "reconciliation"}:
        return expected is observed
    return cast(str, expected).strip().casefold() == cast(str, observed).strip().casefold()


def _derive_cross_source_v22(
    inventory: EvidenceDispositionInventoryV22,
) -> _CrossSourceDerivationV22:
    """Independently derive pair closure, conflicts, missing values, and drops."""

    anchors = {anchor.claim_kind: anchor for anchor in inventory.structured_anchors}
    mapped_items = tuple(
        item for item in inventory.entries if item.claim_kind != "employment_interval"
    )
    mapped: dict[str, list[EvidenceDispositionEntryV22]] = {}
    for item in mapped_items:
        mapped.setdefault(item.claim_kind, []).append(item)

    matched: set[str] = set()
    conflicting: set[str] = set()
    missing: set[str] = set()
    evaluated_ids: set[str] = set()
    for claim_kind in _STRUCTURED_CLAIM_KINDS_V22:
        anchor = anchors[claim_kind]
        items = mapped.get(claim_kind, [])
        if not items:
            if anchor.value is not None:
                missing.add(claim_kind)
            continue
        evaluated_ids.add(anchor.reference.evidence_id)
        evaluated_ids.update(item.reference.evidence_id for item in items)
        comparisons = tuple(
            _structured_values_equal_v22(
                claim_kind,
                anchor.value,
                item.mapped_value,
            )
            for item in items
        )
        group_equivalent = all(
            _structured_values_equal_v22(
                claim_kind,
                left.mapped_value,
                right.mapped_value,
            )
            for index, left in enumerate(items)
            for right in items[index + 1 :]
        )
        if all(comparisons) and group_equivalent:
            matched.add(claim_kind)
        else:
            conflicting.add(claim_kind)

    reasons: set[str]
    if conflicting:
        state: Literal["USABLE", "DEGRADED", "QUARANTINED"] = "QUARANTINED"
        reasons = {"cross_source_conflict", "mapper_disagreement"}
    elif missing:
        state = "DEGRADED"
        reasons = {"cross_source_match", "evidence_missing"}
    else:
        state = "USABLE"
        reasons = {"cross_source_match"}

    # Runtime domain policy operates on values which survived the comparison.
    # A matched monthly volume cannot survive unless invoice processing also
    # matched an explicit true application value.
    if "monthly_invoice_volume" in matched and not (
        "invoice_processing" in matched and anchors["invoice_processing"].value is True
    ):
        matched.discard("monthly_invoice_volume")
        state = "QUARANTINED"
        reasons.update({"domain_invariant_conflict", "mapper_disagreement"})

    unsupported_categories = {
        claim_kind
        for claim_kind in CATEGORICAL_ALLOW_LISTS_V22
        if claim_kind in matched
        and " ".join(cast(str, anchors[claim_kind].value).split()).casefold()
        not in CATEGORICAL_ALLOW_LISTS_V22[claim_kind]
    }
    matched.difference_update(unsupported_categories)
    terminal_reasons = tuple(sorted(reasons))
    gate_reasons = set(reasons)
    if unsupported_categories:
        gate_reasons.add("category_not_supported")
    if state == "USABLE":
        outcome: Literal["ALLOW", "RESTRICT", "QUARANTINE"] = "ALLOW"
    elif state == "DEGRADED":
        outcome = "RESTRICT"
    else:
        outcome = "QUARANTINE"
    return _CrossSourceDerivationV22(
        state=state,
        outcome=outcome,
        gate_reason_codes=tuple(sorted(gate_reasons)),
        terminal_reason_codes=terminal_reasons,
        evidence_ids=tuple(sorted(evaluated_ids)),
        matched_kinds=frozenset(matched),
        conflicting_kinds=frozenset(conflicting),
        missing_kinds=frozenset(missing),
        unsupported_category_kinds=frozenset(unsupported_categories),
    )


def _validate_cross_source_evidence_closure_v22(
    inventory: EvidenceDispositionInventoryV22,
    *,
    cross_source: TrustGateV22,
    catalog_ids: set[str],
    terminal_inventory: EvidenceDispositionInventoryV22 | None,
) -> _CrossSourceDerivationV22:
    """Rebuild the exact typed evidence consumed by a cross-source gate.

    The pre-consumption inventory identifies every visible scalar edge and the
    canonical adapter has exactly one application-JSON edge for every scalar
    kind evaluated at this boundary.  A terminal inventory supplies the
    accepted/dropped partition for ranked and held records, but a cross-source
    decision must retain *all* pairs it evaluated, including conflicting and
    subsequently dropped pairs.  An ordinary cross-source quarantine has no
    terminal disposition inventory, so this distinction is especially
    important: deriving the complete evaluated set from the trusted mapping
    inventory prevents the gate from self-scoring an additional pair as
    omitted while preserving internally coherent pair shapes.
    """

    if terminal_inventory is not None:
        terminal_by_id = {item.reference.evidence_id: item for item in terminal_inventory.entries}
        if len(terminal_by_id) != len(terminal_inventory.entries) or set(terminal_by_id) != {
            item.reference.evidence_id for item in inventory.entries
        }:
            raise ValueError("terminal inventory cannot derive an exact cross-source partition")

    derived = _derive_cross_source_v22(inventory)
    if (
        cross_source.state != derived.state
        or cross_source.outcome != derived.outcome
        or cross_source.reason_codes != derived.gate_reason_codes
        or cross_source.evidence_ids != derived.evidence_ids
        or not set(derived.evidence_ids).issubset(catalog_ids)
    ):
        raise ValueError("cross-source evidence is not its exact typed closure")
    return derived


def _validate_stage_local_closure(projection: DecisionProjectionV22) -> None:
    """Independently derive exact consumed/released/dropped citation closure.

    Reason markers never authorize an evidence superset.  Every record which
    reached a usable provenance boundary must expose a mapping-catalog-anchored
    pre-consumption inventory and the exact path-specific terminal lineage,
    including graph-free quarantines.  Ranked records additionally expose one
    terminal disposition for every consumed reference.  Their released
    partition is reconstructed from the support graph; each legal drop is then
    re-derived from bounded field roles, value hashes, record scalars, and dated
    interval evidence.
    """

    # The dedicated failed-closed validator below proves the stricter, three-
    # plan drift-hold shape and validates each graph-free record inventory.  Do
    # not admit another FAILED_CLOSED shape through the ordinary release path.
    if projection.execution_mode == "FAILED_CLOSED":
        return

    _validate_ordinary_record_inventories(projection)

    for route in projection.routes:
        if route.rank_key is None or route.support_graph is None:
            continue
        graph = route.support_graph
        manifest = {item.evidence_id: item for item in graph.evidence_manifest}
        by_stage: dict[str, TrustGateV22] = {}
        for stage in ("provenance", "timeline", "cross_source", "candidate_validation"):
            matching = tuple(
                gate
                for gate in projection.trust_gates
                if gate.stage == stage
                and gate.scope == "record"
                and gate.candidate_id == route.candidate_id
            )
            if len(matching) != 1:
                raise ValueError("ranked candidate requires one exact disposition-stage lineage")
            by_stage[stage] = matching[0]
        provenance = by_stage["provenance"]
        timeline = by_stage["timeline"]
        cross_source = by_stage["cross_source"]
        terminal = by_stage["candidate_validation"]
        if (
            timeline.input_gate_ids != (provenance.gate_id,)
            or cross_source.input_gate_ids != (timeline.gate_id,)
            or terminal.input_gate_ids != (cross_source.gate_id,)
            or provenance.state != "USABLE"
            or provenance.outcome != "ALLOW"
            or provenance.reason_codes != ("evidence_admissible",)
            or terminal.state != "USABLE"
            or terminal.outcome != "ALLOW"
            or terminal.reason_codes != route.reason_codes
            or terminal.evidence_ids != route.evidence_ids
        ):
            raise ValueError("disposition stages do not form the exact authorized record lineage")

        consumed = provenance.evidence_inventory
        final = terminal.evidence_inventory
        if consumed is None or final is None:
            raise ValueError("ranked candidate lacks complete disposition inventories")
        if (
            consumed.candidate_id != route.candidate_id
            or consumed.snapshot_id != route.snapshot_id
            or final.candidate_id != consumed.candidate_id
            or final.snapshot_id != consumed.snapshot_id
            or final.structured_anchors != consumed.structured_anchors
            or final.record_ap_years_reference != consumed.record_ap_years_reference
            or final.record_invoice_processing_reference
            != consumed.record_invoice_processing_reference
            or final.record_ap_years != consumed.record_ap_years
            or final.record_invoice_processing is not consumed.record_invoice_processing
            or any(
                gate.snapshot_id != route.snapshot_id
                for gate in (provenance, timeline, cross_source, terminal)
            )
        ):
            raise ValueError("disposition inventories escape their candidate or snapshot")
        consumed_by_id = {item.reference.evidence_id: item for item in consumed.entries}
        final_by_id = {item.reference.evidence_id: item for item in final.entries}
        if (
            len(consumed_by_id) != len(consumed.entries)
            or len(final_by_id) != len(final.entries)
            or set(consumed_by_id) != set(final_by_id)
            or set(provenance.evidence_ids) != set(consumed_by_id)
            or len(provenance.evidence_ids) != len(consumed_by_id)
        ):
            raise ValueError("terminal dispositions do not exactly partition consumed evidence")
        mapping_receipts = tuple(
            receipt
            for receipt in projection.receipts
            if receipt.command_kind == "map_candidate_claims" and receipt.status == "completed"
        )
        if len(mapping_receipts) != 1 or not set(consumed_by_id).issubset(
            mapping_receipts[0].evidence_ids
        ):
            raise ValueError("consumed inventory is not anchored to the mapped evidence catalog")
        for evidence_id, consumed_item in consumed_by_id.items():
            final_item = final_by_id[evidence_id]
            if (
                consumed_item.state != "consumed"
                or final_item.state == "consumed"
                or consumed_item.claim_kind != final_item.claim_kind
                or consumed_item.reference != final_item.reference
                or consumed_item.date_value != final_item.date_value
                or consumed_item.mapped_value != final_item.mapped_value
            ):
                raise ValueError("terminal disposition rewrites its consumed evidence edge")

        cross_derivation = _derive_cross_source_v22(consumed)

        released_roles: dict[str, set[str]] = {}
        for fact in graph.facts:
            if fact.kind == "candidate_id":
                continue
            for evidence_id in fact.evidence_ids:
                reference = manifest.get(evidence_id)
                if reference is not None and reference.source_kind == "resume_visible":
                    released_roles.setdefault(evidence_id, set()).add(fact.kind)
        released_ids = {
            evidence_id for evidence_id, item in final_by_id.items() if item.state == "released"
        }
        if released_ids != set(released_roles):
            raise ValueError("released disposition differs from the visible support closure")
        for evidence_id in released_ids:
            item = final_by_id[evidence_id]
            reference = manifest.get(evidence_id)
            roles = released_roles[evidence_id]
            stage_evidence = (
                set(timeline.evidence_ids)
                if item.claim_kind == "employment_interval"
                else set(cross_source.evidence_ids)
            )
            if (
                item.reference != reference
                or (
                    item.claim_kind not in roles
                    and not (
                        item.claim_kind == "employment_interval"
                        and {"ap_years", "employment_interval"}.issubset(roles)
                    )
                )
                or evidence_id not in stage_evidence
            ):
                raise ValueError("released disposition has an unrelated claim or reference")

        fact_kinds = {fact.kind for fact in graph.facts}
        anchors_by_kind = {anchor.claim_kind: anchor for anchor in final.structured_anchors}
        for fact in graph.facts:
            if fact.kind in {"candidate_id", "employment_interval"}:
                continue
            anchor = anchors_by_kind[fact.kind]
            structured_references = tuple(
                manifest[evidence_id]
                for evidence_id in fact.evidence_ids
                if manifest[evidence_id].source_kind == "application_json"
            )
            fact_matches_anchor = (
                fact.source_value == anchor.value
                if fact.kind in CATEGORICAL_ALLOW_LISTS_V22
                else fact.normalized_value == anchor.value
                and type(fact.normalized_value) is type(anchor.value)
            )
            if (
                fact.kind not in cross_derivation.matched_kinds
                or structured_references != (anchor.reference,)
                or not fact_matches_anchor
            ):
                raise ValueError("released fact is not bound to its compared structured anchor")
        ap_fact = next((fact for fact in graph.facts if fact.kind == "ap_years"), None)
        invoice_fact = next(
            (fact for fact in graph.facts if fact.kind == "invoice_processing"), None
        )
        if ap_fact is not None and (
            not _bounded_number(ap_fact.normalized_value, lower=0, upper=80)
            or float(cast(int | float, ap_fact.normalized_value)) != final.record_ap_years
        ):
            raise ValueError("inventory AP scalar differs from released record evidence")
        if invoice_fact is not None and (
            not isinstance(invoice_fact.normalized_value, bool)
            or invoice_fact.normalized_value is not final.record_invoice_processing
        ):
            raise ValueError("inventory invoice scalar differs from released record evidence")
        category_drop = False
        timeline_drop = False
        for item in final_by_id.values():
            if item.state == "released":
                continue
            if item.reference.evidence_id in manifest:
                raise ValueError("dropped disposition remains inside released support")
            if item.state == "dropped_unsupported_category":
                if (
                    item.claim_kind not in cross_derivation.unsupported_category_kinds
                    or item.claim_kind in fact_kinds
                    or item.reference.evidence_id not in cross_source.evidence_ids
                ):
                    raise ValueError("categorical drop is not independently unsupported")
                category_drop = True
            elif item.state == "dropped_timeline_policy":
                if (
                    item.claim_kind != "ap_years"
                    or "ap_years" in fact_kinds
                    or "employment_interval" in fact_kinds
                    or final.record_ap_years <= 0
                    or item.reference.evidence_id not in cross_source.evidence_ids
                    or item.claim_kind not in cross_derivation.matched_kinds
                ):
                    raise ValueError("timeline drop is not derived from the bounded record")
                timeline_drop = True
            else:
                # A ranked record cannot survive a cross-source evidence drop.
                raise ValueError("ranked disposition contains a forbidden cross-source drop")

        if bool(cross_derivation.unsupported_category_kinds) is not category_drop:
            raise ValueError("category marker does not equal the derived category drops")

        intervals = tuple(
            interval
            for fact in graph.facts
            if fact.kind == "employment_interval"
            for interval in fact.employment_intervals
        )
        interval_evidence_ids = tuple(
            sorted(
                {
                    evidence_id
                    for interval in intervals
                    for evidence_id in (
                        interval.start_evidence_id,
                        interval.end_evidence_id,
                    )
                }
            )
        )
        expected_timeline = _expected_timeline_reason_v22(
            intervals,
            record_ap_years=final.record_ap_years,
            record_invoice_processing=final.record_invoice_processing,
        )
        if (
            timeline.reason_codes != (expected_timeline,)
            or timeline.evidence_ids != interval_evidence_ids
            or timeline.state != ("USABLE" if expected_timeline == "timeline_valid" else "DEGRADED")
            or timeline.outcome
            != ("ALLOW" if expected_timeline == "timeline_valid" else "RESTRICT")
        ):
            raise ValueError("timeline gate was not independently derived from record evidence")
        if expected_timeline not in {"timeline_valid", "timeline_unavailable"}:
            raise ValueError("a ranked route cannot survive a conflicting timeline")
        if timeline_drop is not (
            final.record_ap_years > 0 and not intervals and "ap_years" not in fact_kinds
        ):
            raise ValueError("AP-years disposition does not match the timeline policy")


def _validate_failed_closed_drift_hold(
    projection: DecisionProjectionV22,
    *,
    gates: Mapping[str, TrustGateV22],
    receipt_pairs: Mapping[tuple[int, str], list[ReceiptV22]],
    terminal: Mapping[tuple[int, str], str],
) -> None:
    """Admit only the exact fail-closed v3 response to independently proven drift.

    ``FAILED_CLOSED`` is not a general release mode in the semantic harness.  Its
    one representable form is the runtime's bounded response to a v2
    supported-only attempt that cannot release a dated-interval drift record:
    every v2 command is retained as failed/restricted evidence, a v3 hold is
    executed, and no route carries rank or support semantics.
    """

    if (
        projection.strategy != "BATCH_INTEGRITY_HOLD"
        or projection.ranking_scope != "NONE"
        or projection.batch_state != "QUARANTINED"
        or len(projection.plans) != 3
        or tuple(plan.strategy for plan in projection.plans)
        != (
            "FULL_EVIDENCE_RANKING",
            "SUPPORTED_ONLY_RANKING",
            "BATCH_INTEGRITY_HOLD",
        )
        or projection.plans[0].trigger_codes != ("index_valid",)
        or projection.plans[1].trigger_codes != ("evidence_admissible",)
        or projection.plans[2].trigger_codes != ("pre_release_blocked",)
        or projection.plans[0].allowed_evidence_ids
        or not projection.plans[1].allowed_evidence_ids
        or projection.plans[2].allowed_evidence_ids
    ):
        raise ValueError("failed-closed release is not the exact terminal drift-hold plan")

    diff = projection.plan_diff
    initial, rejected, hold = projection.plans
    if diff is None:
        raise ValueError("failed-closed drift hold lacks its terminal plan diff")
    expected_removed = {
        command.command_id
        for command in initial.commands
        if command.kind in _PROVISIONAL_PLAN_STEPS_V22
    }
    if (
        (diff.from_version, diff.to_version) != (2, 3)
        or (diff.strategy_before, diff.strategy_after)
        != ("SUPPORTED_ONLY_RANKING", "BATCH_INTEGRITY_HOLD")
        or diff.trigger_codes != ("pre_release_blocked",)
        or set(diff.removed_command_ids) != expected_removed
        or set(diff.revoked_evidence_ids) != set(rejected.allowed_evidence_ids)
        or diff.granted_evidence_ids
        or tuple(diff.added_commands) != tuple(hold.commands)
    ):
        raise ValueError("failed-closed drift hold has an inexact terminal plan diff")

    acquisition = {
        "fetch_candidate_details",
        "validate_candidate_details",
        "fetch_candidate_resumes",
        "parse_candidate_resumes",
        "validate_candidate_bindings",
        "map_candidate_claims",
        "validate_candidate_evidence",
    }
    expected_statuses: dict[tuple[int, str], str] = {
        **{(1, kind): "completed" for kind in acquisition},
        (2, "quarantine_unsupported"): "failed",
        (2, "rank_supported_evidence"): "restricted",
        (2, "pre_release_audit"): "restricted",
        (2, "release_output"): "restricted",
        (3, "isolate_batch"): "completed",
        (3, "request_corroboration"): "completed",
        (3, "pre_release_audit"): "completed",
        (3, "release_output"): "completed",
    }
    observed_statuses = {
        (plan.version, command.kind): terminal[(plan.version, command.command_id)]
        for plan in projection.plans
        for command in plan.commands
        if (plan.version, command.command_id) in terminal
    }
    if observed_statuses != expected_statuses:
        raise ValueError("failed-closed drift hold does not retain the exact attempted workflow")

    mapping_receipts = tuple(
        pair[1]
        for pair in receipt_pairs.values()
        if pair[1].command_kind == "map_candidate_claims" and pair[1].status == "completed"
    )
    if len(mapping_receipts) != 1 or len(mapping_receipts[0].evidence_ids) != len(
        set(mapping_receipts[0].evidence_ids)
    ):
        raise ValueError("failed-closed drift hold lacks one exact mapping commitment")
    parsing_receipts = tuple(
        pair[1]
        for pair in receipt_pairs.values()
        if pair[1].command_kind == "parse_candidate_resumes" and pair[1].status == "completed"
    )
    if len(parsing_receipts) != 1 or len(parsing_receipts[0].evidence_ids) != len(
        set(parsing_receipts[0].evidence_ids)
    ):
        raise ValueError("failed-closed drift hold lacks one parsed evidence catalog")
    catalog_ids = set(parsing_receipts[0].evidence_ids)
    if not set(mapping_receipts[0].evidence_ids).issubset(catalog_ids):
        raise ValueError("failed-closed mapping commitment escapes parsed evidence")

    blocked = tuple(
        gate
        for gate in projection.trust_gates
        if gate.scope == "batch"
        and gate.stage == "pre_release"
        and gate.state == "QUARANTINED"
        and gate.outcome == "HOLD"
    )
    if (
        len(blocked) != 1
        or blocked[0].reason_codes != ("pre_release_blocked",)
        or blocked[0].evidence_ids
        or len(blocked[0].input_gate_ids) != 1
    ):
        raise ValueError("failed-closed drift hold lacks one exact blocked release boundary")
    blocked_planning = tuple(
        gate
        for gate in projection.trust_gates
        if gate.scope == "batch"
        and gate.stage == "planning"
        and gate.input_gate_ids == (blocked[0].gate_id,)
    )
    rejected_planning = tuple(
        gate
        for gate in projection.trust_gates
        if gate.scope == "batch"
        and gate.stage == "planning"
        and gate.reason_codes == ("plan_revised",)
    )
    if (
        len(blocked_planning) != 1
        or blocked_planning[0].state != "USABLE"
        or blocked_planning[0].outcome != "ALLOW"
        or set(blocked_planning[0].reason_codes) != {"plan_revised", "pre_release_blocked"}
        or blocked_planning[0].evidence_ids
        or len(rejected_planning) != 1
        or rejected_planning[0].state != "USABLE"
        or rejected_planning[0].outcome != "ALLOW"
        or set(rejected_planning[0].evidence_ids) != set(rejected.allowed_evidence_ids)
        or blocked[0].input_gate_ids != rejected_planning[0].input_gate_ids
    ):
        raise ValueError("failed-closed drift hold is not bound to its rejected v2 plan")
    isolate = next(command for command in hold.commands if command.kind == "isolate_batch")
    isolate_pair = receipt_pairs.get((hold.version, isolate.command_id))
    if isolate_pair is None or isolate_pair[1].consumed_gate_ids != (blocked_planning[0].gate_id,):
        raise ValueError("terminal hold did not consume the blocked replanning gate")

    expected_v2_evidence: set[str] = set()
    expected_mapping_ids: set[str] = set()
    drift_candidates: set[str] = set()
    drift_reasons_by_candidate: dict[str, tuple[str, ...]] = {}
    for route in projection.routes:
        if (
            route.band != "INTEGRITY_HOLD"
            or route.queue != "BATCH_INTEGRITY_HOLD"
            or route.rank_key is not None
            or route.evidence_rank is not None
            or route.display_position is not None
            or route.evidence_ids
            or route.support_graph is not None
            or route.reason_codes != ("batch_hold_required",)
        ):
            raise ValueError("failed-closed drift hold contains a released or inexact route")
        timeline_reason, terminal_evidence, record_mapping_ids = (
            _validate_unreleased_record_inventory(
                projection,
                candidate_id=route.candidate_id,
                gates=gates,
                catalog_ids=catalog_ids,
            )
        )
        expected_v2_evidence.update(terminal_evidence)
        expected_mapping_ids.update(record_mapping_ids)
        if timeline_reason == "timeline_drift":
            drift_candidates.add(route.candidate_id)
            terminal_gate = next(
                gate
                for gate in projection.trust_gates
                if gate.scope == "record"
                and gate.stage == "candidate_validation"
                and gate.candidate_id == route.candidate_id
            )
            drift_reasons_by_candidate[route.candidate_id] = terminal_gate.reason_codes

    if (
        not drift_candidates
        or set(rejected.allowed_evidence_ids) != expected_v2_evidence
        or mapping_receipts[0].evidence_ids != tuple(sorted(expected_mapping_ids))
    ):
        raise ValueError("failed-closed hold is not derived from complete material drift evidence")
    mapping_gate_id = mapping_receipts[0].produced_gate_id
    if mapping_gate_id is None or gates[mapping_gate_id].evidence_ids != tuple(
        sorted(expected_mapping_ids)
    ):
        raise ValueError("failed-closed batch mapping gate differs from typed commitments")

    expected_explanations: dict[tuple[str, str | None], frozenset[str]] = {
        ("batch_held", None): frozenset({"batch_hold_required"}),
        **{
            ("record_degraded", candidate_id): frozenset(reasons)
            for candidate_id, reasons in drift_reasons_by_candidate.items()
        },
    }
    observed_explanations = {
        (item.template, item.candidate_id): frozenset(item.reason_codes)
        for item in projection.explanations
    }
    if observed_explanations != expected_explanations:
        raise ValueError("failed-closed drift explanations differ from the proven hold state")


def _validate_unreleased_record_inventory(
    projection: DecisionProjectionV22,
    *,
    candidate_id: str,
    gates: Mapping[str, TrustGateV22],
    catalog_ids: set[str],
) -> tuple[str, set[str], set[str]]:
    """Validate one graph-free candidate chain retained by a terminal hold."""

    by_stage: dict[str, TrustGateV22] = {}
    for stage in (
        "identity",
        "mapping",
        "provenance",
        "timeline",
        "cross_source",
        "candidate_validation",
    ):
        matching = tuple(
            gate
            for gate in projection.trust_gates
            if gate.scope == "record" and gate.stage == stage and gate.candidate_id == candidate_id
        )
        if len(matching) != 1:
            raise ValueError("failed-closed candidate lacks one exact retained record lineage")
        by_stage[stage] = matching[0]
    identity = by_stage["identity"]
    mapping = by_stage["mapping"]
    provenance = by_stage["provenance"]
    timeline = by_stage["timeline"]
    cross_source = by_stage["cross_source"]
    terminal_gate = by_stage["candidate_validation"]
    if (
        provenance.input_gate_ids != (mapping.gate_id,)
        or timeline.input_gate_ids != (provenance.gate_id,)
        or cross_source.input_gate_ids != (timeline.gate_id,)
        or terminal_gate.input_gate_ids != (cross_source.gate_id,)
        or identity.state != "USABLE"
        or identity.outcome != "ALLOW"
        or identity.reason_codes != ("document_identity_valid",)
        or not identity.evidence_ids
        or mapping.state != "USABLE"
        or mapping.outcome != "ALLOW"
        or mapping.reason_codes != ("mapper_output_valid",)
        or mapping.evidence_ids != provenance.evidence_ids
        or provenance.state != "USABLE"
        or provenance.outcome != "ALLOW"
        or provenance.reason_codes != ("evidence_admissible",)
    ):
        raise ValueError("failed-closed candidate has an invalid record gate chain")

    mapped = mapping.evidence_inventory
    consumed = provenance.evidence_inventory
    final = terminal_gate.evidence_inventory
    if mapped is None or consumed is None or final is None or mapped != consumed:
        raise ValueError("failed-closed candidate lacks its exact disposition inventories")
    if (
        consumed.candidate_id != candidate_id
        or consumed.snapshot_id != projection.snapshot_id
        or final.candidate_id != consumed.candidate_id
        or final.snapshot_id != consumed.snapshot_id
        or final.structured_anchors != consumed.structured_anchors
        or final.record_ap_years_reference != consumed.record_ap_years_reference
        or final.record_invoice_processing_reference != consumed.record_invoice_processing_reference
        or final.record_ap_years != consumed.record_ap_years
        or final.record_invoice_processing is not consumed.record_invoice_processing
    ):
        raise ValueError("failed-closed disposition inventory escapes its record lineage")
    consumed_by_id, intervals = _validate_preconsumption_inventory_v22(
        consumed,
        candidate_id=candidate_id,
        snapshot_id=projection.snapshot_id,
        gate_evidence_ids=provenance.evidence_ids,
        catalog_ids=catalog_ids,
    )
    final_by_id = {item.reference.evidence_id: item for item in final.entries}
    if (
        len(consumed_by_id) != len(consumed.entries)
        or len(final_by_id) != len(final.entries)
        or set(consumed_by_id) != set(final_by_id)
        or set(provenance.evidence_ids) != set(consumed_by_id)
        or len(provenance.evidence_ids) != len(consumed_by_id)
        or not set(consumed_by_id).issubset(catalog_ids)
    ):
        raise ValueError("failed-closed dispositions do not partition mapped evidence exactly")
    for evidence_id, consumed_item in consumed_by_id.items():
        final_item = final_by_id[evidence_id]
        if (
            consumed_item.state != "consumed"
            or final_item.state == "consumed"
            or consumed_item.claim_kind != final_item.claim_kind
            or consumed_item.reference != final_item.reference
            or consumed_item.date_value != final_item.date_value
            or consumed_item.mapped_value != final_item.mapped_value
        ):
            raise ValueError("failed-closed terminal disposition rewrites consumed evidence")

    cross_derivation = _validate_cross_source_evidence_closure_v22(
        consumed,
        cross_source=cross_source,
        catalog_ids=catalog_ids,
        terminal_inventory=final,
    )

    timeline_reason = _expected_timeline_reason_v22(
        intervals,
        record_ap_years=consumed.record_ap_years,
        record_invoice_processing=consumed.record_invoice_processing,
    )
    if timeline_reason not in {"timeline_valid", "timeline_drift"}:
        raise ValueError("failed-closed drift hold contains an unrelated timeline condition")
    interval_ids = tuple(
        sorted(
            item.reference.evidence_id
            for item in consumed.entries
            if item.claim_kind == "employment_interval"
        )
    )
    expected_timeline_state = "USABLE" if timeline_reason == "timeline_valid" else "DEGRADED"
    expected_timeline_outcome = "ALLOW" if timeline_reason == "timeline_valid" else "RESTRICT"
    if (
        timeline.reason_codes != (timeline_reason,)
        or timeline.state != expected_timeline_state
        or timeline.outcome != expected_timeline_outcome
        or timeline.evidence_ids != interval_ids
    ):
        raise ValueError("failed-closed timeline marker was not derived from typed endpoints")

    category_drop = False
    for evidence_id, item in final_by_id.items():
        if item.claim_kind in CATEGORICAL_ALLOW_LISTS_V22:
            unsupported = item.claim_kind in cross_derivation.unsupported_category_kinds
            expected_state = "dropped_unsupported_category" if unsupported else "released"
            category_drop = category_drop or unsupported
        else:
            expected_state = "released"
        if item.state != expected_state:
            raise ValueError("failed-closed disposition state was not independently derived")
        stage_ids = (
            set(timeline.evidence_ids)
            if item.claim_kind == "employment_interval"
            else set(cross_source.evidence_ids)
        )
        if evidence_id not in stage_ids:
            raise ValueError("failed-closed disposition lacks its evaluation-stage evidence")

    if cross_derivation.state != "USABLE" or category_drop is not bool(
        cross_derivation.unsupported_category_kinds
    ):
        raise ValueError("failed-closed cross-source state differs from derived dispositions")
    expected_terminal_state = "USABLE" if timeline_reason == "timeline_valid" else "DEGRADED"
    expected_terminal_outcome = "ALLOW" if timeline_reason == "timeline_valid" else "RESTRICT"
    expected_terminal_reasons = {
        *cross_derivation.terminal_reason_codes,
        "evidence_admissible",
        timeline_reason,
    }
    released_terminal_evidence: set[str] = set()
    for item in final.entries:
        if item.state != "released":
            continue
        released_terminal_evidence.add(item.reference.evidence_id)
        if item.claim_kind != "employment_interval":
            structured = next(
                anchor
                for anchor in consumed.structured_anchors
                if anchor.claim_kind == item.claim_kind
            )
            released_terminal_evidence.add(structured.reference.evidence_id)
    expected_terminal_evidence = set(identity.evidence_ids).union(released_terminal_evidence)
    if (
        terminal_gate.state != expected_terminal_state
        or terminal_gate.outcome != expected_terminal_outcome
        or set(terminal_gate.reason_codes) != expected_terminal_reasons
        or set(terminal_gate.evidence_ids) != expected_terminal_evidence
        or len(terminal_gate.evidence_ids) != len(expected_terminal_evidence)
        or not expected_terminal_evidence.issubset(catalog_ids)
    ):
        raise ValueError("failed-closed terminal record state is not its exact evidence closure")
    mapping_ids = {
        *consumed_by_id,
        *(anchor.reference.evidence_id for anchor in consumed.structured_anchors),
    }
    return timeline_reason, expected_terminal_evidence, mapping_ids


def _disposition_intervals_v22(
    inventory: EvidenceDispositionInventoryV22,
) -> tuple[SupportedEmploymentIntervalV22, ...]:
    """Pair the bounded endpoint multisets exactly as the documented policy does."""

    items = tuple(item for item in inventory.entries if item.claim_kind == "employment_interval")
    starts = sorted(
        (
            item
            for item in items
            if _field_role(item.reference.field_path) == "employment_start"
            and item.date_value is not None
        ),
        key=lambda item: (cast(date, item.date_value), item.reference.evidence_id),
    )
    ends = sorted(
        (
            item
            for item in items
            if _field_role(item.reference.field_path) == "employment_end"
            and item.date_value is not None
        ),
        key=lambda item: (cast(date, item.date_value), item.reference.evidence_id),
    )
    if len(starts) + len(ends) != len(items) or len(starts) != len(ends):
        raise ValueError("employment dispositions do not form complete endpoint pairs")
    return tuple(
        SupportedEmploymentIntervalV22(
            start_date=cast(date, start.date_value),
            end_date=cast(date, end.date_value),
            start_evidence_id=start.reference.evidence_id,
            end_evidence_id=end.reference.evidence_id,
        )
        for start, end in zip(starts, ends, strict=True)
    )


def _expected_timeline_reason_v22(
    intervals: Sequence[SupportedEmploymentIntervalV22],
    *,
    record_ap_years: float,
    record_invoice_processing: bool,
) -> str:
    """Recompute the bounded runtime timeline policy without importing it."""

    if not record_invoice_processing and not intervals:
        return "timeline_valid"
    if not intervals:
        return "timeline_unavailable"
    total_years = _merged_interval_days(intervals) / 365.2425
    if total_years + 0.35 < record_ap_years:
        return "timeline_conflict"
    if total_years > record_ap_years + 0.75:
        return "timeline_drift"
    return "timeline_valid"


def _validate_route_reason_semantics(
    projection: DecisionProjectionV22,
    *,
    gates: Mapping[str, TrustGateV22],
) -> None:
    """Derive route reasons from the strategy or terminal candidate decision."""

    terminal_by_candidate = {
        cast(str, gate.candidate_id): gate
        for gate in gates.values()
        if gate.scope == "record" and gate.stage == "candidate_validation"
    }
    ranked_reasons = {"cross_source_match", "evidence_admissible", "timeline_valid"}
    for route in projection.routes:
        observed = set(route.reason_codes)
        if projection.strategy == "BATCH_INTEGRITY_HOLD":
            expected = {"batch_hold_required"}
        elif route.rank_key is not None:
            expected = ranked_reasons
        else:
            terminal = terminal_by_candidate.get(route.candidate_id)
            if terminal is None:
                raise ValueError("unranked route lacks a terminal candidate decision")
            expected = set(terminal.reason_codes)
        if observed != expected:
            raise ValueError("route reasons are not derived from the validated release state")


def _validate_trust_causality(
    projection: DecisionProjectionV22,
    *,
    gates: Mapping[str, TrustGateV22],
    receipt_pairs: Mapping[tuple[int, str], list[ReceiptV22]],
) -> None:
    """Verify the trust ledger's bounded stage graph and terminal release leaf."""

    if not projection.trust_gates:
        raise ValueError("release projection requires a trust ledger")
    roots = [gate for gate in projection.trust_gates if not gate.input_gate_ids]
    if len(roots) != 1 or roots[0] != projection.trust_gates[0] or roots[0].scope != "batch":
        raise ValueError("trust ledger requires exactly one leading batch root")
    if roots[0].stage not in {"retrieval", "schema", "manifest", "planning"}:
        raise ValueError("trust ledger root uses an impossible stage")
    known_candidates = {route.candidate_id for route in projection.routes}
    if any(
        gate.candidate_id is not None and gate.candidate_id not in known_candidates
        for gate in projection.trust_gates
    ):
        raise ValueError("trust ledger references an unknown candidate")

    record_gates_by_candidate: dict[str, list[TrustGateV22]] = {}
    for gate in projection.trust_gates:
        parents = [gates[parent_id] for parent_id in gate.input_gate_ids]
        if gate.scope == "record":
            assert gate.candidate_id is not None
            record_gates_by_candidate.setdefault(gate.candidate_id, []).append(gate)
            record_parents = [item for item in parents if item.scope == "record"]
            if any(item.candidate_id != gate.candidate_id for item in record_parents):
                raise ValueError("record gate contains cross-candidate parentage")
            if len(record_parents) > 1:
                raise ValueError("record validation stages require a single record lineage")
            expected_parent_stage: Mapping[str, frozenset[str]] = {
                "retrieval": frozenset(),
                "schema": frozenset({"retrieval"}),
                "identity": frozenset({"parsing"}),
                "revision": frozenset({"identity"}),
                "manifest": frozenset({"revision"}),
                "parsing": frozenset({"retrieval", "schema", "manifest"}),
                "mapping": frozenset({"parsing"}),
                "provenance": frozenset({"mapping"}),
                "timeline": frozenset({"provenance"}),
                "cross_source": frozenset({"timeline"}),
                "candidate_validation": frozenset(
                    {
                        "retrieval",
                        "schema",
                        "identity",
                        "revision",
                        "manifest",
                        "parsing",
                        "mapping",
                        "provenance",
                        "timeline",
                        "cross_source",
                    }
                ),
            }
            if gate.stage not in expected_parent_stage:
                raise ValueError("record gate uses an impossible validation stage")
            record_parent_stages = {item.stage for item in record_parents}
            if record_parents and not record_parent_stages.issubset(
                expected_parent_stage[gate.stage]
            ):
                raise ValueError("record gate splices incompatible validation stages")
            if not record_parents and gate.stage not in {
                "retrieval",
                "schema",
                "parsing",
                "identity",
                "mapping",
            }:
                raise ValueError("record validation branch starts at an impossible stage")
        else:
            record_parents = [item for item in parents if item.scope == "record"]
            if record_parents and gate.stage not in {"identity", "provenance"}:
                raise ValueError("batch gate contains an unauthorized record fan-in")
            if len({item.candidate_id for item in record_parents}) != len(record_parents):
                raise ValueError("batch fan-in repeats a candidate lineage")

    produced_gate_ids = {
        pair[1].produced_gate_id for pair in receipt_pairs.values() if pair[1].status == "completed"
    }
    for gate in projection.trust_gates:
        if gate.scope != "batch" or gate.gate_id in produced_gate_ids:
            continue
        batch_parents = [
            gates[item] for item in gate.input_gate_ids if gates[item].scope == "batch"
        ]
        if gate is roots[0]:
            continue
        allowed_batch_parents: Mapping[str, frozenset[str]] = {
            "schema": frozenset({"retrieval"}),
            "manifest": frozenset({"schema"}),
            "planning": frozenset({"retrieval", "schema", "manifest", "provenance", "pre_release"}),
            "pre_release": frozenset({"planning", "provenance"}),
        }
        if (
            gate.stage not in allowed_batch_parents
            or len(batch_parents) != 1
            or batch_parents[0].stage not in allowed_batch_parents[gate.stage]
        ):
            raise ValueError("unreceipted batch gate splices incompatible stages")
        if gate.stage == "planning" and not set(gate.reason_codes) & {
            "plan_selected",
            "plan_revised",
            "pre_release_blocked",
        }:
            raise ValueError("unreceipted planning gate lacks a bounded planning reason")

    expected_stage_for_command: Mapping[str, str] = {
        "fetch_candidate_details": "retrieval",
        "validate_candidate_details": "schema",
        "fetch_candidate_resumes": "retrieval",
        "parse_candidate_resumes": "parsing",
        "validate_candidate_bindings": "identity",
        "map_candidate_claims": "mapping",
        "validate_candidate_evidence": "provenance",
        "validate_index_commitments": "manifest",
        "rank_full_evidence": "ranking",
        "rank_supported_evidence": "ranking",
        "rank_partial_evidence": "ranking",
        "quarantine_unsupported": "provenance",
        "mark_evidence_pending": "retrieval",
        "isolate_batch": "ranking",
        "request_corroboration": "planning",
        "pre_release_audit": "pre_release",
        "release_output": "release",
    }
    produced_receipts = [
        pair[1] for pair in receipt_pairs.values() if pair[1].status == "completed"
    ]
    for receipt in produced_receipts:
        assert receipt.produced_gate_id is not None
        expected_stage = expected_stage_for_command.get(receipt.command_kind)
        if expected_stage is None or gates[receipt.produced_gate_id].stage != expected_stage:
            raise ValueError("receipt-produced gate uses the wrong workflow stage")

    for fan_in_stage, command_kind in (
        ("identity", "validate_candidate_bindings"),
        ("provenance", "validate_candidate_evidence"),
    ):
        matching = [
            receipt for receipt in produced_receipts if receipt.command_kind == command_kind
        ]
        if not matching:
            continue
        terminal_receipt = matching[-1]
        assert terminal_receipt.produced_gate_id is not None
        fan_in_gate = gates[terminal_receipt.produced_gate_id]
        if fan_in_gate.stage != fan_in_stage:
            raise ValueError("candidate terminal fan-in uses the wrong batch stage")
        record_parents = [
            gates[item] for item in fan_in_gate.input_gate_ids if gates[item].scope == "record"
        ]
        expected_candidates = set(record_gates_by_candidate)
        if {item.candidate_id for item in record_parents} != expected_candidates:
            raise ValueError("candidate terminal fan-in does not cover every record lineage")
        for parent in record_parents:
            assert parent.candidate_id is not None
            candidate_lineage = record_gates_by_candidate[parent.candidate_id]
            if command_kind == "validate_candidate_bindings":
                permitted_terminal_stages = {
                    "retrieval",
                    "schema",
                    "identity",
                    "manifest",
                    "revision",
                    "parsing",
                }
                terminal_candidates = [
                    item
                    for item in candidate_lineage
                    if item.stage in permitted_terminal_stages
                    and item.gate_id in fan_in_gate.input_gate_ids
                ]
                valid_terminal = (
                    parent.stage in permitted_terminal_stages and terminal_candidates == [parent]
                )
            else:
                valid_terminal = (
                    parent.stage == "candidate_validation"
                    and sum(item.stage == "candidate_validation" for item in candidate_lineage) == 1
                )
            if not valid_terminal:
                raise ValueError("candidate fan-in does not use its required terminal stage")
        if command_kind == "validate_candidate_evidence" and [
            cast(str, item.candidate_id) for item in record_parents
        ] != sorted(cast(str, item.candidate_id) for item in record_parents):
            raise ValueError("candidate validation fan-in is not identity ordered")

    release_receipts = [item for item in produced_receipts if item.command_kind == "release_output"]
    if len(release_receipts) != 1:
        raise ValueError("release projection requires exactly one completed release command")
    release_receipt = release_receipts[0]
    assert release_receipt.produced_gate_id is not None
    release_gate = gates[release_receipt.produced_gate_id]
    pre_release_receipts = [
        item for item in produced_receipts if item.command_kind == "pre_release_audit"
    ]
    if len(pre_release_receipts) != 1:
        raise ValueError("release projection requires exactly one completed pre-release audit")
    pre_release_receipt = pre_release_receipts[0]
    assert pre_release_receipt.produced_gate_id is not None
    pre_release_gate = gates[pre_release_receipt.produced_gate_id]
    if (
        pre_release_gate.state != "USABLE"
        or pre_release_gate.outcome != "ALLOW"
        or set(pre_release_gate.reason_codes) != {"release_authorized", "support_graph_valid"}
    ):
        raise ValueError("pre-release gate polarity does not authorize the released output")
    if (
        release_gate.state != "USABLE"
        or release_gate.outcome != "ALLOW"
        or set(release_gate.reason_codes) != {"release_authorized"}
    ):
        raise ValueError("terminal release gate polarity does not authorize output")
    referenced_as_parent = {
        parent for gate in projection.trust_gates for parent in gate.input_gate_ids
    }
    if (
        release_gate.stage != "release"
        or release_gate.gate_id in referenced_as_parent
        or release_gate != projection.trust_gates[-1]
    ):
        raise ValueError("released output is not the terminal trust-ledger leaf")


def _validate_corroboration_semantics(
    projection: DecisionProjectionV22,
    *,
    terminal: Mapping[tuple[int, str], str],
    gates: Mapping[str, TrustGateV22],
) -> None:
    completed_command_kinds = {
        command.kind
        for plan in projection.plans
        for command in plan.commands
        if terminal.get((plan.version, command.command_id)) == "completed"
    }
    request_completed = "request_corroboration" in completed_command_kinds
    if request_completed is not (len(projection.corroboration_requests) == 1):
        raise ValueError("corroboration artifact does not match executed commands")
    if projection.strategy in {"FULL_EVIDENCE_RANKING", "SUPPORTED_ONLY_RANKING"}:
        if projection.corroboration_requests:
            raise ValueError("complete/supported-only ranking cannot request corroboration")
        return
    if not projection.corroboration_requests:
        raise ValueError("partial or held release requires a corroboration request")
    request = projection.corroboration_requests[0]
    if set(request.reason_codes) != {"corroboration_required"} or set(
        request.requested_evidence_kinds
    ) != {"candidate_id", "ap_years"}:
        raise ValueError("corroboration request is outside the bounded policy")
    if projection.strategy == "PARTIAL_SAFE_RANKING":
        expected_candidates = {
            route.candidate_id
            for route in projection.routes
            if route.band == "EVIDENCE_UNAVAILABLE"
        }
    else:
        expected_candidates = {
            cast(str, gate.candidate_id)
            for gate in gates.values()
            if gate.stage == "candidate_validation" and gate.state in {"QUARANTINED", "UNAVAILABLE"}
        }
        if (
            projection.execution_mode != "FAILED_CLOSED"
            and not expected_candidates
            and any(
                gate.scope == "batch"
                and gate.stage in {"retrieval", "schema", "manifest", "pre_release"}
                and gate.outcome in {"QUARANTINE", "UNAVAILABLE", "HOLD"}
                for gate in gates.values()
            )
        ):
            expected_candidates = {route.candidate_id for route in projection.routes}
    if set(request.candidate_ids) != expected_candidates:
        raise ValueError("corroboration candidates do not match affected evidence")


def _validate_plan_triggers(projection: DecisionProjectionV22) -> None:
    allowed_trigger_vocabulary = {
        "index_valid",
        "manifest_conflict",
        "index_conflict",
        "candidate_unavailable",
        "mapper_disagreement",
        "evidence_admissible",
        "pre_release_blocked",
        "retrieval_failed",
        "schema_invalid",
        "parsing_failed",
        "document_identity_missing",
        "document_identity_conflict",
    }
    ledger_reasons = {reason for gate in projection.trust_gates for reason in gate.reason_codes}
    derived_reasons = set(ledger_reasons)
    if "manifest_valid" in ledger_reasons:
        derived_reasons.add("index_valid")
    if "manifest_conflict" in ledger_reasons:
        derived_reasons.add("index_conflict")
    if ledger_reasons & {
        "mapper_disagreement",
        "semantic_hash_conflict",
        "resume_hash_conflict",
        "revision_conflict",
        "cross_source_conflict",
        "timeline_conflict",
        "domain_invariant_conflict",
        "evidence_value_conflict",
        "document_identity_missing",
        "document_identity_conflict",
    }:
        derived_reasons.add("mapper_disagreement")
    for plan in projection.plans:
        if not set(plan.trigger_codes).issubset(allowed_trigger_vocabulary) or not set(
            plan.trigger_codes
        ).issubset(derived_reasons):
            raise ValueError("plan trigger is not derived from observed trust state")


def _validate_ranked_route_semantics(route: RouteV22) -> None:
    """Independently derive a ranked route from its bounded evidence graph."""

    graph = route.support_graph
    rank_key = route.rank_key
    if graph is None or rank_key is None:
        raise ValueError("ranked routes require support semantics")
    manifest = {item.evidence_id: item for item in graph.evidence_manifest}
    facts = {item.fact_id: item for item in graph.facts}
    features = {item.feature_id: item for item in graph.features}
    by_kind = {item.kind: item for item in graph.facts}
    by_name = {item.name: item for item in graph.features}
    if len(by_kind) != len(facts) or len(by_name) != len(features):
        raise ValueError("support facts and features require unique semantic roles")
    if any(
        item.source_kind not in {"application_json", "resume_visible"}
        or not item.visible
        or not item.admissible
        for item in manifest.values()
    ):
        raise ValueError("released support contains an inadmissible source role")
    identity = by_kind.get("candidate_id")
    if identity is None or identity.normalized_value != route.candidate_id:
        raise ValueError("support identity does not bind the ranked candidate")
    interval = by_kind.get("employment_interval")
    for fact in facts.values():
        _validate_fact_evidence_binding(
            fact,
            manifest,
            route.candidate_id,
            permitted_extra_evidence_ids=(
                set(interval.evidence_ids)
                if fact.kind == "ap_years" and interval is not None
                else set()
            ),
        )

    ap = by_kind.get("ap_years")
    ap_value: float | None = None
    if ap is not None:
        if not _bounded_number(ap.normalized_value, lower=0, upper=80):
            raise ValueError("AP-years fact is outside the bounded numeric contract")
        ap_value = float(cast(int | float, ap.normalized_value))
        if ap_value > 0 and interval is None:
            raise ValueError("positive AP years require independently dated support")
        if interval is not None:
            if not _bounded_number(interval.normalized_value, lower=0, upper=80):
                raise ValueError("employment duration is outside the bounded contract")
            interval_years = float(cast(int | float, interval.normalized_value))
            recomputed_years = round(
                _merged_interval_days(interval.employment_intervals) / 365.2425,
                4,
            )
            if interval_years != recomputed_years:
                raise ValueError("employment duration was not derived from its endpoints")
            if ap_value > interval_years + 0.35:
                raise ValueError("claimed AP years exceed dated support")

    for kind in ("invoice_processing", "reconciliation"):
        boolean_fact = by_kind.get(kind)
        if boolean_fact is not None and not isinstance(boolean_fact.normalized_value, bool):
            raise ValueError("boolean evidence fact has the wrong type")
    volume = by_kind.get("monthly_invoice_volume")
    invoice = by_kind.get("invoice_processing")
    if volume is not None:
        if not _bounded_number(volume.normalized_value, lower=0, upper=100_000_000):
            raise ValueError("monthly volume is outside the bounded numeric contract")
        if invoice is None or invoice.normalized_value is not True:
            raise ValueError("monthly volume requires supported invoice processing")

    essentials = sum(
        (
            invoice is not None and invoice.normalized_value is True,
            by_kind.get("reconciliation") is not None
            and by_kind["reconciliation"].normalized_value is True,
            "spreadsheet" in by_kind,
            "accounting_platform" in by_kind,
        )
    )
    preferred = sum(
        (
            ap_value is not None and ap_value >= 2.0,
            volume is not None and float(cast(int | float, volume.normalized_value)) >= 300,
            "qualification" in by_kind,
        )
    )
    corroborated = len(set(by_kind) - {"candidate_id"})
    if essentials == 4 and preferred > 0:
        band, queue, priority = (
            "STRONG_EVIDENCE_MATCH",
            "PRIORITY_HUMAN_REVIEW",
            2,
        )
    elif essentials == 3 or (essentials == 4 and preferred == 0):
        band, queue, priority = (
            "POTENTIAL_EVIDENCE_MATCH",
            "STANDARD_HUMAN_REVIEW",
            1,
        )
    else:
        band, queue, priority = (
            "INSUFFICIENT_SUPPORTED_EVIDENCE",
            "EVIDENCE_CHECK",
            0,
        )
    if (route.band, route.queue) != (band, queue) or rank_key.tuple() != (
        priority,
        essentials,
        preferred,
        corroborated,
    ):
        raise ValueError("released route was not derived from its supported facts")
    _validate_feature_semantics(
        graph,
        by_kind,
        by_name,
        essentials=essentials,
        preferred=preferred,
        corroborated=corroborated,
        priority=priority,
        band=band,
        queue=queue,
    )


def _validate_fact_evidence_binding(
    fact: SupportedFactV22,
    manifest: Mapping[str, EvidenceRefV22],
    candidate_id: str,
    permitted_extra_evidence_ids: set[str],
) -> None:
    references = tuple(manifest[item] for item in fact.evidence_ids)
    if set(fact.source_roles) != {item.source_kind for item in references}:
        raise ValueError("fact source roles do not match its evidence")
    if fact.kind == "employment_interval":
        endpoint_ids: set[str] = set()
        for interval in fact.employment_intervals:
            start = manifest[interval.start_evidence_id]
            end = manifest[interval.end_evidence_id]
            if (
                start.source_kind != "resume_visible"
                or end.source_kind != "resume_visible"
                or _field_role(start.field_path) != "employment_start"
                or _field_role(end.field_path) != "employment_end"
                or start.semantic_hash != _evidence_value_sha256(interval.start_date.isoformat())
                or end.semantic_hash != _evidence_value_sha256(interval.end_date.isoformat())
            ):
                raise ValueError("employment interval endpoints do not match evidence hashes")
            endpoint_ids.update((interval.start_evidence_id, interval.end_evidence_id))
        if endpoint_ids != set(fact.evidence_ids):
            raise ValueError("employment interval contains unrelated evidence")
        return
    if fact.employment_intervals:
        raise ValueError("scalar facts cannot contain employment intervals")
    scalar_references = tuple(
        item for item in references if _field_role(item.field_path) == fact.kind
    )
    extra_ids = {item.evidence_id for item in references} - {
        item.evidence_id for item in scalar_references
    }
    if extra_ids != permitted_extra_evidence_ids:
        raise ValueError("fact evidence uses the wrong semantic field")
    if {item.source_kind for item in scalar_references} != {
        "application_json",
        "resume_visible",
    }:
        raise ValueError("scalar facts require structured and visible résumé support")
    if fact.kind == "candidate_id":
        expected_value: object = candidate_id
    elif fact.kind in {
        "ap_years",
        "invoice_processing",
        "reconciliation",
        "monthly_invoice_volume",
    }:
        expected_value = fact.normalized_value
        if fact.kind == "monthly_invoice_volume" and isinstance(expected_value, float):
            expected_value = int(expected_value) if expected_value.is_integer() else expected_value
    elif fact.kind in CATEGORICAL_ALLOW_LISTS_V22:
        if fact.source_value is None:
            raise ValueError("categorical fact has no source value")
        expected_value = fact.source_value
    else:
        raise ValueError("fact kind has no evidence-binding rule")
    expected_hash = _evidence_value_sha256(expected_value)
    structured_references = tuple(
        item for item in scalar_references if item.source_kind == "application_json"
    )
    visible_references = tuple(
        item for item in scalar_references if item.source_kind == "resume_visible"
    )
    if (
        len(structured_references) != 1
        or not visible_references
        or structured_references[0].semantic_hash != expected_hash
        or (
            fact.kind == "candidate_id"
            and any(item.semantic_hash != expected_hash for item in visible_references)
        )
    ):
        raise ValueError("fact value does not match its evidence hashes")


def _validate_feature_semantics(
    graph: SupportGraphV22,
    by_kind: Mapping[str, SupportedFactV22],
    by_name: Mapping[str, DerivedFeatureV22],
    *,
    essentials: int,
    preferred: int,
    corroborated: int,
    priority: int,
    band: str,
    queue: str,
) -> None:
    optional_names: list[str] = []
    direct_fact_features = {
        "essential_invoice_processing": "invoice_processing",
        "essential_reconciliation": "reconciliation",
        "essential_spreadsheet": "spreadsheet",
        "essential_accounting_platform": "accounting_platform",
        "preferred_qualification": "qualification",
    }
    direct_values = {
        "essential_invoice_processing": (
            by_kind.get("invoice_processing") is not None
            and by_kind["invoice_processing"].normalized_value is True
        ),
        "essential_reconciliation": (
            by_kind.get("reconciliation") is not None
            and by_kind["reconciliation"].normalized_value is True
        ),
        "essential_spreadsheet": "spreadsheet" in by_kind,
        "essential_accounting_platform": "accounting_platform" in by_kind,
        "preferred_qualification": "qualification" in by_kind,
    }
    for name, kind in direct_fact_features.items():
        feature = by_name.get(name)
        fact = by_kind.get(kind)
        if (feature is None) is (fact is not None):
            raise ValueError("fact-derived feature presence is inconsistent")
        if feature is not None and fact is not None:
            if (
                feature.normalized_value is not direct_values[name]
                or set(feature.dependency_fact_ids) != {fact.fact_id}
                or feature.dependency_feature_ids
            ):
                raise ValueError("fact-derived feature has invalid value or topology")
            optional_names.append(name)

    ap = by_kind.get("ap_years")
    interval = by_kind.get("employment_interval")
    ap_feature = by_name.get("preferred_ap_years")
    expects_ap = ap is not None and (
        interval is not None or float(cast(int | float, ap.normalized_value or 0)) == 0
    )
    if (ap_feature is not None) is not expects_ap:
        raise ValueError("AP threshold feature presence is inconsistent")
    if ap_feature is not None and ap is not None:
        expected_facts = (ap.fact_id, interval.fact_id) if interval is not None else (ap.fact_id,)
        if (
            ap_feature.normalized_value
            is not (float(cast(int | float, ap.normalized_value)) >= 2.0)
            or set(ap_feature.dependency_fact_ids) != set(expected_facts)
            or ap_feature.dependency_feature_ids
        ):
            raise ValueError("AP threshold feature is not evidence-derived")
        optional_names.append("preferred_ap_years")

    volume = by_kind.get("monthly_invoice_volume")
    invoice = by_kind.get("invoice_processing")
    volume_feature = by_name.get("preferred_volume")
    expects_volume = volume is not None and invoice is not None
    if (volume_feature is not None) is not expects_volume:
        raise ValueError("volume threshold feature presence is inconsistent")
    if volume_feature is not None and volume is not None and invoice is not None:
        expected_value = (
            invoice.normalized_value is True
            and float(cast(int | float, volume.normalized_value)) >= 300
        )
        if (
            volume_feature.normalized_value is not expected_value
            or set(volume_feature.dependency_fact_ids) != {invoice.fact_id, volume.fact_id}
            or volume_feature.dependency_feature_ids
        ):
            raise ValueError("volume threshold feature is not evidence-derived")
        optional_names.append("preferred_volume")

    fixed_names = {
        "essentials_count",
        "preferred_count",
        "corroborated_count",
        "band",
        "rank_band_priority",
        "rank_essentials",
        "rank_preferred",
        "rank_corroborated",
        "rank_key",
        "queue",
        "route",
    }
    if set(by_name) != fixed_names | set(optional_names):
        raise ValueError("support graph contains missing or unrecognized feature semantics")
    required_values: Mapping[str, JsonScalar] = {
        "essentials_count": essentials,
        "preferred_count": preferred,
        "corroborated_count": corroborated,
        "rank_band_priority": priority,
        "rank_essentials": essentials,
        "rank_preferred": preferred,
        "rank_corroborated": corroborated,
        "rank_key": f"{priority}-{essentials}-{preferred}-{corroborated}",
        "band": band,
        "queue": queue,
        "route": "human_review_route",
    }
    if any(by_name[name].normalized_value != value for name, value in required_values.items()):
        raise ValueError("derived feature values do not match the evidence reduction")

    def feature_ids(names: Sequence[str]) -> tuple[str, ...]:
        return tuple(by_name[name].feature_id for name in names if name in by_name)

    identity = by_kind["candidate_id"]
    expected_dependencies: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
        "essentials_count": (
            (identity.fact_id,),
            feature_ids(
                (
                    "essential_invoice_processing",
                    "essential_reconciliation",
                    "essential_spreadsheet",
                    "essential_accounting_platform",
                )
            ),
        ),
        "preferred_count": (
            (identity.fact_id,),
            feature_ids(("preferred_ap_years", "preferred_volume", "preferred_qualification")),
        ),
        "corroborated_count": (tuple(item.fact_id for item in graph.facts), ()),
        "band": ((), feature_ids(("essentials_count", "preferred_count"))),
        "rank_band_priority": ((), feature_ids(("band",))),
        "rank_essentials": ((), feature_ids(("essentials_count",))),
        "rank_preferred": ((), feature_ids(("preferred_count",))),
        "rank_corroborated": ((), feature_ids(("corroborated_count",))),
        "rank_key": (
            (),
            feature_ids(
                (
                    "rank_band_priority",
                    "rank_essentials",
                    "rank_preferred",
                    "rank_corroborated",
                )
            ),
        ),
        "queue": ((), feature_ids(("band",))),
        "route": ((), feature_ids(("rank_key", "band", "queue"))),
    }
    if any(
        set(by_name[name].dependency_fact_ids) != set(fact_ids)
        or set(by_name[name].dependency_feature_ids) != set(feature_ids_value)
        for name, (fact_ids, feature_ids_value) in expected_dependencies.items()
    ):
        raise ValueError("derived feature topology does not match the bounded reducer")
    if graph.route_support_ids != (by_name["route"].feature_id,):
        raise ValueError("route support does not terminate at the route feature")
    used_fact_ids: set[str] = set()
    visited: set[str] = set()

    def visit(feature_id: str) -> None:
        if feature_id in visited:
            return
        feature = next(item for item in graph.features if item.feature_id == feature_id)
        used_fact_ids.update(feature.dependency_fact_ids)
        for dependency in feature.dependency_feature_ids:
            visit(dependency)
        visited.add(feature_id)

    visit(graph.route_support_ids[0])
    if used_fact_ids != {item.fact_id for item in graph.facts}:
        raise ValueError("route feature closure does not consume every supported fact")
    evidence_closure = {
        evidence_id
        for fact in graph.facts
        if fact.fact_id in used_fact_ids
        for evidence_id in fact.evidence_ids
    }
    if evidence_closure != set(graph.evidence_ids):
        raise ValueError("route feature closure does not consume every evidence reference")


def _field_role(field_path: str | None) -> str | None:
    return None if field_path is None else field_path.rsplit(".", maxsplit=1)[-1]


def _evidence_value_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _bounded_number(value: object, *, lower: float, upper: float) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and lower <= float(value) <= upper
    )


def _merged_interval_days(
    intervals: Sequence[SupportedEmploymentIntervalV22],
) -> int:
    ordered = sorted((item.start_date, item.end_date) for item in intervals)
    if not ordered:
        return 0
    total = 0
    current_start, current_end = ordered[0]
    for start, end in ordered[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            total += (current_end - current_start).days
            current_start, current_end = start, end
    return total + (current_end - current_start).days


def canonical_json_bytes(value: object) -> bytes:
    _validate_json_value(value, depth=0)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def load_strict_json_object(path: Path, *, maximum_bytes: int) -> JsonObject:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseSpecV22Error("V2.2 release input could not be read") from exc
    return decode_strict_json_object_v22(raw, maximum_bytes=maximum_bytes)


def decode_strict_json_object_v22(raw: bytes, *, maximum_bytes: int) -> JsonObject:
    """Decode one bounded JSON object while rejecting duplicates and non-finite constants."""

    if not raw or len(raw) > maximum_bytes:
        raise ReleaseSpecV22Error("V2.2 release input has an invalid byte length")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ReleaseSpecV22Error) as exc:
        raise ReleaseSpecV22Error("V2.2 release input is not strict JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReleaseSpecV22Error("V2.2 release input must be an object")
    return cast(JsonObject, value)


def implementation_tree_sha256_v22(paths: Sequence[Path], *, repository_root: Path) -> str:
    """Hash the exact current implementation tree without importing V1 evidence code."""

    root = repository_root.resolve()
    entries: list[JsonObject] = []
    files: list[Path] = []
    for raw in paths:
        selected = raw.resolve()
        if selected != root and root not in selected.parents:
            raise ReleaseSpecV22Error("implementation path escapes the repository")
        if selected.is_dir():
            files.extend(
                path
                for path in selected.rglob("*")
                if path.is_file()
                and "__pycache__" not in path.parts
                and not path.name.endswith((".pyc", ".pyo"))
            )
        elif selected.is_file():
            files.append(selected)
        else:
            raise ReleaseSpecV22Error("implementation path is missing")
    for path in sorted(set(files), key=lambda item: item.relative_to(root).as_posix()):
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return hashlib.sha256(IMPLEMENTATION_TREE_DOMAIN + canonical_json_bytes(entries)).hexdigest()


def release_implementation_paths_v22(repository_root: Path) -> tuple[Path, ...]:
    """Return the exact V2.2 code, evaluator, experiment, and property-gate roots."""

    return (
        repository_root / "src",
        repository_root / "evaluation",
        repository_root / "experiments",
        repository_root / "tests",
        repository_root / "pyproject.toml",
        repository_root / "uv.lock",
    )


def _project_runtime_observation(observation: Mapping[str, object]) -> JsonObject:
    raw = deepcopy(dict(observation))
    plans = _objects(raw.get("plans"), "plans", maximum=3)
    final_plan_raw = _object(raw.get("plan"), "plan")
    if not plans or plans[-1] != final_plan_raw:
        raise ReleaseSpecV22Error("runtime final plan is absent from its plan history")

    command_aliases: dict[tuple[int, str], str] = {}
    for raw_plan in plans:
        version = _int(raw_plan.get("version"), "plan version")
        commands = _objects(raw_plan.get("commands"), "commands", maximum=64)
        for index, command in enumerate(commands, start=1):
            command_id = _string(command.get("command_id"), "command ID")
            kind = _string(command.get("kind"), "command kind")
            command_aliases[(version, command_id)] = f"p{version}:c{index}:{kind}"

    gate_aliases: dict[str, str] = {}
    ledger = _objects(raw.get("trust_ledger"), "trust ledger", maximum=1_024)
    for index, decision in enumerate(ledger, start=1):
        gate_aliases[_string(decision.get("decision_id"), "decision ID")] = f"g{index:04d}"

    projected_plans: list[JsonObject] = []
    for raw_plan in plans:
        version = _int(raw_plan.get("version"), "plan version")
        projected_commands: list[JsonObject] = []
        for command in _objects(raw_plan.get("commands"), "commands", maximum=64):
            original = _string(command.get("command_id"), "command ID")
            projected_commands.append(
                {
                    "command_id": command_aliases[(version, original)],
                    "kind": command.get("kind"),
                    "scope": command.get("scope"),
                    "candidate_id": command.get("candidate_id"),
                    "dependency_ids": [
                        _command_alias(command_aliases, version, item)
                        for item in _strings(command.get("dependency_ids", []), "dependencies")
                    ],
                }
            )
        projected_plans.append(
            {
                "version": version,
                "objective": raw_plan.get("objective"),
                "strategy": raw_plan.get("strategy"),
                "commands": projected_commands,
                "trigger_codes": raw_plan.get("trigger_codes", []),
                "allowed_evidence_ids": raw_plan.get("allowed_evidence_ids", []),
                "prohibited_actions": raw_plan.get("prohibited_actions", []),
            }
        )

    projected_diff: JsonObject | None = None
    if raw.get("plan_diff") is not None:
        diff = _object(raw.get("plan_diff"), "plan diff")
        from_version = _int(diff.get("from_version"), "from version")
        to_version = _int(diff.get("to_version"), "to version")
        added: list[JsonObject] = []
        for command in _objects(diff.get("added_commands", []), "added commands", maximum=64):
            original = _string(command.get("command_id"), "added command ID")
            added.append(
                {
                    "command_id": _command_alias(command_aliases, to_version, original),
                    "kind": command.get("kind"),
                    "scope": command.get("scope"),
                    "candidate_id": command.get("candidate_id"),
                    "dependency_ids": [
                        _command_alias(command_aliases, to_version, item)
                        for item in _strings(command.get("dependency_ids", []), "dependencies")
                    ],
                }
            )
        projected_diff = {
            "from_version": from_version,
            "to_version": to_version,
            "strategy_before": diff.get("strategy_before"),
            "strategy_after": diff.get("strategy_after"),
            "objective_before": diff.get("objective_before"),
            "objective_after": diff.get("objective_after"),
            "trigger_codes": diff.get("trigger_codes", []),
            "removed_command_ids": [
                _historical_command_alias(command_aliases, from_version, item)
                for item in _strings(diff.get("removed_command_ids", []), "removed commands")
            ],
            "added_commands": added,
            "revoked_evidence_ids": diff.get("revoked_evidence_ids", []),
            "granted_evidence_ids": diff.get("granted_evidence_ids", []),
            "added_prohibitions": diff.get("added_prohibitions", []),
        }

    receipts: list[JsonObject] = []
    for raw_receipt in _objects(raw.get("step_receipts"), "step receipts", maximum=512):
        version = _int(raw_receipt.get("plan_version"), "receipt plan version")
        original = _string(raw_receipt.get("command_id"), "receipt command ID")
        sequence = _int(raw_receipt.get("sequence"), "receipt sequence")
        receipts.append(
            {
                "receipt_id": f"r{sequence:04d}",
                "sequence": sequence,
                "plan_version": version,
                "command_id": _command_alias(command_aliases, version, original),
                "command_kind": raw_receipt.get("command_kind"),
                "status": raw_receipt.get("status"),
                "candidate_id": raw_receipt.get("candidate_id"),
                "reason_codes": raw_receipt.get("reason_codes", []),
                "evidence_ids": raw_receipt.get("evidence_ids", []),
                "produced_gate_id": _optional_gate_alias(
                    gate_aliases, raw_receipt.get("produced_gate_id")
                ),
                "consumed_gate_ids": [
                    _gate_alias(gate_aliases, item)
                    for item in _strings(
                        raw_receipt.get("consumed_gate_ids", []), "consumed gate IDs"
                    )
                ],
            }
        )

    projected_gates: list[JsonObject] = []
    for decision in ledger:
        original = _string(decision.get("decision_id"), "decision ID")
        projected_gates.append(
            {
                "gate_id": gate_aliases[original],
                "stage": decision.get("stage"),
                "scope": decision.get("scope"),
                "state": decision.get("state"),
                "outcome": decision.get("outcome"),
                "candidate_id": decision.get("candidate_id"),
                "snapshot_id": decision.get("snapshot_id"),
                "reason_codes": decision.get("reason_codes", []),
                "evidence_ids": decision.get("evidence_ids", []),
                "input_gate_ids": [
                    _gate_alias(gate_aliases, item)
                    for item in _strings(decision.get("input_gate_ids", []), "input gates")
                ],
                "evidence_inventory": decision.get("evidence_inventory"),
            }
        )

    requests: list[JsonObject] = []
    for request in _objects(
        raw.get("corroboration_requests", []), "corroboration requests", maximum=50
    ):
        requests.append(
            {
                "candidate_ids": request.get("candidate_ids", []),
                "reason_codes": request.get("reason_codes", []),
                "requested_evidence_kinds": request.get("requested_evidence_kinds", []),
            }
        )

    explanations: list[JsonObject] = []
    for explanation in _objects(raw.get("explanations", []), "explanations", maximum=50):
        explanations.append(
            {
                "template": explanation.get("template"),
                "candidate_id": explanation.get("candidate_id"),
                "reason_codes": explanation.get("reason_codes", []),
            }
        )

    final_plan = projected_plans[-1]
    return {
        "schema_version": SCHEMA_VERSION_V22,
        "protocol_version": PROTOCOL_VERSION_V22,
        "batch_id": raw.get("batch_id"),
        "snapshot_id": raw.get("snapshot_id"),
        "strategy": raw.get("strategy"),
        "ranking_scope": raw.get("ranking_scope"),
        "execution_mode": raw.get("execution_mode"),
        "batch_state": raw.get("batch_state"),
        "plans": projected_plans,
        "plan_diff": projected_diff,
        "receipts": receipts,
        "trust_gates": projected_gates,
        "routes": raw.get("routes"),
        "corroboration_requests": requests,
        "explanations": explanations,
        "prohibited_actions": final_plan["prohibited_actions"],
    }


def _canonical_plan(value: JsonObject) -> JsonObject:
    result = dict(value)
    result["trigger_codes"] = sorted(cast(list[str], result["trigger_codes"]))
    result["allowed_evidence_ids"] = sorted(cast(list[str], result["allowed_evidence_ids"]))
    result["prohibited_actions"] = sorted(cast(list[str], result["prohibited_actions"]))
    result["commands"] = [
        {
            **cast(JsonObject, command),
            "dependency_ids": sorted(cast(list[str], cast(JsonObject, command)["dependency_ids"])),
        }
        for command in cast(list[object], result["commands"])
    ]
    return result


def _canonical_plan_diff(value: JsonObject) -> JsonObject:
    result = dict(value)
    for field in (
        "trigger_codes",
        "removed_command_ids",
        "revoked_evidence_ids",
        "granted_evidence_ids",
        "added_prohibitions",
    ):
        result[field] = sorted(cast(list[str], result[field]))
    result["added_commands"] = [
        {
            **cast(JsonObject, command),
            "dependency_ids": sorted(cast(list[str], cast(JsonObject, command)["dependency_ids"])),
        }
        for command in cast(list[object], result["added_commands"])
    ]
    return result


def _canonical_receipt(value: JsonObject) -> JsonObject:
    result = dict(value)
    for field in ("reason_codes", "evidence_ids", "consumed_gate_ids"):
        result[field] = sorted(cast(list[str], result[field]))
    return result


def _canonical_gate(value: JsonObject) -> JsonObject:
    result = dict(value)
    for field in ("reason_codes", "evidence_ids", "input_gate_ids"):
        result[field] = sorted(cast(list[str], result[field]))
    if result["evidence_inventory"] is not None:
        inventory = dict(cast(JsonObject, result["evidence_inventory"]))
        inventory["entries"] = sorted(
            cast(list[JsonObject], inventory["entries"]),
            key=lambda item: cast(
                str,
                cast(JsonObject, item["reference"])["evidence_id"],
            ),
        )
        result["evidence_inventory"] = inventory
    return result


def _canonical_route(value: JsonObject) -> JsonObject:
    result = dict(value)
    result["reason_codes"] = sorted(cast(list[str], result["reason_codes"]))
    result["evidence_ids"] = sorted(cast(list[str], result["evidence_ids"]))
    if result["support_graph"] is not None:
        graph = dict(cast(JsonObject, result["support_graph"]))
        graph["evidence_ids"] = sorted(cast(list[str], graph["evidence_ids"]))
        graph["evidence_manifest"] = sorted(
            cast(list[JsonObject], graph["evidence_manifest"]),
            key=lambda item: cast(str, item["evidence_id"]),
        )
        graph["facts"] = sorted(
            (
                {
                    **item,
                    "source_roles": sorted(cast(list[str], item["source_roles"])),
                    "evidence_ids": sorted(cast(list[str], item["evidence_ids"])),
                    "employment_intervals": sorted(
                        cast(list[JsonObject], item["employment_intervals"]),
                        key=_canonical_sort_key,
                    ),
                }
                for item in cast(list[JsonObject], graph["facts"])
            ),
            key=lambda item: cast(str, item["fact_id"]),
        )
        graph["features"] = sorted(
            (
                {
                    **item,
                    "dependency_fact_ids": sorted(cast(list[str], item["dependency_fact_ids"])),
                    "dependency_feature_ids": sorted(
                        cast(list[str], item["dependency_feature_ids"])
                    ),
                }
                for item in cast(list[JsonObject], graph["features"])
            ),
            key=lambda item: cast(str, item["feature_id"]),
        )
        graph["route_support_ids"] = sorted(cast(list[str], graph["route_support_ids"]))
        result["support_graph"] = graph
    return result


def _canonical_corroboration(value: JsonObject) -> JsonObject:
    result = dict(value)
    for field in ("candidate_ids", "reason_codes", "requested_evidence_kinds"):
        result[field] = sorted(cast(list[str], result[field]))
    return result


def _canonical_explanation(value: JsonObject) -> JsonObject:
    result = dict(value)
    result["reason_codes"] = sorted(cast(list[str], result["reason_codes"]))
    return result


def _canonical_sort_key(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _command_alias(
    aliases: Mapping[tuple[int, str], str], version: int, raw_command_id: object
) -> str:
    command_id = _string(raw_command_id, "command ID")
    try:
        return aliases[(version, command_id)]
    except KeyError as exc:
        raise ReleaseSpecV22Error("command reference is outside the plan history") from exc


def _historical_command_alias(
    aliases: Mapping[tuple[int, str], str], through_version: int, raw_command_id: object
) -> str:
    """Resolve one cumulative removed-command reference without ambiguity.

    A terminal v3 diff retains the still-unattempted commands removed in the
    earlier v1 -> v2 transition.  All other command cross-references remain
    bound to their exact plan version; this helper is used only for that
    cumulative audit set and rejects both future and colliding identifiers.
    """

    command_id = _string(raw_command_id, "command ID")
    matching = tuple(
        alias
        for (version, candidate), alias in aliases.items()
        if version <= through_version and candidate == command_id
    )
    if len(matching) != 1:
        raise ReleaseSpecV22Error("removed command is ambiguous or outside prior plans")
    return matching[0]


def _gate_alias(aliases: Mapping[str, str], raw_gate_id: object) -> str:
    gate_id = _string(raw_gate_id, "gate ID")
    try:
        return aliases[gate_id]
    except KeyError as exc:
        raise ReleaseSpecV22Error("gate reference is outside the trust ledger") from exc


def _optional_gate_alias(aliases: Mapping[str, str], value: object) -> str | None:
    if value is None:
        return None
    return _gate_alias(aliases, value)


def _validate_json_value(value: object, *, depth: int) -> None:
    if depth > 64:
        raise ReleaseSpecV22Error("canonical JSON is too deeply nested")
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        if abs(value) > 2**63 - 1:
            raise ReleaseSpecV22Error("canonical JSON integer is outside the bounded range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ReleaseSpecV22Error("canonical JSON cannot contain non-finite values")
        return
    if isinstance(value, list | tuple):
        if len(value) > 10_000:
            raise ReleaseSpecV22Error("canonical JSON array is too large")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 1_000 or any(not isinstance(key, str) for key in value):
            raise ReleaseSpecV22Error("canonical JSON object is invalid")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    raise ReleaseSpecV22Error("canonical JSON contains a non-JSON value")


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseSpecV22Error("strict JSON cannot contain duplicate keys")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ReleaseSpecV22Error(f"strict JSON cannot contain {value}")


def _object(value: object, name: str) -> JsonObject:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReleaseSpecV22Error(f"{name} must be an object")
    return cast(JsonObject, value)


def _objects(value: object, name: str, *, maximum: int) -> list[JsonObject]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ReleaseSpecV22Error(f"{name} must be a bounded array")
    return [_object(item, name) for item in value]


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseSpecV22Error(f"{name} must be a non-empty string")
    return value


def _strings(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ReleaseSpecV22Error(f"{name} must be a string array")
    return cast(list[str], value)


def _int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ReleaseSpecV22Error(f"{name} must be an integer")
    return value
