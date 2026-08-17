"""Strict evidence validation and support-graph construction.

This module is deliberately a leaf. It consumes typed data and a narrow gate
port supplied by the orchestrator; it cannot retrieve data, select a workflow,
rank candidates, or authorize release.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol

from pydantic import ValidationError

from cv_trust_agent.models import (
    STRUCTURED_FIELD_KINDS,
    BatchIndex,
    CandidateIndexEntry,
    CandidateRecord,
    CandidateRoute,
    ClaimKind,
    DecisionSupportGraph,
    DerivedFeature,
    EvidenceDispositionEntry,
    EvidenceDispositionInventory,
    EvidenceDispositionState,
    EvidenceRef,
    MappedClaim,
    MapperOutput,
    MapperRequest,
    NormalizationMode,
    ReasonCode,
    ReviewBand,
    ReviewQueue,
    SourceKind,
    StageHandle,
    StructuredFieldAnchor,
    SupportedEmploymentInterval,
    SupportedFact,
    TrustDecision,
    TrustOutcome,
    TrustScope,
    TrustStage,
    TrustState,
    ValidatedCandidateEvidence,
)

SEMANTIC_FIELDS = (
    "ap_years",
    "invoice_processing",
    "reconciliation",
    "spreadsheet",
    "accounting_platform",
    "monthly_invoice_volume",
    "qualification",
    "note",
)
SUPPORTED_SPREADSHEETS = frozenset({"excel", "google sheets"})
SUPPORTED_ACCOUNTING_PLATFORMS = frozenset({"xero", "sage", "quickbooks", "netsuite", "sap"})
SUPPORTED_QUALIFICATIONS = frozenset({"aat level 2", "aat level 3", "aat level 4", "acca"})
CATEGORICAL_ALLOW_LISTS = {
    ClaimKind.SPREADSHEET: SUPPORTED_SPREADSHEETS,
    ClaimKind.ACCOUNTING_PLATFORM: SUPPORTED_ACCOUNTING_PLATFORMS,
    ClaimKind.QUALIFICATION: SUPPORTED_QUALIFICATIONS,
}
_CANONICAL_VALUE_DOMAIN = b"cv-trust-agent/canonical-value/v2\0"


class _TrustGatePort(Protocol):
    def _append_decision(
        self,
        ledger: list[TrustDecision],
        *,
        run_id: str,
        stage: TrustStage,
        scope: TrustScope,
        state: TrustState,
        outcome: TrustOutcome,
        reasons: tuple[ReasonCode, ...],
        candidate_id: str | None = None,
        snapshot_id: str | None = None,
        evidence_ids: tuple[str, ...] = (),
        input_gate_ids: tuple[str, ...] = (),
        evidence_inventory: EvidenceDispositionInventory | None = None,
    ) -> TrustDecision: ...

    def _consume_gate(
        self,
        *,
        run_id: str,
        value: Any,
        decision: TrustDecision,
        provenance_ids: tuple[str, ...] = (),
    ) -> Any | None: ...

    def _create_gate(
        self,
        *,
        run_id: str,
        value: Any,
        decision: TrustDecision,
        provenance_ids: tuple[str, ...] = (),
    ) -> StageHandle: ...


class SourceSchemaError(ValueError):
    """A source index failed its strict public schema."""


def parse_batch_index(payload: BatchIndex | Mapping[str, Any]) -> BatchIndex:
    if isinstance(payload, BatchIndex):
        return payload
    try:
        return BatchIndex.model_validate(payload)
    except ValidationError as exc:
        raise SourceSchemaError("source index violates the strict schema") from exc


def compute_record_semantic_hash(record: CandidateRecord | Mapping[str, Any]) -> str:
    values = record.model_dump(mode="json") if isinstance(record, CandidateRecord) else dict(record)
    return _sha256_json({field: values.get(field) for field in SEMANTIC_FIELDS})


def compute_index_manifest_hash(
    entries: Sequence[CandidateIndexEntry | Mapping[str, Any]],
) -> str:
    """Hash ordered identity/content commitments, excluding transport URLs."""

    manifest: list[dict[str, Any]] = []
    for entry in entries:
        values = entry.model_dump(mode="json") if isinstance(entry, CandidateIndexEntry) else entry
        manifest.append(
            {
                "candidate_id": values.get("candidate_id"),
                "record_revision": values.get("record_revision"),
                "semantic_hash": values.get("semantic_hash"),
                "resume_sha256": values.get("resume_sha256"),
            }
        )
    return _sha256_json(manifest)


def compute_evidence_value_hash(value: bool | int | float | str | None) -> str:
    return _sha256_json(value)


def compute_support_graph_hash(routes: Sequence[CandidateRoute]) -> str:
    """Hash semantic support topology without volatile document-bound node IDs."""

    topology: list[dict[str, Any]] = []
    for route in sorted(routes, key=lambda item: item.candidate_id):
        graph = route.support_graph
        if graph is None:
            topology.append({"candidate_id": route.candidate_id, "graph": None})
            continue
        fact_kind_by_id = {fact.fact_id: fact.kind.value for fact in graph.facts}
        feature_name_by_id = {feature.feature_id: feature.name for feature in graph.features}
        manifest = {item.evidence_id: item for item in graph.evidence_manifest}
        topology.append(
            {
                "candidate_id": route.candidate_id,
                "facts": [
                    {
                        "kind": fact.kind.value,
                        "value": fact.normalized_value,
                        "support_roles": sorted(
                            (
                                manifest[evidence_id].source_kind.value,
                                _semantic_field_role(manifest[evidence_id].field_path),
                            )
                            for evidence_id in fact.evidence_ids
                        ),
                    }
                    for fact in sorted(graph.facts, key=lambda item: item.kind.value)
                ],
                "features": [
                    {
                        "name": feature.name,
                        "value": feature.normalized_value,
                        "dependency_kinds": sorted(
                            fact_kind_by_id[fact_id] for fact_id in feature.dependency_fact_ids
                        ),
                        "dependency_features": sorted(
                            feature_name_by_id[feature_id]
                            for feature_id in feature.dependency_feature_ids
                        ),
                    }
                    for feature in sorted(graph.features, key=lambda item: item.name)
                ],
                "route_support": sorted(
                    feature_name_by_id[feature_id] for feature_id in graph.route_support_ids
                ),
            }
        )
    return _sha256_json(topology)


def _semantic_field_role(field_path: str | None) -> str:
    if field_path is None:
        return "unlabelled"
    return field_path.rsplit(".", maxsplit=1)[-1]


def safe_conflict_value(kind: ClaimKind, value: Any) -> str:
    """Render a bounded normalized value without reflecting arbitrary source text."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        numeric = float(value)
        return str(int(numeric)) if numeric.is_integer() else f"{numeric:.2f}".rstrip("0")
    normalized = str(value).strip()
    if kind is ClaimKind.SPREADSHEET:
        allowed = set(SUPPORTED_SPREADSHEETS)
    elif kind is ClaimKind.ACCOUNTING_PLATFORM:
        allowed = set(SUPPORTED_ACCOUNTING_PLATFORMS)
    elif kind is ClaimKind.QUALIFICATION:
        allowed = set(SUPPORTED_QUALIFICATIONS)
    else:
        allowed = {"not-stated"}
    allowed.add("not-stated")
    return normalized if normalized.casefold() in allowed else "unsupported-label"


def safe_evidence_source_label(source_kinds: tuple[SourceKind, ...]) -> str:
    """Reduce cited provenance classes to a fixed, non-source-controlled label."""

    sources = set(source_kinds)
    if SourceKind.RESUME_VISIBLE in sources:
        return "visible resume evidence"
    if SourceKind.APPLICATION_JSON in sources:
        return "application JSON evidence"
    if SourceKind.RESUME_NON_VISIBLE in sources:
        return "non-visible resume evidence"
    if SourceKind.PDF_METADATA in sources:
        return "PDF metadata evidence"
    return "cited evidence"


def _sha256_json(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class EvidenceConflict:
    kind: ClaimKind
    expected: Any
    observed: Any
    evidence_ids: tuple[str, ...]
    snapshot_id: str
    source_kinds: tuple[SourceKind, ...]
    values_match: bool


@dataclass(frozen=True)
class CandidateAssessment:
    evidence: ValidatedCandidateEvidence
    mapper_disagreement: bool
    conflicts: tuple[EvidenceConflict, ...] = ()
    evidence_inventory: EvidenceDispositionInventory | None = None


@dataclass(frozen=True)
class PreparedMapperClaims:
    """Trusted, bounded mapper closure before any claim reaches provenance."""

    claims: tuple[MappedClaim, ...]
    inventory: EvidenceDispositionInventory
    provenance_state: TrustState
    provenance_reasons: tuple[ReasonCode, ...]

    @property
    def mapping_commitment_ids(self) -> tuple[str, ...]:
        if self.provenance_state is not TrustState.USABLE:
            return ()
        return tuple(
            sorted(
                {
                    *(anchor.reference.evidence_id for anchor in self.inventory.structured_anchors),
                    *(item.reference.evidence_id for item in self.inventory.entries),
                }
            )
        )


@dataclass(frozen=True)
class CandidateBindingAssessment:
    """Trusted pre-mapper binding verdict for one parsed candidate."""

    valid: bool
    reason_codes: tuple[ReasonCode, ...]
    evidence_ids: tuple[str, ...]
    terminal_handle: StageHandle

    @property
    def terminal_decision_id(self) -> str:
        return self.terminal_handle.handle_id


def canonicalize_categorical(kind: ClaimKind, value: str) -> str | None:
    """Return the bounded field-aware canonical value, or ``None`` if unsupported."""

    normalized = " ".join(value.split()).casefold()
    allowed = CATEGORICAL_ALLOW_LISTS.get(kind)
    if allowed is None or normalized not in allowed:
        return None
    return normalized


def compute_canonical_value_hash(value: str) -> str:
    return hashlib.sha256(_CANONICAL_VALUE_DOMAIN + value.encode("utf-8")).hexdigest()


class CandidateEvidenceValidator:
    """Validate one candidate while preserving orchestrator-owned causal gates."""

    def validate_candidate_binding(
        self,
        index: BatchIndex,
        entry: CandidateIndexEntry,
        record: CandidateRecord,
        request: MapperRequest,
        run_id: str,
        ledger: list[TrustDecision],
        *,
        input_gate_id: str,
        gate_port: _TrustGatePort,
    ) -> CandidateBindingAssessment:
        """Mediate all identity/content commitments before any mapper call."""

        identity_refs = tuple(
            reference
            for reference in request.evidence_catalog
            if reference.evidence_id in request.document_identity_evidence_ids
        )
        json_identity_refs = tuple(
            reference
            for reference in request.evidence_catalog
            if reference.source_kind is SourceKind.APPLICATION_JSON
            and reference.field_path is not None
            and reference.field_path.endswith(".candidate_id")
            and reference.semantic_hash == compute_evidence_value_hash(record.candidate_id)
        )
        document_identity_valid = (
            request.document_candidate_id == entry.candidate_id
            and len(request.document_identity_evidence_ids) == 1
            and len(identity_refs) == 1
            and identity_refs[0].source_kind is SourceKind.RESUME_VISIBLE
            and identity_refs[0].visible
            and identity_refs[0].admissible
            and identity_refs[0].field_path == "resume.candidate_id"
            and identity_refs[0].semantic_hash == compute_evidence_value_hash(entry.candidate_id)
            and len(json_identity_refs) == 1
        )
        identity_valid = (
            record.candidate_id == entry.candidate_id
            and request.candidate_id == entry.candidate_id
            and request.record == record
            and request.snapshot_id == index.index_id
            and all(
                reference.candidate_id == entry.candidate_id
                and reference.snapshot_id == index.index_id
                for reference in request.evidence_catalog
            )
            and document_identity_valid
        )
        identity_reason = (
            ReasonCode.DOCUMENT_IDENTITY_VALID
            if identity_valid
            else ReasonCode.DOCUMENT_IDENTITY_MISSING
            if not request.document_identity_evidence_ids
            else ReasonCode.DOCUMENT_IDENTITY_CONFLICT
        )
        identity_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.IDENTITY,
            scope=TrustScope.RECORD,
            state=TrustState.USABLE if identity_valid else TrustState.QUARANTINED,
            outcome=TrustOutcome.ALLOW if identity_valid else TrustOutcome.QUARANTINE,
            reasons=(identity_reason,),
            candidate_id=entry.candidate_id,
            snapshot_id=index.index_id,
            evidence_ids=tuple(
                sorted(
                    {
                        *request.document_identity_evidence_ids,
                        *(reference.evidence_id for reference in json_identity_refs),
                    }
                )
            ),
            input_gate_ids=(input_gate_id,),
        )
        if not identity_valid:
            identity_handle = gate_port._create_gate(
                run_id=run_id,
                value=None,
                decision=identity_decision,
                provenance_ids=identity_decision.evidence_ids,
            )
            return CandidateBindingAssessment(
                valid=False,
                reason_codes=(identity_reason,),
                evidence_ids=identity_decision.evidence_ids,
                terminal_handle=identity_handle,
            )
        identity_gate = gate_port._consume_gate(
            run_id=run_id,
            value=(record, request),
            decision=identity_decision,
            provenance_ids=identity_decision.evidence_ids,
        )
        if identity_gate is None:
            raise RuntimeError("usable identity gate unexpectedly blocked")
        revision_valid = record.record_revision == entry.record_revision
        resume_url_valid = record.resume_url == entry.resume_url
        record_self_hash_valid = compute_record_semantic_hash(record) == record.semantic_hash
        semantic_commitment_valid = record.semantic_hash == entry.semantic_hash
        resume_valid = request.document_hash == entry.resume_sha256
        request_valid = bool(request.evidence_catalog) and len(
            {reference.evidence_id for reference in request.evidence_catalog}
        ) == len(request.evidence_catalog)
        revision_binding_valid = revision_valid and resume_url_valid
        manifest_binding_valid = (
            record_self_hash_valid and semantic_commitment_valid and resume_valid
        )
        revision_reasons = tuple(
            sorted(
                {
                    ReasonCode.REVISION_VALID if revision_valid else ReasonCode.REVISION_CONFLICT,
                    *(() if resume_url_valid else (ReasonCode.INDEX_CONFLICT,)),
                },
                key=str,
            )
        )
        revision_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.REVISION,
            scope=TrustScope.RECORD,
            state=TrustState.USABLE if revision_binding_valid else TrustState.QUARANTINED,
            outcome=(TrustOutcome.ALLOW if revision_binding_valid else TrustOutcome.QUARANTINE),
            reasons=revision_reasons,
            candidate_id=entry.candidate_id,
            snapshot_id=index.index_id,
            evidence_ids=identity_decision.evidence_ids,
            input_gate_ids=(identity_decision.decision_id,),
        )
        if not revision_binding_valid:
            revision_handle = gate_port._create_gate(
                run_id=run_id,
                value=None,
                decision=revision_decision,
                provenance_ids=revision_decision.evidence_ids,
            )
            return CandidateBindingAssessment(
                valid=False,
                reason_codes=revision_reasons,
                evidence_ids=identity_decision.evidence_ids,
                terminal_handle=revision_handle,
            )
        revision_pair = gate_port._consume_gate(
            run_id=run_id,
            value=identity_gate,
            decision=revision_decision,
        )
        if revision_pair is None:
            raise RuntimeError("usable revision gate unexpectedly blocked")
        manifest_reasons = (
            ReasonCode.SEMANTIC_HASH_VALID
            if record_self_hash_valid and semantic_commitment_valid
            else ReasonCode.SEMANTIC_HASH_CONFLICT,
            ReasonCode.RESUME_HASH_VALID if resume_valid else ReasonCode.RESUME_HASH_CONFLICT,
        )
        manifest_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.MANIFEST,
            scope=TrustScope.RECORD,
            state=TrustState.USABLE if manifest_binding_valid else TrustState.QUARANTINED,
            outcome=(TrustOutcome.ALLOW if manifest_binding_valid else TrustOutcome.QUARANTINE),
            reasons=manifest_reasons,
            candidate_id=entry.candidate_id,
            snapshot_id=index.index_id,
            evidence_ids=identity_decision.evidence_ids,
            input_gate_ids=(revision_decision.decision_id,),
        )
        if not manifest_binding_valid:
            manifest_handle = gate_port._create_gate(
                run_id=run_id,
                value=None,
                decision=manifest_decision,
                provenance_ids=manifest_decision.evidence_ids,
            )
            return CandidateBindingAssessment(
                valid=False,
                reason_codes=tuple(sorted(set(manifest_reasons), key=str)),
                evidence_ids=identity_decision.evidence_ids,
                terminal_handle=manifest_handle,
            )
        manifest_pair = gate_port._consume_gate(
            run_id=run_id,
            value=revision_pair,
            decision=manifest_decision,
        )
        if manifest_pair is None:
            raise RuntimeError("usable manifest gate unexpectedly blocked")
        parsing_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.PARSING,
            scope=TrustScope.RECORD,
            state=TrustState.USABLE if request_valid else TrustState.QUARANTINED,
            outcome=TrustOutcome.ALLOW if request_valid else TrustOutcome.QUARANTINE,
            reasons=(
                ReasonCode.EVIDENCE_ADMISSIBLE if request_valid else ReasonCode.INDEX_CONFLICT,
            ),
            candidate_id=entry.candidate_id,
            snapshot_id=index.index_id,
            evidence_ids=identity_decision.evidence_ids,
            input_gate_ids=(manifest_decision.decision_id,),
        )
        parsing_handle = gate_port._create_gate(
            run_id=run_id,
            value=manifest_pair if request_valid else None,
            decision=parsing_decision,
            provenance_ids=parsing_decision.evidence_ids,
        )
        if not request_valid:
            return CandidateBindingAssessment(
                valid=False,
                reason_codes=(ReasonCode.INDEX_CONFLICT,),
                evidence_ids=identity_decision.evidence_ids,
                terminal_handle=parsing_handle,
            )
        return CandidateBindingAssessment(
            valid=True,
            reason_codes=(
                ReasonCode.DOCUMENT_IDENTITY_VALID,
                ReasonCode.REVISION_VALID,
                ReasonCode.SEMANTIC_HASH_VALID,
                ReasonCode.RESUME_HASH_VALID,
                ReasonCode.EVIDENCE_ADMISSIBLE,
            ),
            evidence_ids=identity_decision.evidence_ids,
            terminal_handle=parsing_handle,
        )

    def assess_candidate(
        self,
        index: BatchIndex,
        entry: CandidateIndexEntry,
        record: CandidateRecord,
        request: MapperRequest,
        run_id: str,
        ledger: list[TrustDecision],
        *,
        mapped_output: MapperOutput | None,
        prepared_claims: PreparedMapperClaims | None,
        mapping_failed: bool,
        binding: CandidateBindingAssessment,
        gate_port: _TrustGatePort,
    ) -> CandidateAssessment:
        if not binding.valid:
            return CandidateAssessment(
                evidence=self.empty_candidate(
                    entry.candidate_id,
                    index.index_id,
                    TrustState.QUARANTINED,
                    binding.reason_codes,
                ),
                mapper_disagreement=True,
            )
        if mapping_failed or mapped_output is None or prepared_claims is None:
            mapping_failure = gate_port._append_decision(
                ledger,
                run_id=run_id,
                stage=TrustStage.MAPPING,
                scope=TrustScope.RECORD,
                state=TrustState.UNAVAILABLE,
                outcome=TrustOutcome.UNAVAILABLE,
                reasons=(ReasonCode.MAPPER_UNAVAILABLE,),
                candidate_id=entry.candidate_id,
                snapshot_id=index.index_id,
                input_gate_ids=(binding.terminal_decision_id,),
            )
            gate_port._create_gate(
                run_id=run_id,
                value=None,
                decision=mapping_failure,
            )
            return CandidateAssessment(
                evidence=self.empty_candidate(
                    entry.candidate_id,
                    index.index_id,
                    TrustState.UNAVAILABLE,
                    (ReasonCode.MAPPER_UNAVAILABLE,),
                ),
                mapper_disagreement=True,
            )
        return self._validate_mapper_output(
            record,
            request,
            prepared_claims,
            run_id,
            ledger,
            input_gate_id=binding.terminal_decision_id,
            gate_port=gate_port,
        )

    def prepare_mapper_output(
        self,
        record: CandidateRecord,
        request: MapperRequest,
        output: MapperOutput,
    ) -> PreparedMapperClaims:
        """Validate and commit the exact claims that a mapping gate may hand on."""

        catalog = {item.evidence_id: item for item in request.evidence_catalog}
        valid_claims: list[MappedClaim] = []
        provenance_reasons: set[ReasonCode] = set()
        provenance_state = TrustState.USABLE
        for claim in output.claims:
            references = [catalog.get(evidence_id) for evidence_id in claim.evidence_ids]
            if any(reference is None for reference in references):
                provenance_reasons.add(ReasonCode.EVIDENCE_UNKNOWN)
                provenance_state = TrustState.QUARANTINED
                continue
            typed_refs = tuple(reference for reference in references if reference is not None)
            if any(
                not ref.admissible
                or not ref.visible
                or ref.source_kind is not SourceKind.RESUME_VISIBLE
                for ref in typed_refs
            ):
                provenance_reasons.add(ReasonCode.EVIDENCE_INADMISSIBLE)
                provenance_state = TrustState.QUARANTINED
                continue
            hashes_match = all(self._claim_matches_evidence_hash(claim, ref) for ref in typed_refs)
            if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL:
                endpoint_fields = tuple(
                    ref.field_path.rsplit(".", maxsplit=1)[-1]
                    for ref in typed_refs
                    if ref.field_path is not None
                )
                hashes_match = (
                    hashes_match
                    and len(typed_refs) == 2
                    and endpoint_fields.count("employment_start") == 1
                    and endpoint_fields.count("employment_end") == 1
                )
            if not hashes_match:
                provenance_reasons.add(ReasonCode.EVIDENCE_VALUE_CONFLICT)
                provenance_state = TrustState.QUARANTINED
                continue
            valid_claims.append(claim)
        # Identity proposals are checked above but never enter the consumable
        # mapping closure; trusted binding evidence supplies candidate identity.
        consumable_claims = tuple(
            claim for claim in valid_claims if claim.kind is not ClaimKind.CANDIDATE_ID
        )
        inventory = self._consumption_inventory(
            record,
            request,
            consumable_claims,
            catalog,
        )
        if provenance_state is TrustState.QUARANTINED:
            provenance_reasons.add(ReasonCode.MAPPER_DISAGREEMENT)
        if not provenance_reasons:
            provenance_reasons.add(ReasonCode.EVIDENCE_ADMISSIBLE)
        return PreparedMapperClaims(
            claims=consumable_claims,
            inventory=inventory,
            provenance_state=provenance_state,
            provenance_reasons=tuple(sorted(provenance_reasons, key=str)),
        )

    def _validate_mapper_output(
        self,
        record: CandidateRecord,
        request: MapperRequest,
        prepared: PreparedMapperClaims,
        run_id: str,
        ledger: list[TrustDecision],
        *,
        input_gate_id: str,
        gate_port: _TrustGatePort,
    ) -> CandidateAssessment:
        catalog = {item.evidence_id: item for item in request.evidence_catalog}
        consumable_claims = prepared.claims
        consumption_inventory = prepared.inventory
        provenance_state = prepared.provenance_state
        provenance_reasons = prepared.provenance_reasons
        mapping_inventory = consumption_inventory if provenance_state is TrustState.USABLE else None
        mapping_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.MAPPING,
            scope=TrustScope.RECORD,
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reasons=(ReasonCode.MAPPER_OUTPUT_VALID,),
            candidate_id=record.candidate_id,
            snapshot_id=request.snapshot_id,
            evidence_ids=(
                tuple(item.reference.evidence_id for item in consumption_inventory.entries)
                if mapping_inventory is not None
                else ()
            ),
            input_gate_ids=(input_gate_id,),
            evidence_inventory=mapping_inventory,
        )
        mapped_claims = gate_port._consume_gate(
            run_id=run_id,
            value=consumable_claims,
            decision=mapping_decision,
            provenance_ids=mapping_decision.evidence_ids,
        )
        if not isinstance(mapped_claims, tuple):
            raise RuntimeError("usable mapping gate returned an invalid claim bundle")
        provenance_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.PROVENANCE,
            scope=TrustScope.RECORD,
            state=provenance_state,
            outcome=self.outcome_for(provenance_state),
            reasons=provenance_reasons,
            candidate_id=record.candidate_id,
            snapshot_id=request.snapshot_id,
            evidence_ids=tuple(
                item.reference.evidence_id for item in consumption_inventory.entries
            ),
            input_gate_ids=(mapping_decision.decision_id,),
            evidence_inventory=(
                consumption_inventory if provenance_state is TrustState.USABLE else None
            ),
        )
        provenance_claims = gate_port._consume_gate(
            run_id=run_id,
            value=mapped_claims,
            decision=provenance_decision,
            provenance_ids=provenance_decision.evidence_ids,
        )
        if provenance_claims is None:
            return CandidateAssessment(
                evidence=self.empty_candidate(
                    record.candidate_id,
                    request.snapshot_id,
                    TrustState.QUARANTINED,
                    provenance_reasons,
                ),
                mapper_disagreement=True,
            )
        if not isinstance(provenance_claims, tuple):
            raise RuntimeError("provenance gate returned an invalid claim bundle")

        timeline_state, timeline_reason, interval_evidence_ids = self.validate_timeline(
            record, provenance_claims
        )
        timeline_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.TIMELINE,
            scope=TrustScope.RECORD,
            state=timeline_state,
            outcome=self.outcome_for(timeline_state),
            reasons=(timeline_reason,),
            candidate_id=record.candidate_id,
            snapshot_id=request.snapshot_id,
            evidence_ids=interval_evidence_ids,
            input_gate_ids=(provenance_decision.decision_id,),
        )
        timeline_claims = gate_port._consume_gate(
            run_id=run_id,
            value=provenance_claims,
            decision=timeline_decision,
            provenance_ids=interval_evidence_ids,
        )
        if timeline_claims is None:
            intervals = tuple(
                (claim.start_date, claim.end_date)
                for claim in provenance_claims
                if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL
                and claim.start_date is not None
                and claim.end_date is not None
            )
            observed_years = round(_merged_interval_days(intervals) / 365.2425, 1)
            source_kinds = tuple(
                sorted(
                    {
                        catalog[evidence_id].source_kind
                        for evidence_id in interval_evidence_ids
                        if evidence_id in catalog
                    },
                    key=str,
                )
            )
            conflict = EvidenceConflict(
                kind=ClaimKind.AP_YEARS,
                expected=record.ap_years,
                observed=observed_years,
                evidence_ids=interval_evidence_ids,
                snapshot_id=request.snapshot_id,
                source_kinds=source_kinds,
                values_match=False,
            )
            return CandidateAssessment(
                evidence=self.empty_candidate(
                    record.candidate_id,
                    request.snapshot_id,
                    TrustState.QUARANTINED,
                    tuple(
                        sorted(
                            {
                                *provenance_reasons,
                                timeline_reason,
                                ReasonCode.MAPPER_DISAGREEMENT,
                            },
                            key=str,
                        )
                    ),
                ),
                mapper_disagreement=True,
                conflicts=(conflict,),
            )
        if not isinstance(timeline_claims, tuple):
            raise RuntimeError("timeline gate returned an invalid claim bundle")

        (
            cross_state,
            cross_reasons,
            values,
            evidence_ids,
            kinds,
            conflicts,
            fact_evidence,
        ) = self._cross_source(record, timeline_claims, catalog)
        if (
            values.get("monthly_invoice_volume") is not None
            and values.get("invoice_processing") is not True
        ):
            fact_evidence.pop(ClaimKind.MONTHLY_INVOICE_VOLUME, ())
            values.pop("monthly_invoice_volume", None)
            kinds.discard(ClaimKind.MONTHLY_INVOICE_VOLUME)
            cross_state = TrustState.QUARANTINED
            cross_reasons = tuple(
                sorted(
                    {
                        *cross_reasons,
                        ReasonCode.DOMAIN_INVARIANT_CONFLICT,
                        ReasonCode.MAPPER_DISAGREEMENT,
                    },
                    key=str,
                )
            )
        category_dropped = False
        for unsupported_kind, supported in (
            (ClaimKind.SPREADSHEET, values.get("spreadsheet_supported") is True),
            (
                ClaimKind.ACCOUNTING_PLATFORM,
                values.get("accounting_platform_supported") is True,
            ),
            (ClaimKind.QUALIFICATION, values.get("qualification_supported") is True),
        ):
            if supported:
                continue
            if unsupported_kind in fact_evidence:
                category_dropped = True
            fact_evidence.pop(unsupported_kind, ())
            kinds.discard(unsupported_kind)
        # The dropped-category marker is audit provenance for this gate only.
        # Candidate reason codes and routes keep the V2.1 action semantics, so
        # a supported ranking is unchanged while the audit trace records that
        # accepted citations were consumed here without becoming facts.
        cross_gate_reasons = cross_reasons
        if category_dropped:
            cross_gate_reasons = tuple(
                sorted({*cross_reasons, ReasonCode.CATEGORY_NOT_SUPPORTED}, key=str)
            )
        cross_decision = gate_port._append_decision(
            ledger,
            run_id=run_id,
            stage=TrustStage.CROSS_SOURCE,
            scope=TrustScope.RECORD,
            state=cross_state,
            outcome=self.outcome_for(cross_state),
            reasons=cross_gate_reasons,
            candidate_id=record.candidate_id,
            snapshot_id=request.snapshot_id,
            evidence_ids=evidence_ids,
            input_gate_ids=(timeline_decision.decision_id,),
        )
        cross_payload = gate_port._consume_gate(
            run_id=run_id,
            value=(values, evidence_ids, kinds, fact_evidence),
            decision=cross_decision,
            provenance_ids=evidence_ids,
        )
        if cross_payload is None:
            return CandidateAssessment(
                evidence=self.empty_candidate(
                    record.candidate_id,
                    request.snapshot_id,
                    TrustState.QUARANTINED,
                    tuple(
                        sorted(
                            {*provenance_reasons, timeline_reason, *cross_reasons},
                            key=str,
                        )
                    ),
                ),
                mapper_disagreement=True,
                conflicts=conflicts,
            )
        if not isinstance(cross_payload, tuple) or len(cross_payload) != 4:
            raise RuntimeError("cross-source gate returned an invalid evidence bundle")
        values, evidence_ids, kinds, fact_evidence = cross_payload
        if (
            timeline_state is TrustState.USABLE
            and any(claim.kind is ClaimKind.EMPLOYMENT_INTERVAL for claim in timeline_claims)
        ) or (timeline_state is TrustState.DEGRADED and bool(interval_evidence_ids)):
            kinds.add(ClaimKind.EMPLOYMENT_INTERVAL)
            fact_evidence[ClaimKind.EMPLOYMENT_INTERVAL] = interval_evidence_ids
        if interval_evidence_ids and ClaimKind.AP_YEARS in fact_evidence:
            fact_evidence[ClaimKind.AP_YEARS] = tuple(
                sorted({*fact_evidence[ClaimKind.AP_YEARS], *interval_evidence_ids})
            )
        elif (
            ClaimKind.AP_YEARS in fact_evidence
            and values.get("ap_years") == 0
            and timeline_state is TrustState.USABLE
        ):
            # A corroborated zero-experience claim has no positive employment
            # interval to cite.  Keep the explicit JSON/PDF scalar pair as the
            # support for that bounded negative fact; positive AP-years claims
            # still require both dated interval endpoints below.
            pass
        elif timeline_state is not TrustState.QUARANTINED:
            rejected_ap_ids = set(fact_evidence.pop(ClaimKind.AP_YEARS, ()))
            evidence_ids = tuple(item for item in evidence_ids if item not in rejected_ap_ids)
            kinds.discard(ClaimKind.AP_YEARS)
            values.pop("ap_years", None)
        state = self._worst_state(provenance_state, cross_state, timeline_state)
        reasons = set(provenance_reasons).union(cross_reasons, {timeline_reason})
        identity_evidence_ids = tuple(
            sorted(
                {
                    *request.document_identity_evidence_ids,
                    *(
                        reference.evidence_id
                        for reference in request.evidence_catalog
                        if reference.source_kind is SourceKind.APPLICATION_JSON
                        and reference.field_path is not None
                        and reference.field_path.endswith(".candidate_id")
                        and reference.semantic_hash
                        == compute_evidence_value_hash(record.candidate_id)
                    ),
                }
            )
        )
        if identity_evidence_ids:
            fact_evidence[ClaimKind.CANDIDATE_ID] = identity_evidence_ids
        interval_claims = tuple(
            claim
            for claim in timeline_claims
            if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL
            and claim.start_date is not None
            and claim.end_date is not None
        )
        normalized_values: dict[ClaimKind, bool | int | float | str] = {
            ClaimKind.CANDIDATE_ID: record.candidate_id,
        }
        categorical_source_values: dict[ClaimKind, str] = {}
        scalar_fact_values: tuple[tuple[ClaimKind, str], ...] = (
            (ClaimKind.AP_YEARS, "ap_years"),
            (ClaimKind.INVOICE_PROCESSING, "invoice_processing"),
            (ClaimKind.RECONCILIATION, "reconciliation"),
            (ClaimKind.MONTHLY_INVOICE_VOLUME, "monthly_invoice_volume"),
        )
        for kind, key in scalar_fact_values:
            value = values.get(key)
            if kind in fact_evidence and isinstance(value, (bool, int, float)):
                normalized_values[kind] = value
        categorical_record_values = {
            ClaimKind.SPREADSHEET: record.spreadsheet,
            ClaimKind.ACCOUNTING_PLATFORM: record.accounting_platform,
            ClaimKind.QUALIFICATION: record.qualification,
        }
        for kind, source_value in categorical_record_values.items():
            if kind not in fact_evidence or source_value is None:
                continue
            canonical_value = canonicalize_categorical(kind, source_value)
            if canonical_value is None:
                fact_evidence.pop(kind, None)
                kinds.discard(kind)
                continue
            normalized_values[kind] = canonical_value
            categorical_source_values[kind] = source_value
        if ClaimKind.EMPLOYMENT_INTERVAL in fact_evidence and interval_claims:
            intervals = tuple(
                (claim.start_date, claim.end_date)
                for claim in interval_claims
                if claim.start_date is not None and claim.end_date is not None
            )
            normalized_values[ClaimKind.EMPLOYMENT_INTERVAL] = round(
                _merged_interval_days(intervals) / 365.2425,
                4,
            )
        supported_intervals = tuple(
            SupportedEmploymentInterval(
                start_date=claim.start_date,
                end_date=claim.end_date,
                start_evidence_id=next(
                    evidence_id
                    for evidence_id in claim.evidence_ids
                    if (field_path := catalog[evidence_id].field_path) is not None
                    and field_path.rsplit(".", maxsplit=1)[-1] == "employment_start"
                ),
                end_evidence_id=next(
                    evidence_id
                    for evidence_id in claim.evidence_ids
                    if (field_path := catalog[evidence_id].field_path) is not None
                    and field_path.rsplit(".", maxsplit=1)[-1] == "employment_end"
                ),
            )
            for claim in interval_claims
            if claim.start_date is not None and claim.end_date is not None
        )
        support_graph = self._support_graph(
            record.candidate_id,
            request.snapshot_id,
            fact_evidence,
            normalized_values,
            categorical_source_values,
            supported_intervals,
            catalog,
        )
        final_inventory = self._finalize_evidence_inventory(
            consumption_inventory,
            support_graph,
        )
        complete_evidence_ids = support_graph.evidence_ids
        return CandidateAssessment(
            evidence=ValidatedCandidateEvidence(
                candidate_id=record.candidate_id,
                snapshot_id=request.snapshot_id,
                trust_state=state,
                ap_years=values.get("ap_years"),
                invoice_processing=values.get("invoice_processing"),
                reconciliation=values.get("reconciliation"),
                spreadsheet_supported=bool(values.get("spreadsheet_supported")),
                accounting_platform_supported=bool(values.get("accounting_platform_supported")),
                monthly_invoice_volume=values.get("monthly_invoice_volume"),
                qualification_supported=bool(values.get("qualification_supported")),
                corroborated_claim_kinds=tuple(sorted(kinds, key=str)),
                evidence_ids=complete_evidence_ids,
                support_graph=support_graph,
                reason_codes=tuple(sorted(reasons, key=str)),
            ),
            mapper_disagreement=state in {TrustState.QUARANTINED, TrustState.UNAVAILABLE},
            conflicts=conflicts,
            evidence_inventory=final_inventory,
        )

    def _cross_source(
        self,
        record: CandidateRecord,
        claims: Sequence[MappedClaim],
        catalog: Mapping[str, EvidenceRef],
    ) -> tuple[
        TrustState,
        tuple[ReasonCode, ...],
        dict[str, Any],
        tuple[str, ...],
        set[ClaimKind],
        tuple[EvidenceConflict, ...],
        dict[ClaimKind, tuple[str, ...]],
    ]:
        expected: dict[ClaimKind, Any] = {
            ClaimKind.AP_YEARS: record.ap_years,
            ClaimKind.INVOICE_PROCESSING: record.invoice_processing,
            ClaimKind.RECONCILIATION: record.reconciliation,
            ClaimKind.SPREADSHEET: record.spreadsheet,
            ClaimKind.ACCOUNTING_PLATFORM: record.accounting_platform,
            ClaimKind.MONTHLY_INVOICE_VOLUME: record.monthly_invoice_volume,
            ClaimKind.QUALIFICATION: record.qualification,
        }
        grouped: dict[ClaimKind, list[MappedClaim]] = {}
        for claim in claims:
            if claim.kind is not ClaimKind.EMPLOYMENT_INTERVAL:
                grouped.setdefault(claim.kind, []).append(claim)
        conflict = False
        missing = False
        values: dict[str, Any] = {}
        accepted_ids: set[str] = set()
        accepted_kinds: set[ClaimKind] = set()
        fact_evidence: dict[ClaimKind, tuple[str, ...]] = {}
        conflict_details: list[EvidenceConflict] = []
        for kind, expected_value in expected.items():
            kind_claims = grouped.get(kind, [])
            canonical_json: tuple[EvidenceRef, ...] = ()
            if kind_claims:
                # CROSS_SOURCE is the audit record for every comparison, not
                # merely the facts which survive it. Preserve both the mapped
                # visible side and canonical application side before deciding
                # whether the pair matches, conflicts, or is later dropped.
                accepted_ids.update(
                    evidence_id for claim in kind_claims for evidence_id in claim.evidence_ids
                )
                canonical_json = tuple(
                    reference
                    for reference in catalog.values()
                    if reference.candidate_id == record.candidate_id
                    and reference.source_kind is SourceKind.APPLICATION_JSON
                    and reference.admissible
                    and reference.visible
                    and reference.field_path is not None
                    and reference.field_path.endswith(f".{kind.value}")
                )
                if len(canonical_json) == 1:
                    accepted_ids.add(canonical_json[0].evidence_id)
                else:
                    conflict = True
            if expected_value is None:
                if kind_claims:
                    conflict = True
                    for claim in kind_claims:
                        conflict_details.append(
                            self._conflict(kind, "not-stated", claim, catalog, False)
                        )
                continue
            if not kind_claims:
                missing = True
                continue
            matching: list[MappedClaim] = []
            for claim in kind_claims:
                refs = tuple(catalog[item] for item in claim.evidence_ids)
                visible_resume = any(
                    ref.source_kind is SourceKind.RESUME_VISIBLE and ref.visible and ref.admissible
                    for ref in refs
                )
                values_match = self._values_equal(kind, expected_value, self._claim_value(claim))
                if visible_resume and values_match:
                    matching.append(claim)
                else:
                    conflict = True
                    conflict_details.append(
                        self._conflict(kind, expected_value, claim, catalog, values_match)
                    )
            mapped_values = tuple(self._claim_value(claim) for claim in matching)
            values_are_consistent = all(
                self._values_equal(kind, left, right)
                for index, left in enumerate(mapped_values)
                for right in mapped_values[index + 1 :]
            )
            if len(matching) != len(kind_claims) or not matching or not values_are_consistent:
                conflict = True
                continue
            expected_hash_value: bool | int | float | str = expected_value
            if kind is ClaimKind.MONTHLY_INVOICE_VOLUME:
                expected_hash_value = int(expected_value)
            expected_hash = compute_evidence_value_hash(expected_hash_value)
            json_matches = tuple(
                reference
                for reference in canonical_json
                if reference.semantic_hash == expected_hash
            )
            if len(json_matches) != 1:
                conflict = True
                continue
            accepted_kinds.add(kind)
            accepted_ids.update(item for claim in matching for item in claim.evidence_ids)
            accepted_ids.update(reference.evidence_id for reference in json_matches)
            fact_evidence[kind] = tuple(
                sorted(
                    {
                        *(item for claim in matching for item in claim.evidence_ids),
                        *(reference.evidence_id for reference in json_matches),
                    }
                )
            )
            if kind is ClaimKind.AP_YEARS:
                values["ap_years"] = float(expected_value)
            elif kind is ClaimKind.INVOICE_PROCESSING:
                values["invoice_processing"] = bool(expected_value)
            elif kind is ClaimKind.RECONCILIATION:
                values["reconciliation"] = bool(expected_value)
            elif kind is ClaimKind.SPREADSHEET:
                values["spreadsheet_supported"] = str(expected_value).strip().casefold() in (
                    SUPPORTED_SPREADSHEETS
                )
            elif kind is ClaimKind.ACCOUNTING_PLATFORM:
                values["accounting_platform_supported"] = (
                    str(expected_value).strip().casefold() in SUPPORTED_ACCOUNTING_PLATFORMS
                )
            elif kind is ClaimKind.MONTHLY_INVOICE_VOLUME:
                values["monthly_invoice_volume"] = int(expected_value)
            elif kind is ClaimKind.QUALIFICATION:
                values["qualification_supported"] = str(expected_value).strip().casefold() in (
                    SUPPORTED_QUALIFICATIONS
                )
        if conflict:
            return (
                TrustState.QUARANTINED,
                (ReasonCode.CROSS_SOURCE_CONFLICT, ReasonCode.MAPPER_DISAGREEMENT),
                values,
                tuple(sorted(accepted_ids)),
                accepted_kinds,
                tuple(conflict_details),
                fact_evidence,
            )
        if missing:
            return (
                TrustState.DEGRADED,
                (ReasonCode.CROSS_SOURCE_MATCH, ReasonCode.EVIDENCE_MISSING),
                values,
                tuple(sorted(accepted_ids)),
                accepted_kinds,
                (),
                fact_evidence,
            )
        return (
            TrustState.USABLE,
            (ReasonCode.CROSS_SOURCE_MATCH,),
            values,
            tuple(sorted(accepted_ids)),
            accepted_kinds,
            (),
            fact_evidence,
        )

    @staticmethod
    def _conflict(
        kind: ClaimKind,
        expected: Any,
        claim: MappedClaim,
        catalog: Mapping[str, EvidenceRef],
        values_match: bool,
    ) -> EvidenceConflict:
        refs = tuple(catalog[item] for item in claim.evidence_ids)
        return EvidenceConflict(
            kind=kind,
            expected=expected,
            observed=CandidateEvidenceValidator._claim_value(claim),
            evidence_ids=claim.evidence_ids,
            snapshot_id=claim.snapshot_id,
            source_kinds=tuple(sorted({item.source_kind for item in refs}, key=str)),
            values_match=values_match,
        )

    @staticmethod
    def _claim_matches_evidence_hash(claim: MappedClaim, evidence: EvidenceRef) -> bool:
        if evidence.field_path is None:
            return False
        field = evidence.field_path.rsplit(".", maxsplit=1)[-1]
        if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL:
            if field == "employment_start" and claim.start_date is not None:
                value: bool | int | float | str = claim.start_date.isoformat()
            elif field == "employment_end" and claim.end_date is not None:
                value = claim.end_date.isoformat()
            else:
                return False
            return compute_evidence_value_hash(value) == evidence.semantic_hash
        if field != claim.kind.value:
            return False
        value = CandidateEvidenceValidator._claim_value(claim)
        if value is None:
            return False
        if claim.kind is ClaimKind.MONTHLY_INVOICE_VOLUME:
            number = float(value)
            value = int(number) if number.is_integer() else number
        return compute_evidence_value_hash(value) == evidence.semantic_hash

    @staticmethod
    def _consumption_inventory(
        record: CandidateRecord,
        request: MapperRequest,
        claims: Sequence[MappedClaim],
        catalog: Mapping[str, EvidenceRef],
    ) -> EvidenceDispositionInventory:
        """Capture the exact sanitized claim/evidence edges before consumption."""

        def structured_anchor(
            kind: ClaimKind,
            value: bool | int | float | str | None,
        ) -> StructuredFieldAnchor:
            expected_hash = compute_evidence_value_hash(value)
            matches = tuple(
                reference
                for reference in catalog.values()
                if reference.candidate_id == record.candidate_id
                and reference.snapshot_id == request.snapshot_id
                and reference.source_kind is SourceKind.APPLICATION_JSON
                and reference.visible
                and reference.admissible
                and reference.field_path is not None
                and reference.field_path.rsplit(".", maxsplit=1)[-1] == kind.value
                and reference.semantic_hash == expected_hash
            )
            if len(matches) != 1:
                raise RuntimeError("structured field anchor is missing or ambiguous")
            return StructuredFieldAnchor(
                claim_kind=kind,
                value=value,
                reference=matches[0],
            )

        record_values: dict[ClaimKind, bool | int | float | str | None] = {
            ClaimKind.AP_YEARS: record.ap_years,
            ClaimKind.INVOICE_PROCESSING: record.invoice_processing,
            ClaimKind.RECONCILIATION: record.reconciliation,
            ClaimKind.SPREADSHEET: record.spreadsheet,
            ClaimKind.ACCOUNTING_PLATFORM: record.accounting_platform,
            ClaimKind.MONTHLY_INVOICE_VOLUME: record.monthly_invoice_volume,
            ClaimKind.QUALIFICATION: record.qualification,
        }
        structured_anchors = tuple(
            structured_anchor(kind, record_values[kind]) for kind in STRUCTURED_FIELD_KINDS
        )
        anchors_by_kind = {anchor.claim_kind: anchor for anchor in structured_anchors}

        def mapped_value(claim: MappedClaim) -> bool | int | float | str | None:
            if claim.kind in {ClaimKind.INVOICE_PROCESSING, ClaimKind.RECONCILIATION}:
                return claim.bool_value
            if claim.kind is ClaimKind.AP_YEARS:
                return claim.number_value
            if claim.kind is ClaimKind.MONTHLY_INVOICE_VOLUME:
                number = claim.number_value
                if number is None or not number.is_integer():
                    raise RuntimeError("monthly invoice volume claim is not integral")
                return int(number)
            if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL:
                return None
            return claim.text_value

        entries: dict[str, EvidenceDispositionEntry] = {}
        for claim in claims:
            for evidence_id in claim.evidence_ids:
                reference = catalog[evidence_id]
                date_value: date | None = None
                if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL:
                    role = (
                        reference.field_path.rsplit(".", maxsplit=1)[-1]
                        if reference.field_path is not None
                        else ""
                    )
                    date_value = claim.start_date if role == "employment_start" else claim.end_date
                entry = EvidenceDispositionEntry(
                    claim_kind=claim.kind,
                    reference=reference,
                    state=EvidenceDispositionState.CONSUMED,
                    date_value=date_value,
                    mapped_value=mapped_value(claim),
                )
                previous = entries.get(evidence_id)
                if previous is not None and previous != entry:
                    raise RuntimeError("one evidence reference was assigned incompatible claims")
                entries[evidence_id] = entry
        return EvidenceDispositionInventory(
            candidate_id=record.candidate_id,
            snapshot_id=request.snapshot_id,
            record_ap_years=record.ap_years,
            record_invoice_processing=record.invoice_processing,
            record_ap_years_reference=anchors_by_kind[ClaimKind.AP_YEARS].reference,
            record_invoice_processing_reference=(
                anchors_by_kind[ClaimKind.INVOICE_PROCESSING].reference
            ),
            structured_anchors=structured_anchors,
            entries=tuple(entries[evidence_id] for evidence_id in sorted(entries)),
        )

    @staticmethod
    def _finalize_evidence_inventory(
        consumed: EvidenceDispositionInventory,
        graph: DecisionSupportGraph,
    ) -> EvidenceDispositionInventory:
        """Account for every consumed edge after deterministic validation."""

        manifest = {item.evidence_id: item for item in graph.evidence_manifest}
        released_resume_ids = {
            evidence_id
            for fact in graph.facts
            if fact.kind is not ClaimKind.CANDIDATE_ID
            for evidence_id in fact.evidence_ids
            if (reference := manifest.get(evidence_id)) is not None
            and reference.source_kind is SourceKind.RESUME_VISIBLE
        }
        categorical_kinds = {
            ClaimKind.SPREADSHEET,
            ClaimKind.ACCOUNTING_PLATFORM,
            ClaimKind.QUALIFICATION,
        }
        entries: list[EvidenceDispositionEntry] = []
        for item in consumed.entries:
            evidence_id = item.reference.evidence_id
            if evidence_id in released_resume_ids:
                state = EvidenceDispositionState.RELEASED
            elif item.claim_kind in categorical_kinds:
                state = EvidenceDispositionState.DROPPED_UNSUPPORTED_CATEGORY
            elif item.claim_kind in {ClaimKind.AP_YEARS, ClaimKind.EMPLOYMENT_INTERVAL}:
                state = EvidenceDispositionState.DROPPED_TIMELINE_POLICY
            else:
                state = EvidenceDispositionState.DROPPED_CROSS_SOURCE
            entries.append(item.model_copy(update={"state": state}))
        return consumed.model_copy(update={"entries": tuple(entries)})

    @staticmethod
    def validate_timeline(
        record: CandidateRecord,
        claims: Sequence[MappedClaim],
    ) -> tuple[TrustState, ReasonCode, tuple[str, ...]]:
        interval_claims = [
            claim
            for claim in claims
            if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL
            and claim.start_date is not None
            and claim.end_date is not None
        ]
        intervals: list[tuple[date, date]] = []
        for claim in interval_claims:
            if claim.start_date is not None and claim.end_date is not None:
                intervals.append((claim.start_date, claim.end_date))
        interval_evidence_ids = tuple(
            sorted({item for claim in interval_claims for item in claim.evidence_ids})
        )
        if not record.invoice_processing and not intervals:
            return TrustState.USABLE, ReasonCode.TIMELINE_VALID, ()
        if not intervals:
            return TrustState.DEGRADED, ReasonCode.TIMELINE_UNAVAILABLE, ()
        total_years = _merged_interval_days(intervals) / 365.2425
        if total_years + 0.35 < record.ap_years:
            return (
                TrustState.QUARANTINED,
                ReasonCode.TIMELINE_CONFLICT,
                interval_evidence_ids,
            )
        if total_years > record.ap_years + 0.75:
            return TrustState.DEGRADED, ReasonCode.TIMELINE_DRIFT, interval_evidence_ids
        return TrustState.USABLE, ReasonCode.TIMELINE_VALID, interval_evidence_ids

    @staticmethod
    def _support_graph(
        candidate_id: str,
        snapshot_id: str,
        fact_evidence: Mapping[ClaimKind, tuple[str, ...]],
        normalized_values: Mapping[ClaimKind, bool | int | float | str],
        categorical_source_values: Mapping[ClaimKind, str],
        employment_intervals: tuple[SupportedEmploymentInterval, ...],
        catalog: Mapping[str, EvidenceRef],
    ) -> DecisionSupportGraph:
        facts = tuple(
            SupportedFact(
                fact_id=f"fact:{snapshot_id}:{candidate_id}:{kind.value}",
                candidate_id=candidate_id,
                snapshot_id=snapshot_id,
                kind=kind,
                normalized_value=normalized_values[kind],
                source_value=categorical_source_values.get(kind),
                canonical_value=(
                    str(normalized_values[kind]) if kind in CATEGORICAL_ALLOW_LISTS else None
                ),
                normalization_mode=(
                    NormalizationMode.BOUNDED_ALLOW_LIST_V1
                    if kind in CATEGORICAL_ALLOW_LISTS
                    else None
                ),
                canonical_value_sha256=(
                    compute_canonical_value_hash(str(normalized_values[kind]))
                    if kind in CATEGORICAL_ALLOW_LISTS
                    else None
                ),
                employment_intervals=(
                    employment_intervals if kind is ClaimKind.EMPLOYMENT_INTERVAL else ()
                ),
                source_roles=tuple(
                    sorted(
                        {catalog[evidence_id].source_kind for evidence_id in evidence_ids},
                        key=str,
                    )
                ),
                evidence_ids=tuple(sorted(set(evidence_ids))),
            )
            for kind, evidence_ids in sorted(fact_evidence.items(), key=lambda item: str(item[0]))
            if evidence_ids
            and kind in normalized_values
            and all(evidence_id in catalog for evidence_id in evidence_ids)
        )
        facts_by_kind = {fact.kind: fact for fact in facts}
        identity_fact = facts_by_kind[ClaimKind.CANDIDATE_ID]
        features: list[DerivedFeature] = []

        def fact_feature(name: str, kind: ClaimKind, value: bool) -> str | None:
            fact = facts_by_kind.get(kind)
            if fact is None:
                return None
            feature_id = f"feature:{snapshot_id}:{candidate_id}:{name}"
            features.append(
                DerivedFeature(
                    feature_id=feature_id,
                    candidate_id=candidate_id,
                    snapshot_id=snapshot_id,
                    name=name,
                    normalized_value=value,
                    dependency_fact_ids=(fact.fact_id,),
                )
            )
            return feature_id

        essential_ids = tuple(
            item
            for item in (
                fact_feature(
                    "essential_invoice_processing",
                    ClaimKind.INVOICE_PROCESSING,
                    facts_by_kind.get(ClaimKind.INVOICE_PROCESSING) is not None
                    and facts_by_kind[ClaimKind.INVOICE_PROCESSING].normalized_value is True,
                ),
                fact_feature(
                    "essential_reconciliation",
                    ClaimKind.RECONCILIATION,
                    facts_by_kind.get(ClaimKind.RECONCILIATION) is not None
                    and facts_by_kind[ClaimKind.RECONCILIATION].normalized_value is True,
                ),
                fact_feature(
                    "essential_spreadsheet",
                    ClaimKind.SPREADSHEET,
                    ClaimKind.SPREADSHEET in facts_by_kind,
                ),
                fact_feature(
                    "essential_accounting_platform",
                    ClaimKind.ACCOUNTING_PLATFORM,
                    ClaimKind.ACCOUNTING_PLATFORM in facts_by_kind,
                ),
            )
            if item is not None
        )
        ap_fact = facts_by_kind.get(ClaimKind.AP_YEARS)
        interval_fact = facts_by_kind.get(ClaimKind.EMPLOYMENT_INTERVAL)
        preferred_ids: list[str] = []
        if ap_fact is not None and (
            interval_fact is not None or float(ap_fact.normalized_value or 0) == 0
        ):
            feature_id = f"feature:{snapshot_id}:{candidate_id}:preferred_ap_years"
            dependency_fact_ids = (
                (ap_fact.fact_id, interval_fact.fact_id)
                if interval_fact is not None
                else (ap_fact.fact_id,)
            )
            features.append(
                DerivedFeature(
                    feature_id=feature_id,
                    candidate_id=candidate_id,
                    snapshot_id=snapshot_id,
                    name="preferred_ap_years",
                    normalized_value=float(ap_fact.normalized_value or 0) >= 2.0,
                    dependency_fact_ids=dependency_fact_ids,
                )
            )
            preferred_ids.append(feature_id)
        volume_fact = facts_by_kind.get(ClaimKind.MONTHLY_INVOICE_VOLUME)
        invoice_fact = facts_by_kind.get(ClaimKind.INVOICE_PROCESSING)
        if volume_fact is not None and invoice_fact is not None:
            feature_id = f"feature:{snapshot_id}:{candidate_id}:preferred_volume"
            features.append(
                DerivedFeature(
                    feature_id=feature_id,
                    candidate_id=candidate_id,
                    snapshot_id=snapshot_id,
                    name="preferred_volume",
                    normalized_value=(
                        invoice_fact.normalized_value is True
                        and float(volume_fact.normalized_value or 0) >= 300
                    ),
                    dependency_fact_ids=(invoice_fact.fact_id, volume_fact.fact_id),
                )
            )
            preferred_ids.append(feature_id)
        qualification_id = fact_feature(
            "preferred_qualification",
            ClaimKind.QUALIFICATION,
            ClaimKind.QUALIFICATION in facts_by_kind,
        )
        if qualification_id is not None:
            preferred_ids.append(qualification_id)

        feature_by_id = {feature.feature_id: feature for feature in features}
        essentials_count = sum(
            feature_by_id[item].normalized_value is True for item in essential_ids
        )
        preferred_count = sum(
            feature_by_id[item].normalized_value is True for item in preferred_ids
        )
        corroborated_count = len(
            {fact.kind for fact in facts if fact.kind is not ClaimKind.CANDIDATE_ID}
        )
        count_feature_ids: list[str] = []
        for name, value, dependencies in (
            ("essentials_count", essentials_count, essential_ids),
            ("preferred_count", preferred_count, tuple(preferred_ids)),
        ):
            feature_id = f"feature:{snapshot_id}:{candidate_id}:{name}"
            features.append(
                DerivedFeature(
                    feature_id=feature_id,
                    candidate_id=candidate_id,
                    snapshot_id=snapshot_id,
                    name=name,
                    normalized_value=value,
                    dependency_fact_ids=(identity_fact.fact_id,),
                    dependency_feature_ids=dependencies,
                )
            )
            count_feature_ids.append(feature_id)
        corroborated_id = f"feature:{snapshot_id}:{candidate_id}:corroborated_count"
        features.append(
            DerivedFeature(
                feature_id=corroborated_id,
                candidate_id=candidate_id,
                snapshot_id=snapshot_id,
                name="corroborated_count",
                normalized_value=corroborated_count,
                dependency_fact_ids=tuple(fact.fact_id for fact in facts),
            )
        )
        if essentials_count == 4 and preferred_count > 0:
            band = ReviewBand.STRONG_EVIDENCE_MATCH
            queue = ReviewQueue.PRIORITY_HUMAN_REVIEW
            band_priority = 2
        elif essentials_count == 3 or (essentials_count == 4 and preferred_count == 0):
            band = ReviewBand.POTENTIAL_EVIDENCE_MATCH
            queue = ReviewQueue.STANDARD_HUMAN_REVIEW
            band_priority = 1
        else:
            band = ReviewBand.INSUFFICIENT_SUPPORTED_EVIDENCE
            queue = ReviewQueue.EVIDENCE_CHECK
            band_priority = 0
        essentials_id, preferred_count_id = count_feature_ids
        band_id = f"feature:{snapshot_id}:{candidate_id}:band"
        features.append(
            DerivedFeature(
                feature_id=band_id,
                candidate_id=candidate_id,
                snapshot_id=snapshot_id,
                name="band",
                normalized_value=band.value,
                dependency_feature_ids=(essentials_id, preferred_count_id),
            )
        )
        component_values = (
            ("rank_band_priority", band_priority, (band_id,)),
            ("rank_essentials", essentials_count, (essentials_id,)),
            ("rank_preferred", preferred_count, (preferred_count_id,)),
            ("rank_corroborated", corroborated_count, (corroborated_id,)),
        )
        rank_component_ids: list[str] = []
        for name, value, dependencies in component_values:
            feature_id = f"feature:{snapshot_id}:{candidate_id}:{name}"
            features.append(
                DerivedFeature(
                    feature_id=feature_id,
                    candidate_id=candidate_id,
                    snapshot_id=snapshot_id,
                    name=name,
                    normalized_value=value,
                    dependency_feature_ids=dependencies,
                )
            )
            rank_component_ids.append(feature_id)
        rank_key_id = f"feature:{snapshot_id}:{candidate_id}:rank_key"
        features.append(
            DerivedFeature(
                feature_id=rank_key_id,
                candidate_id=candidate_id,
                snapshot_id=snapshot_id,
                name="rank_key",
                normalized_value=(
                    f"{band_priority}-{essentials_count}-{preferred_count}-{corroborated_count}"
                ),
                dependency_feature_ids=tuple(rank_component_ids),
            )
        )
        queue_id = f"feature:{snapshot_id}:{candidate_id}:queue"
        features.append(
            DerivedFeature(
                feature_id=queue_id,
                candidate_id=candidate_id,
                snapshot_id=snapshot_id,
                name="queue",
                normalized_value=queue.value,
                dependency_feature_ids=(band_id,),
            )
        )
        route_id = f"feature:{snapshot_id}:{candidate_id}:route"
        features.append(
            DerivedFeature(
                feature_id=route_id,
                candidate_id=candidate_id,
                snapshot_id=snapshot_id,
                name="route",
                normalized_value="human_review_route",
                dependency_feature_ids=(rank_key_id, band_id, queue_id),
            )
        )
        evidence_ids = tuple(sorted({item for fact in facts for item in fact.evidence_ids}))
        return DecisionSupportGraph(
            candidate_id=candidate_id,
            snapshot_id=snapshot_id,
            evidence_ids=evidence_ids,
            evidence_manifest=tuple(
                sorted(
                    (catalog[evidence_id] for evidence_id in evidence_ids),
                    key=lambda item: item.evidence_id,
                )
            ),
            facts=facts,
            features=tuple(features),
            route_support_ids=(route_id,),
        )

    @staticmethod
    def empty_candidate(
        candidate_id: str,
        snapshot_id: str,
        state: TrustState,
        reasons: tuple[ReasonCode, ...],
    ) -> ValidatedCandidateEvidence:
        return ValidatedCandidateEvidence(
            candidate_id=candidate_id,
            snapshot_id=snapshot_id,
            trust_state=state,
            reason_codes=reasons,
        )

    @staticmethod
    def _claim_value(claim: MappedClaim) -> Any:
        if claim.bool_value is not None:
            return claim.bool_value
        if claim.number_value is not None:
            return claim.number_value
        return claim.text_value

    @staticmethod
    def _values_equal(kind: ClaimKind, expected: Any, observed: Any) -> bool:
        if kind in {ClaimKind.AP_YEARS, ClaimKind.MONTHLY_INVOICE_VOLUME}:
            return abs(float(expected) - float(observed)) <= 0.01
        if kind in {ClaimKind.INVOICE_PROCESSING, ClaimKind.RECONCILIATION}:
            return bool(expected) is bool(observed)
        return str(expected).strip().casefold() == str(observed).strip().casefold()

    @staticmethod
    def _worst_state(*states: TrustState) -> TrustState:
        order = {
            TrustState.USABLE: 0,
            TrustState.DEGRADED: 1,
            TrustState.UNAVAILABLE: 2,
            TrustState.QUARANTINED: 3,
        }
        return max(states, key=order.__getitem__)

    @staticmethod
    def outcome_for(state: TrustState) -> TrustOutcome:
        return {
            TrustState.USABLE: TrustOutcome.ALLOW,
            TrustState.DEGRADED: TrustOutcome.RESTRICT,
            TrustState.QUARANTINED: TrustOutcome.QUARANTINE,
            TrustState.UNAVAILABLE: TrustOutcome.UNAVAILABLE,
        }[state]


def unique_by_candidate(items: Sequence[Any]) -> tuple[dict[str, Any], bool]:
    result: dict[str, Any] = {}
    duplicate = False
    for item in items:
        if item.candidate_id in result:
            duplicate = True
        result[item.candidate_id] = item
    return result, duplicate


def unique_request_map(items: Sequence[MapperRequest]) -> tuple[dict[str, MapperRequest], bool]:
    result: dict[str, MapperRequest] = {}
    duplicate = False
    for item in items:
        if item.candidate_id in result:
            duplicate = True
        result[item.candidate_id] = item
    return result, duplicate


def _merged_interval_days(intervals: Sequence[tuple[date, date]]) -> int:
    ordered = sorted(intervals)
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
