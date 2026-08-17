"""Independent, deterministic authorization of a proposed ranking release."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from cv_trust_agent.models import (
    STRUCTURED_FIELD_KINDS,
    CandidateRoute,
    ClaimKind,
    DerivedFeature,
    EvidenceDispositionEntry,
    EvidenceDispositionInventory,
    EvidenceDispositionState,
    EvidenceRef,
    ExecutionPlan,
    NormalizationMode,
    PlanObjective,
    PlanStep,
    ProhibitedAction,
    ReasonCode,
    ReviewBand,
    ReviewQueue,
    SourceKind,
    StepReceipt,
    StepStatus,
    Strategy,
    StructuredFieldAnchor,
    SupportedFact,
    TrustDecision,
    TrustOutcome,
    TrustScope,
    TrustStage,
    TrustState,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)

_CANONICAL_VALUE_DOMAIN = b"cv-trust-agent/canonical-value/v2\0"
_SAFE_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .+#&/_()-]*$")
_CATEGORICAL_ALLOW_LISTS = {
    ClaimKind.SPREADSHEET: frozenset({"excel", "google sheets"}),
    ClaimKind.ACCOUNTING_PLATFORM: frozenset({"xero", "sage", "quickbooks", "netsuite", "sap"}),
    ClaimKind.QUALIFICATION: frozenset({"aat level 2", "aat level 3", "aat level 4", "acca"}),
}

_BASE_PROHIBITIONS = (
    ProhibitedAction.AUTOMATED_HIRE,
    ProhibitedAction.AUTOMATED_REJECT,
    ProhibitedAction.EXECUTE_SOURCE_INSTRUCTIONS,
    ProhibitedAction.USE_RAW_SOURCE_TEXT,
    ProhibitedAction.USE_PROTECTED_ATTRIBUTES,
    ProhibitedAction.RANK_QUARANTINED_EVIDENCE,
    ProhibitedAction.RANK_UNAVAILABLE_CANDIDATE,
)
_OBJECTIVE_BY_STRATEGY = {
    Strategy.FULL_EVIDENCE_RANKING: PlanObjective.RANK_FULL_CORROBORATED_EVIDENCE,
    Strategy.SUPPORTED_ONLY_RANKING: PlanObjective.RANK_SUPPORTED_EVIDENCE_ONLY,
    Strategy.PARTIAL_SAFE_RANKING: PlanObjective.RANK_AVAILABLE_EVIDENCE_SAFELY,
    Strategy.BATCH_INTEGRITY_HOLD: PlanObjective.HOLD_BATCH_FOR_INTEGRITY_REVIEW,
}
_FINAL_STEPS_BY_STRATEGY = {
    Strategy.FULL_EVIDENCE_RANKING: (
        PlanStep.RANK_FULL_EVIDENCE,
        PlanStep.PRE_RELEASE_AUDIT,
        PlanStep.RELEASE_OUTPUT,
    ),
    Strategy.SUPPORTED_ONLY_RANKING: (
        PlanStep.QUARANTINE_UNSUPPORTED,
        PlanStep.RANK_SUPPORTED_EVIDENCE,
        PlanStep.PRE_RELEASE_AUDIT,
        PlanStep.RELEASE_OUTPUT,
    ),
    Strategy.PARTIAL_SAFE_RANKING: (
        PlanStep.MARK_EVIDENCE_PENDING,
        PlanStep.RANK_PARTIAL_EVIDENCE,
        PlanStep.REQUEST_CORROBORATION,
        PlanStep.PRE_RELEASE_AUDIT,
        PlanStep.RELEASE_OUTPUT,
    ),
    Strategy.BATCH_INTEGRITY_HOLD: (
        PlanStep.ISOLATE_BATCH,
        PlanStep.REQUEST_CORROBORATION,
        PlanStep.PRE_RELEASE_AUDIT,
        PlanStep.RELEASE_OUTPUT,
    ),
}
_FULL_V1_STEPS = (
    PlanStep.FETCH_CANDIDATE_DETAILS,
    PlanStep.VALIDATE_CANDIDATE_DETAILS,
    PlanStep.FETCH_CANDIDATE_RESUMES,
    PlanStep.PARSE_CANDIDATE_RESUMES,
    PlanStep.VALIDATE_CANDIDATE_BINDINGS,
    PlanStep.MAP_CANDIDATE_CLAIMS,
    PlanStep.VALIDATE_CANDIDATE_EVIDENCE,
    *_FINAL_STEPS_BY_STRATEGY[Strategy.FULL_EVIDENCE_RANKING],
)
_COMMAND_GATE_POLICY: dict[PlanStep, tuple[TrustStage, frozenset[ReasonCode]]] = {
    PlanStep.FETCH_CANDIDATE_DETAILS: (
        TrustStage.RETRIEVAL,
        frozenset({ReasonCode.COMMAND_COMPLETED}),
    ),
    PlanStep.VALIDATE_CANDIDATE_DETAILS: (
        TrustStage.SCHEMA,
        frozenset({ReasonCode.COMMAND_COMPLETED}),
    ),
    PlanStep.FETCH_CANDIDATE_RESUMES: (
        TrustStage.RETRIEVAL,
        frozenset({ReasonCode.COMMAND_COMPLETED}),
    ),
    PlanStep.PARSE_CANDIDATE_RESUMES: (
        TrustStage.PARSING,
        frozenset({ReasonCode.COMMAND_COMPLETED}),
    ),
    PlanStep.VALIDATE_CANDIDATE_BINDINGS: (
        TrustStage.IDENTITY,
        frozenset({ReasonCode.COMMAND_COMPLETED}),
    ),
    PlanStep.MAP_CANDIDATE_CLAIMS: (
        TrustStage.MAPPING,
        frozenset({ReasonCode.COMMAND_COMPLETED}),
    ),
    PlanStep.VALIDATE_CANDIDATE_EVIDENCE: (
        TrustStage.PROVENANCE,
        frozenset({ReasonCode.COMMAND_COMPLETED}),
    ),
    PlanStep.VALIDATE_INDEX_COMMITMENTS: (
        TrustStage.MANIFEST,
        frozenset({ReasonCode.MANIFEST_CONFLICT}),
    ),
    PlanStep.QUARANTINE_UNSUPPORTED: (
        TrustStage.PROVENANCE,
        frozenset({ReasonCode.RECORD_QUARANTINED}),
    ),
    PlanStep.MARK_EVIDENCE_PENDING: (
        TrustStage.RETRIEVAL,
        frozenset({ReasonCode.CANDIDATE_UNAVAILABLE}),
    ),
    PlanStep.RANK_FULL_EVIDENCE: (
        TrustStage.RANKING,
        frozenset({ReasonCode.RANKING_ALLOWED}),
    ),
    PlanStep.RANK_SUPPORTED_EVIDENCE: (
        TrustStage.RANKING,
        frozenset({ReasonCode.RANKING_RESTRICTED}),
    ),
    PlanStep.RANK_PARTIAL_EVIDENCE: (
        TrustStage.RANKING,
        frozenset({ReasonCode.RANKING_PARTIAL}),
    ),
    PlanStep.ISOLATE_BATCH: (
        TrustStage.RANKING,
        frozenset({ReasonCode.RANKING_HELD, ReasonCode.BATCH_HOLD_REQUIRED}),
    ),
    PlanStep.REQUEST_CORROBORATION: (
        TrustStage.PLANNING,
        frozenset({ReasonCode.CORROBORATION_REQUIRED}),
    ),
    PlanStep.PRE_RELEASE_AUDIT: (
        TrustStage.PRE_RELEASE,
        frozenset({ReasonCode.SUPPORT_GRAPH_VALID, ReasonCode.RELEASE_AUTHORIZED}),
    ),
    PlanStep.RELEASE_OUTPUT: (
        TrustStage.RELEASE,
        frozenset({ReasonCode.RELEASE_AUTHORIZED}),
    ),
}


def _canonicalize_categorical(kind: ClaimKind, value: str) -> str | None:
    normalized = " ".join(value.split()).casefold()
    return normalized if normalized in _CATEGORICAL_ALLOW_LISTS.get(kind, ()) else None


def _canonical_value_hash(value: str) -> str:
    return hashlib.sha256(_CANONICAL_VALUE_DOMAIN + value.encode("utf-8")).hexdigest()


def _bounded_evidence_id(prefix: str, *parts: str) -> str:
    """Independently reproduce the canonical adapter's bounded identifier.

    Source identifiers and claim-kind values have already crossed strict
    allow-list boundaries, so length is the only condition that can force the
    canonical adapter's digest fallback for these application-JSON IDs.
    """

    readable = ":".join((prefix, *parts))
    if len(readable) <= 128:
        return readable
    return f"{prefix}:{hashlib.sha256(readable.encode('utf-8')).hexdigest()}"


def _expected_json_evidence_id(
    candidate_id: str,
    snapshot_id: str,
    kind: ClaimKind | str,
    semantic_hash: str,
) -> str:
    role = kind.value if isinstance(kind, ClaimKind) else kind
    return _bounded_evidence_id("json", snapshot_id, candidate_id, semantic_hash, role)


def _expected_json_field_path(candidate_id: str, role: str) -> str:
    detailed = f"records[{candidate_id}].{role}"
    return detailed if len(detailed) <= 160 else f"record.{role}"


def _structured_value_valid(
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
    if kind in _CATEGORICAL_ALLOW_LISTS:
        shape_valid = (
            type(value) is str
            and value == value.strip()
            and 1 <= len(value) <= 80
            and _SAFE_LABEL_PATTERN.fullmatch(value) is not None
        )
        return shape_valid and isinstance(value, str)
    return False


def _structured_values_equal(kind: ClaimKind, expected: object, observed: object) -> bool:
    if kind in {ClaimKind.AP_YEARS, ClaimKind.MONTHLY_INVOICE_VOLUME}:
        if not isinstance(expected, int | float) or not isinstance(observed, int | float):
            return False
        if isinstance(expected, bool) or isinstance(observed, bool):
            return False
        return abs(float(expected) - float(observed)) <= 0.01
    if kind in {ClaimKind.INVOICE_PROCESSING, ClaimKind.RECONCILIATION}:
        return type(expected) is bool and expected is observed
    return (
        type(expected) is str
        and type(observed) is str
        and expected.strip().casefold() == observed.strip().casefold()
    )


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


@dataclass(frozen=True)
class AuthorizationResult:
    authorized: bool
    reason_codes: tuple[ReasonCode, ...]


@dataclass(frozen=True)
class _CrossSourceProjection:
    state: TrustState
    outcome: TrustOutcome
    reason_codes: tuple[ReasonCode, ...]
    gate_reason_codes: tuple[ReasonCode, ...]
    evidence_ids: tuple[str, ...]
    matched_kinds: frozenset[ClaimKind]
    dropped_category_kinds: frozenset[ClaimKind]


class ReleaseAuthorizer:
    """Check release invariants without recomputing ranks or calling the controller."""

    def authorize(
        self,
        batch: ValidatedBatchEvidence,
        routes: Sequence[CandidateRoute],
        plan: ExecutionPlan,
        receipts: Sequence[StepReceipt],
        *,
        trust_ledger: Sequence[TrustDecision],
        plan_history: Sequence[ExecutionPlan] | None = None,
    ) -> AuthorizationResult:
        reasons: set[ReasonCode] = set()
        try:
            if not self._release_policy_valid(batch, routes, plan, trust_ledger):
                reasons.add(ReasonCode.RELEASE_BLOCKED)
            if not self._trust_ledger_valid(batch, receipts, trust_ledger):
                reasons.add(ReasonCode.RELEASE_BLOCKED)
            if not self._plan_receipts_valid(
                plan,
                receipts,
                trust_ledger,
                tuple(plan_history or (plan,)),
            ):
                reasons.add(ReasonCode.RELEASE_BLOCKED)
            if not self._routes_match_scope(batch, routes, plan):
                reasons.add(ReasonCode.RELEASE_BLOCKED)
            if not self._support_is_closed(batch, routes, plan):
                reasons.update({ReasonCode.SUPPORT_GRAPH_INCOMPLETE, ReasonCode.RELEASE_BLOCKED})
            if not self._provenance_closure_valid(batch, routes, receipts, trust_ledger):
                reasons.update({ReasonCode.SUPPORT_GRAPH_INCOMPLETE, ReasonCode.RELEASE_BLOCKED})
            if not self._order_is_valid(routes):
                reasons.add(ReasonCode.RELEASE_BLOCKED)
        except (ArithmeticError, AttributeError, KeyError, TypeError, ValueError):
            reasons.add(ReasonCode.RELEASE_BLOCKED)
        if reasons:
            return AuthorizationResult(False, tuple(sorted(reasons, key=str)))
        return AuthorizationResult(
            True,
            (ReasonCode.SUPPORT_GRAPH_VALID, ReasonCode.RELEASE_AUTHORIZED),
        )

    @staticmethod
    def _provenance_closure_valid(
        batch: ValidatedBatchEvidence,
        routes: Sequence[CandidateRoute],
        receipts: Sequence[StepReceipt],
        trust_ledger: Sequence[TrustDecision],
    ) -> bool:
        """Re-derive exact consumed/released/dropped evidence accounting.

        A reason marker never authorizes a superset.  The provenance gate must
        carry the exact pre-consumption inventory, the terminal candidate gate
        must disposition every one of those same typed references, and the
        released subset must equal the visible non-identity support graph.
        """

        has_ranked_route = any(route.rank_key is not None for route in routes)
        has_audit_inventory = any(
            decision.evidence_inventory is not None
            for decision in trust_ledger
            if decision.scope is TrustScope.RECORD
        )
        has_completed_record_mapping = any(
            decision.scope is TrustScope.RECORD
            and decision.stage is TrustStage.MAPPING
            and decision.state is TrustState.USABLE
            and decision.outcome is TrustOutcome.ALLOW
            and decision.reason_codes == (ReasonCode.MAPPER_OUTPUT_VALID,)
            for decision in trust_ledger
        )
        if not has_ranked_route and not has_audit_inventory and not has_completed_record_mapping:
            return True
        mapping_receipts = tuple(
            receipt
            for receipt in receipts
            if receipt.command_kind is PlanStep.MAP_CANDIDATE_CLAIMS
            and receipt.status is StepStatus.COMPLETED
        )
        catalog_receipts = tuple(
            receipt
            for receipt in receipts
            if receipt.command_kind is PlanStep.PARSE_CANDIDATE_RESUMES
            and receipt.status is StepStatus.COMPLETED
        )
        if len(mapping_receipts) != 1 or len(catalog_receipts) != 1:
            return False
        catalog_ids = set(catalog_receipts[0].evidence_ids)
        mapping_ids = set(mapping_receipts[0].evidence_ids)
        if (
            len(catalog_ids) != len(catalog_receipts[0].evidence_ids)
            or len(mapping_ids) != len(mapping_receipts[0].evidence_ids)
            or not mapping_ids.issubset(catalog_ids)
        ):
            return False
        derived_mapping_ids: set[str] = set()
        candidates = {candidate.candidate_id: candidate for candidate in batch.candidates}
        for route in routes:
            candidate = candidates.get(route.candidate_id)
            if candidate is None:
                return False
            ranked = route.rank_key is not None
            graph = candidate.support_graph
            if ranked and graph is None:
                return False
            record_gates = {
                stage: tuple(
                    decision
                    for decision in trust_ledger
                    if decision.stage is stage
                    and decision.scope is TrustScope.RECORD
                    and decision.candidate_id == route.candidate_id
                )
                for stage in (
                    TrustStage.MAPPING,
                    TrustStage.PROVENANCE,
                    TrustStage.TIMELINE,
                    TrustStage.CROSS_SOURCE,
                    TrustStage.CANDIDATE_VALIDATION,
                )
            }
            if any(len(items) > 1 for items in record_gates.values()):
                return False
            mapping_items = record_gates[TrustStage.MAPPING]
            provenance_items = record_gates[TrustStage.PROVENANCE]
            timeline_items = record_gates[TrustStage.TIMELINE]
            cross_items = record_gates[TrustStage.CROSS_SOURCE]
            terminal_items = record_gates[TrustStage.CANDIDATE_VALIDATION]
            consumed = provenance_items[0].evidence_inventory if provenance_items else None
            final = terminal_items[0].evidence_inventory if terminal_items else None
            if consumed is None:
                completed_mapping = bool(
                    mapping_items
                    and mapping_items[0].state is TrustState.USABLE
                    and mapping_items[0].outcome is TrustOutcome.ALLOW
                    and mapping_items[0].reason_codes == (ReasonCode.MAPPER_OUTPUT_VALID,)
                )
                usable_provenance = bool(
                    provenance_items
                    and provenance_items[0].state is TrustState.USABLE
                    and provenance_items[0].outcome is TrustOutcome.ALLOW
                )
                if (
                    ranked
                    or final is not None
                    or (completed_mapping and not provenance_items)
                    or (mapping_items and mapping_items[0].evidence_inventory is not None)
                    or (completed_mapping and usable_provenance)
                ):
                    return False
                continue
            if (
                len(mapping_items) != 1
                or not provenance_items
                or not timeline_items
                or not terminal_items
            ):
                return False
            mapping = mapping_items[0]
            provenance = provenance_items[0]
            timeline = timeline_items[0]
            cross_source = cross_items[0] if cross_items else None
            terminal = terminal_items[0]
            expected_terminal_parent = (
                cross_source.decision_id if cross_source is not None else timeline.decision_id
            )
            if (
                provenance.input_gate_ids != (mapping.decision_id,)
                or mapping.state is not TrustState.USABLE
                or mapping.outcome is not TrustOutcome.ALLOW
                or mapping.reason_codes != (ReasonCode.MAPPER_OUTPUT_VALID,)
                or mapping.evidence_inventory != consumed
                or mapping.evidence_ids != provenance.evidence_ids
                or timeline.input_gate_ids != (provenance.decision_id,)
                or (
                    cross_source is not None
                    and cross_source.input_gate_ids != (timeline.decision_id,)
                )
                or terminal.input_gate_ids != (expected_terminal_parent,)
                or provenance.state is not TrustState.USABLE
                or provenance.outcome is not TrustOutcome.ALLOW
                or provenance.reason_codes != (ReasonCode.EVIDENCE_ADMISSIBLE,)
                or terminal.state is not candidate.trust_state
                or terminal.outcome
                is not ReleaseAuthorizer._outcome_for_state(candidate.trust_state)
                or terminal.reason_codes != candidate.reason_codes
                or terminal.evidence_ids != candidate.evidence_ids
            ):
                return False
            if (
                consumed.candidate_id != route.candidate_id
                or consumed.snapshot_id != candidate.snapshot_id
            ):
                return False
            consumed_by_id = ReleaseAuthorizer._inventory_by_id(consumed.entries)
            if consumed_by_id is None:
                return False
            if set(provenance.evidence_ids) != set(consumed_by_id) or len(
                provenance.evidence_ids
            ) != len(consumed_by_id):
                return False
            for evidence_id, consumed_item in consumed_by_id.items():
                if (
                    consumed_item.state is not EvidenceDispositionState.CONSUMED
                    or not ReleaseAuthorizer._disposition_reference_valid(
                        consumed_item,
                        candidate_id=route.candidate_id,
                        snapshot_id=candidate.snapshot_id,
                    )
                    or evidence_id not in catalog_ids
                ):
                    return False
            candidate_mapping_ids = {
                *consumed_by_id,
                *(anchor.reference.evidence_id for anchor in consumed.structured_anchors),
            }
            if derived_mapping_ids.intersection(candidate_mapping_ids):
                return False
            derived_mapping_ids.update(candidate_mapping_ids)
            if not ReleaseAuthorizer._consumed_inventory_values_valid(
                consumed,
                consumed_by_id,
                catalog_ids=catalog_ids,
            ):
                return False
            if not ReleaseAuthorizer._timeline_inventory_matches_gate(
                consumed_by_id,
                timeline,
                record_ap_years=consumed.record_ap_years,
                record_invoice_processing=consumed.record_invoice_processing,
            ):
                return False
            cross_projection: _CrossSourceProjection | None = None
            if cross_source is not None:
                cross_projection = ReleaseAuthorizer._cross_source_inventory_matches_gate(
                    consumed,
                    consumed_by_id,
                    cross_source,
                    catalog_ids=catalog_ids,
                )
                if cross_projection is None:
                    return False
            if final is None:
                if ranked:
                    return False
                if not ReleaseAuthorizer._unranked_dispositions_match_gates(
                    candidate,
                    consumed_by_id,
                    provenance,
                    timeline,
                    cross_source,
                    cross_projection,
                    terminal,
                    catalog_ids,
                ):
                    return False
                continue
            if cross_source is None or (
                final.candidate_id != consumed.candidate_id
                or final.snapshot_id != consumed.snapshot_id
                or final.record_ap_years != consumed.record_ap_years
                or final.record_invoice_processing is not consumed.record_invoice_processing
                or final.record_ap_years_reference != consumed.record_ap_years_reference
                or final.record_invoice_processing_reference
                != consumed.record_invoice_processing_reference
                or final.structured_anchors != consumed.structured_anchors
            ):
                return False
            final_by_id = ReleaseAuthorizer._inventory_by_id(final.entries)
            if final_by_id is None or set(consumed_by_id) != set(final_by_id):
                return False
            for evidence_id, consumed_item in consumed_by_id.items():
                final_item = final_by_id[evidence_id]
                if (
                    final_item.state is EvidenceDispositionState.CONSUMED
                    or consumed_item.claim_kind is not final_item.claim_kind
                    or consumed_item.reference != final_item.reference
                    or consumed_item.date_value != final_item.date_value
                    or consumed_item.mapped_value != final_item.mapped_value
                    or type(consumed_item.mapped_value) is not type(final_item.mapped_value)
                ):
                    return False
            if graph is not None and not ReleaseAuthorizer._dispositions_match_release(
                candidate,
                graph.facts,
                graph.evidence_manifest,
                final_by_id,
                timeline,
                cross_source,
                structured_anchors=final.structured_anchors,
                record_ap_years=final.record_ap_years,
                record_invoice_processing=final.record_invoice_processing,
            ):
                return False
        return derived_mapping_ids == mapping_ids

    @staticmethod
    def _inventory_by_id(
        entries: Sequence[EvidenceDispositionEntry],
    ) -> dict[str, EvidenceDispositionEntry] | None:
        result = {item.reference.evidence_id: item for item in entries}
        return result if len(result) == len(entries) else None

    @staticmethod
    def _consumed_inventory_values_valid(
        inventory: EvidenceDispositionInventory,
        entries: dict[str, EvidenceDispositionEntry],
        *,
        catalog_ids: set[str],
    ) -> bool:
        """Independently validate the complete typed structured evidence set."""

        anchors = inventory.structured_anchors
        if (
            type(anchors) is not tuple
            or len(anchors) != len(STRUCTURED_FIELD_KINDS)
            or tuple(anchor.claim_kind for anchor in anchors) != STRUCTURED_FIELD_KINDS
        ):
            return False
        candidate_id = inventory.candidate_id
        snapshot_id = inventory.snapshot_id
        anchor_ids: set[str] = set()
        anchors_by_kind: dict[ClaimKind, StructuredFieldAnchor] = {}
        for anchor in anchors:
            if not isinstance(anchor, StructuredFieldAnchor):
                return False
            kind = anchor.claim_kind
            value = anchor.value
            reference = anchor.reference
            role = kind.value
            if (
                kind in anchors_by_kind
                or not _structured_value_valid(kind, value, allow_null=True)
                or reference.evidence_id in anchor_ids
                or reference.evidence_id in entries
                or reference.evidence_id not in catalog_ids
                or reference.candidate_id != candidate_id
                or reference.snapshot_id != snapshot_id
                or reference.source_kind is not SourceKind.APPLICATION_JSON
                or reference.visible is not True
                or reference.admissible is not True
                or reference.field_path != _expected_json_field_path(candidate_id, role)
                or reference.evidence_id
                != _expected_json_evidence_id(
                    candidate_id,
                    snapshot_id,
                    role,
                    reference.semantic_hash,
                )
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
                or reference.semantic_hash != ReleaseAuthorizer._evidence_value_hash(value)
            ):
                return False
            anchor_ids.add(reference.evidence_id)
            anchors_by_kind[kind] = anchor

        ap_anchor = anchors_by_kind[ClaimKind.AP_YEARS]
        invoice_anchor = anchors_by_kind[ClaimKind.INVOICE_PROCESSING]
        return (
            type(inventory.record_ap_years) is float
            and inventory.record_ap_years == ap_anchor.value
            and type(inventory.record_ap_years) is type(ap_anchor.value)
            and inventory.record_ap_years_reference == ap_anchor.reference
            and type(inventory.record_invoice_processing) is bool
            and inventory.record_invoice_processing is invoice_anchor.value
            and inventory.record_invoice_processing_reference == invoice_anchor.reference
        )

    @staticmethod
    def _cross_source_inventory_matches_gate(
        inventory: EvidenceDispositionInventory,
        entries: dict[str, EvidenceDispositionEntry],
        cross_source: TrustDecision,
        *,
        catalog_ids: set[str],
    ) -> _CrossSourceProjection | None:
        """Derive the exact typed cross-source closure for one mapped record.

        A cross-source gate carries every mapped non-employment visible-resume
        reference and exactly one canonical application-JSON reference for
        every compared kind. That includes conflicting and unsupported pairs:
        terminal survival is not the audit oracle. Reconstructing this exact
        set from the typed mapping inventory and validated scalar anchors closes
        deletion and same-count rewrites for ranked, unranked, and graph-free
        failed-closed decisions alike.
        """

        cross_ids = cross_source.evidence_ids
        if (
            cross_source.candidate_id != inventory.candidate_id
            or cross_source.snapshot_id != inventory.snapshot_id
            or cross_ids != tuple(sorted(cross_ids))
            or len(cross_ids) != len(set(cross_ids))
            or not set(cross_ids).issubset(catalog_ids)
        ):
            return None

        anchors = {anchor.claim_kind: anchor for anchor in inventory.structured_anchors}
        grouped: dict[ClaimKind, list[EvidenceDispositionEntry]] = {
            kind: [] for kind in STRUCTURED_FIELD_KINDS
        }
        for item in entries.values():
            if item.claim_kind is not ClaimKind.EMPLOYMENT_INTERVAL:
                if item.claim_kind not in grouped:
                    return None
                grouped[item.claim_kind].append(item)

        conflict = False
        missing = False
        matched_kinds: set[ClaimKind] = set()
        expected_ids: set[str] = set()
        for kind in STRUCTURED_FIELD_KINDS:
            anchor = anchors[kind]
            mapped = tuple(grouped[kind])
            if mapped:
                expected_ids.add(anchor.reference.evidence_id)
                expected_ids.update(item.reference.evidence_id for item in mapped)
            if anchor.value is None:
                conflict = conflict or bool(mapped)
                continue
            if not mapped:
                missing = True
                continue
            mapped_values = tuple(item.mapped_value for item in mapped)
            values_match_anchor = all(
                _structured_values_equal(kind, anchor.value, value) for value in mapped_values
            )
            values_are_consistent = all(
                _structured_values_equal(kind, left, right)
                for index, left in enumerate(mapped_values)
                for right in mapped_values[index + 1 :]
            )
            if values_match_anchor and values_are_consistent:
                matched_kinds.add(kind)
            else:
                conflict = True

        if conflict:
            state = TrustState.QUARANTINED
            reasons = {
                ReasonCode.CROSS_SOURCE_CONFLICT,
                ReasonCode.MAPPER_DISAGREEMENT,
            }
        elif missing:
            state = TrustState.DEGRADED
            reasons = {
                ReasonCode.CROSS_SOURCE_MATCH,
                ReasonCode.EVIDENCE_MISSING,
            }
        else:
            state = TrustState.USABLE
            reasons = {ReasonCode.CROSS_SOURCE_MATCH}

        if ClaimKind.MONTHLY_INVOICE_VOLUME in matched_kinds and (
            ClaimKind.INVOICE_PROCESSING not in matched_kinds
            or anchors[ClaimKind.INVOICE_PROCESSING].value is not True
        ):
            matched_kinds.discard(ClaimKind.MONTHLY_INVOICE_VOLUME)
            state = TrustState.QUARANTINED
            reasons.update(
                {
                    ReasonCode.DOMAIN_INVARIANT_CONFLICT,
                    ReasonCode.MAPPER_DISAGREEMENT,
                }
            )

        dropped_categories: set[ClaimKind] = set()
        for kind in _CATEGORICAL_ALLOW_LISTS:
            value = anchors[kind].value
            if (
                kind in matched_kinds
                and isinstance(value, str)
                and _canonicalize_categorical(kind, value) is None
            ):
                dropped_categories.add(kind)
        matched_kinds.difference_update(dropped_categories)
        gate_reasons = set(reasons)
        if dropped_categories:
            gate_reasons.add(ReasonCode.CATEGORY_NOT_SUPPORTED)

        projection = _CrossSourceProjection(
            state=state,
            outcome=ReleaseAuthorizer._outcome_for_state(state),
            reason_codes=tuple(sorted(reasons, key=str)),
            gate_reason_codes=tuple(sorted(gate_reasons, key=str)),
            evidence_ids=tuple(sorted(expected_ids)),
            matched_kinds=frozenset(matched_kinds),
            dropped_category_kinds=frozenset(dropped_categories),
        )
        if (
            cross_source.state is not projection.state
            or cross_source.outcome is not projection.outcome
            or cross_source.reason_codes != projection.gate_reason_codes
            or cross_ids != projection.evidence_ids
        ):
            return None
        return projection

    @staticmethod
    def _unranked_dispositions_match_gates(
        candidate: ValidatedCandidateEvidence,
        inventory: dict[str, EvidenceDispositionEntry],
        provenance: TrustDecision,
        timeline: TrustDecision,
        cross_source: TrustDecision | None,
        cross_projection: _CrossSourceProjection | None,
        terminal: TrustDecision,
        catalog_ids: set[str],
    ) -> bool:
        """Verify a mapped quarantine even though it has no support graph."""

        if (
            candidate.trust_state is not TrustState.QUARANTINED
            or candidate.support_graph is not None
            or candidate.evidence_ids
            or candidate.corroborated_claim_kinds
            or candidate.ap_years is not None
            or candidate.invoice_processing is not None
            or candidate.reconciliation is not None
            or candidate.spreadsheet_supported
            or candidate.accounting_platform_supported
            or candidate.monthly_invoice_volume is not None
            or candidate.qualification_supported
            or terminal.evidence_inventory is not None
            or terminal.evidence_ids
        ):
            return False

        inventory_ids = set(inventory)
        if not inventory_ids.issubset(catalog_ids):
            return False
        if timeline.state is TrustState.QUARANTINED:
            expected_reasons = tuple(
                sorted(
                    {
                        *provenance.reason_codes,
                        *timeline.reason_codes,
                        ReasonCode.MAPPER_DISAGREEMENT,
                    },
                    key=str,
                )
            )
            return (
                cross_source is None
                and timeline.reason_codes == (ReasonCode.TIMELINE_CONFLICT,)
                and terminal.input_gate_ids == (timeline.decision_id,)
                and terminal.reason_codes == expected_reasons
            )

        if (
            cross_source is None
            or cross_projection is None
            or cross_source.state is not TrustState.QUARANTINED
            or cross_source.outcome is not TrustOutcome.QUARANTINE
            or cross_source.input_gate_ids != (timeline.decision_id,)
            or terminal.input_gate_ids != (cross_source.decision_id,)
            or len(cross_source.evidence_ids) != len(set(cross_source.evidence_ids))
            or not set(cross_source.evidence_ids).issubset(catalog_ids)
        ):
            return False

        expected_terminal_reasons = tuple(
            sorted(
                {
                    *provenance.reason_codes,
                    *timeline.reason_codes,
                    *cross_projection.reason_codes,
                },
                key=str,
            )
        )
        return terminal.reason_codes == expected_terminal_reasons

    @staticmethod
    def _timeline_inventory_matches_gate(
        inventory: dict[str, EvidenceDispositionEntry],
        timeline: TrustDecision,
        *,
        record_ap_years: float,
        record_invoice_processing: bool,
    ) -> bool:
        """Recompute timeline semantics from sanitized consumed endpoints only."""

        if (
            not isinstance(record_ap_years, float)
            or isinstance(record_ap_years, bool)
            or not math.isfinite(record_ap_years)
            or not 0 <= record_ap_years <= 80
            or type(record_invoice_processing) is not bool
        ):
            return False
        interval_items = tuple(
            item for item in inventory.values() if item.claim_kind is ClaimKind.EMPLOYMENT_INTERVAL
        )
        starts: list[date] = []
        ends: list[date] = []
        for item in interval_items:
            if type(item.date_value) is not date or item.reference.field_path is None:
                return False
            role = item.reference.field_path.rsplit(".", maxsplit=1)[-1]
            if role == "employment_start":
                starts.append(item.date_value)
            elif role == "employment_end":
                ends.append(item.date_value)
            else:
                return False
        starts.sort()
        ends.sort()
        if len(starts) + len(ends) != len(interval_items) or len(starts) != len(ends):
            return False
        intervals = tuple(zip(starts, ends, strict=True))
        if any(end < start for start, end in intervals):
            return False
        expected_evidence_ids = tuple(sorted(item.reference.evidence_id for item in interval_items))
        if not record_invoice_processing and not intervals:
            expected_state = TrustState.USABLE
            expected_reason = ReasonCode.TIMELINE_VALID
        elif not intervals:
            expected_state = TrustState.DEGRADED
            expected_reason = ReasonCode.TIMELINE_UNAVAILABLE
        else:
            total_years = _merged_interval_days(intervals) / 365.2425
            if total_years + 0.35 < record_ap_years:
                expected_state = TrustState.QUARANTINED
                expected_reason = ReasonCode.TIMELINE_CONFLICT
            elif total_years > record_ap_years + 0.75:
                expected_state = TrustState.DEGRADED
                expected_reason = ReasonCode.TIMELINE_DRIFT
            else:
                expected_state = TrustState.USABLE
                expected_reason = ReasonCode.TIMELINE_VALID
        return (
            timeline.state is expected_state
            and timeline.outcome is ReleaseAuthorizer._outcome_for_state(expected_state)
            and timeline.reason_codes == (expected_reason,)
            and timeline.evidence_ids == expected_evidence_ids
        )

    @staticmethod
    def _dispositions_match_release(
        candidate: ValidatedCandidateEvidence,
        facts: Sequence[SupportedFact],
        evidence_manifest: Sequence[EvidenceRef],
        inventory: dict[str, EvidenceDispositionEntry],
        timeline: TrustDecision,
        cross_source: TrustDecision,
        *,
        structured_anchors: Sequence[StructuredFieldAnchor],
        record_ap_years: float,
        record_invoice_processing: bool,
    ) -> bool:
        references = {reference.evidence_id: reference for reference in evidence_manifest}
        anchors = {anchor.claim_kind: anchor.reference for anchor in structured_anchors}
        for fact in facts:
            if fact.kind not in STRUCTURED_FIELD_KINDS:
                continue
            anchor = anchors.get(fact.kind)
            if anchor is None or references.get(anchor.evidence_id) != anchor:
                return False
            json_ids = {
                evidence_id
                for evidence_id in fact.evidence_ids
                if (reference := references.get(evidence_id)) is not None
                and reference.source_kind is SourceKind.APPLICATION_JSON
            }
            if json_ids != {anchor.evidence_id}:
                return False
        released_roles: dict[str, set[ClaimKind]] = {}
        for fact in facts:
            if fact.kind is ClaimKind.CANDIDATE_ID:
                continue
            for evidence_id in fact.evidence_ids:
                reference = references.get(evidence_id)
                if reference is not None and reference.source_kind is SourceKind.RESUME_VISIBLE:
                    released_roles.setdefault(evidence_id, set()).add(fact.kind)
        released_ids = {
            evidence_id
            for evidence_id, item in inventory.items()
            if item.state is EvidenceDispositionState.RELEASED
        }
        if released_ids != set(released_roles):
            return False
        for evidence_id in released_ids:
            item = inventory[evidence_id]
            if item.reference != references.get(evidence_id):
                return False
            roles = released_roles[evidence_id]
            if item.claim_kind not in roles and not (
                item.claim_kind is ClaimKind.EMPLOYMENT_INTERVAL
                and ClaimKind.AP_YEARS in roles
                and ClaimKind.EMPLOYMENT_INTERVAL in roles
            ):
                return False

        fact_kinds = {fact.kind for fact in facts}
        categorical_flags = {
            ClaimKind.SPREADSHEET: candidate.spreadsheet_supported,
            ClaimKind.ACCOUNTING_PLATFORM: candidate.accounting_platform_supported,
            ClaimKind.QUALIFICATION: candidate.qualification_supported,
        }
        category_drop = False
        timeline_drop = False
        cross_ids = set(cross_source.evidence_ids)
        timeline_ids = set(timeline.evidence_ids)
        for item in inventory.values():
            if item.state is EvidenceDispositionState.RELEASED:
                stage_ids = (
                    timeline_ids if item.claim_kind is ClaimKind.EMPLOYMENT_INTERVAL else cross_ids
                )
                if item.reference.evidence_id not in stage_ids:
                    return False
                continue
            if item.state is EvidenceDispositionState.DROPPED_UNSUPPORTED_CATEGORY:
                if (
                    item.claim_kind not in categorical_flags
                    or categorical_flags[item.claim_kind]
                    or item.claim_kind in fact_kinds
                    or item.reference.evidence_id not in cross_ids
                ):
                    return False
                category_drop = True
            elif item.state is EvidenceDispositionState.DROPPED_TIMELINE_POLICY:
                if (
                    item.claim_kind is not ClaimKind.AP_YEARS
                    or ClaimKind.AP_YEARS in fact_kinds
                    or item.reference.evidence_id not in cross_ids
                ):
                    return False
                timeline_drop = True
            else:
                # A ranked candidate cannot release after a cross-source drop.
                return False

        marker_present = ReasonCode.CATEGORY_NOT_SUPPORTED in cross_source.reason_codes
        if marker_present is not category_drop:
            return False
        expected_timeline = ReleaseAuthorizer._expected_timeline_reason(
            facts,
            record_ap_years=record_ap_years,
            record_invoice_processing=record_invoice_processing,
        )
        expected_timeline_state = (
            TrustState.USABLE
            if expected_timeline is ReasonCode.TIMELINE_VALID
            else TrustState.DEGRADED
        )
        expected_timeline_ids = {
            evidence_id
            for fact in facts
            if fact.kind is ClaimKind.EMPLOYMENT_INTERVAL
            for evidence_id in fact.evidence_ids
        }
        if (
            expected_timeline is ReasonCode.TIMELINE_CONFLICT
            or timeline.reason_codes != (expected_timeline,)
            or timeline.state is not expected_timeline_state
            or timeline.outcome is not ReleaseAuthorizer._outcome_for_state(expected_timeline_state)
            or set(timeline.evidence_ids) != expected_timeline_ids
            or len(timeline.evidence_ids) != len(expected_timeline_ids)
        ):
            return False
        if timeline_drop:
            if any(fact.kind is ClaimKind.EMPLOYMENT_INTERVAL for fact in facts):
                return False
            ap_hash = ReleaseAuthorizer._evidence_value_hash(record_ap_years)
            if not any(
                item.claim_kind is ClaimKind.AP_YEARS
                and item.state is EvidenceDispositionState.DROPPED_TIMELINE_POLICY
                and item.reference.semantic_hash == ap_hash
                for item in inventory.values()
            ):
                return False
        if candidate.ap_years is not None and candidate.ap_years != record_ap_years:
            return False
        return (
            candidate.invoice_processing is None
            or candidate.invoice_processing is record_invoice_processing
        )

    @staticmethod
    def _disposition_reference_valid(
        item: EvidenceDispositionEntry,
        *,
        candidate_id: str,
        snapshot_id: str,
    ) -> bool:
        """Validate inventory references without trusting model construction.

        Hostile tests can use ``model_copy`` to bypass Pydantic validators.  The
        release boundary therefore repeats the bounded source, ownership, role,
        hash, and geometry checks for every consumed reference, including ones
        that never enter the released support graph.
        """

        reference = item.reference
        if (
            item.claim_kind is ClaimKind.CANDIDATE_ID
            or reference.candidate_id != candidate_id
            or reference.snapshot_id != snapshot_id
            or reference.source_kind is not SourceKind.RESUME_VISIBLE
            or reference.visible is not True
            or reference.admissible is not True
            or reference.field_path is None
            or not ReleaseAuthorizer._visible_geometry_valid(reference)
            or not isinstance(reference.semantic_hash, str)
            or len(reference.semantic_hash) != 64
            or any(character not in "0123456789abcdef" for character in reference.semantic_hash)
        ):
            return False
        role = reference.field_path.rsplit(".", maxsplit=1)[-1]
        if item.claim_kind is ClaimKind.EMPLOYMENT_INTERVAL:
            return (
                role in {"employment_start", "employment_end"}
                and type(item.date_value) is date
                and item.mapped_value is None
                and reference.semantic_hash
                == ReleaseAuthorizer._evidence_value_hash(item.date_value.isoformat())
            )
        return (
            item.date_value is None
            and role == item.claim_kind.value
            and _structured_value_valid(item.claim_kind, item.mapped_value, allow_null=False)
            and reference.semantic_hash == ReleaseAuthorizer._evidence_value_hash(item.mapped_value)
        )

    @staticmethod
    def _expected_timeline_reason(
        facts: Sequence[SupportedFact],
        *,
        record_ap_years: float,
        record_invoice_processing: bool,
    ) -> ReasonCode:
        intervals = tuple(
            (interval.start_date, interval.end_date)
            for fact in facts
            if fact.kind is ClaimKind.EMPLOYMENT_INTERVAL
            for interval in fact.employment_intervals
        )
        if not record_invoice_processing and not intervals:
            return ReasonCode.TIMELINE_VALID
        if not intervals:
            return ReasonCode.TIMELINE_UNAVAILABLE
        total_years = _merged_interval_days(intervals) / 365.2425
        if total_years + 0.35 < record_ap_years:
            return ReasonCode.TIMELINE_CONFLICT
        if total_years > record_ap_years + 0.75:
            return ReasonCode.TIMELINE_DRIFT
        return ReasonCode.TIMELINE_VALID

    @staticmethod
    def _outcome_for_state(state: TrustState) -> TrustOutcome:
        return {
            TrustState.USABLE: TrustOutcome.ALLOW,
            TrustState.DEGRADED: TrustOutcome.RESTRICT,
            TrustState.QUARANTINED: TrustOutcome.QUARANTINE,
            TrustState.UNAVAILABLE: TrustOutcome.UNAVAILABLE,
        }[state]

    @staticmethod
    def _evidence_value_hash(value: object) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _release_policy_valid(
        batch: ValidatedBatchEvidence,
        routes: Sequence[CandidateRoute],
        plan: ExecutionPlan,
        trust_ledger: Sequence[TrustDecision],
    ) -> bool:
        if (
            type(batch.batch_integrity_valid) is not bool
            or type(batch.mapper_disagreement) is not bool
            or type(plan.version) is not int
            or plan.version not in {1, 2, 3}
        ):
            return False
        candidates = {candidate.candidate_id: candidate for candidate in batch.candidates}
        unavailable = tuple(batch.unavailable_candidate_ids)
        unavailable_from_state = {
            candidate.candidate_id
            for candidate in batch.candidates
            if candidate.trust_state is TrustState.UNAVAILABLE
        }
        if (
            len(candidates) != len(batch.candidates)
            or len(routes) != len(batch.candidates)
            or len({route.candidate_id for route in routes}) != len(routes)
            or len(unavailable) != len(set(unavailable))
            or set(unavailable) != unavailable_from_state
        ):
            return False
        rankable_ids = {
            candidate.candidate_id
            for candidate in batch.candidates
            if candidate.trust_state in {TrustState.USABLE, TrustState.DEGRADED}
        }
        has_unavailable = bool(unavailable)
        has_local_restriction = batch.mapper_disagreement or any(
            candidate.trust_state
            in {TrustState.DEGRADED, TrustState.QUARANTINED, TrustState.UNAVAILABLE}
            for candidate in batch.candidates
        )
        if (
            not batch.batch_integrity_valid
            or not rankable_ids
            or (has_unavailable and batch.mapper_disagreement)
        ):
            expected_strategy = Strategy.BATCH_INTEGRITY_HOLD
        elif has_unavailable:
            expected_strategy = Strategy.PARTIAL_SAFE_RANKING
        elif has_local_restriction:
            expected_strategy = Strategy.SUPPORTED_ONLY_RANKING
        else:
            expected_strategy = Strategy.FULL_EVIDENCE_RANKING
        expected_steps = (
            _FULL_V1_STEPS
            if expected_strategy is Strategy.FULL_EVIDENCE_RANKING and plan.version == 1
            else _FINAL_STEPS_BY_STRATEGY[expected_strategy]
        )
        expected_prohibitions = (
            (*_BASE_PROHIBITIONS, ProhibitedAction.RELEASE_FINAL_QUALIFICATION_DECISION)
            if expected_strategy is Strategy.BATCH_INTEGRITY_HOLD
            else _BASE_PROHIBITIONS
        )
        if (
            plan.strategy is not expected_strategy
            or plan.objective is not _OBJECTIVE_BY_STRATEGY[expected_strategy]
            or tuple(command.kind for command in plan.commands) != expected_steps
            or len(plan.allowed_evidence_ids) != len(set(plan.allowed_evidence_ids))
            or plan.allowed_evidence_ids != tuple(sorted(plan.allowed_evidence_ids))
            or plan.prohibited_actions != expected_prohibitions
        ):
            return False
        previous_id: str | None = None
        for command in plan.commands:
            expected_id = f"p{plan.version}:{command.kind.value}"
            if (
                command.command_id != expected_id
                or command.scope is not TrustScope.BATCH
                or command.candidate_id is not None
                or command.dependency_ids != (() if previous_id is None else (previous_id,))
            ):
                return False
            previous_id = command.command_id
        ranked_ids = {route.candidate_id for route in routes if route.evidence_rank is not None}
        expected_ranked_ids = (
            set() if expected_strategy is Strategy.BATCH_INTEGRITY_HOLD else rankable_ids
        )
        if ranked_ids != expected_ranked_ids:
            return False
        if any(route.candidate_id not in candidates for route in routes):
            return False
        if not ReleaseAuthorizer._triggers_are_derived(
            batch,
            plan,
            trust_ledger,
        ):
            return False
        return ReleaseAuthorizer._route_reasons_match(batch, routes, expected_strategy)

    @staticmethod
    def _triggers_are_derived(
        batch: ValidatedBatchEvidence,
        plan: ExecutionPlan,
        trust_ledger: Sequence[TrustDecision],
    ) -> bool:
        actual = set(plan.trigger_codes)
        if len(actual) != len(plan.trigger_codes):
            return False
        ledger_reasons = {reason for decision in trust_ledger for reason in decision.reason_codes}
        if plan.version == 1:
            if plan.strategy is Strategy.FULL_EVIDENCE_RANKING:
                return actual == {ReasonCode.INDEX_VALID}
            typed_failures = {
                ReasonCode.RETRIEVAL_FAILED,
                ReasonCode.SCHEMA_INVALID,
                ReasonCode.PARSING_FAILED,
            }
            return (
                not batch.candidates
                and len(actual) == 1
                and actual.issubset(typed_failures.intersection(ledger_reasons))
            )
        if plan.version == 3:
            return actual == {ReasonCode.PRE_RELEASE_BLOCKED} and (
                ReasonCode.PRE_RELEASE_BLOCKED in ledger_reasons
            )
        required: set[ReasonCode] = set()
        if not batch.batch_integrity_valid:
            required.add(ReasonCode.INDEX_CONFLICT)
        if batch.unavailable_candidate_ids:
            required.add(ReasonCode.CANDIDATE_UNAVAILABLE)
        if batch.mapper_disagreement:
            required.add(ReasonCode.MAPPER_DISAGREEMENT)
        if not required:
            required.add(ReasonCode.EVIDENCE_ADMISSIBLE)
        permitted_extras = {
            ReasonCode.RETRIEVAL_FAILED,
            ReasonCode.SCHEMA_INVALID,
            ReasonCode.PARSING_FAILED,
            ReasonCode.PRE_RELEASE_BLOCKED,
        }.intersection(ledger_reasons)
        return required.issubset(actual) and actual.difference(required).issubset(permitted_extras)

    @staticmethod
    def _route_reasons_match(
        batch: ValidatedBatchEvidence,
        routes: Sequence[CandidateRoute],
        strategy: Strategy,
    ) -> bool:
        candidates = {candidate.candidate_id: candidate for candidate in batch.candidates}
        for route in routes:
            candidate = candidates.get(route.candidate_id)
            if candidate is None or len(route.reason_codes) != len(set(route.reason_codes)):
                return False
            expected: tuple[ReasonCode, ...]
            if strategy is Strategy.BATCH_INTEGRITY_HOLD:
                expected = (ReasonCode.BATCH_HOLD_REQUIRED,)
            elif candidate.trust_state is TrustState.UNAVAILABLE:
                expected = candidate.reason_codes or (ReasonCode.CANDIDATE_UNAVAILABLE,)
            elif candidate.trust_state is TrustState.QUARANTINED:
                expected = candidate.reason_codes or (ReasonCode.RECORD_QUARANTINED,)
            else:
                expected = candidate.reason_codes
            if route.reason_codes != expected:
                return False
        return True

    @staticmethod
    def _trust_ledger_valid(
        batch: ValidatedBatchEvidence,
        receipts: Sequence[StepReceipt],
        trust_ledger: Sequence[TrustDecision],
    ) -> bool:
        """Validate the complete trust-decision DAG, not only receipt-linked gates."""

        if not trust_ledger:
            return False
        decisions = {decision.decision_id: decision for decision in trust_ledger}
        if len(decisions) != len(trust_ledger):
            return False

        first_prefix, separator, first_ordinal = trust_ledger[0].decision_id.rpartition(":")
        if not separator or not first_prefix.startswith("td:") or first_ordinal != "1":
            return False
        pre_snapshot = tuple(decision for decision in trust_ledger if decision.snapshot_id is None)
        if len(pre_snapshot) > 1:
            return False
        if pre_snapshot:
            root = pre_snapshot[0]
            if (
                root is not trust_ledger[0]
                or root.input_gate_ids
                or root.scope is not TrustScope.BATCH
                or root.stage is not TrustStage.RETRIEVAL
                or root.state is not TrustState.USABLE
                or root.outcome is not TrustOutcome.ALLOW
                or root.reason_codes != (ReasonCode.FETCH_SUCCEEDED,)
            ):
                return False
        for ordinal, decision in enumerate(trust_ledger, start=1):
            if decision.decision_id != f"{first_prefix}:{ordinal}":
                return False
            if decision.snapshot_id is not None and decision.snapshot_id != batch.snapshot_id:
                return False
            if len(decision.input_gate_ids) > len(batch.candidates) + 1:
                return False

        candidates = {candidate.candidate_id: candidate for candidate in batch.candidates}
        if len(candidates) != len(batch.candidates):
            return False
        for decision in trust_ledger:
            if decision.scope is TrustScope.RECORD and decision.candidate_id not in candidates:
                return False

        decision_order = {
            decision.decision_id: index for index, decision in enumerate(trust_ledger)
        }
        children: dict[str, list[TrustDecision]] = {
            decision.decision_id: [] for decision in trust_ledger
        }
        record_pairs = {
            (TrustStage.IDENTITY, TrustStage.REVISION),
            (TrustStage.REVISION, TrustStage.MANIFEST),
            (TrustStage.MANIFEST, TrustStage.PARSING),
            (TrustStage.PARSING, TrustStage.MAPPING),
            (TrustStage.MAPPING, TrustStage.PROVENANCE),
            (TrustStage.PROVENANCE, TrustStage.TIMELINE),
            (TrustStage.TIMELINE, TrustStage.CROSS_SOURCE),
            (TrustStage.RETRIEVAL, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.SCHEMA, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.IDENTITY, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.REVISION, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.MANIFEST, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.PARSING, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.MAPPING, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.PROVENANCE, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.TIMELINE, TrustStage.CANDIDATE_VALIDATION),
            (TrustStage.CROSS_SOURCE, TrustStage.CANDIDATE_VALIDATION),
        }
        batch_pairs = {
            (TrustStage.RETRIEVAL, TrustStage.SCHEMA),
            (TrustStage.RETRIEVAL, TrustStage.PARSING),
            (TrustStage.RETRIEVAL, TrustStage.RANKING),
            (TrustStage.SCHEMA, TrustStage.MANIFEST),
            (TrustStage.SCHEMA, TrustStage.RETRIEVAL),
            (TrustStage.MANIFEST, TrustStage.PLANNING),
            (TrustStage.PLANNING, TrustStage.RETRIEVAL),
            (TrustStage.PLANNING, TrustStage.MANIFEST),
            (TrustStage.PLANNING, TrustStage.PROVENANCE),
            (TrustStage.PLANNING, TrustStage.RANKING),
            (TrustStage.PLANNING, TrustStage.PRE_RELEASE),
            (TrustStage.PARSING, TrustStage.MAPPING),
            (TrustStage.PARSING, TrustStage.IDENTITY),
            (TrustStage.IDENTITY, TrustStage.MAPPING),
            (TrustStage.MAPPING, TrustStage.PROVENANCE),
            (TrustStage.PROVENANCE, TrustStage.PLANNING),
            (TrustStage.PROVENANCE, TrustStage.RANKING),
            (TrustStage.PROVENANCE, TrustStage.PRE_RELEASE),
            (TrustStage.RANKING, TrustStage.PLANNING),
            (TrustStage.RANKING, TrustStage.PRE_RELEASE),
            (TrustStage.CROSS_SOURCE, TrustStage.PLANNING),
            (TrustStage.CROSS_SOURCE, TrustStage.PRE_RELEASE),
            (TrustStage.PRE_RELEASE, TrustStage.RELEASE),
        }
        typed_failure_reasons = {
            TrustStage.RETRIEVAL: ReasonCode.RETRIEVAL_FAILED,
            TrustStage.SCHEMA: ReasonCode.SCHEMA_INVALID,
            TrustStage.PARSING: ReasonCode.PARSING_FAILED,
            TrustStage.MANIFEST: ReasonCode.MANIFEST_CONFLICT,
            TrustStage.PROVENANCE: ReasonCode.COMMAND_FAILED,
            TrustStage.PRE_RELEASE: ReasonCode.PRE_RELEASE_BLOCKED,
        }

        def typed_failure(decision: TrustDecision) -> bool:
            expected = typed_failure_reasons.get(decision.stage)
            return (
                expected is not None
                and expected in decision.reason_codes
                and decision.outcome
                in {TrustOutcome.QUARANTINE, TrustOutcome.UNAVAILABLE, TrustOutcome.HOLD}
            )

        roots: list[TrustDecision] = []
        for decision in trust_ledger:
            if not decision.input_gate_ids:
                roots.append(decision)
                continue
            if len(decision.input_gate_ids) > 1:
                parents = tuple(decisions.get(item) for item in decision.input_gate_ids)
                if any(parent is None for parent in parents):
                    return False
                typed_parents = tuple(parent for parent in parents if parent is not None)
                batch_parents = tuple(
                    parent for parent in typed_parents if parent.scope is TrustScope.BATCH
                )
                record_parents = tuple(
                    parent for parent in typed_parents if parent.scope is TrustScope.RECORD
                )
                valid_binding_fan_in = (
                    decision.scope is TrustScope.BATCH
                    and decision.stage is TrustStage.IDENTITY
                    and decision.outcome is TrustOutcome.ALLOW
                    and len(batch_parents) == 1
                    and batch_parents[0].decision_id == decision.input_gate_ids[0]
                    and batch_parents[0].stage is TrustStage.PARSING
                    and batch_parents[0].outcome in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
                    and len(record_parents) == len(candidates)
                    and {parent.candidate_id for parent in record_parents} == set(candidates)
                    and tuple(parent.candidate_id for parent in record_parents)
                    == tuple(sorted(candidates))
                    and all(
                        parent.stage
                        in {
                            TrustStage.RETRIEVAL,
                            TrustStage.SCHEMA,
                            TrustStage.IDENTITY,
                            TrustStage.REVISION,
                            TrustStage.MANIFEST,
                            TrustStage.PARSING,
                        }
                        for parent in record_parents
                    )
                    and set(decision.evidence_ids)
                    == {
                        evidence_id
                        for parent in record_parents
                        for evidence_id in parent.evidence_ids
                    }
                )
                valid_candidate_validation_fan_in = (
                    decision.scope is TrustScope.BATCH
                    and decision.stage is TrustStage.PROVENANCE
                    and decision.outcome is TrustOutcome.ALLOW
                    and len(batch_parents) == 1
                    and batch_parents[0].decision_id == decision.input_gate_ids[0]
                    and batch_parents[0].stage is TrustStage.MAPPING
                    and batch_parents[0].outcome in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
                    and len(record_parents) == len(candidates)
                    and all(
                        parent.stage is TrustStage.CANDIDATE_VALIDATION
                        and parent.snapshot_id == batch.snapshot_id
                        for parent in record_parents
                    )
                    and tuple(parent.candidate_id for parent in record_parents)
                    == tuple(sorted(candidates))
                    and set(decision.evidence_ids)
                    == {
                        evidence_id
                        for parent in record_parents
                        for evidence_id in parent.evidence_ids
                    }
                )
                if not (valid_binding_fan_in or valid_candidate_validation_fan_in):
                    return False
                for parent in typed_parents:
                    if decision_order[parent.decision_id] >= decision_order[decision.decision_id]:
                        return False
                    children[parent.decision_id].append(decision)
                continue
            resolved_parent = decisions.get(decision.input_gate_ids[0])
            if (
                resolved_parent is None
                or decision_order[resolved_parent.decision_id]
                >= decision_order[decision.decision_id]
            ):
                return False
            children[resolved_parent.decision_id].append(decision)
            parent_is_blocked = resolved_parent.outcome not in {
                TrustOutcome.ALLOW,
                TrustOutcome.RESTRICT,
            }
            if parent_is_blocked:
                candidate_terminal = (
                    decision.scope is TrustScope.RECORD
                    and decision.stage is TrustStage.CANDIDATE_VALIDATION
                    and decision.candidate_id == resolved_parent.candidate_id
                    and decision.state in {TrustState.QUARANTINED, TrustState.UNAVAILABLE}
                    and decision.outcome
                    in {
                        TrustOutcome.QUARANTINE,
                        TrustOutcome.UNAVAILABLE,
                        TrustOutcome.HOLD,
                    }
                    and set(resolved_parent.reason_codes).issubset(decision.reason_codes)
                    and set(decision.evidence_ids).issubset(resolved_parent.evidence_ids)
                )
                if not candidate_terminal and not (
                    typed_failure(resolved_parent)
                    and decision.scope is TrustScope.BATCH
                    and decision.stage is TrustStage.PLANNING
                    and decision.outcome is TrustOutcome.ALLOW
                ):
                    return False
                continue
            if resolved_parent.scope is TrustScope.RECORD:
                if (
                    decision.scope is not TrustScope.RECORD
                    or decision.candidate_id != resolved_parent.candidate_id
                    or (resolved_parent.stage, decision.stage) not in record_pairs
                ):
                    return False
            elif decision.scope is TrustScope.RECORD:
                if (resolved_parent.stage, decision.stage) not in {
                    (TrustStage.PARSING, TrustStage.IDENTITY),
                    (TrustStage.PARSING, TrustStage.RETRIEVAL),
                    (TrustStage.PARSING, TrustStage.SCHEMA),
                    (TrustStage.PARSING, TrustStage.PARSING),
                    (TrustStage.MAPPING, TrustStage.RETRIEVAL),
                    (TrustStage.MAPPING, TrustStage.SCHEMA),
                    (TrustStage.MAPPING, TrustStage.PARSING),
                    (TrustStage.MAPPING, TrustStage.CANDIDATE_VALIDATION),
                }:
                    return False
            elif (resolved_parent.stage, decision.stage) not in batch_pairs:
                return False

        for root_index, root in enumerate(roots):
            initial_retrieval = (
                root_index == 0
                and root is trust_ledger[0]
                and root.scope is TrustScope.BATCH
                and root.stage is TrustStage.RETRIEVAL
                and root.outcome in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
            )
            if not initial_retrieval and not typed_failure(root):
                return False

        for decision in trust_ledger:
            decision_children = children[decision.decision_id]
            record_children = tuple(
                child for child in decision_children if child.scope is TrustScope.RECORD
            )
            batch_children = tuple(
                child for child in decision_children if child.scope is TrustScope.BATCH
            )
            if decision.scope is TrustScope.RECORD and len(record_children) > 1:
                return False
            if len(batch_children) > 1:
                fallback_fork = (
                    len(batch_children) == 2
                    and {child.stage for child in batch_children}
                    == {TrustStage.PLANNING, TrustStage.PRE_RELEASE}
                    and any(
                        child.stage is TrustStage.PRE_RELEASE
                        and child.outcome is TrustOutcome.HOLD
                        and ReasonCode.PRE_RELEASE_BLOCKED in child.reason_codes
                        for child in batch_children
                    )
                    and any(receipt.status is StepStatus.FAILED for receipt in receipts)
                )
                if not fallback_fork:
                    return False
            if record_children and decision.scope is TrustScope.BATCH:
                if decision.stage not in {TrustStage.PARSING, TrustStage.MAPPING}:
                    return False
                if len({child.candidate_id for child in record_children}) != len(record_children):
                    return False

        for candidate_id, candidate in candidates.items():
            candidate_decisions = tuple(
                decision
                for decision in trust_ledger
                if decision.scope is TrustScope.RECORD and decision.candidate_id == candidate_id
            )
            if not candidate_decisions:
                continue
            candidate_roots = tuple(
                decision
                for decision in candidate_decisions
                if not decision.input_gate_ids
                or decisions[decision.input_gate_ids[0]].scope is TrustScope.BATCH
            )
            candidate_leaves = tuple(
                decision
                for decision in candidate_decisions
                if not any(
                    child.scope is TrustScope.RECORD and child.candidate_id == candidate_id
                    for child in children[decision.decision_id]
                )
            )
            if len(candidate_roots) != 1 or len(candidate_leaves) != 1:
                return False
            leaf = candidate_leaves[0]
            if leaf.evidence_ids != candidate.evidence_ids:
                return False
            if candidate.trust_state is TrustState.USABLE and not (
                leaf.stage is TrustStage.CANDIDATE_VALIDATION
                and leaf.outcome is TrustOutcome.ALLOW
                and leaf.state is TrustState.USABLE
            ):
                return False
            if candidate.trust_state is TrustState.DEGRADED and not (
                leaf.stage is TrustStage.CANDIDATE_VALIDATION
                and leaf.outcome is TrustOutcome.RESTRICT
                and leaf.state is TrustState.DEGRADED
            ):
                return False
            if candidate.trust_state in {TrustState.QUARANTINED, TrustState.UNAVAILABLE} and (
                leaf.stage is not TrustStage.CANDIDATE_VALIDATION
                or leaf.outcome
                not in {TrustOutcome.QUARANTINE, TrustOutcome.UNAVAILABLE, TrustOutcome.HOLD}
            ):
                return False

        completed_gates = tuple(
            receipt
            for receipt in receipts
            if receipt.status is StepStatus.COMPLETED and receipt.produced_gate_id is not None
        )
        if not completed_gates:
            return False
        terminal_batch_gate = max(
            completed_gates, key=lambda receipt: receipt.sequence
        ).produced_gate_id
        batch_leaves = tuple(
            decision
            for decision in trust_ledger
            if decision.scope is TrustScope.BATCH and not children[decision.decision_id]
        )
        terminal_leaves = tuple(
            decision for decision in batch_leaves if decision.decision_id == terminal_batch_gate
        )
        if len(terminal_leaves) != 1:
            return False
        interrupted_leaves = tuple(
            decision for decision in batch_leaves if decision.decision_id != terminal_batch_gate
        )
        failed_receipt_count = sum(receipt.status is StepStatus.FAILED for receipt in receipts)
        if len(interrupted_leaves) > failed_receipt_count:
            return False
        for decision in interrupted_leaves:
            next_index = decision_order[decision.decision_id] + 1
            if (
                decision.outcome not in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
                or next_index >= len(trust_ledger)
                or not typed_failure(trust_ledger[next_index])
            ):
                return False
        return True

    @staticmethod
    def _plan_receipts_valid(
        plan: ExecutionPlan,
        receipts: Sequence[StepReceipt],
        trust_ledger: Sequence[TrustDecision],
        plan_history: Sequence[ExecutionPlan],
    ) -> bool:
        status_markers = {
            StepStatus.STARTED: ReasonCode.COMMAND_STARTED,
            StepStatus.COMPLETED: ReasonCode.COMMAND_COMPLETED,
            StepStatus.RESTRICTED: ReasonCode.COMMAND_RESTRICTED,
            StepStatus.FAILED: ReasonCode.COMMAND_FAILED,
        }
        all_status_markers = frozenset(status_markers.values())
        for receipt in receipts:
            expected_marker = status_markers[receipt.status]
            present_markers = all_status_markers.intersection(receipt.reason_codes)
            if receipt.status is StepStatus.STARTED:
                if receipt.reason_codes != (expected_marker,):
                    return False
            elif expected_marker not in present_markers or present_markers != {expected_marker}:
                return False
        if (
            not plan_history
            or plan_history[-1] != plan
            or len({item.version for item in plan_history}) != len(plan_history)
        ):
            return False
        known_commands = {
            (history_plan.version, command.command_id): command
            for history_plan in plan_history
            for command in history_plan.commands
        }
        if any(
            (command := known_commands.get((receipt.plan_version, receipt.command_id))) is None
            or receipt.command_kind is not command.kind
            for receipt in receipts
        ):
            return False
        relevant = tuple(receipt for receipt in receipts if receipt.plan_version == plan.version)
        commands = {command.command_id: command for command in plan.commands}
        if any(
            receipt.command_id not in commands
            or receipt.command_kind is not commands[receipt.command_id].kind
            for receipt in relevant
        ):
            return False
        sequences = [receipt.sequence for receipt in receipts]
        if len(sequences) != len(set(sequences)) or sequences != sorted(sequences):
            return False
        if len({receipt.receipt_id for receipt in receipts}) != len(receipts):
            return False
        by_command = {
            command.command_id: tuple(
                receipt for receipt in relevant if receipt.command_id == command.command_id
            )
            for command in plan.commands
        }
        audit_index = next(
            (
                index
                for index, command in enumerate(plan.commands)
                if command.kind is PlanStep.PRE_RELEASE_AUDIT
            ),
            None,
        )
        if audit_index is None:
            return False
        audit_command = plan.commands[audit_index]
        audit_receipts = by_command[audit_command.command_id]
        if len(audit_receipts) == 1 and audit_receipts[0].status is StepStatus.STARTED:
            expected = plan.commands[:audit_index]
            if any(by_command[command.command_id] for command in plan.commands[audit_index + 1 :]):
                return False
        elif (
            len(audit_receipts) == 2
            and audit_receipts[0].status is StepStatus.STARTED
            and audit_receipts[1].status is StepStatus.COMPLETED
        ):
            expected = plan.commands
        else:
            return False
        if any(
            len(by_command[command.command_id]) != 2
            or by_command[command.command_id][0].status is not StepStatus.STARTED
            or by_command[command.command_id][1].status is not StepStatus.COMPLETED
            for command in expected
        ):
            return False
        decisions = {decision.decision_id: decision for decision in trust_ledger}
        if len(decisions) != len(trust_ledger):
            return False
        decision_order = {
            decision.decision_id: index for index, decision in enumerate(trust_ledger)
        }
        produced: set[str] = set()
        consumed: set[str] = set()
        previous_terminal_sequence = 0
        previous_gate_id: str | None = None
        previous_command_kind: PlanStep | None = None
        validation_gate_ids = {
            receipt.produced_gate_id
            for receipt in receipts
            if receipt.status is StepStatus.COMPLETED
            and receipt.command_kind
            in {
                PlanStep.VALIDATE_CANDIDATE_EVIDENCE,
                PlanStep.VALIDATE_INDEX_COMMITMENTS,
            }
            and receipt.produced_gate_id is not None
        }
        final_entry_kinds = {
            PlanStep.RANK_FULL_EVIDENCE,
            PlanStep.QUARANTINE_UNSUPPORTED,
            PlanStep.MARK_EVIDENCE_PENDING,
            PlanStep.ISOLATE_BATCH,
        }
        for command in expected:
            started, terminal = by_command[command.command_id]
            fan_in_command = command.kind in {
                PlanStep.VALIDATE_CANDIDATE_BINDINGS,
                PlanStep.VALIDATE_CANDIDATE_EVIDENCE,
            }
            consumed_ids = terminal.consumed_gate_ids
            if (
                started.sequence <= previous_terminal_sequence
                or terminal.sequence <= started.sequence
                or terminal.produced_gate_id is None
                or terminal.produced_gate_id in produced
                or (len(consumed_ids) <= 1 if fan_in_command else len(consumed_ids) != 1)
                or len(consumed_ids) != len(set(consumed_ids))
                or bool(set(consumed_ids).intersection(consumed))
            ):
                return False
            consumed_id = consumed_ids[0]
            gate = decisions.get(consumed_id)
            consumed_gates = tuple(decisions.get(item) for item in consumed_ids)
            produced_gate = decisions.get(terminal.produced_gate_id)
            produced_inputs_match = bool(
                produced_gate is not None and produced_gate.input_gate_ids == consumed_ids
            )
            expected_fan_in_stage = {
                PlanStep.VALIDATE_CANDIDATE_BINDINGS: TrustStage.IDENTITY,
                PlanStep.VALIDATE_CANDIDATE_EVIDENCE: TrustStage.PROVENANCE,
            }.get(command.kind)
            expected_record_stages = (
                {
                    TrustStage.RETRIEVAL,
                    TrustStage.SCHEMA,
                    TrustStage.IDENTITY,
                    TrustStage.REVISION,
                    TrustStage.MANIFEST,
                    TrustStage.PARSING,
                }
                if command.kind is PlanStep.VALIDATE_CANDIDATE_BINDINGS
                else {TrustStage.CANDIDATE_VALIDATION}
            )
            expected_batch_parent_stage = (
                TrustStage.PARSING
                if command.kind is PlanStep.VALIDATE_CANDIDATE_BINDINGS
                else TrustStage.MAPPING
            )
            fan_in_valid = not fan_in_command or (
                produced_gate is not None
                and gate is not None
                and gate.stage is expected_batch_parent_stage
                and produced_gate.scope is TrustScope.BATCH
                and produced_gate.stage is expected_fan_in_stage
                and all(item is not None for item in consumed_gates)
                and all(
                    item is not None
                    and item.scope is TrustScope.RECORD
                    and item.candidate_id is not None
                    and item.snapshot_id == produced_gate.snapshot_id
                    and item.stage in expected_record_stages
                    for item in consumed_gates[1:]
                )
                and len({item.candidate_id for item in consumed_gates[1:] if item is not None})
                == len(consumed_gates) - 1
                and tuple(item.candidate_id for item in consumed_gates[1:] if item is not None)
                == tuple(
                    sorted(
                        item.candidate_id
                        for item in consumed_gates[1:]
                        if item is not None and item.candidate_id is not None
                    )
                )
                and set(produced_gate.evidence_ids)
                == {
                    evidence_id
                    for item in consumed_gates[1:]
                    if item is not None
                    for evidence_id in item.evidence_ids
                }
            )
            terminal_domain_reasons = tuple(
                reason for reason in terminal.reason_codes if reason not in all_status_markers
            )
            produced_domain_reasons = (
                ()
                if produced_gate is None
                else tuple(
                    reason
                    for reason in produced_gate.reason_codes
                    if reason not in all_status_markers
                )
            )
            command_policy = _COMMAND_GATE_POLICY.get(command.kind)
            produced_reason_policy_valid = bool(
                produced_gate is not None
                and command_policy is not None
                and produced_gate.stage is command_policy[0]
                and produced_gate.outcome is TrustOutcome.ALLOW
                and len(produced_gate.reason_codes) == len(set(produced_gate.reason_codes))
                and frozenset(produced_gate.reason_codes) == command_policy[1]
                and terminal_domain_reasons == produced_domain_reasons
            )
            if (
                gate is None
                or produced_gate is None
                or gate.outcome not in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
                or produced_gate.outcome not in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
                or not produced_inputs_match
                or not fan_in_valid
                or not produced_reason_policy_valid
                or terminal.evidence_ids != produced_gate.evidence_ids
                or any(
                    item is None
                    or decision_order[item.decision_id] >= decision_order[produced_gate.decision_id]
                    for item in consumed_gates
                )
            ):
                return False
            if command.kind in {
                PlanStep.RANK_FULL_EVIDENCE,
                PlanStep.RANK_SUPPORTED_EVIDENCE,
                PlanStep.RANK_PARTIAL_EVIDENCE,
                PlanStep.PRE_RELEASE_AUDIT,
                PlanStep.RELEASE_OUTPUT,
            } and set(terminal.evidence_ids) != set(plan.allowed_evidence_ids):
                return False
            if previous_gate_id is None:
                if gate.stage is not TrustStage.PLANNING or len(gate.input_gate_ids) != 1:
                    return False
                parent = decisions.get(gate.input_gate_ids[0])
                if (
                    parent is None
                    or decision_order[parent.decision_id] >= decision_order[gate.decision_id]
                ):
                    return False
                if plan.version > 1 and parent.decision_id not in validation_gate_ids:
                    typed_fail_closed_parent = (
                        plan.strategy is Strategy.BATCH_INTEGRITY_HOLD
                        and parent.outcome is TrustOutcome.HOLD
                        and bool(
                            set(parent.reason_codes).intersection(
                                {
                                    ReasonCode.RETRIEVAL_FAILED,
                                    ReasonCode.SCHEMA_INVALID,
                                    ReasonCode.PARSING_FAILED,
                                    ReasonCode.COMMAND_FAILED,
                                    ReasonCode.PRE_RELEASE_BLOCKED,
                                }
                            )
                        )
                    )
                    if not typed_fail_closed_parent:
                        return False
            elif consumed_id != previous_gate_id:
                # The only permitted discontinuity is the exact validation→
                # selected-plan mediation recorded on the planning decision.
                if (
                    command.kind not in final_entry_kinds
                    or previous_command_kind
                    not in {
                        PlanStep.VALIDATE_CANDIDATE_EVIDENCE,
                        PlanStep.VALIDATE_INDEX_COMMITMENTS,
                    }
                    or gate.stage is not TrustStage.PLANNING
                    or gate.input_gate_ids != (previous_gate_id,)
                ):
                    return False
            produced.add(terminal.produced_gate_id)
            consumed.update(consumed_ids)
            previous_gate_id = terminal.produced_gate_id
            previous_terminal_sequence = terminal.sequence
            previous_command_kind = command.kind
        return True

    @staticmethod
    def _routes_match_scope(
        batch: ValidatedBatchEvidence,
        routes: Sequence[CandidateRoute],
        plan: ExecutionPlan,
    ) -> bool:
        candidates = {candidate.candidate_id: candidate for candidate in batch.candidates}
        if (
            len(candidates) != len(batch.candidates)
            or {route.candidate_id for route in routes} != set(candidates)
            or any(candidate.snapshot_id != batch.snapshot_id for candidate in candidates.values())
            or any(route.snapshot_id != batch.snapshot_id for route in routes)
        ):
            return False
        if plan.strategy is Strategy.BATCH_INTEGRITY_HOLD:
            return all(
                route.band is ReviewBand.INTEGRITY_HOLD
                and route.queue is ReviewQueue.BATCH_INTEGRITY_HOLD
                and route.evidence_rank is None
                and route.display_position is None
                and route.rank_key is None
                and not route.evidence_ids
                and route.support_graph is None
                for route in routes
            )
        unavailable = set(batch.unavailable_candidate_ids)
        for route in routes:
            candidate = candidates[route.candidate_id]
            is_unavailable = (
                route.candidate_id in unavailable or candidate.trust_state is TrustState.UNAVAILABLE
            )
            is_quarantined = candidate.trust_state is TrustState.QUARANTINED
            if is_unavailable:
                if (
                    route.band is not ReviewBand.EVIDENCE_UNAVAILABLE
                    or route.queue is not ReviewQueue.EVIDENCE_PENDING
                    or route.evidence_rank is not None
                    or route.display_position is not None
                    or route.rank_key is not None
                ):
                    return False
                continue
            if is_quarantined:
                if (
                    route.band is not ReviewBand.INTEGRITY_HOLD
                    or route.queue is not ReviewQueue.INTEGRITY_REVIEW
                    or route.evidence_rank is not None
                    or route.display_position is not None
                    or route.rank_key is not None
                ):
                    return False
                continue
            if route.evidence_rank is None:
                return False
            if (
                plan.strategy is Strategy.FULL_EVIDENCE_RANKING
                and candidate.trust_state is not TrustState.USABLE
            ):
                return False
        return True

    @staticmethod
    def _support_is_closed(
        batch: ValidatedBatchEvidence,
        routes: Sequence[CandidateRoute],
        plan: ExecutionPlan,
    ) -> bool:
        allowed = set(plan.allowed_evidence_ids)
        released_union = {
            evidence_id
            for route in routes
            if route.evidence_rank is not None
            for evidence_id in route.evidence_ids
        }
        if allowed != released_union:
            return False
        candidates = {candidate.candidate_id: candidate for candidate in batch.candidates}
        for route in routes:
            if route.evidence_rank is None:
                if route.evidence_ids or route.support_graph is not None:
                    return False
                continue
            graph = route.support_graph
            if (
                graph is None
                or route.snapshot_id != batch.snapshot_id
                or graph.snapshot_id != batch.snapshot_id
                or len(route.evidence_ids) != len(set(route.evidence_ids))
                or len(graph.evidence_ids) != len(set(graph.evidence_ids))
                or set(route.evidence_ids) != set(graph.evidence_ids)
            ):
                return False
            candidate = candidates.get(route.candidate_id)
            if (
                candidate is None
                or route.evidence_ids != candidate.evidence_ids
                or graph != candidate.support_graph
            ):
                return False
            manifest = {item.evidence_id: item for item in graph.evidence_manifest}
            if (
                len(manifest) != len(graph.evidence_manifest)
                or set(manifest) != set(graph.evidence_ids)
                or any(
                    item.candidate_id != route.candidate_id
                    or item.snapshot_id != batch.snapshot_id
                    or not item.visible
                    or not item.admissible
                    or item.source_kind
                    not in {SourceKind.APPLICATION_JSON, SourceKind.RESUME_VISIBLE}
                    or (
                        item.source_kind is SourceKind.RESUME_VISIBLE
                        and not ReleaseAuthorizer._visible_geometry_valid(item)
                    )
                    for item in manifest.values()
                )
            ):
                return False
            facts = {fact.fact_id: fact for fact in graph.facts}
            features = {feature.feature_id: feature for feature in graph.features}
            if len(facts) != len(graph.facts) or len(features) != len(graph.features):
                return False
            if any(
                fact.snapshot_id != batch.snapshot_id or fact.candidate_id != route.candidate_id
                for fact in graph.facts
            ) or any(
                feature.snapshot_id != batch.snapshot_id
                or feature.candidate_id != route.candidate_id
                for feature in graph.features
            ):
                return False
            if any(
                set(feature.dependency_fact_ids).difference(facts)
                or set(feature.dependency_feature_ids).difference(features)
                for feature in graph.features
            ):
                return False
            used_fact_ids: set[str] = set()
            visited_features: set[str] = set()
            visiting_features: set[str] = set()

            def traverse(
                feature_id: str,
                *,
                _features: dict[str, DerivedFeature] = features,
                _visited: set[str] = visited_features,
                _visiting: set[str] = visiting_features,
                _used: set[str] = used_fact_ids,
            ) -> bool:
                if feature_id in _visited:
                    return True
                if feature_id in _visiting:
                    return False
                feature = _features.get(feature_id)
                if feature is None:
                    return False
                _visiting.add(feature_id)
                _used.update(feature.dependency_fact_ids)
                valid = all(traverse(item) for item in feature.dependency_feature_ids)
                _visiting.remove(feature_id)
                if valid:
                    _visited.add(feature_id)
                return valid

            if not all(traverse(item) for item in graph.route_support_ids):
                return False
            closure = {
                evidence for fact_id in used_fact_ids for evidence in facts[fact_id].evidence_ids
            }
            if closure != set(graph.evidence_ids):
                return False
            if any(
                len(fact.evidence_ids) != len(set(fact.evidence_ids))
                or set(fact.evidence_ids).difference(manifest)
                or set(fact.source_roles)
                != {manifest[item].source_kind for item in fact.evidence_ids}
                for fact in facts.values()
            ):
                return False
            if not ReleaseAuthorizer._semantics_match(
                candidate,
                route,
                facts,
                features,
                manifest,
            ):
                return False
        return True

    @staticmethod
    def _semantics_match(
        candidate: ValidatedCandidateEvidence,
        route: CandidateRoute,
        facts: dict[str, SupportedFact],
        features: dict[str, DerivedFeature],
        manifest: dict[str, EvidenceRef],
    ) -> bool:
        by_kind = {fact.kind: fact for fact in facts.values()}
        if len(by_kind) != len(facts):
            return False
        identity = by_kind.get(ClaimKind.CANDIDATE_ID)
        if identity is None or identity.normalized_value != candidate.candidate_id:
            return False
        if not ReleaseAuthorizer._fact_bindings_valid(by_kind, manifest, candidate.candidate_id):
            return False
        if any(
            not isinstance(by_kind[kind].normalized_value, str)
            or by_kind[kind].normalized_value not in allowed
            for kind, allowed in _CATEGORICAL_ALLOW_LISTS.items()
            if kind in by_kind
        ):
            return False
        if any(
            kind in by_kind and not isinstance(by_kind[kind].normalized_value, bool)
            for kind in (ClaimKind.INVOICE_PROCESSING, ClaimKind.RECONCILIATION)
        ):
            return False
        ap = by_kind.get(ClaimKind.AP_YEARS)
        interval = by_kind.get(ClaimKind.EMPLOYMENT_INTERVAL)
        if (
            ap is not None
            and interval is not None
            and not set(interval.evidence_ids).issubset(ap.evidence_ids)
        ):
            return False
        ap_value: float | None = None
        if ap is not None:
            if not isinstance(ap.normalized_value, (int, float)) or isinstance(
                ap.normalized_value, bool
            ):
                return False
            ap_value = float(ap.normalized_value)
            if (
                not math.isfinite(ap_value)
                or ap_value < 0
                or (ap_value == 0.0 and math.copysign(1.0, ap_value) < 0)
            ):
                return False
            if ap_value > 0:
                if (
                    interval is None
                    or not isinstance(interval.normalized_value, (int, float))
                    or isinstance(interval.normalized_value, bool)
                ):
                    return False
                interval_value = float(interval.normalized_value)
                if (
                    not math.isfinite(interval_value)
                    or interval_value < 0
                    or (interval_value == 0.0 and math.copysign(1.0, interval_value) < 0)
                    or ap_value > interval_value + 0.35
                ):
                    return False
                interval_paths = {
                    field_path.rsplit(".", maxsplit=1)[-1]
                    for item in interval.evidence_ids
                    if (field_path := manifest[item].field_path) is not None
                }
                if not {"employment_start", "employment_end"}.issubset(interval_paths):
                    return False
            elif interval is not None:
                # A zero-experience fact normally has no dated AP interval. If
                # one is present it must still be a valid, near-zero interval.
                if not isinstance(interval.normalized_value, (int, float)) or isinstance(
                    interval.normalized_value, bool
                ):
                    return False
                interval_value = float(interval.normalized_value)
                if (
                    not math.isfinite(interval_value)
                    or interval_value < 0
                    or (interval_value == 0.0 and math.copysign(1.0, interval_value) < 0)
                    or interval_value > 0.35
                ):
                    return False
        volume = by_kind.get(ClaimKind.MONTHLY_INVOICE_VOLUME)
        invoice = by_kind.get(ClaimKind.INVOICE_PROCESSING)
        if volume is not None and (invoice is None or invoice.normalized_value is not True):
            return False
        if volume is not None:
            normalized_volume = volume.normalized_value
            if not isinstance(normalized_volume, (int, float)) or isinstance(
                normalized_volume, bool
            ):
                return False
            volume_value = float(normalized_volume)
            if (
                not math.isfinite(volume_value)
                or volume_value < 0
                or volume_value > 100_000_000
                or not volume_value.is_integer()
                or (volume_value == 0.0 and math.copysign(1.0, volume_value) < 0)
            ):
                return False
        reconciliation = by_kind.get(ClaimKind.RECONCILIATION)
        if (
            (
                candidate.invoice_processing is not None
                and not isinstance(candidate.invoice_processing, bool)
            )
            or (
                candidate.reconciliation is not None
                and not isinstance(candidate.reconciliation, bool)
            )
            or any(
                not isinstance(value, bool)
                for value in (
                    candidate.spreadsheet_supported,
                    candidate.accounting_platform_supported,
                    candidate.qualification_supported,
                )
            )
        ):
            return False
        if candidate.ap_years is not None and (
            not math.isfinite(candidate.ap_years)
            or candidate.ap_years < 0
            or (candidate.ap_years == 0.0 and math.copysign(1.0, candidate.ap_years) < 0)
        ):
            return False
        if candidate.monthly_invoice_volume is not None and (
            not isinstance(candidate.monthly_invoice_volume, int)
            or isinstance(candidate.monthly_invoice_volume, bool)
            or candidate.monthly_invoice_volume < 0
            or candidate.monthly_invoice_volume > 100_000_000
        ):
            return False
        candidate_ap_value = ap_value
        candidate_volume_value = (
            int(volume.normalized_value)
            if volume is not None
            and isinstance(volume.normalized_value, (int, float))
            and not isinstance(volume.normalized_value, bool)
            else None
        )
        if (
            candidate.ap_years != candidate_ap_value
            or candidate.invoice_processing
            != (bool(invoice.normalized_value) if invoice is not None else None)
            or candidate.reconciliation
            != (bool(reconciliation.normalized_value) if reconciliation is not None else None)
            or candidate.spreadsheet_supported is not (ClaimKind.SPREADSHEET in by_kind)
            or candidate.accounting_platform_supported
            is not (ClaimKind.ACCOUNTING_PLATFORM in by_kind)
            or candidate.monthly_invoice_volume != candidate_volume_value
            or candidate.qualification_supported is not (ClaimKind.QUALIFICATION in by_kind)
            or set(candidate.corroborated_claim_kinds)
            != {kind for kind in by_kind if kind is not ClaimKind.CANDIDATE_ID}
        ):
            return False
        essentials = sum(
            (
                invoice is not None and invoice.normalized_value is True,
                by_kind.get(ClaimKind.RECONCILIATION) is not None
                and by_kind[ClaimKind.RECONCILIATION].normalized_value is True,
                ClaimKind.SPREADSHEET in by_kind,
                ClaimKind.ACCOUNTING_PLATFORM in by_kind,
            )
        )
        preferred = sum(
            (
                ap_value is not None and ap_value >= 2.0,
                volume is not None
                and isinstance(volume.normalized_value, (int, float))
                and not isinstance(volume.normalized_value, bool)
                and math.isfinite(float(volume.normalized_value))
                and float(volume.normalized_value).is_integer()
                and float(volume.normalized_value) >= 300,
                ClaimKind.QUALIFICATION in by_kind,
            )
        )
        corroborated = len({kind for kind in by_kind if kind is not ClaimKind.CANDIDATE_ID})
        if essentials == 4 and preferred > 0:
            band, queue, priority = (
                ReviewBand.STRONG_EVIDENCE_MATCH,
                ReviewQueue.PRIORITY_HUMAN_REVIEW,
                2,
            )
        elif essentials == 3 or (essentials == 4 and preferred == 0):
            band, queue, priority = (
                ReviewBand.POTENTIAL_EVIDENCE_MATCH,
                ReviewQueue.STANDARD_HUMAN_REVIEW,
                1,
            )
        else:
            band, queue, priority = (
                ReviewBand.INSUFFICIENT_SUPPORTED_EVIDENCE,
                ReviewQueue.EVIDENCE_CHECK,
                0,
            )
        if route.band is not band or route.queue is not queue or route.rank_key is None:
            return False
        if route.rank_key.as_tuple() != (priority, essentials, preferred, corroborated):
            return False
        values = {feature.name: feature.normalized_value for feature in features.values()}
        required = {
            "essentials_count": essentials,
            "preferred_count": preferred,
            "corroborated_count": corroborated,
            "rank_band_priority": priority,
            "rank_essentials": essentials,
            "rank_preferred": preferred,
            "rank_corroborated": corroborated,
            "rank_key": f"{priority}-{essentials}-{preferred}-{corroborated}",
            "band": band.value,
            "queue": queue.value,
            "route": "human_review_route",
        }
        return all(values.get(name) == value for name, value in required.items()) and (
            ReleaseAuthorizer._feature_topology_matches(
                route,
                by_kind,
                features,
            )
        )

    @staticmethod
    def _fact_bindings_valid(
        by_kind: dict[ClaimKind, SupportedFact],
        manifest: dict[str, EvidenceRef],
        candidate_id: str,
    ) -> bool:
        def role_ids(fact: SupportedFact, field: str) -> tuple[EvidenceRef, ...]:
            references = tuple(manifest[evidence_id] for evidence_id in fact.evidence_ids)
            expected_json_path = f"records[{candidate_id}].{field}"
            expected_resume_path = f"resume.{field}"
            permitted_resume_paths = {expected_resume_path}
            if fact.kind is ClaimKind.AP_YEARS:
                permitted_resume_paths.update({"resume.employment_start", "resume.employment_end"})
            if any(
                (
                    reference.source_kind is SourceKind.APPLICATION_JSON
                    and reference.field_path != expected_json_path
                )
                or (
                    reference.source_kind is SourceKind.RESUME_VISIBLE
                    and reference.field_path not in permitted_resume_paths
                )
                or reference.source_kind
                not in {SourceKind.APPLICATION_JSON, SourceKind.RESUME_VISIBLE}
                or (
                    reference.source_kind is SourceKind.RESUME_VISIBLE
                    and not ReleaseAuthorizer._visible_geometry_valid(reference)
                )
                for reference in references
            ):
                return ()
            return tuple(
                reference
                for reference in references
                if reference.field_path in {expected_json_path, expected_resume_path}
            )

        def hash_value(value: object) -> str:
            encoded = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            return hashlib.sha256(encoded).hexdigest()

        for kind, fact in by_kind.items():
            if any(evidence_id not in manifest for evidence_id in fact.evidence_ids):
                return False
            categorical_metadata = (
                fact.source_value,
                fact.canonical_value,
                fact.normalization_mode,
                fact.canonical_value_sha256,
            )
            if kind not in _CATEGORICAL_ALLOW_LISTS and any(
                value is not None for value in categorical_metadata
            ):
                return False
            if kind is ClaimKind.EMPLOYMENT_INTERVAL:
                if not fact.employment_intervals:
                    return False
                endpoint_ids: set[str] = set()
                intervals: list[tuple[date, date]] = []
                for interval in fact.employment_intervals:
                    if interval.end_date < interval.start_date:
                        return False
                    start = manifest.get(interval.start_evidence_id)
                    end = manifest.get(interval.end_evidence_id)
                    if (
                        start is None
                        or end is None
                        or start.evidence_id == end.evidence_id
                        or start.source_kind is not SourceKind.RESUME_VISIBLE
                        or end.source_kind is not SourceKind.RESUME_VISIBLE
                        or start.field_path != "resume.employment_start"
                        or end.field_path != "resume.employment_end"
                        or not ReleaseAuthorizer._visible_geometry_valid(start)
                        or not ReleaseAuthorizer._visible_geometry_valid(end)
                        or start.semantic_hash != hash_value(interval.start_date.isoformat())
                        or end.semantic_hash != hash_value(interval.end_date.isoformat())
                    ):
                        return False
                    endpoint_ids.update((start.evidence_id, end.evidence_id))
                    intervals.append((interval.start_date, interval.end_date))
                expected_duration = round(_merged_interval_days(intervals) / 365.2425, 4)
                normalized_duration = (
                    float(fact.normalized_value)
                    if isinstance(fact.normalized_value, (int, float))
                    and not isinstance(fact.normalized_value, bool)
                    else None
                )
                if (
                    endpoint_ids != set(fact.evidence_ids)
                    or len(endpoint_ids) != 2 * len(fact.employment_intervals)
                    or normalized_duration is None
                    or not math.isfinite(normalized_duration)
                    or normalized_duration < 0
                    or (normalized_duration == 0.0 and math.copysign(1.0, normalized_duration) < 0)
                    or normalized_duration != expected_duration
                ):
                    return False
                continue
            if fact.employment_intervals:
                return False
            field = kind.value
            scalar_refs = role_ids(fact, field)
            sources = {item.source_kind for item in scalar_refs}
            if sources != {SourceKind.APPLICATION_JSON, SourceKind.RESUME_VISIBLE}:
                return False
            scalar_hashes = {item.semantic_hash for item in scalar_refs}
            if len(scalar_hashes) != 1:
                return False
            if kind is ClaimKind.CANDIDATE_ID:
                if scalar_hashes != {hash_value(candidate_id)}:
                    return False
            elif kind in {
                ClaimKind.AP_YEARS,
                ClaimKind.INVOICE_PROCESSING,
                ClaimKind.RECONCILIATION,
                ClaimKind.MONTHLY_INVOICE_VOLUME,
            }:
                value: object = fact.normalized_value
                if kind is ClaimKind.MONTHLY_INVOICE_VOLUME and isinstance(value, float):
                    value = int(value) if value.is_integer() else value
                if scalar_hashes != {hash_value(value)}:
                    return False
            elif kind in _CATEGORICAL_ALLOW_LISTS:
                if (
                    fact.source_value is None
                    or fact.canonical_value is None
                    or fact.normalization_mode is not NormalizationMode.BOUNDED_ALLOW_LIST_V1
                    or fact.canonical_value_sha256 is None
                ):
                    return False
                canonical = _canonicalize_categorical(kind, fact.source_value)
                if (
                    canonical is None
                    or fact.normalized_value != canonical
                    or fact.canonical_value != canonical
                    or fact.canonical_value_sha256 != _canonical_value_hash(canonical)
                    or scalar_hashes != {hash_value(fact.source_value)}
                ):
                    return False
            else:
                return False
        return True

    @staticmethod
    def _visible_geometry_valid(reference: EvidenceRef) -> bool:
        if (
            reference.page is None
            or reference.document_page_count is None
            or reference.page_width is None
            or reference.page_height is None
            or reference.bbox is None
            or isinstance(reference.page, bool)
            or not isinstance(reference.page, int)
            or isinstance(reference.document_page_count, bool)
            or not isinstance(reference.document_page_count, int)
            or not 1 <= reference.page <= reference.document_page_count <= 10
        ):
            return False
        try:
            page_width = reference.page_width
            page_height = reference.page_height
            x0, top, x1, bottom = reference.bbox
            return (
                isinstance(page_width, (int, float))
                and not isinstance(page_width, bool)
                and math.isfinite(page_width)
                and page_width > 0
                and isinstance(page_height, (int, float))
                and not isinstance(page_height, bool)
                and math.isfinite(page_height)
                and page_height > 0
                and all(
                    isinstance(item, (int, float))
                    and not isinstance(item, bool)
                    and math.isfinite(item)
                    for item in reference.bbox
                )
                and 0 <= x0 <= x1 <= page_width
                and 0 <= top <= bottom <= page_height
            )
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _feature_topology_matches(
        route: CandidateRoute,
        by_kind: dict[ClaimKind, SupportedFact],
        features: dict[str, DerivedFeature],
    ) -> bool:
        by_name = {feature.name: feature for feature in features.values()}
        if len(by_name) != len(features):
            return False

        optional_names: list[str] = []
        fact_feature_kinds = {
            "essential_invoice_processing": ClaimKind.INVOICE_PROCESSING,
            "essential_reconciliation": ClaimKind.RECONCILIATION,
            "essential_spreadsheet": ClaimKind.SPREADSHEET,
            "essential_accounting_platform": ClaimKind.ACCOUNTING_PLATFORM,
            "preferred_qualification": ClaimKind.QUALIFICATION,
        }
        for name, kind in fact_feature_kinds.items():
            feature = by_name.get(name)
            fact = by_kind.get(kind)
            if (feature is None) is (fact is not None):
                return False
            if feature is not None and fact is not None:
                if feature.dependency_fact_ids != (fact.fact_id,) or feature.dependency_feature_ids:
                    return False
                optional_names.append(name)

        ap = by_kind.get(ClaimKind.AP_YEARS)
        interval = by_kind.get(ClaimKind.EMPLOYMENT_INTERVAL)
        ap_feature = by_name.get("preferred_ap_years")
        expects_ap_feature = ap is not None and (
            interval is not None or float(ap.normalized_value or 0) == 0
        )
        if (ap_feature is not None) is not expects_ap_feature:
            return False
        if ap_feature is not None and ap is not None:
            expected_ap_facts = (
                (ap.fact_id, interval.fact_id) if interval is not None else (ap.fact_id,)
            )
            if (
                ap_feature.dependency_fact_ids != expected_ap_facts
                or ap_feature.dependency_feature_ids
            ):
                return False
            optional_names.append("preferred_ap_years")

        volume = by_kind.get(ClaimKind.MONTHLY_INVOICE_VOLUME)
        invoice = by_kind.get(ClaimKind.INVOICE_PROCESSING)
        volume_feature = by_name.get("preferred_volume")
        expects_volume_feature = volume is not None and invoice is not None
        if (volume_feature is not None) is not expects_volume_feature:
            return False
        if volume_feature is not None and volume is not None and invoice is not None:
            if (
                volume_feature.dependency_fact_ids
                != (
                    invoice.fact_id,
                    volume.fact_id,
                )
                or volume_feature.dependency_feature_ids
            ):
                return False
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
        if set(by_name) != fixed_names.union(optional_names):
            return False
        identity = by_kind[ClaimKind.CANDIDATE_ID]

        def feature_ids(names: Sequence[str]) -> tuple[str, ...]:
            return tuple(by_name[name].feature_id for name in names if name in by_name)

        essential_names = (
            "essential_invoice_processing",
            "essential_reconciliation",
            "essential_spreadsheet",
            "essential_accounting_platform",
        )
        preferred_names = (
            "preferred_ap_years",
            "preferred_volume",
            "preferred_qualification",
        )
        expected_dependencies = {
            "essentials_count": ((identity.fact_id,), feature_ids(essential_names)),
            "preferred_count": ((identity.fact_id,), feature_ids(preferred_names)),
            "corroborated_count": (
                tuple(fact.fact_id for fact in by_kind.values()),
                (),
            ),
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
            by_name[name].dependency_fact_ids != fact_ids
            or by_name[name].dependency_feature_ids != feature_ids_value
            for name, (fact_ids, feature_ids_value) in expected_dependencies.items()
        ):
            return False
        graph = route.support_graph
        return graph is not None and graph.route_support_ids == (by_name["route"].feature_id,)

    @staticmethod
    def _order_is_valid(routes: Sequence[CandidateRoute]) -> bool:
        ranked = sorted(
            (route for route in routes if route.display_position is not None),
            key=lambda route: route.display_position or 0,
        )
        if [route.display_position for route in ranked] != list(range(1, len(ranked) + 1)):
            return False
        previous_key: tuple[int, int, int, int] | None = None
        previous_rank = 0
        previous_candidate_id: str | None = None
        seen_keys: list[tuple[int, int, int, int]] = []
        for route in ranked:
            if route.rank_key is None or route.evidence_rank is None:
                return False
            key = route.rank_key.as_tuple()
            if previous_key is not None and key > previous_key:
                return False
            if key == previous_key:
                if (
                    route.evidence_rank != previous_rank
                    or previous_candidate_id is None
                    or route.candidate_id <= previous_candidate_id
                ):
                    return False
            else:
                seen_keys.append(key)
                if route.evidence_rank != len(seen_keys):
                    return False
            previous_key = key
            previous_rank = route.evidence_rank
            previous_candidate_id = route.candidate_id
        return True
