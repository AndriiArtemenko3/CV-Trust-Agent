from __future__ import annotations

import hashlib
from datetime import date, timedelta

import pytest

from cv_trust_agent.engine import TrustedAgentEngine
from cv_trust_agent.evidence_validation import compute_evidence_value_hash
from cv_trust_agent.mappers import DeterministicMapper
from cv_trust_agent.models import (
    CandidateRoute,
    ClaimKind,
    DecisionSupportGraph,
    DerivedFeature,
    EvidenceDispositionInventory,
    EvidenceRankKey,
    ExecutionPlan,
    PlanStep,
    ProhibitedAction,
    ReasonCode,
    ReviewBand,
    ReviewQueue,
    RunDecision,
    SourceKind,
    StepReceipt,
    StepStatus,
    Strategy,
    TrustDecision,
    TrustOutcome,
    TrustScope,
    TrustStage,
    TrustState,
    UnavailableCandidate,
    UnavailableComponent,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)
from cv_trust_agent.release import (
    ReleaseAuthorizer,
    _expected_json_evidence_id,
    _merged_interval_days,
)
from tests.test_engine_unit import _Case, _case, _record, _run, _StaticProvider


def _authorization_fixture(
    *, two_candidates: bool = False, exact_tie: bool = False
) -> tuple[RunDecision, ValidatedBatchEvidence]:
    records = (
        (
            _record("AP-001"),
            _record("AP-002") if exact_tie else _record("AP-002", ap_years=1.0),
        )
        if two_candidates
        else (_record("AP-001"),)
    )
    case: _Case = _case(records)
    decision = _run(case)
    routes = {route.candidate_id: route for route in decision.routes}
    candidates = tuple(
        ValidatedCandidateEvidence(
            candidate_id=record.candidate_id,
            snapshot_id=decision.snapshot_id,
            trust_state=TrustState.USABLE,
            ap_years=record.ap_years,
            invoice_processing=record.invoice_processing,
            reconciliation=record.reconciliation,
            spreadsheet_supported=record.spreadsheet == "Excel",
            accounting_platform_supported=record.accounting_platform == "Xero",
            monthly_invoice_volume=record.monthly_invoice_volume,
            qualification_supported=record.qualification == "AAT Level 3",
            corroborated_claim_kinds=tuple(
                fact.kind
                for fact in routes[record.candidate_id].support_graph.facts
                if fact.kind.value != "candidate_id"
            ),
            evidence_ids=routes[record.candidate_id].evidence_ids,
            support_graph=routes[record.candidate_id].support_graph,
            reason_codes=routes[record.candidate_id].reason_codes,
        )
        for record in records
    )
    batch = ValidatedBatchEvidence(
        batch_id=decision.batch_id,
        snapshot_id=decision.snapshot_id,
        candidates=candidates,
        batch_integrity_valid=True,
        mapper_disagreement=False,
    )
    return decision, batch


def test_interval_duration_merge_handles_empty_overlapping_and_disjoint_ranges() -> None:
    assert _merged_interval_days(()) == 0
    assert (
        _merged_interval_days(
            (
                (date(2026, 1, 5), date(2026, 1, 20)),
                (date(2026, 1, 1), date(2026, 1, 10)),
            )
        )
        == 19
    )
    assert (
        _merged_interval_days(
            (
                (date(2026, 2, 1), date(2026, 2, 3)),
                (date(2026, 1, 1), date(2026, 1, 10)),
            )
        )
        == 11
    )


def test_expected_json_evidence_id_matches_bounded_digest_fallback() -> None:
    candidate_id = "C" * 80
    snapshot_id = "S" * 80
    semantic_hash = compute_evidence_value_hash(4.0)
    readable = f"json:{snapshot_id}:{candidate_id}:{semantic_hash}:ap_years"

    assert (
        _expected_json_evidence_id(
            candidate_id,
            snapshot_id,
            ClaimKind.AP_YEARS,
            semantic_hash,
        )
        == f"json:{hashlib.sha256(readable.encode('utf-8')).hexdigest()}"
    )


def _v2_authorization_fixture() -> tuple[RunDecision, ValidatedBatchEvidence]:
    case = _case((_record("AP-001"), _record("AP-002")))
    engine = TrustedAgentEngine(DeterministicMapper(case.outputs))
    decision = engine.execute(
        engine.start(case.index),
        _StaticProvider(
            case.records,
            case.requests,
            (
                UnavailableCandidate(
                    candidate_id="AP-002",
                    component=UnavailableComponent.RESUME,
                    reason=ReasonCode.RETRIEVAL_FAILED,
                ),
            ),
        ),
    )
    healthy_route = next(route for route in decision.routes if route.candidate_id == "AP-001")
    unavailable_route = next(route for route in decision.routes if route.candidate_id == "AP-002")
    graph = healthy_route.support_graph
    assert graph is not None and decision.plan.version == 2
    batch = ValidatedBatchEvidence(
        batch_id=decision.batch_id,
        snapshot_id=decision.snapshot_id,
        candidates=(
            ValidatedCandidateEvidence(
                candidate_id="AP-001",
                snapshot_id=decision.snapshot_id,
                trust_state=TrustState.USABLE,
                ap_years=4.0,
                invoice_processing=True,
                reconciliation=True,
                spreadsheet_supported=True,
                accounting_platform_supported=True,
                monthly_invoice_volume=600,
                qualification_supported=True,
                corroborated_claim_kinds=tuple(
                    fact.kind for fact in graph.facts if fact.kind.value != "candidate_id"
                ),
                evidence_ids=healthy_route.evidence_ids,
                support_graph=graph,
                reason_codes=healthy_route.reason_codes,
            ),
            ValidatedCandidateEvidence(
                candidate_id="AP-002",
                snapshot_id=decision.snapshot_id,
                trust_state=TrustState.UNAVAILABLE,
                reason_codes=unavailable_route.reason_codes,
            ),
        ),
        unavailable_candidate_ids=("AP-002",),
        batch_integrity_valid=True,
        mapper_disagreement=False,
    )
    return decision, batch


def test_authorizer_accepts_valid_v2_partial_safe_release() -> None:
    decision, batch = _v2_authorization_fixture()

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert result.authorized


def _replace_graph(
    decision: RunDecision,
    batch: ValidatedBatchEvidence,
    graph: DecisionSupportGraph,
) -> tuple[CandidateRoute, ValidatedBatchEvidence, ExecutionPlan]:
    route = decision.routes[0].model_copy(update={"support_graph": graph})
    candidate = batch.candidates[0].model_copy(update={"support_graph": graph})
    return route, batch.model_copy(update={"candidates": (candidate,)}), decision.plan


def _fact_with_value(
    graph: DecisionSupportGraph,
    kind: ClaimKind,
    value: bool | int | float | str,
) -> DecisionSupportGraph:
    fact = next(item for item in graph.facts if item.kind is kind)
    changed = fact.model_copy(update={"normalized_value": value})
    semantic_hash = compute_evidence_value_hash(value)
    manifest = tuple(
        reference.model_copy(update={"semantic_hash": semantic_hash})
        if reference.field_path is not None
        and reference.field_path.rsplit(".", maxsplit=1)[-1] == kind.value
        else reference
        for reference in graph.evidence_manifest
    )
    return graph.model_copy(
        update={
            "facts": tuple(
                changed if item.fact_id == fact.fact_id else item for item in graph.facts
            ),
            "evidence_manifest": manifest,
        }
    )


def _assert_graph_rejected(
    decision: RunDecision,
    batch: ValidatedBatchEvidence,
    graph: DecisionSupportGraph,
) -> None:
    route, changed_batch, plan = _replace_graph(decision, batch, graph)
    result = ReleaseAuthorizer().authorize(
        changed_batch,
        (route,),
        plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
    )
    assert not result.authorized


def test_authorizer_accepts_complete_executed_release_without_recomputing_rank() -> None:
    decision, batch = _authorization_fixture()

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
    )

    assert result.authorized
    assert result.reason_codes == (
        ReasonCode.SUPPORT_GRAPH_VALID,
        ReasonCode.RELEASE_AUTHORIZED,
    )


def test_authorizer_rejects_ranked_cross_source_catalog_substitution() -> None:
    decision, batch = _authorization_fixture()
    cross_source = next(
        item
        for item in decision.trust_ledger
        if item.scope is TrustScope.RECORD and item.stage is TrustStage.CROSS_SOURCE
    )
    parse_receipt = next(
        item
        for item in decision.step_receipts
        if item.command_kind is PlanStep.PARSE_CANDIDATE_RESUMES
        and item.status is StepStatus.COMPLETED
    )
    target = next(
        evidence_id
        for evidence_id in cross_source.evidence_ids
        if evidence_id.startswith("json:") and evidence_id.endswith(":accounting_platform")
    )
    replacement = next(
        evidence_id
        for evidence_id in parse_receipt.evidence_ids
        if evidence_id.endswith(":candidate_id") and evidence_id not in cross_source.evidence_ids
    )
    changed_cross_source = cross_source.model_copy(
        update={
            "evidence_ids": tuple(
                sorted(
                    replacement if evidence_id == target else evidence_id
                    for evidence_id in cross_source.evidence_ids
                )
            )
        }
    )
    ledger = tuple(
        changed_cross_source if item is cross_source else item for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=ledger,
    )

    assert not result.authorized


def test_authorizer_rederives_ranked_false_valid_scalar_rewrite() -> None:
    """A still-top-band scalar rewrite cannot retain a clean cross-source gate."""

    decision, batch = _authorization_fixture()
    candidate = batch.candidates[0]
    graph = candidate.support_graph
    assert graph is not None
    changed_graph = _fact_with_value(graph, ClaimKind.MONTHLY_INVOICE_VOLUME, 601)
    route, changed_batch, plan = _replace_graph(decision, batch, changed_graph)
    changed_batch = changed_batch.model_copy(
        update={
            "candidates": (
                changed_batch.candidates[0].model_copy(update={"monthly_invoice_volume": 601}),
            )
        }
    )

    def rewrite_inventory(
        inventory: EvidenceDispositionInventory,
    ) -> EvidenceDispositionInventory:
        changed_entries = tuple(
            item.model_copy(
                update={
                    "mapped_value": 601,
                    "reference": item.reference.model_copy(
                        update={"semantic_hash": compute_evidence_value_hash(601)}
                    ),
                }
            )
            if item.claim_kind is ClaimKind.MONTHLY_INVOICE_VOLUME
            else item
            for item in inventory.entries
        )
        return inventory.model_copy(update={"entries": changed_entries})

    ledger = tuple(
        item.model_copy(update={"evidence_inventory": rewrite_inventory(item.evidence_inventory)})
        if item.scope is TrustScope.RECORD
        and item.candidate_id == candidate.candidate_id
        and item.stage
        in {
            TrustStage.MAPPING,
            TrustStage.PROVENANCE,
            TrustStage.CANDIDATE_VALIDATION,
        }
        and item.evidence_inventory is not None
        else item
        for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        changed_batch,
        (route,),
        plan,
        decision.step_receipts,
        trust_ledger=ledger,
    )

    assert not result.authorized


@pytest.mark.parametrize(
    "mutation",
    ["id", "path", "hash", "value", "coherent_value", "source", "snapshot"],
)
def test_authorizer_rejects_structured_anchor_rewrites(mutation: str) -> None:
    decision, batch = _authorization_fixture()

    def rewrite_inventory(
        inventory: EvidenceDispositionInventory,
    ) -> EvidenceDispositionInventory:
        anchors = tuple(inventory.structured_anchors)
        target = next(item for item in anchors if item.claim_kind is ClaimKind.RECONCILIATION)
        reference = target.reference
        value: object = target.value
        if mutation == "id":
            reference = reference.model_copy(update={"evidence_id": "json:forged:reconciliation"})
        elif mutation == "path":
            reference = reference.model_copy(update={"field_path": "record.spreadsheet"})
        elif mutation == "hash":
            reference = reference.model_copy(
                update={"semantic_hash": compute_evidence_value_hash(False)}
            )
        elif mutation == "value":
            value = False
        elif mutation == "coherent_value":
            value = False
            semantic_hash = compute_evidence_value_hash(False)
            reference = reference.model_copy(
                update={
                    "semantic_hash": semantic_hash,
                    "evidence_id": _expected_json_evidence_id(
                        inventory.candidate_id,
                        inventory.snapshot_id,
                        ClaimKind.RECONCILIATION,
                        semantic_hash,
                    ),
                }
            )
        elif mutation == "source":
            reference = reference.model_copy(update={"source_kind": SourceKind.RESUME_VISIBLE})
        else:
            reference = reference.model_copy(update={"snapshot_id": "stale-snapshot"})
        changed_target = target.model_copy(update={"value": value, "reference": reference})
        return inventory.model_copy(
            update={
                "structured_anchors": tuple(
                    changed_target if item is target else item for item in anchors
                )
            }
        )

    ledger = tuple(
        item.model_copy(update={"evidence_inventory": rewrite_inventory(item.evidence_inventory)})
        if item.scope is TrustScope.RECORD
        and item.candidate_id == "AP-001"
        and item.stage
        in {
            TrustStage.MAPPING,
            TrustStage.PROVENANCE,
            TrustStage.CANDIDATE_VALIDATION,
        }
        and item.evidence_inventory is not None
        else item
        for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=ledger,
    )

    assert not result.authorized


def test_authorizer_rejects_missing_and_failed_command_receipts() -> None:
    decision, batch = _authorization_fixture()
    rank_command = next(
        command for command in decision.plan.commands if command.kind.value.startswith("rank_")
    )
    missing = tuple(
        receipt
        for receipt in decision.step_receipts
        if not (
            receipt.command_id == rank_command.command_id and receipt.status is StepStatus.COMPLETED
        )
    )
    failed = tuple(
        receipt.model_copy(update={"status": StepStatus.FAILED})
        if receipt.command_id == rank_command.command_id and receipt.status is StepStatus.COMPLETED
        else receipt
        for receipt in decision.step_receipts
    )

    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch,
            decision.routes,
            decision.plan,
            missing,
            trust_ledger=decision.trust_ledger,
        )
        .authorized
    )
    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch,
            decision.routes,
            decision.plan,
            failed,
            trust_ledger=decision.trust_ledger,
        )
        .authorized
    )


@pytest.mark.parametrize("mutation", ["missing_route", "wrong_hold_scope", "ranked_excluded"])
def test_authorizer_rejects_route_scope_mutations(mutation: str) -> None:
    decision, batch = _authorization_fixture()
    routes = decision.routes
    plan = decision.plan
    if mutation == "missing_route":
        routes = ()
    elif mutation == "wrong_hold_scope":
        plan = plan.model_copy(update={"strategy": Strategy.BATCH_INTEGRITY_HOLD})
    else:
        routes = (routes[0].model_copy(update={"band": ReviewBand.INTEGRITY_HOLD}),)

    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch,
            routes,
            plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
        )
        .authorized
    )


def test_authorizer_rejects_unavailable_candidate_released_as_ranked() -> None:
    decision, batch = _authorization_fixture()
    unavailable = batch.model_copy(update={"unavailable_candidate_ids": ("AP-001",)})

    result = ReleaseAuthorizer().authorize(
        unavailable,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
    )

    assert not result.authorized


@pytest.mark.parametrize("mutation", ["duplicate", "missing", "foreign"])
def test_authorizer_requires_unavailable_ids_to_exactly_match_unavailable_state(
    mutation: str,
) -> None:
    decision, batch = _v2_authorization_fixture()
    unavailable_ids = {
        "duplicate": ("AP-002", "AP-002"),
        "missing": (),
        "foreign": ("AP-001", "AP-002"),
    }[mutation]

    result = ReleaseAuthorizer().authorize(
        batch.model_copy(update={"unavailable_candidate_ids": unavailable_ids}),
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_route",
        "objective",
        "command_shape",
        "command_chain",
        "trigger",
        "prohibition_order",
        "coerced_batch_flag",
        "allowed_evidence_order",
    ],
)
def test_authorizer_independently_rederives_release_policy(mutation: str) -> None:
    decision, batch = _authorization_fixture()
    routes = decision.routes
    plan = decision.plan
    if mutation == "duplicate_route":
        routes = (routes[0], routes[0])
    elif mutation == "objective":
        plan = plan.model_copy(update={"objective": "hold_batch_for_integrity_review"})
    elif mutation == "command_shape":
        plan = plan.model_copy(update={"commands": plan.commands[1:]})
    elif mutation == "command_chain":
        second = plan.commands[1].model_copy(update={"dependency_ids": ()})
        plan = plan.model_copy(update={"commands": (plan.commands[0], second, *plan.commands[2:])})
    elif mutation == "trigger":
        plan = plan.model_copy(
            update={"trigger_codes": (*plan.trigger_codes, ReasonCode.MAPPER_DISAGREEMENT)}
        )
    elif mutation == "prohibition_order":
        plan = plan.model_copy(
            update={"prohibited_actions": tuple(reversed(plan.prohibited_actions))}
        )
    elif mutation == "coerced_batch_flag":
        batch = batch.model_copy(update={"batch_integrity_valid": "true"})
    else:
        plan = plan.model_copy(
            update={"allowed_evidence_ids": tuple(reversed(plan.allowed_evidence_ids))}
        )

    result = ReleaseAuthorizer().authorize(
        batch,
        routes,
        plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=(plan,),
    )

    assert not result.authorized


@pytest.mark.parametrize("state", [TrustState.QUARANTINED, TrustState.DEGRADED])
def test_authorizer_rejects_ranked_route_for_nonusable_candidate(state: TrustState) -> None:
    decision, batch = _authorization_fixture()
    candidate = batch.candidates[0].model_copy(update={"trust_state": state})

    result = ReleaseAuthorizer().authorize(
        batch.model_copy(update={"candidates": (candidate,)}),
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
    )

    assert not result.authorized


@pytest.mark.parametrize(
    "mutation",
    [
        "outside_allowlist",
        "unranked_with_evidence",
        "missing_graph",
        "unknown_fact",
        "open_closure",
    ],
)
def test_authorizer_rejects_support_graph_mutations(mutation: str) -> None:
    decision, batch = _authorization_fixture()
    route = decision.routes[0]
    plan = decision.plan
    graph = route.support_graph
    assert graph is not None
    if mutation == "outside_allowlist":
        route = route.model_copy(update={"evidence_ids": (*route.evidence_ids, "raw:note")})
    elif mutation == "unranked_with_evidence":
        route = route.model_copy(
            update={"evidence_rank": None, "display_position": None, "rank_key": None}
        )
        plan = plan.model_copy(update={"allowed_evidence_ids": ()})
    elif mutation == "missing_graph":
        route = route.model_copy(update={"support_graph": None})
    elif mutation == "unknown_fact":
        feature = graph.features[0].model_copy(update={"dependency_fact_ids": ("fact:unknown",)})
        graph = graph.model_copy(
            update={
                "features": tuple(
                    feature if item.feature_id == feature.feature_id else item
                    for item in graph.features
                )
            }
        )
        route = route.model_copy(update={"support_graph": graph})
        candidate = batch.candidates[0].model_copy(update={"support_graph": graph})
        batch = batch.model_copy(update={"candidates": (candidate,)})
    else:
        graph = graph.model_copy(update={"evidence_ids": (*graph.evidence_ids, "ev:unused")})
        route = route.model_copy(
            update={"evidence_ids": graph.evidence_ids, "support_graph": graph}
        )
        plan = plan.model_copy(
            update={"allowed_evidence_ids": (*plan.allowed_evidence_ids, "ev:unused")}
        )
        candidate = batch.candidates[0].model_copy(
            update={"evidence_ids": graph.evidence_ids, "support_graph": graph}
        )
        batch = batch.model_copy(update={"candidates": (candidate,)})

    result = ReleaseAuthorizer().authorize(
        batch,
        (route,),
        plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
    )

    assert not result.authorized
    assert ReasonCode.RELEASE_BLOCKED in result.reason_codes


@pytest.mark.parametrize(
    "mutation",
    ["position_gap", "missing_key", "inverted", "equal_wrong_rank", "bad_dense_rank"],
)
def test_authorizer_rejects_order_and_dense_rank_mutations(mutation: str) -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    first, second = decision.routes
    if mutation == "position_gap":
        first = first.model_copy(update={"display_position": 3})
    elif mutation == "missing_key":
        first = first.model_copy(update={"rank_key": None})
    elif mutation == "inverted":
        first = first.model_copy(
            update={
                "rank_key": EvidenceRankKey(
                    band_priority=0,
                    essentials_count=0,
                    preferred_count=0,
                    corroborated_claim_count=0,
                )
            }
        )
    elif mutation == "equal_wrong_rank":
        second = second.model_copy(update={"rank_key": first.rank_key, "evidence_rank": 2})
    else:
        second = second.model_copy(update={"evidence_rank": 4})

    result = ReleaseAuthorizer().authorize(
        batch,
        (first, second),
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
    )

    assert not result.authorized


def test_authorizer_requires_candidate_id_order_inside_exact_rank_key_ties() -> None:
    decision, batch = _authorization_fixture(two_candidates=True, exact_tie=True)
    first, second = decision.routes
    assert first.rank_key == second.rank_key
    assert first.evidence_rank == second.evidence_rank
    swapped = (
        first.model_copy(update={"display_position": second.display_position}),
        second.model_copy(update={"display_position": first.display_position}),
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        swapped,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_authorizer_binds_route_reason_codes_to_validated_candidate() -> None:
    decision, batch = _authorization_fixture()
    route = decision.routes[0].model_copy(
        update={"reason_codes": (ReasonCode.BATCH_HOLD_REQUIRED,)}
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        (route,),
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_authorizer_rejects_removed_safety_prohibition() -> None:
    decision, batch = _authorization_fixture()
    plan = decision.plan.model_copy(
        update={
            "prohibited_actions": tuple(
                action
                for action in decision.plan.prohibited_actions
                if action is not ProhibitedAction.USE_RAW_SOURCE_TEXT
            )
        }
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
    )

    assert not result.authorized


def test_authorizer_and_run_contract_reject_unknown_receipts() -> None:
    decision, batch = _authorization_fixture()
    unknown = decision.step_receipts[-1].model_copy(
        update={
            "receipt_id": "receipt:unknown",
            "sequence": len(decision.step_receipts) + 1,
            "command_id": "p1:unknown",
        }
    )
    receipts = (*decision.step_receipts, unknown)

    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch,
            decision.routes,
            decision.plan,
            receipts,
            trust_ledger=decision.trust_ledger,
            plan_history=decision.plans,
        )
        .authorized
    )
    payload = decision.model_dump(mode="python")
    payload["step_receipts"] = receipts
    with pytest.raises(ValueError, match="exact planned command"):
        RunDecision.model_validate(payload)


def test_authorizer_rejects_unknown_v1_receipt_in_a_v2_release() -> None:
    decision, batch = _v2_authorization_fixture()
    unknown = decision.step_receipts[-1].model_copy(
        update={
            "receipt_id": "receipt:v1:unknown",
            "sequence": len(decision.step_receipts) + 1,
            "plan_version": 1,
            "command_id": "p1:unknown",
        }
    )

    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch,
            decision.routes,
            decision.plan,
            (*decision.step_receipts, unknown),
            trust_ledger=decision.trust_ledger,
            plan_history=decision.plans,
        )
        .authorized
    )


def test_authorizer_rejects_planning_gate_spliced_into_command_chain() -> None:
    decision, batch = _authorization_fixture()
    target = next(
        receipt
        for receipt in decision.step_receipts
        if receipt.command_kind is PlanStep.VALIDATE_CANDIDATE_DETAILS
        and receipt.status is StepStatus.COMPLETED
    )
    forged = TrustDecision(
        decision_id="td:forged:planning",
        stage=TrustStage.PLANNING,
        scope=TrustScope.BATCH,
        state=TrustState.USABLE,
        outcome=TrustOutcome.ALLOW,
        reason_codes=(ReasonCode.PLAN_SELECTED,),
        input_gate_ids=target.consumed_gate_ids,
    )
    assert target.produced_gate_id is not None
    produced = next(
        decision
        for decision in decision.trust_ledger
        if decision.decision_id == target.produced_gate_id
    )
    receipts = tuple(
        receipt.model_copy(update={"consumed_gate_ids": (forged.decision_id,)})
        if receipt is target
        else receipt
        for receipt in decision.step_receipts
    )
    ledger: list[TrustDecision] = []
    for item in decision.trust_ledger:
        if item is produced:
            ledger.append(forged)
            item = item.model_copy(update={"input_gate_ids": (forged.decision_id,)})
        ledger.append(item)

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        receipts,
        trust_ledger=tuple(ledger),
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_full_strategy_cannot_replace_a_usable_route_with_integrity_hold() -> None:
    decision, batch = _authorization_fixture()
    held = decision.routes[0].model_copy(
        update={
            "band": ReviewBand.INTEGRITY_HOLD,
            "queue": ReviewQueue.INTEGRITY_REVIEW,
            "evidence_rank": None,
            "display_position": None,
            "rank_key": None,
            "evidence_ids": (),
            "support_graph": None,
        }
    )
    plan = decision.plan.model_copy(update={"allowed_evidence_ids": ()})

    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch,
            (held,),
            plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
            plan_history=(plan,),
        )
        .authorized
    )


def test_authorizer_rejects_forged_manifest_even_when_route_and_batch_match() -> None:
    decision, batch = _authorization_fixture()
    route = decision.routes[0]
    graph = route.support_graph
    assert graph is not None
    forged_graph = graph.model_copy(
        update={
            "evidence_manifest": tuple(
                reference.model_copy(update={"semantic_hash": "0" * 64})
                for reference in graph.evidence_manifest
            )
        }
    )
    forged_route = route.model_copy(update={"support_graph": forged_graph})
    forged_candidate = batch.candidates[0].model_copy(update={"support_graph": forged_graph})
    forged_batch = batch.model_copy(update={"candidates": (forged_candidate,)})

    assert (
        not ReleaseAuthorizer()
        .authorize(
            forged_batch,
            (forged_route,),
            decision.plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
        )
        .authorized
    )


def test_authorizer_rejects_scalar_fact_supported_by_resume_only() -> None:
    decision, batch = _authorization_fixture()
    route = decision.routes[0]
    graph = route.support_graph
    assert graph is not None
    ap_fact = next(fact for fact in graph.facts if fact.kind.value == "ap_years")
    json_id = next(
        evidence_id
        for evidence_id in ap_fact.evidence_ids
        if next(
            reference
            for reference in graph.evidence_manifest
            if reference.evidence_id == evidence_id
        ).source_kind
        is SourceKind.APPLICATION_JSON
    )
    forged_fact = ap_fact.model_copy(
        update={
            "evidence_ids": tuple(item for item in ap_fact.evidence_ids if item != json_id),
            "source_roles": (SourceKind.RESUME_VISIBLE,),
        }
    )
    evidence_ids = tuple(item for item in graph.evidence_ids if item != json_id)
    forged_graph = graph.model_copy(
        update={
            "evidence_ids": evidence_ids,
            "evidence_manifest": tuple(
                item for item in graph.evidence_manifest if item.evidence_id != json_id
            ),
            "facts": tuple(
                forged_fact if fact.fact_id == ap_fact.fact_id else fact for fact in graph.facts
            ),
        }
    )
    forged_route = route.model_copy(
        update={"evidence_ids": evidence_ids, "support_graph": forged_graph}
    )
    forged_candidate = batch.candidates[0].model_copy(
        update={"evidence_ids": evidence_ids, "support_graph": forged_graph}
    )
    forged_plan = decision.plan.model_copy(update={"allowed_evidence_ids": evidence_ids})

    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch.model_copy(update={"candidates": (forged_candidate,)}),
            (forged_route,),
            forged_plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
            plan_history=(forged_plan,),
        )
        .authorized
    )


def test_authorizer_rejects_semantic_feature_topology_forgery() -> None:
    decision, batch = _authorization_fixture()
    route = decision.routes[0]
    graph = route.support_graph
    assert graph is not None
    corroborated = next(
        feature for feature in graph.features if feature.name == "corroborated_count"
    )
    forged_features = tuple(
        feature.model_copy(
            update={
                "dependency_feature_ids": (corroborated.feature_id,),
                "dependency_fact_ids": (),
            }
        )
        if feature.name == "route"
        else feature
        for feature in graph.features
    )
    forged_graph = graph.model_copy(update={"features": forged_features})
    forged_route = route.model_copy(update={"support_graph": forged_graph})
    forged_candidate = batch.candidates[0].model_copy(update={"support_graph": forged_graph})
    forged_batch = batch.model_copy(update={"candidates": (forged_candidate,)})

    assert (
        not ReleaseAuthorizer()
        .authorize(
            forged_batch,
            (forged_route,),
            decision.plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
        )
        .authorized
    )


def test_authorizer_binds_graph_facts_back_to_validated_candidate_fields() -> None:
    decision, batch = _authorization_fixture()
    inconsistent = batch.candidates[0].model_copy(update={"ap_years": 1.0})

    assert (
        not ReleaseAuthorizer()
        .authorize(
            batch.model_copy(update={"candidates": (inconsistent,)}),
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
        )
        .authorized
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_plan_version",
        "duplicate_sequence",
        "duplicate_receipt_id",
        "missing_audit_command",
        "unfinished_audit_with_release",
        "audit_completed_without_start",
        "duplicate_trust_decision",
        "reused_produced_gate",
        "first_gate_not_planning",
        "missing_planning_parent",
    ],
)
def test_authorizer_rejects_receipt_and_gate_chain_mutations(mutation: str) -> None:
    decision, batch = _authorization_fixture()
    plan = decision.plan
    receipts = decision.step_receipts
    ledger = decision.trust_ledger
    history = decision.plans
    if mutation == "duplicate_plan_version":
        history = (plan, plan)
    elif mutation == "duplicate_sequence":
        receipts = (
            *receipts[:-1],
            receipts[-1].model_copy(update={"sequence": receipts[-2].sequence}),
        )
    elif mutation == "duplicate_receipt_id":
        receipts = (
            *receipts[:-1],
            receipts[-1].model_copy(update={"receipt_id": receipts[-2].receipt_id}),
        )
    elif mutation == "missing_audit_command":
        plan = plan.model_copy(
            update={
                "commands": tuple(
                    command
                    for command in plan.commands
                    if command.kind is not PlanStep.PRE_RELEASE_AUDIT
                )
            }
        )
        receipts = tuple(
            receipt
            for receipt in receipts
            if receipt.command_kind is not PlanStep.PRE_RELEASE_AUDIT
        )
        history = (plan,)
    elif mutation == "unfinished_audit_with_release":
        receipts = tuple(
            receipt
            for receipt in receipts
            if not (
                receipt.command_kind is PlanStep.PRE_RELEASE_AUDIT
                and receipt.status is StepStatus.COMPLETED
            )
        )
    elif mutation == "audit_completed_without_start":
        receipts = tuple(
            receipt
            for receipt in receipts
            if not (
                receipt.command_kind is PlanStep.PRE_RELEASE_AUDIT
                and receipt.status is StepStatus.STARTED
            )
        )
    elif mutation == "duplicate_trust_decision":
        ledger = (*ledger, ledger[-1])
    elif mutation == "reused_produced_gate":
        first_terminal = next(
            receipt for receipt in receipts if receipt.status is StepStatus.COMPLETED
        )
        second_terminal = tuple(
            receipt for receipt in receipts if receipt.status is StepStatus.COMPLETED
        )[1]
        receipts = tuple(
            receipt.model_copy(update={"produced_gate_id": first_terminal.produced_gate_id})
            if receipt is second_terminal
            else receipt
            for receipt in receipts
        )
    elif mutation == "first_gate_not_planning":
        first_terminal = next(
            receipt for receipt in receipts if receipt.status is StepStatus.COMPLETED
        )
        manifest = next(item for item in ledger if item.stage is TrustStage.MANIFEST)
        assert first_terminal.produced_gate_id is not None
        receipts = tuple(
            receipt.model_copy(update={"consumed_gate_ids": (manifest.decision_id,)})
            if receipt is first_terminal
            else receipt
            for receipt in receipts
        )
        ledger = tuple(
            item.model_copy(update={"input_gate_ids": (manifest.decision_id,)})
            if item.decision_id == first_terminal.produced_gate_id
            else item
            for item in ledger
        )
    else:
        first_terminal = next(
            receipt for receipt in receipts if receipt.status is StepStatus.COMPLETED
        )
        planning_id = first_terminal.consumed_gate_ids[0]
        ledger = tuple(
            item.model_copy(update={"input_gate_ids": ("td:missing",)})
            if item.decision_id == planning_id
            else item
            for item in ledger
        )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        plan,
        receipts,
        trust_ledger=ledger,
        plan_history=history,
    )

    assert not result.authorized


def test_authorizer_rejects_v2_plan_gate_not_parented_by_validation() -> None:
    decision, batch = _v2_authorization_fixture()
    first_v2_terminal = next(
        receipt
        for receipt in decision.step_receipts
        if receipt.plan_version == 2 and receipt.status is StepStatus.COMPLETED
    )
    earlier_non_validation_gate = next(
        receipt.produced_gate_id
        for receipt in decision.step_receipts
        if receipt.plan_version == 1
        and receipt.command_kind is PlanStep.MAP_CANDIDATE_CLAIMS
        and receipt.status is StepStatus.COMPLETED
    )
    assert earlier_non_validation_gate is not None
    planning_id = first_v2_terminal.consumed_gate_ids[0]
    ledger = tuple(
        item.model_copy(update={"input_gate_ids": (earlier_non_validation_gate,)})
        if item.decision_id == planning_id
        else item
        for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_fact_kind",
        "identity_value",
        "unsupported_canonical_label",
        "invoice_nonboolean",
        "ap_nonnumber",
        "ap_exceeds_interval",
        "missing_interval",
        "volume_without_invoice",
        "volume_nonnumber",
        "identity_hash",
        "interval_missing_end",
        "categorical_source_value",
        "categorical_value_hash",
        "fact_snapshot",
        "interval_start_date",
        "interval_duration",
        "interval_endpoint_hash",
        "json_candidate_path",
        "resume_wrong_path",
        "resume_missing_page",
        "resume_missing_document_page_count",
        "resume_missing_page_width",
        "resume_missing_page_height",
        "resume_missing_bbox",
        "resume_string_bbox",
        "resume_page_11",
        "resume_page_999",
        "resume_document_page_count_999",
        "resume_bbox_left_of_page",
        "resume_bbox_above_page",
        "resume_bbox_right_of_page",
        "resume_bbox_below_page",
    ],
)
def test_authorizer_rejects_semantically_invalid_support_graph(mutation: str) -> None:
    decision, batch = _authorization_fixture()
    graph = decision.routes[0].support_graph
    assert graph is not None
    facts = {fact.kind: fact for fact in graph.facts}
    if mutation == "duplicate_fact_kind":
        target = facts[ClaimKind.RECONCILIATION]
        changed = target.model_copy(update={"kind": ClaimKind.INVOICE_PROCESSING})
        graph = graph.model_copy(
            update={
                "facts": tuple(
                    changed if fact.fact_id == target.fact_id else fact for fact in graph.facts
                )
            }
        )
    elif mutation == "identity_value":
        identity = facts[ClaimKind.CANDIDATE_ID]
        changed = identity.model_copy(update={"normalized_value": "AP-999"})
        graph = graph.model_copy(
            update={
                "facts": tuple(
                    changed if fact.fact_id == identity.fact_id else fact for fact in graph.facts
                )
            }
        )
    elif mutation == "unsupported_canonical_label":
        graph = _fact_with_value(graph, ClaimKind.SPREADSHEET, "unsupported")
    elif mutation == "invoice_nonboolean":
        graph = _fact_with_value(graph, ClaimKind.INVOICE_PROCESSING, 1)
    elif mutation == "ap_nonnumber":
        graph = _fact_with_value(graph, ClaimKind.AP_YEARS, "many")
    elif mutation == "ap_exceeds_interval":
        graph = _fact_with_value(graph, ClaimKind.AP_YEARS, 99.0)
    elif mutation == "missing_interval":
        interval = facts[ClaimKind.EMPLOYMENT_INTERVAL]
        ap_feature = next(item for item in graph.features if item.name == "preferred_ap_years")
        corroborated = next(item for item in graph.features if item.name == "corroborated_count")
        changed_ap = ap_feature.model_copy(
            update={"dependency_fact_ids": (facts[ClaimKind.AP_YEARS].fact_id,)}
        )
        changed_corroborated = corroborated.model_copy(
            update={
                "dependency_fact_ids": tuple(
                    fact_id
                    for fact_id in corroborated.dependency_fact_ids
                    if fact_id != interval.fact_id
                )
            }
        )
        graph = graph.model_copy(
            update={
                "facts": tuple(fact for fact in graph.facts if fact.fact_id != interval.fact_id),
                "features": tuple(
                    changed_ap
                    if feature.feature_id == ap_feature.feature_id
                    else changed_corroborated
                    if feature.feature_id == corroborated.feature_id
                    else feature
                    for feature in graph.features
                ),
            }
        )
    elif mutation == "volume_without_invoice":
        graph = _fact_with_value(graph, ClaimKind.INVOICE_PROCESSING, False)
    elif mutation == "volume_nonnumber":
        graph = _fact_with_value(graph, ClaimKind.MONTHLY_INVOICE_VOLUME, "many")
    elif mutation == "identity_hash":
        graph = graph.model_copy(
            update={
                "evidence_manifest": tuple(
                    reference.model_copy(update={"semantic_hash": "0" * 64})
                    if reference.field_path is not None
                    and reference.field_path.rsplit(".", maxsplit=1)[-1] == "candidate_id"
                    else reference
                    for reference in graph.evidence_manifest
                )
            }
        )
    elif mutation == "interval_missing_end":
        interval = facts[ClaimKind.EMPLOYMENT_INTERVAL]
        changed = interval.model_copy(
            update={
                "evidence_ids": tuple(
                    evidence_id
                    for evidence_id in interval.evidence_ids
                    if not evidence_id.endswith(":employment_end")
                )
            }
        )
        graph = graph.model_copy(
            update={
                "facts": tuple(
                    changed if fact.fact_id == interval.fact_id else fact for fact in graph.facts
                )
            }
        )
    elif mutation in {"categorical_source_value", "categorical_value_hash"}:
        spreadsheet = facts[ClaimKind.SPREADSHEET]
        update = (
            {"source_value": "Google Sheets"}
            if mutation == "categorical_source_value"
            else {"canonical_value_sha256": "0" * 64}
        )
        changed = spreadsheet.model_copy(update=update)
        graph = graph.model_copy(
            update={
                "facts": tuple(
                    changed if fact.fact_id == spreadsheet.fact_id else fact for fact in graph.facts
                )
            }
        )
    elif mutation == "fact_snapshot":
        target = facts[ClaimKind.RECONCILIATION]
        changed = target.model_copy(update={"snapshot_id": "index-stale"})
        graph = graph.model_copy(
            update={
                "facts": tuple(
                    changed if fact.fact_id == target.fact_id else fact for fact in graph.facts
                )
            }
        )
    elif mutation in {"interval_start_date", "interval_duration"}:
        interval = facts[ClaimKind.EMPLOYMENT_INTERVAL]
        if mutation == "interval_start_date":
            dated = interval.employment_intervals[0]
            changed = interval.model_copy(
                update={
                    "employment_intervals": (
                        dated.model_copy(
                            update={"start_date": dated.start_date + timedelta(days=1)}
                        ),
                    )
                }
            )
        else:
            changed = interval.model_copy(
                update={"normalized_value": float(interval.normalized_value or 0) + 0.1}
            )
        graph = graph.model_copy(
            update={
                "facts": tuple(
                    changed if fact.fact_id == interval.fact_id else fact for fact in graph.facts
                )
            }
        )
    elif mutation == "interval_endpoint_hash":
        interval = facts[ClaimKind.EMPLOYMENT_INTERVAL]
        start_id = interval.employment_intervals[0].start_evidence_id
        graph = graph.model_copy(
            update={
                "evidence_manifest": tuple(
                    reference.model_copy(update={"semantic_hash": "0" * 64})
                    if reference.evidence_id == start_id
                    else reference
                    for reference in graph.evidence_manifest
                )
            }
        )
    else:
        source_kind = (
            SourceKind.APPLICATION_JSON
            if mutation == "json_candidate_path"
            else SourceKind.RESUME_VISIBLE
        )
        field_path = (
            "records[AP-001].reconciliation"
            if mutation == "json_candidate_path"
            else "resume.reconciliation"
        )
        reference = next(
            item
            for item in graph.evidence_manifest
            if item.source_kind is source_kind and item.field_path == field_path
        )
        reference_update: dict[str, object]
        if mutation == "json_candidate_path":
            reference_update = {"field_path": "records[AP-999].reconciliation"}
        elif mutation == "resume_wrong_path":
            reference_update = {"field_path": "resume.ap_years"}
        elif mutation == "resume_missing_page":
            reference_update = {"page": None}
        elif mutation == "resume_missing_document_page_count":
            reference_update = {"document_page_count": None}
        elif mutation == "resume_missing_page_width":
            reference_update = {"page_width": None}
        elif mutation == "resume_missing_page_height":
            reference_update = {"page_height": None}
        elif mutation == "resume_missing_bbox":
            reference_update = {"bbox": None}
        elif mutation == "resume_string_bbox":
            reference_update = {"bbox": ("10", "20", "30", "40")}
        elif mutation == "resume_page_11":
            reference_update = {"page": 11, "document_page_count": 10}
        elif mutation == "resume_page_999":
            reference_update = {"page": 999, "document_page_count": 10}
        elif mutation == "resume_document_page_count_999":
            reference_update = {"document_page_count": 999}
        elif mutation == "resume_bbox_left_of_page":
            reference_update = {"bbox": (-1.0, 10.0, 30.0, 40.0)}
        elif mutation == "resume_bbox_above_page":
            reference_update = {"bbox": (10.0, -1.0, 30.0, 40.0)}
        elif mutation == "resume_bbox_right_of_page":
            reference_update = {"bbox": (10.0, 20.0, float(reference.page_width or 0) + 1.0, 40.0)}
        else:
            reference_update = {"bbox": (10.0, 20.0, 30.0, float(reference.page_height or 0) + 1.0)}
        changed_reference = reference.model_copy(update=reference_update)
        graph = graph.model_copy(
            update={
                "evidence_manifest": tuple(
                    changed_reference if item.evidence_id == reference.evidence_id else item
                    for item in graph.evidence_manifest
                )
            }
        )

    _assert_graph_rejected(decision, batch, graph)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), -0.0, {}])
def test_authorizer_fails_closed_on_malformed_internal_ap_values(value: object) -> None:
    decision, batch = _authorization_fixture()
    graph = decision.routes[0].support_graph
    assert graph is not None
    ap_fact = next(fact for fact in graph.facts if fact.kind is ClaimKind.AP_YEARS)
    changed = ap_fact.model_copy(update={"normalized_value": value})
    graph = graph.model_copy(
        update={
            "facts": tuple(
                changed if fact.fact_id == ap_fact.fact_id else fact for fact in graph.facts
            )
        }
    )

    _assert_graph_rejected(decision, batch, graph)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), -0.0, {}])
def test_authorizer_fails_closed_on_malformed_validated_candidate_values(
    value: object,
) -> None:
    decision, batch = _authorization_fixture()
    candidate = batch.candidates[0].model_copy(update={"ap_years": value})

    result = ReleaseAuthorizer().authorize(
        batch.model_copy(update={"candidates": (candidate,)}),
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_authorizer_fails_closed_on_malformed_internal_rank_key() -> None:
    decision, batch = _authorization_fixture()
    route = decision.routes[0].model_copy(update={"rank_key": {"untrusted": "shape"}})

    result = ReleaseAuthorizer().authorize(
        batch,
        (route,),
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_authorizer_does_not_truncate_fractional_invoice_volume() -> None:
    decision, batch = _authorization_fixture()
    graph = decision.routes[0].support_graph
    assert graph is not None

    graph = _fact_with_value(graph, ClaimKind.MONTHLY_INVOICE_VOLUME, 600.5)

    _assert_graph_rejected(decision, batch, graph)


@pytest.mark.parametrize("target", ["route", "candidate"])
def test_authorizer_rejects_stale_snapshot_on_every_release_object(target: str) -> None:
    decision, batch = _authorization_fixture()
    routes = decision.routes
    if target == "route":
        routes = (routes[0].model_copy(update={"snapshot_id": "index-stale"}),)
    else:
        batch = batch.model_copy(
            update={
                "candidates": (
                    batch.candidates[0].model_copy(update={"snapshot_id": "index-stale"}),
                )
            }
        )

    result = ReleaseAuthorizer().authorize(
        batch,
        routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_authorizer_permits_only_the_initial_retrieval_gate_before_snapshot_binding() -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    root = decision.trust_ledger[0]
    assert root.stage is TrustStage.RETRIEVAL
    assert not root.input_gate_ids
    ledger = (
        root.model_copy(update={"snapshot_id": None}),
        *decision.trust_ledger[1:],
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=ledger,
        plan_history=decision.plans,
    )

    assert result.authorized


@pytest.mark.parametrize(
    ("stage", "occurrence"),
    [
        (TrustStage.SCHEMA, 0),
        (TrustStage.RETRIEVAL, 1),
        (TrustStage.SCHEMA, 1),
        (TrustStage.RETRIEVAL, 2),
    ],
)
def test_authorizer_rejects_erased_snapshot_on_every_nonroot_retrieval_or_schema_gate(
    stage: TrustStage,
    occurrence: int,
) -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    targets = tuple(item for item in decision.trust_ledger if item.stage is stage)
    target = targets[occurrence]
    assert target is not decision.trust_ledger[0]
    ledger = tuple(
        item.model_copy(update={"snapshot_id": None}) if item is target else item
        for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_authorizer_rejects_a_ledger_with_every_snapshot_erased() -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    ledger = tuple(item.model_copy(update={"snapshot_id": None}) for item in decision.trust_ledger)

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_authorizer_rejects_cross_field_evidence_rebinding() -> None:
    decision, batch = _authorization_fixture()
    graph = decision.routes[0].support_graph
    assert graph is not None
    facts = {fact.kind: fact for fact in graph.facts}
    ap_fact = facts[ClaimKind.AP_YEARS]
    reconciliation_json = next(
        reference.evidence_id
        for reference in graph.evidence_manifest
        if reference.source_kind is SourceKind.APPLICATION_JSON
        and reference.field_path is not None
        and reference.field_path.endswith(".reconciliation")
    )
    ap_json = next(
        evidence_id
        for evidence_id in ap_fact.evidence_ids
        if next(
            reference
            for reference in graph.evidence_manifest
            if reference.evidence_id == evidence_id
        ).source_kind
        is SourceKind.APPLICATION_JSON
    )
    changed = ap_fact.model_copy(
        update={
            "evidence_ids": tuple(
                reconciliation_json if item == ap_json else item for item in ap_fact.evidence_ids
            )
        }
    )
    graph = graph.model_copy(
        update={
            "facts": tuple(
                changed if fact.fact_id == ap_fact.fact_id else fact for fact in graph.facts
            )
        }
    )

    _assert_graph_rejected(decision, batch, graph)


@pytest.mark.parametrize("mutation", ["missing", "reordered", "foreign"])
def test_authorizer_rejects_mutated_binding_fan_in_receipts(mutation: str) -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    target = next(
        receipt
        for receipt in decision.step_receipts
        if receipt.command_kind is PlanStep.VALIDATE_CANDIDATE_BINDINGS
        and receipt.status is StepStatus.COMPLETED
    )
    assert target.produced_gate_id is not None and len(target.consumed_gate_ids) == 3
    consumed = list(target.consumed_gate_ids)
    if mutation == "missing":
        consumed.pop()
    elif mutation == "reordered":
        consumed[1:] = reversed(consumed[1:])
    else:
        foreign = next(
            item.decision_id
            for item in decision.trust_ledger
            if item.scope is TrustScope.BATCH and item.stage is TrustStage.MAPPING
        )
        consumed[-1] = foreign
    consumed_ids = tuple(consumed)
    receipts = tuple(
        receipt.model_copy(update={"consumed_gate_ids": consumed_ids})
        if receipt is target
        else receipt
        for receipt in decision.step_receipts
    )
    ledger = tuple(
        item.model_copy(update={"input_gate_ids": consumed_ids})
        if item.decision_id == target.produced_gate_id
        else item
        for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        receipts,
        trust_ledger=ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


def test_candidate_validation_receipt_proves_exact_terminal_fan_in() -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    target = next(
        receipt
        for receipt in decision.step_receipts
        if receipt.command_kind is PlanStep.VALIDATE_CANDIDATE_EVIDENCE
        and receipt.status is StepStatus.COMPLETED
    )
    decisions = {item.decision_id: item for item in decision.trust_ledger}

    assert target.produced_gate_id is not None
    assert len(target.consumed_gate_ids) == len(batch.candidates) + 1
    batch_parent = decisions[target.consumed_gate_ids[0]]
    candidate_parents = tuple(decisions[item] for item in target.consumed_gate_ids[1:])
    produced = decisions[target.produced_gate_id]

    assert batch_parent.scope is TrustScope.BATCH
    assert batch_parent.stage is TrustStage.MAPPING
    assert tuple(parent.candidate_id for parent in candidate_parents) == tuple(
        sorted(candidate.candidate_id for candidate in batch.candidates)
    )
    assert all(parent.scope is TrustScope.RECORD for parent in candidate_parents)
    assert all(parent.stage is TrustStage.CANDIDATE_VALIDATION for parent in candidate_parents)
    assert all(parent.snapshot_id == batch.snapshot_id for parent in candidate_parents)
    assert produced.input_gate_ids == target.consumed_gate_ids
    assert set(produced.evidence_ids) == {
        evidence_id for parent in candidate_parents for evidence_id in parent.evidence_ids
    }


@pytest.mark.parametrize(
    ("status", "marker"),
    [
        (StepStatus.STARTED, ReasonCode.COMMAND_STARTED),
        (StepStatus.COMPLETED, ReasonCode.COMMAND_COMPLETED),
        (StepStatus.RESTRICTED, ReasonCode.COMMAND_RESTRICTED),
        (StepStatus.FAILED, ReasonCode.COMMAND_FAILED),
    ],
)
def test_receipt_contract_requires_the_marker_for_its_status(
    status: StepStatus,
    marker: ReasonCode,
) -> None:
    extra_reasons = () if status is StepStatus.STARTED else (ReasonCode.SCHEMA_VALID,)
    receipt = StepReceipt(
        receipt_id=f"receipt-marker-{status.value}",
        sequence=1,
        plan_version=1,
        command_id="cmd-marker",
        command_kind=PlanStep.FETCH_CANDIDATE_DETAILS,
        status=status,
        reason_codes=(marker, *extra_reasons),
    )

    assert marker in receipt.reason_codes
    with pytest.raises(ValueError, match="receipt"):
        StepReceipt(
            receipt_id=f"receipt-wrong-{status.value}",
            sequence=1,
            plan_version=1,
            command_id="cmd-marker",
            command_kind=PlanStep.FETCH_CANDIDATE_DETAILS,
            status=status,
            reason_codes=(ReasonCode.PLAN_SELECTED,),
        )


@pytest.mark.parametrize("mutation", ["completed_missing", "started_extra"])
def test_authorizer_rejects_untrusted_receipt_status_markers(mutation: str) -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    target = next(
        receipt
        for receipt in decision.step_receipts
        if (
            receipt.status is StepStatus.COMPLETED
            if mutation == "completed_missing"
            else receipt.status is StepStatus.STARTED
        )
    )
    reason_codes = (
        tuple(
            reason for reason in target.reason_codes if reason is not ReasonCode.COMMAND_COMPLETED
        )
        if mutation == "completed_missing"
        else (*target.reason_codes, ReasonCode.PLAN_SELECTED)
    )
    receipts = tuple(
        receipt.model_copy(update={"reason_codes": reason_codes}) if receipt is target else receipt
        for receipt in decision.step_receipts
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


@pytest.mark.parametrize("mutation", ["receipt_only", "gate_and_receipt", "wrong_stage"])
def test_authorizer_binds_terminal_domain_reasons_to_command_gate_policy(
    mutation: str,
) -> None:
    decision, batch = _authorization_fixture()
    target = next(
        receipt
        for receipt in decision.step_receipts
        if receipt.command_kind is PlanStep.RANK_FULL_EVIDENCE
        and receipt.status is StepStatus.COMPLETED
    )
    assert target.produced_gate_id is not None
    gate = next(
        item for item in decision.trust_ledger if item.decision_id == target.produced_gate_id
    )
    receipt_reasons: tuple[ReasonCode, ...] = (
        ReasonCode.COMMAND_COMPLETED,
        ReasonCode.SCHEMA_VALID,
    )
    mutated_gate = gate
    if mutation == "gate_and_receipt":
        mutated_gate = gate.model_copy(update={"reason_codes": (ReasonCode.SCHEMA_VALID,)})
    elif mutation == "wrong_stage":
        receipt_reasons = target.reason_codes
        mutated_gate = gate.model_copy(update={"stage": TrustStage.PROVENANCE})
    receipts = tuple(
        receipt.model_copy(update={"reason_codes": receipt_reasons})
        if receipt is target
        else receipt
        for receipt in decision.step_receipts
    )
    ledger = tuple(
        mutated_gate if item.decision_id == gate.decision_id else item
        for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        receipts,
        trust_ledger=ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


@pytest.mark.parametrize("mutation", ["missing", "reordered", "foreign_candidate"])
def test_authorizer_rejects_mutated_candidate_validation_fan_in_receipts(
    mutation: str,
) -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    target = next(
        receipt
        for receipt in decision.step_receipts
        if receipt.command_kind is PlanStep.VALIDATE_CANDIDATE_EVIDENCE
        and receipt.status is StepStatus.COMPLETED
    )
    assert target.produced_gate_id is not None and len(target.consumed_gate_ids) == 3
    consumed = list(target.consumed_gate_ids)
    if mutation == "missing":
        consumed.pop()
    elif mutation == "reordered":
        consumed[1:] = reversed(consumed[1:])
    consumed_ids = tuple(consumed)
    foreign_gate_id = target.consumed_gate_ids[-1]
    receipts = tuple(
        receipt.model_copy(update={"consumed_gate_ids": consumed_ids})
        if receipt is target
        else receipt
        for receipt in decision.step_receipts
    )
    ledger = tuple(
        item.model_copy(
            update={
                **(
                    {"input_gate_ids": consumed_ids}
                    if item.decision_id == target.produced_gate_id
                    else {}
                ),
                **(
                    {"candidate_id": "AP-999"}
                    if mutation == "foreign_candidate" and item.decision_id == foreign_gate_id
                    else {}
                ),
            }
        )
        if item.decision_id in {target.produced_gate_id, foreign_gate_id}
        else item
        for item in decision.trust_ledger
    )

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        receipts,
        trust_ledger=ledger,
        plan_history=decision.plans,
    )

    assert not result.authorized


@pytest.mark.parametrize(
    "mutation",
    [
        "invisible_manifest",
        "duplicate_fact_id",
        "duplicate_feature_id",
        "missing_feature_dependency",
        "feature_cycle",
        "fact_role_mismatch",
        "duplicate_feature_name",
        "missing_essential_feature",
        "bad_essential_dependency",
        "missing_ap_feature",
        "bad_ap_dependency",
        "missing_volume_feature",
        "bad_volume_dependency",
        "extra_feature",
    ],
)
def test_authorizer_rejects_structurally_invalid_support_graph(mutation: str) -> None:
    decision, batch = _authorization_fixture()
    graph = decision.routes[0].support_graph
    assert graph is not None
    by_name = {feature.name: feature for feature in graph.features}
    facts = {fact.kind: fact for fact in graph.facts}
    features = graph.features
    if mutation == "invisible_manifest":
        graph = graph.model_copy(
            update={
                "evidence_manifest": (
                    graph.evidence_manifest[0].model_copy(update={"visible": False}),
                    *graph.evidence_manifest[1:],
                )
            }
        )
    elif mutation == "duplicate_fact_id":
        graph = graph.model_copy(update={"facts": (*graph.facts, graph.facts[0])})
    elif mutation == "duplicate_feature_id":
        graph = graph.model_copy(update={"features": (*features, features[0])})
    elif mutation == "missing_feature_dependency":
        route = by_name["route"].model_copy(update={"dependency_feature_ids": ("feature:missing",)})
        graph = graph.model_copy(
            update={
                "features": tuple(
                    route if feature.name == "route" else feature for feature in features
                )
            }
        )
    elif mutation == "feature_cycle":
        route = by_name["route"]
        changed = route.model_copy(update={"dependency_feature_ids": (route.feature_id,)})
        graph = graph.model_copy(
            update={
                "features": tuple(
                    changed if feature.name == "route" else feature for feature in features
                )
            }
        )
    elif mutation == "fact_role_mismatch":
        fact = graph.facts[0].model_copy(update={"source_roles": (SourceKind.RESUME_VISIBLE,)})
        graph = graph.model_copy(update={"facts": (fact, *graph.facts[1:])})
    elif mutation == "duplicate_feature_name":
        duplicate = by_name["route"].model_copy(update={"feature_id": "feature:duplicate"})
        graph = graph.model_copy(update={"features": (*features, duplicate)})
    elif mutation in {"missing_essential_feature", "missing_ap_feature", "missing_volume_feature"}:
        removed_name, parent_name = {
            "missing_essential_feature": ("essential_invoice_processing", "essentials_count"),
            "missing_ap_feature": ("preferred_ap_years", "preferred_count"),
            "missing_volume_feature": ("preferred_volume", "preferred_count"),
        }[mutation]
        removed = by_name[removed_name]
        parent = by_name[parent_name].model_copy(
            update={
                "dependency_feature_ids": tuple(
                    feature_id
                    for feature_id in by_name[parent_name].dependency_feature_ids
                    if feature_id != removed.feature_id
                )
            }
        )
        graph = graph.model_copy(
            update={
                "features": tuple(
                    parent if feature.name == parent_name else feature
                    for feature in features
                    if feature.name != removed_name
                )
            }
        )
    elif mutation in {"bad_essential_dependency", "bad_ap_dependency", "bad_volume_dependency"}:
        name = {
            "bad_essential_dependency": "essential_invoice_processing",
            "bad_ap_dependency": "preferred_ap_years",
            "bad_volume_dependency": "preferred_volume",
        }[mutation]
        changed = by_name[name].model_copy(
            update={"dependency_fact_ids": (facts[ClaimKind.CANDIDATE_ID].fact_id,)}
        )
        graph = graph.model_copy(
            update={
                "features": tuple(
                    changed if feature.name == name else feature for feature in features
                )
            }
        )
    else:
        graph = graph.model_copy(
            update={
                "features": (
                    *features,
                    DerivedFeature(
                        feature_id="feature:extra",
                        candidate_id="AP-001",
                        snapshot_id=decision.snapshot_id,
                        name="extra",
                        normalized_value="bounded",
                        dependency_fact_ids=(facts[ClaimKind.CANDIDATE_ID].fact_id,),
                    ),
                )
            }
        )

    _assert_graph_rejected(decision, batch, graph)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_parent",
        "forward_parent",
        "cycle",
        "cross_candidate_parent",
        "forged_branch",
        "foreign_run_id",
        "unknown_candidate",
        "snapshot_mismatch",
        "record_stage_splice",
        "blocked_gate_consumed",
    ],
)
def test_authorizer_validates_every_record_decision_in_full_ledger(mutation: str) -> None:
    decision, batch = _authorization_fixture(two_candidates=True)
    ledger = decision.trust_ledger

    def record(candidate_id: str, stage: TrustStage) -> TrustDecision:
        return next(
            item for item in ledger if item.candidate_id == candidate_id and item.stage is stage
        )

    identity = record("AP-001", TrustStage.IDENTITY)
    revision = record("AP-001", TrustStage.REVISION)
    manifest = record("AP-001", TrustStage.MANIFEST)
    provenance = record("AP-001", TrustStage.PROVENANCE)
    timeline = record("AP-001", TrustStage.TIMELINE)
    cross_source = record("AP-001", TrustStage.CROSS_SOURCE)
    replacements: dict[str, TrustDecision] = {}
    appended: tuple[TrustDecision, ...] = ()

    if mutation == "missing_parent":
        replacements[revision.decision_id] = revision.model_copy(
            update={"input_gate_ids": ("td:missing",)}
        )
    elif mutation == "forward_parent":
        replacements[revision.decision_id] = revision.model_copy(
            update={"input_gate_ids": (manifest.decision_id,)}
        )
    elif mutation == "cycle":
        replacements[revision.decision_id] = revision.model_copy(
            update={"input_gate_ids": (manifest.decision_id,)}
        )
        replacements[manifest.decision_id] = manifest.model_copy(
            update={"input_gate_ids": (revision.decision_id,)}
        )
    elif mutation == "cross_candidate_parent":
        other_revision = record("AP-002", TrustStage.REVISION)
        replacements[other_revision.decision_id] = other_revision.model_copy(
            update={"input_gate_ids": (identity.decision_id,)}
        )
    elif mutation == "forged_branch":
        run_prefix = ledger[0].decision_id.rsplit(":", maxsplit=1)[0]
        appended = (
            cross_source.model_copy(
                update={
                    "decision_id": f"{run_prefix}:{len(ledger) + 1}",
                    "input_gate_ids": (timeline.decision_id,),
                }
            ),
        )
    elif mutation == "foreign_run_id":
        replacements[cross_source.decision_id] = cross_source.model_copy(
            update={"decision_id": "td:another-run:999"}
        )
    elif mutation == "unknown_candidate":
        replacements[cross_source.decision_id] = cross_source.model_copy(
            update={"candidate_id": "AP-999"}
        )
    elif mutation == "snapshot_mismatch":
        replacements[cross_source.decision_id] = cross_source.model_copy(
            update={"snapshot_id": "index-foreign"}
        )
    elif mutation == "record_stage_splice":
        replacements[cross_source.decision_id] = cross_source.model_copy(
            update={"input_gate_ids": (provenance.decision_id,)}
        )
    else:
        replacements[timeline.decision_id] = timeline.model_copy(
            update={
                "state": TrustState.QUARANTINED,
                "outcome": TrustOutcome.QUARANTINE,
            }
        )

    mutated = tuple(replacements.get(item.decision_id, item) for item in ledger) + appended
    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=mutated,
        plan_history=decision.plans,
    )

    assert not result.authorized
    assert ReasonCode.RELEASE_BLOCKED in result.reason_codes
