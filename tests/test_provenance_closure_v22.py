"""Diagnosis-A regressions: exact stage-local provenance closure at runtime."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date

import pytest

from cv_trust_agent.engine import TrustedAgentEngine
from cv_trust_agent.evidence_validation import compute_evidence_value_hash
from cv_trust_agent.mappers import DeterministicMapper
from cv_trust_agent.models import (
    CandidateRoute,
    ClaimKind,
    EvidenceDispositionEntry,
    EvidenceDispositionInventory,
    EvidenceDispositionState,
    ExecutionMode,
    MappedClaim,
    MapperOutput,
    MapperRequest,
    PlanStep,
    ReasonCode,
    RunDecision,
    SourceKind,
    StepStatus,
    Strategy,
    TrustDecision,
    TrustOutcome,
    TrustScope,
    TrustStage,
    TrustState,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)
from cv_trust_agent.policy import DecisionController
from cv_trust_agent.release import ReleaseAuthorizer
from tests.test_engine_unit import _Case, _case, _record, _StaticProvider
from tests.test_release_authorizer import _authorization_fixture


class _ExtraIdentityClaimMapper:
    """Wrap the deterministic mapper with a validated identity proposal.

    This reproduces the live V2.1 failure mechanism: a schema-legal
    ``candidate_id`` claim citing the visible identity line, which V2.1
    admitted into the provenance gate's evidence set.
    """

    def __init__(self, base: DeterministicMapper, target: str) -> None:
        self._base = base
        self._target = target

    @property
    def name(self) -> str:
        return self._base.name

    def map_claims(self, request: MapperRequest) -> MapperOutput:
        output = self._base.map_claims(request)
        if request.candidate_id != self._target:
            return output
        identity_reference = next(
            reference
            for reference in request.evidence_catalog
            if reference.source_kind is SourceKind.RESUME_VISIBLE
            and (reference.field_path or "").rsplit(".", maxsplit=1)[-1] == "candidate_id"
        )
        extra = MappedClaim(
            claim_id=f"extra:{request.candidate_id}:candidate-id",
            candidate_id=request.candidate_id,
            snapshot_id=request.snapshot_id,
            kind=ClaimKind.CANDIDATE_ID,
            text_value=request.candidate_id,
            evidence_ids=(identity_reference.evidence_id,),
        )
        return output.model_copy(update={"claims": (*output.claims, extra)})


def _run_with_extra_identity_claim() -> tuple[RunDecision, RunDecision]:
    case = _case((_record("AP-001"), _record("AP-002", ap_years=1.0)))
    baseline_engine = TrustedAgentEngine(DeterministicMapper(case.outputs))
    baseline = baseline_engine.execute(
        baseline_engine.start(case.index, run_id="run-closure-base"),
        _StaticProvider(case.records, case.requests),
    )
    injected_engine = TrustedAgentEngine(
        _ExtraIdentityClaimMapper(DeterministicMapper(case.outputs), "AP-001")
    )
    injected = injected_engine.execute(
        injected_engine.start(case.index, run_id="run-closure-injected"),
        _StaticProvider(case.records, case.requests),
    )
    return baseline, injected


def _normalized_ledger(decision: RunDecision, run_id: str) -> list[dict[str, object]]:
    rows = []
    for item in decision.trust_ledger:
        row = item.model_dump(mode="json")
        row["decision_id"] = row["decision_id"].replace(run_id, "R")
        row["input_gate_ids"] = [gate_id.replace(run_id, "R") for gate_id in row["input_gate_ids"]]
        rows.append(row)
    return rows


class TestValidatedIdentityProposalIsInert:
    def test_extra_candidate_id_claim_leaves_the_whole_ledger_unchanged(self) -> None:
        baseline, injected = _run_with_extra_identity_claim()
        assert baseline.strategy == injected.strategy
        assert baseline.support_graph_hash == injected.support_graph_hash
        assert [route.model_dump(mode="json") for route in baseline.routes] == [
            route.model_dump(mode="json") for route in injected.routes
        ]
        assert _normalized_ledger(baseline, "run-closure-base") == _normalized_ledger(
            injected, "run-closure-injected"
        )

    def test_wrong_identity_claim_still_quarantines(self) -> None:
        case = _case((_record("AP-001"), _record("AP-002", ap_years=1.0)))

        class WrongIdentityMapper:
            name = "wrong_identity_mapper"

            def __init__(self, base: DeterministicMapper) -> None:
                self._base = base

            def map_claims(self, request: MapperRequest) -> MapperOutput:
                output = self._base.map_claims(request)
                if request.candidate_id != "AP-001":
                    return output
                identity_reference = next(
                    reference
                    for reference in request.evidence_catalog
                    if reference.source_kind is SourceKind.RESUME_VISIBLE
                    and (reference.field_path or "").rsplit(".", maxsplit=1)[-1] == "candidate_id"
                )
                extra = MappedClaim(
                    claim_id="extra:AP-001:wrong-identity",
                    candidate_id=request.candidate_id,
                    snapshot_id=request.snapshot_id,
                    kind=ClaimKind.CANDIDATE_ID,
                    text_value="AP-999",
                    evidence_ids=(identity_reference.evidence_id,),
                )
                return output.model_copy(update={"claims": (*output.claims, extra)})

        engine = TrustedAgentEngine(WrongIdentityMapper(DeterministicMapper(case.outputs)))
        decision = engine.execute(
            engine.start(case.index),
            _StaticProvider(case.records, case.requests),
        )
        target_route = next(route for route in decision.routes if route.candidate_id == "AP-001")
        assert target_route.evidence_rank is None
        assert ReasonCode.EVIDENCE_VALUE_CONFLICT in set(target_route.reason_codes)


def _provenance_gate_index(ledger: Sequence[TrustDecision], candidate_id: str) -> int:
    return _record_gate_index(ledger, candidate_id, TrustStage.PROVENANCE)


def _record_gate_index(
    ledger: Sequence[TrustDecision],
    candidate_id: str,
    stage: TrustStage,
) -> int:
    for index, decision in enumerate(ledger):
        if (
            decision.stage is stage
            and decision.scope is TrustScope.RECORD
            and decision.candidate_id == candidate_id
        ):
            return index
    raise AssertionError(f"no record {stage.value} gate for {candidate_id}")


def _with_gate_evidence(
    ledger: Sequence[TrustDecision],
    candidate_id: str,
    evidence_ids: tuple[str, ...],
) -> tuple[TrustDecision, ...]:
    index = _provenance_gate_index(ledger, candidate_id)
    mutated = ledger[index].model_copy(update={"evidence_ids": evidence_ids})
    return (*ledger[:index], mutated, *ledger[index + 1 :])


def _with_gate_reasons(
    ledger: Sequence[TrustDecision],
    candidate_id: str,
    stage: TrustStage,
    reason_codes: tuple[ReasonCode, ...],
) -> tuple[TrustDecision, ...]:
    index = _record_gate_index(ledger, candidate_id, stage)
    mutated = ledger[index].model_copy(update={"reason_codes": reason_codes})
    return (*ledger[:index], mutated, *ledger[index + 1 :])


class TestAuthorizerClosureIndependence:
    def test_clean_release_authorizes(self) -> None:
        decision, batch = _authorization_fixture(two_candidates=True)
        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
        )
        assert result.authorized

    @pytest.mark.parametrize(
        "mutation",
        [
            "drop_one",
            "add_identity",
            "add_application_json",
            "add_fabricated_visible",
            "duplicate",
        ],
    )
    def test_gate_closure_mutations_block_release(self, mutation: str) -> None:
        decision, batch = _authorization_fixture(two_candidates=True)
        candidate = batch.candidates[0]
        graph = candidate.support_graph
        assert graph is not None
        manifest = {item.evidence_id: item for item in graph.evidence_manifest}
        identity_ids = tuple(
            evidence_id
            for fact in graph.facts
            if fact.kind is ClaimKind.CANDIDATE_ID
            for evidence_id in fact.evidence_ids
            if manifest[evidence_id].source_kind is SourceKind.RESUME_VISIBLE
        )
        json_ids = tuple(
            evidence_id
            for evidence_id, reference in manifest.items()
            if reference.source_kind is SourceKind.APPLICATION_JSON
        )
        gate = decision.trust_ledger[
            _provenance_gate_index(decision.trust_ledger, candidate.candidate_id)
        ]
        current = gate.evidence_ids
        if mutation == "drop_one":
            evidence = current[:-1]
        elif mutation == "add_identity":
            evidence = tuple(sorted({*current, identity_ids[0]}))
        elif mutation == "add_application_json":
            evidence = tuple(sorted({*current, json_ids[0]}))
        elif mutation == "add_fabricated_visible":
            evidence = tuple(
                sorted({*current, "pdfline:index-2026-08-15:AP-001:p1:visible:l9:aaaa"})
            )
        else:
            evidence = (*current, current[0])
        mutated_ledger = _with_gate_evidence(
            decision.trust_ledger, candidate.candidate_id, evidence
        )
        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=mutated_ledger,
        )
        assert not result.authorized

    def test_missing_provenance_gate_blocks_release(self) -> None:
        decision, batch = _authorization_fixture(two_candidates=True)
        index = _provenance_gate_index(decision.trust_ledger, "AP-001")
        pruned = (*decision.trust_ledger[:index], *decision.trust_ledger[index + 1 :])
        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=pruned,
        )
        assert not result.authorized

    @pytest.mark.parametrize(
        "extra_kind",
        ["identity", "application_json", "other_candidate", "fabricated"],
    )
    def test_audit_marker_cannot_authorize_an_unrelated_gate_citation(
        self,
        extra_kind: str,
    ) -> None:
        decision, batch = _authorization_fixture(two_candidates=True)
        candidate = batch.candidates[0]
        graph = candidate.support_graph
        other_graph = batch.candidates[1].support_graph
        assert graph is not None and other_graph is not None
        manifest = {item.evidence_id: item for item in graph.evidence_manifest}
        if extra_kind == "identity":
            extra_id = next(
                evidence_id
                for fact in graph.facts
                if fact.kind is ClaimKind.CANDIDATE_ID
                for evidence_id in fact.evidence_ids
                if manifest[evidence_id].source_kind is SourceKind.RESUME_VISIBLE
            )
        elif extra_kind == "application_json":
            extra_id = next(
                evidence_id
                for evidence_id, reference in manifest.items()
                if reference.source_kind is SourceKind.APPLICATION_JSON
            )
        elif extra_kind == "other_candidate":
            extra_id = next(
                reference.evidence_id
                for reference in other_graph.evidence_manifest
                if reference.source_kind is SourceKind.RESUME_VISIBLE
            )
        else:
            extra_id = "pdfline:index-2026-08-15:AP-001:p1:visible:l99:fabricated"

        provenance_index = _provenance_gate_index(decision.trust_ledger, candidate.candidate_id)
        current = decision.trust_ledger[provenance_index].evidence_ids
        mutated = _with_gate_evidence(
            decision.trust_ledger,
            candidate.candidate_id,
            tuple(sorted({*current, extra_id})),
        )
        cross_index = _record_gate_index(
            mutated,
            candidate.candidate_id,
            TrustStage.CROSS_SOURCE,
        )
        cross_reasons = tuple(
            sorted(
                {
                    *mutated[cross_index].reason_codes,
                    ReasonCode.CATEGORY_NOT_SUPPORTED,
                },
                key=str,
            )
        )
        mutated = _with_gate_reasons(
            mutated,
            candidate.candidate_id,
            TrustStage.CROSS_SOURCE,
            cross_reasons,
        )

        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=mutated,
        )
        assert not result.authorized

    def test_reason_swap_cannot_authorize_a_clean_timeline(self) -> None:
        decision, batch = _authorization_fixture(two_candidates=True)
        mutated = _with_gate_reasons(
            decision.trust_ledger,
            "AP-001",
            TrustStage.TIMELINE,
            (ReasonCode.TIMELINE_DRIFT,),
        )

        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=mutated,
        )
        assert not result.authorized

    def test_category_marker_requires_a_matching_dropped_category(self) -> None:
        decision, batch = _authorization_fixture(two_candidates=True)
        cross_index = _record_gate_index(
            decision.trust_ledger,
            "AP-001",
            TrustStage.CROSS_SOURCE,
        )
        current = decision.trust_ledger[cross_index].reason_codes
        mutated = _with_gate_reasons(
            decision.trust_ledger,
            "AP-001",
            TrustStage.CROSS_SOURCE,
            tuple(sorted({*current, ReasonCode.CATEGORY_NOT_SUPPORTED}, key=str)),
        )

        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=mutated,
        )
        assert not result.authorized

    def test_wrong_drop_disposition_is_rejected_even_with_a_matching_marker(self) -> None:
        decision, batch = _authorization_fixture(two_candidates=True)
        terminal_index = _record_gate_index(
            decision.trust_ledger,
            "AP-001",
            TrustStage.CANDIDATE_VALIDATION,
        )
        terminal = decision.trust_ledger[terminal_index]
        inventory = terminal.evidence_inventory
        assert inventory is not None
        released = next(
            item
            for item in inventory.entries
            if item.state is EvidenceDispositionState.RELEASED
            and item.claim_kind is ClaimKind.SPREADSHEET
        )
        entries = tuple(
            item.model_copy(update={"state": EvidenceDispositionState.DROPPED_UNSUPPORTED_CATEGORY})
            if item.reference.evidence_id == released.reference.evidence_id
            else item
            for item in inventory.entries
        )
        mutated_terminal = terminal.model_copy(
            update={"evidence_inventory": inventory.model_copy(update={"entries": entries})}
        )
        mutated = (
            *decision.trust_ledger[:terminal_index],
            mutated_terminal,
            *decision.trust_ledger[terminal_index + 1 :],
        )
        cross_index = _record_gate_index(mutated, "AP-001", TrustStage.CROSS_SOURCE)
        mutated = _with_gate_reasons(
            mutated,
            "AP-001",
            TrustStage.CROSS_SOURCE,
            tuple(
                sorted(
                    {
                        *mutated[cross_index].reason_codes,
                        ReasonCode.CATEGORY_NOT_SUPPORTED,
                    },
                    key=str,
                )
            ),
        )

        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=mutated,
        )
        assert not result.authorized

    def test_fabricated_drop_cannot_extend_both_inventories_past_the_map_catalog(self) -> None:
        record = _record("AP-001", spreadsheet="Lotus 1-2-3")
        case = _case((record,))
        engine = TrustedAgentEngine(DeterministicMapper(case.outputs))
        decision = engine.execute(
            engine.start(case.index, run_id="run-fabricated-disposition"),
            _StaticProvider(case.records, case.requests),
        )
        route = decision.routes[0]
        graph = route.support_graph
        assert graph is not None and route.evidence_rank is not None
        candidate = ValidatedCandidateEvidence(
            candidate_id=record.candidate_id,
            snapshot_id=decision.snapshot_id,
            trust_state=TrustState.USABLE,
            ap_years=record.ap_years,
            invoice_processing=record.invoice_processing,
            reconciliation=record.reconciliation,
            spreadsheet_supported=False,
            accounting_platform_supported=True,
            monthly_invoice_volume=record.monthly_invoice_volume,
            qualification_supported=True,
            corroborated_claim_kinds=tuple(
                fact.kind for fact in graph.facts if fact.kind is not ClaimKind.CANDIDATE_ID
            ),
            evidence_ids=route.evidence_ids,
            support_graph=graph,
            reason_codes=route.reason_codes,
        )
        batch = ValidatedBatchEvidence(
            batch_id=decision.batch_id,
            snapshot_id=decision.snapshot_id,
            candidates=(candidate,),
            batch_integrity_valid=True,
            mapper_disagreement=False,
        )
        baseline = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=decision.trust_ledger,
        )
        assert baseline.authorized

        cross_index = _record_gate_index(
            decision.trust_ledger,
            "AP-001",
            TrustStage.CROSS_SOURCE,
        )
        cross_source = decision.trust_ledger[cross_index]
        spreadsheet_pair = {
            evidence_id
            for evidence_id in cross_source.evidence_ids
            if evidence_id.endswith(":spreadsheet")
        }
        assert len(spreadsheet_pair) == 2
        underclosed_cross_source = cross_source.model_copy(
            update={
                "evidence_ids": tuple(
                    evidence_id
                    for evidence_id in cross_source.evidence_ids
                    if evidence_id not in spreadsheet_pair
                )
            }
        )
        underclosed_ledger = (
            *decision.trust_ledger[:cross_index],
            underclosed_cross_source,
            *decision.trust_ledger[cross_index + 1 :],
        )
        assert (
            not ReleaseAuthorizer()
            .authorize(
                batch,
                decision.routes,
                decision.plan,
                decision.step_receipts,
                trust_ledger=underclosed_ledger,
            )
            .authorized
        )

        provenance_index = _provenance_gate_index(decision.trust_ledger, "AP-001")
        terminal_index = _record_gate_index(
            decision.trust_ledger,
            "AP-001",
            TrustStage.CANDIDATE_VALIDATION,
        )
        provenance = decision.trust_ledger[provenance_index]
        terminal = decision.trust_ledger[terminal_index]
        consumed_inventory = provenance.evidence_inventory
        final_inventory = terminal.evidence_inventory
        assert consumed_inventory is not None and final_inventory is not None
        dropped = next(
            item
            for item in final_inventory.entries
            if item.claim_kind is ClaimKind.SPREADSHEET
            and item.state is EvidenceDispositionState.DROPPED_UNSUPPORTED_CATEGORY
        )
        fabricated_id = "pdfline:index-2026-08-15:AP-001:p1:visible:l99:0123456789abcdef"
        fabricated_reference = dropped.reference.model_copy(update={"evidence_id": fabricated_id})
        fabricated_consumed = dropped.model_copy(
            update={
                "reference": fabricated_reference,
                "state": EvidenceDispositionState.CONSUMED,
            }
        )
        fabricated_dropped = dropped.model_copy(update={"reference": fabricated_reference})
        changed_provenance = provenance.model_copy(
            update={
                "evidence_ids": tuple(sorted({*provenance.evidence_ids, fabricated_id})),
                "evidence_inventory": consumed_inventory.model_copy(
                    update={"entries": (*consumed_inventory.entries, fabricated_consumed)}
                ),
            }
        )
        changed_terminal = terminal.model_copy(
            update={
                "evidence_inventory": final_inventory.model_copy(
                    update={"entries": (*final_inventory.entries, fabricated_dropped)}
                )
            }
        )
        mutated = tuple(
            changed_provenance
            if index == provenance_index
            else changed_terminal
            if index == terminal_index
            else gate
            for index, gate in enumerate(decision.trust_ledger)
        )

        result = ReleaseAuthorizer().authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts,
            trust_ledger=mutated,
        )
        assert not result.authorized


def test_positive_ap_years_without_an_interval_can_release_when_ap_work_is_absent() -> None:
    record = _record(
        "AP-001",
        invoice_processing=False,
        monthly_invoice_volume=None,
    )
    case = _case((record,))
    key = (case.index.index_id, record.candidate_id)
    output = case.outputs[key]
    outputs = {
        **case.outputs,
        key: output.model_copy(
            update={
                "claims": tuple(
                    claim
                    for claim in output.claims
                    if claim.kind is not ClaimKind.EMPLOYMENT_INTERVAL
                )
            }
        ),
    }
    engine = TrustedAgentEngine(DeterministicMapper(outputs))
    decision = engine.execute(
        engine.start(case.index, run_id="run-positive-ap-without-interval"),
        _StaticProvider(case.records, case.requests),
    )

    route = decision.routes[0]
    assert decision.execution_mode is ExecutionMode.EXECUTED
    assert route.evidence_rank is not None
    assert route.support_graph is not None
    assert all(fact.kind is not ClaimKind.AP_YEARS for fact in route.support_graph.facts)
    timeline = decision.trust_ledger[
        _record_gate_index(decision.trust_ledger, "AP-001", TrustStage.TIMELINE)
    ]
    terminal = decision.trust_ledger[
        _record_gate_index(
            decision.trust_ledger,
            "AP-001",
            TrustStage.CANDIDATE_VALIDATION,
        )
    ]
    assert timeline.reason_codes == (ReasonCode.TIMELINE_VALID,)
    assert terminal.evidence_inventory is not None
    assert any(
        item.claim_kind is ClaimKind.AP_YEARS
        and item.state is EvidenceDispositionState.DROPPED_TIMELINE_POLICY
        for item in terminal.evidence_inventory.entries
    )


class _CapturingLeakyController(DecisionController):
    def __init__(self) -> None:
        self.batches: list[ValidatedBatchEvidence] = []

    def select_strategy(self, batch: ValidatedBatchEvidence) -> Strategy:
        self.batches.append(batch)
        return super().select_strategy(batch)

    def rank(
        self,
        batch: ValidatedBatchEvidence,
        strategy: Strategy,
    ) -> tuple[CandidateRoute, ...]:
        routes = super().rank(batch, strategy)
        if strategy is Strategy.BATCH_INTEGRITY_HOLD or not routes:
            return routes
        first = routes[0].model_copy(
            update={"evidence_ids": (*routes[0].evidence_ids, "raw:audit-probe")}
        )
        return (first, *routes[1:])


def _timeline_drift_hold_fixture() -> tuple[RunDecision, ValidatedBatchEvidence]:
    record = _record("AP-001", ap_years=1.0)
    base = _case((record,))
    key = (base.index.index_id, record.candidate_id)
    output = base.outputs[key]
    request = base.requests[0]
    start = date(2020, 1, 1)
    end = date(2026, 1, 1)
    interval = next(
        claim for claim in output.claims if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL
    ).model_copy(update={"start_date": start, "end_date": end})
    claims = tuple(
        interval if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL else claim
        for claim in output.claims
    )
    catalog = tuple(
        reference.model_copy(
            update={
                "semantic_hash": compute_evidence_value_hash(
                    (
                        start if reference.field_path == "resume.employment_start" else end
                    ).isoformat()
                )
            }
        )
        if reference.field_path in {"resume.employment_start", "resume.employment_end"}
        else reference
        for reference in request.evidence_catalog
    )
    case = _Case(
        index=base.index,
        records=base.records,
        requests=(request.model_copy(update={"evidence_catalog": catalog}),),
        outputs={key: output.model_copy(update={"claims": claims})},
    )
    controller = _CapturingLeakyController()
    engine = TrustedAgentEngine(
        DeterministicMapper(case.outputs),
        controller=controller,
    )
    decision = engine.execute(
        engine.start(case.index, run_id="run-timeline-drift-hold"),
        _StaticProvider(case.records, case.requests),
    )
    assert decision.strategy is Strategy.BATCH_INTEGRITY_HOLD
    assert decision.execution_mode is ExecutionMode.FAILED_CLOSED
    assert controller.batches
    final_batch = controller.batches[-1].model_copy(
        update={"batch_integrity_valid": False, "mapper_disagreement": True}
    )
    audit_only_batch = final_batch.model_copy(
        update={
            "candidates": tuple(
                candidate.model_copy(update={"support_graph": None})
                for candidate in final_batch.candidates
            )
        }
    )
    return decision, audit_only_batch


def test_timeline_drift_is_independently_auditable_on_a_fail_closed_hold() -> None:
    decision, batch = _timeline_drift_hold_fixture()
    assert all(route.support_graph is None for route in decision.routes)
    timeline = decision.trust_ledger[
        _record_gate_index(decision.trust_ledger, "AP-001", TrustStage.TIMELINE)
    ]
    assert timeline.reason_codes == (ReasonCode.TIMELINE_DRIFT,)

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=decision.trust_ledger,
        plan_history=decision.plans,
    )

    assert result.authorized


def test_timeline_drift_hold_rejects_cross_source_catalog_substitution() -> None:
    decision, batch = _timeline_drift_hold_fixture()
    cross_source_index = _record_gate_index(
        decision.trust_ledger,
        "AP-001",
        TrustStage.CROSS_SOURCE,
    )
    cross_source = decision.trust_ledger[cross_source_index]
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
    ledger = (
        *decision.trust_ledger[:cross_source_index],
        changed_cross_source,
        *decision.trust_ledger[cross_source_index + 1 :],
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


@pytest.mark.parametrize("claim_kind", [ClaimKind.SPREADSHEET, ClaimKind.QUALIFICATION])
def test_timeline_drift_hold_rejects_cross_source_pair_deletion(
    claim_kind: ClaimKind,
) -> None:
    decision, batch = _timeline_drift_hold_fixture()
    cross_source_index = _record_gate_index(
        decision.trust_ledger,
        "AP-001",
        TrustStage.CROSS_SOURCE,
    )
    cross_source = decision.trust_ledger[cross_source_index]
    pair_ids = {
        evidence_id
        for evidence_id in cross_source.evidence_ids
        if evidence_id.endswith(f":{claim_kind.value}")
    }
    assert len(pair_ids) == 2
    changed_cross_source = cross_source.model_copy(
        update={
            "evidence_ids": tuple(
                evidence_id
                for evidence_id in cross_source.evidence_ids
                if evidence_id not in pair_ids
            )
        }
    )
    ledger = (
        *decision.trust_ledger[:cross_source_index],
        changed_cross_source,
        *decision.trust_ledger[cross_source_index + 1 :],
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


def test_timeline_drift_hold_rederives_false_valid_scalar_rewrite() -> None:
    decision, batch = _timeline_drift_hold_fixture()

    def rewrite_inventory(
        inventory: EvidenceDispositionInventory,
    ) -> EvidenceDispositionInventory:
        entries = tuple(
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
        return inventory.model_copy(update={"entries": entries})

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
        plan_history=decision.plans,
    )

    assert not result.authorized


@pytest.mark.parametrize("mutation", ["date", "hash", "missing", "swap", "reason"])
def test_timeline_drift_hold_rejects_forged_audit_semantics(mutation: str) -> None:
    decision, batch = _timeline_drift_hold_fixture()
    ledger = decision.trust_ledger
    provenance = ledger[_provenance_gate_index(ledger, "AP-001")]
    inventory = provenance.evidence_inventory
    assert inventory is not None
    endpoints = {
        item.reference.field_path: item.date_value
        for item in inventory.entries
        if item.claim_kind is ClaimKind.EMPLOYMENT_INTERVAL
    }
    start = endpoints["resume.employment_start"]
    end = endpoints["resume.employment_end"]
    assert type(start) is date and type(end) is date

    if mutation == "reason":
        timeline_index = _record_gate_index(ledger, "AP-001", TrustStage.TIMELINE)
        changed_timeline = ledger[timeline_index].model_copy(
            update={
                "state": TrustState.USABLE,
                "outcome": TrustOutcome.ALLOW,
                "reason_codes": (ReasonCode.TIMELINE_VALID,),
            }
        )
        mutated = (*ledger[:timeline_index], changed_timeline, *ledger[timeline_index + 1 :])
    else:

        def alter_entry(item: EvidenceDispositionEntry) -> EvidenceDispositionEntry:
            if item.claim_kind is not ClaimKind.EMPLOYMENT_INTERVAL:
                return item
            role = item.reference.field_path
            changed_date = item.date_value
            changed_reference = item.reference
            if mutation == "date" and role == "resume.employment_end":
                changed_date = date(2020, 5, 1)
                changed_reference = item.reference.model_copy(
                    update={"semantic_hash": compute_evidence_value_hash(changed_date.isoformat())}
                )
            elif mutation == "hash" and role == "resume.employment_start":
                changed_reference = item.reference.model_copy(update={"semantic_hash": "0" * 64})
            elif mutation == "missing" and role == "resume.employment_start":
                changed_date = None
            elif mutation == "swap":
                changed_date = end if role == "resume.employment_start" else start
                changed_reference = item.reference.model_copy(
                    update={"semantic_hash": compute_evidence_value_hash(changed_date.isoformat())}
                )
            return item.model_copy(
                update={"date_value": changed_date, "reference": changed_reference}
            )

        changed_ledger: list[TrustDecision] = []
        for gate in ledger:
            gate_inventory = gate.evidence_inventory
            if gate.candidate_id != "AP-001" or gate_inventory is None:
                changed_ledger.append(gate)
                continue
            entries = tuple(alter_entry(item) for item in gate_inventory.entries)
            changed_ledger.append(
                gate.model_copy(
                    update={
                        "evidence_inventory": gate_inventory.model_copy(update={"entries": entries})
                    }
                )
            )
        mutated = tuple(changed_ledger)

    result = ReleaseAuthorizer().authorize(
        batch,
        decision.routes,
        decision.plan,
        decision.step_receipts,
        trust_ledger=mutated,
        plan_history=decision.plans,
    )
    assert not result.authorized
