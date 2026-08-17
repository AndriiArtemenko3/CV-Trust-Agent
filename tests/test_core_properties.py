from __future__ import annotations

import hashlib
from datetime import date

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from cv_trust_agent.models import (  # noqa: E402
    ClaimKind,
    DecisionSupportGraph,
    DerivedFeature,
    ExecutionPlan,
    NormalizationMode,
    PlanCommand,
    PlanObjective,
    PlanStep,
    ReasonCode,
    StepReceipt,
    StepStatus,
    Strategy,
    SupportedEmploymentInterval,
    SupportedFact,
    TrustDecision,
    TrustOutcome,
    TrustScope,
    TrustStage,
    TrustState,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)
from cv_trust_agent.policy import DecisionController  # noqa: E402
from cv_trust_agent.workflow import (  # noqa: E402
    CommandHandler,
    CommandResult,
    StageInput,
    StageVault,
    WorkflowExecutor,
)
from tests.test_engine_unit import _case, _record, _run  # noqa: E402

_FACT_KINDS = (
    ClaimKind.CANDIDATE_ID,
    ClaimKind.AP_YEARS,
    ClaimKind.INVOICE_PROCESSING,
    ClaimKind.RECONCILIATION,
    ClaimKind.SPREADSHEET,
    ClaimKind.ACCOUNTING_PLATFORM,
    ClaimKind.EMPLOYMENT_INTERVAL,
)
_CATEGORY_VALUES = {
    ClaimKind.SPREADSHEET: "excel",
    ClaimKind.ACCOUNTING_PLATFORM: "xero",
}
_CANONICAL_VALUE_DOMAIN = b"cv-trust-agent/canonical-value/v2\0"


@settings(max_examples=30, deadline=None)
@given(st.lists(st.sampled_from(_FACT_KINDS), min_size=1, unique=True))
def test_support_graph_property_requires_complete_provenance_closure(
    kinds: list[ClaimKind],
) -> None:
    def supported_fact(kind: ClaimKind) -> SupportedFact:
        evidence_ids: tuple[str, ...] = (
            (
                "ev:index-1:AP-001:employment_start",
                "ev:index-1:AP-001:employment_end",
            )
            if kind is ClaimKind.EMPLOYMENT_INTERVAL
            else (f"ev:index-1:AP-001:{kind.value}",)
        )
        return SupportedFact(
            fact_id=f"fact:index-1:AP-001:{kind.value}",
            candidate_id="AP-001",
            snapshot_id="index-1",
            kind=kind,
            normalized_value=(
                1.0 if kind is ClaimKind.EMPLOYMENT_INTERVAL else _CATEGORY_VALUES.get(kind)
            ),
            source_value=_CATEGORY_VALUES.get(kind),
            canonical_value=_CATEGORY_VALUES.get(kind),
            normalization_mode=(
                NormalizationMode.BOUNDED_ALLOW_LIST_V1 if kind in _CATEGORY_VALUES else None
            ),
            canonical_value_sha256=(
                hashlib.sha256(
                    _CANONICAL_VALUE_DOMAIN + _CATEGORY_VALUES[kind].encode("utf-8")
                ).hexdigest()
                if kind in _CATEGORY_VALUES
                else None
            ),
            employment_intervals=(
                (
                    SupportedEmploymentInterval(
                        start_date=date(2025, 1, 1),
                        end_date=date(2026, 1, 1),
                        start_evidence_id=evidence_ids[0],
                        end_evidence_id=evidence_ids[1],
                    ),
                )
                if kind is ClaimKind.EMPLOYMENT_INTERVAL
                else ()
            ),
            evidence_ids=evidence_ids,
        )

    facts = tuple(supported_fact(kind) for kind in kinds)
    feature = DerivedFeature(
        feature_id="feature:index-1:AP-001:rank_key",
        candidate_id="AP-001",
        snapshot_id="index-1",
        name="rank_key",
        dependency_fact_ids=tuple(fact.fact_id for fact in facts),
    )
    evidence_ids = tuple(item for fact in facts for item in fact.evidence_ids)
    graph = DecisionSupportGraph(
        candidate_id="AP-001",
        snapshot_id="index-1",
        evidence_ids=evidence_ids,
        facts=facts,
        features=(feature,),
        route_support_ids=(feature.feature_id,),
    )

    assert set(graph.evidence_ids) == {item for fact in graph.facts for item in fact.evidence_ids}
    with pytest.raises(ValidationError, match="outside graph closure"):
        DecisionSupportGraph(
            candidate_id="AP-001",
            snapshot_id="index-1",
            evidence_ids=evidence_ids[1:],
            facts=facts,
            features=(feature,),
            route_support_ids=(feature.feature_id,),
        )


@settings(max_examples=40, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.sampled_from((0.5, 1.0, 2.0, 3.5)),
            st.booleans(),
            st.booleans(),
            st.booleans(),
            st.booleans(),
        ),
        min_size=1,
        max_size=8,
    )
)
def test_dense_evidence_ranking_property_is_permutation_invariant(
    features: list[tuple[float, bool, bool, bool, bool]],
) -> None:
    candidates = tuple(
        ValidatedCandidateEvidence(
            candidate_id=f"AP-{index:03d}",
            snapshot_id="index-property",
            trust_state=TrustState.USABLE,
            ap_years=ap_years,
            invoice_processing=invoice_processing,
            reconciliation=reconciliation,
            spreadsheet_supported=spreadsheet,
            accounting_platform_supported=platform,
        )
        for index, (
            ap_years,
            invoice_processing,
            reconciliation,
            spreadsheet,
            platform,
        ) in enumerate(features, start=1)
    )
    controller = DecisionController()

    def rank(items: tuple[ValidatedCandidateEvidence, ...]) -> dict[str, tuple[object, ...]]:
        batch = ValidatedBatchEvidence(
            batch_id="batch-property",
            snapshot_id="index-property",
            candidates=items,
            batch_integrity_valid=True,
            mapper_disagreement=False,
        )
        return {
            route.candidate_id: (
                route.evidence_rank,
                route.display_position,
                route.rank_key,
                route.queue,
            )
            for route in controller.rank(batch, Strategy.FULL_EVIDENCE_RANKING)
        }

    assert rank(candidates) == rank(tuple(reversed(candidates)))


@settings(max_examples=25, deadline=None)
@given(
    st.lists(
        st.sampled_from(
            (
                PlanStep.QUARANTINE_UNSUPPORTED,
                PlanStep.RANK_SUPPORTED_EVIDENCE,
                PlanStep.REQUEST_CORROBORATION,
                PlanStep.PRE_RELEASE_AUDIT,
                PlanStep.RELEASE_OUTPUT,
            )
        ),
        min_size=1,
        max_size=5,
        unique=True,
    )
)
def test_workflow_executor_property_executes_each_planned_command_once(
    steps: list[PlanStep],
) -> None:
    commands: list[PlanCommand] = []
    previous: str | None = None
    for step in steps:
        command_id = f"p1:{step.value}"
        commands.append(
            PlanCommand(
                command_id=command_id,
                kind=step,
                dependency_ids=() if previous is None else (previous,),
            )
        )
        previous = command_id
    plan = ExecutionPlan(
        version=1,
        objective=PlanObjective.RANK_SUPPORTED_EVIDENCE_ONLY,
        strategy=Strategy.SUPPORTED_ONLY_RANKING,
        commands=tuple(commands),
        trigger_codes=(ReasonCode.PLAN_SELECTED,),
    )
    calls: list[str] = []

    def make_handler() -> CommandHandler:
        def handler(
            command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            calls.append(command.command_id)
            consumed_gate_ids = tuple(
                dependency.handle.decision.decision_id for dependency in dependencies
            )
            decision = TrustDecision(
                decision_id=f"td:{command.command_id}",
                stage=TrustStage.PLANNING,
                scope=TrustScope.BATCH,
                state=TrustState.USABLE,
                outcome=TrustOutcome.ALLOW,
                reason_codes=(ReasonCode.COMMAND_COMPLETED,),
                input_gate_ids=consumed_gate_ids,
            )
            return CommandResult(
                stage_handle=vault.create(value=command.command_id, decision=decision),
            )

        return handler

    handlers: dict[PlanStep, CommandHandler] = {step: make_handler() for step in steps}
    vault = StageVault("run-property")
    root_decision = TrustDecision(
        decision_id="td:root",
        stage=TrustStage.PLANNING,
        scope=TrustScope.BATCH,
        state=TrustState.USABLE,
        outcome=TrustOutcome.ALLOW,
        reason_codes=(ReasonCode.PLAN_SELECTED,),
    )
    root_gate = vault.create(value="root", decision=root_decision)
    report = WorkflowExecutor().execute(plan, handlers, vault=vault, root_gate=root_gate)

    assert report.complete
    assert calls == [command.command_id for command in commands]
    assert len(report.receipts) == 2 * len(commands)


def test_workflow_executor_fails_missing_handler_and_restricts_dependent_command() -> None:
    first = PlanCommand(command_id="p1:first", kind=PlanStep.QUARANTINE_UNSUPPORTED)
    second = PlanCommand(
        command_id="p1:second",
        kind=PlanStep.RANK_SUPPORTED_EVIDENCE,
        dependency_ids=(first.command_id,),
    )
    plan = ExecutionPlan(
        version=1,
        objective=PlanObjective.RANK_SUPPORTED_EVIDENCE_ONLY,
        strategy=Strategy.SUPPORTED_ONLY_RANKING,
        commands=(first, second),
        trigger_codes=(ReasonCode.PLAN_SELECTED,),
    )

    report = WorkflowExecutor().execute(plan, {}, vault=StageVault("run-missing"))

    assert not report.complete
    assert report.terminal_statuses == {
        first.command_id: StepStatus.FAILED,
        second.command_id: StepStatus.RESTRICTED,
    }


def test_workflow_executor_rejects_handler_that_does_not_consume_exact_dependencies() -> None:
    command = PlanCommand(command_id="p1:rank", kind=PlanStep.RANK_SUPPORTED_EVIDENCE)
    plan = ExecutionPlan(
        version=1,
        objective=PlanObjective.RANK_SUPPORTED_EVIDENCE_ONLY,
        strategy=Strategy.SUPPORTED_ONLY_RANKING,
        commands=(command,),
        trigger_codes=(ReasonCode.PLAN_SELECTED,),
    )

    def invalid_handler(
        _command: PlanCommand,
        _receipts: tuple[StepReceipt, ...],
        _dependencies: tuple[StageInput, ...],
    ) -> CommandResult:
        decision = TrustDecision(
            decision_id="td:invalid",
            stage=TrustStage.RANKING,
            scope=TrustScope.BATCH,
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reason_codes=(ReasonCode.COMMAND_COMPLETED,),
            input_gate_ids=("td:not-a-dependency",),
        )
        return CommandResult(
            stage_handle=vault.create(value="ranked", decision=decision),
        )

    vault = StageVault("run-invalid")
    root_decision = TrustDecision(
        decision_id="td:root",
        stage=TrustStage.PLANNING,
        scope=TrustScope.BATCH,
        state=TrustState.USABLE,
        outcome=TrustOutcome.ALLOW,
        reason_codes=(ReasonCode.PLAN_SELECTED,),
    )
    root_gate = vault.create(value="root", decision=root_decision)
    report = WorkflowExecutor().execute(
        plan,
        {PlanStep.RANK_SUPPORTED_EVIDENCE: invalid_handler},
        vault=vault,
        root_gate=root_gate,
    )

    assert not report.complete
    assert report.terminal_statuses == {command.command_id: StepStatus.FAILED}
    assert not report.stage_results


@settings(max_examples=25, deadline=None)
@given(
    st.text(
        alphabet=st.characters(min_codepoint=32, max_codepoint=126),
        min_size=1,
        max_size=80,
    )
)
def test_untrusted_note_property_cannot_affect_or_enter_released_output(note: str) -> None:
    clean = _case((_record("AP-001", note="ordinary availability note"),))
    mutated = _case((_record("AP-001", note=f"UNTRUSTED-SENTINEL-{note}"),))

    clean_decision = _run(clean)
    mutated_decision = _run(mutated)

    assert clean_decision.routes == mutated_decision.routes
    assert clean_decision.support_graph_hash == mutated_decision.support_graph_hash
    assert "UNTRUSTED-SENTINEL-" not in mutated_decision.model_dump_json()
