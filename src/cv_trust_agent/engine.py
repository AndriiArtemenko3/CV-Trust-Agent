"""Trusted validation, evidence-strength ranking, and finite replanning."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import uuid4

from cv_trust_agent.evidence_validation import (
    CandidateAssessment,
    CandidateBindingAssessment,
    CandidateEvidenceValidator,
    PreparedMapperClaims,
    SourceSchemaError,
    compute_index_manifest_hash,
    compute_support_graph_hash,
    parse_batch_index,
    safe_conflict_value,
    safe_evidence_source_label,
    unique_by_candidate,
    unique_request_map,
)
from cv_trust_agent.intake import PreparedCandidateDetail
from cv_trust_agent.mappers import ClaimMapper, MapperError, MapperFailureCode
from cv_trust_agent.models import (
    BatchIndex,
    CandidateRecord,
    CandidateRoute,
    ClaimKind,
    CorroborationRequest,
    DecisionExplanation,
    EvidenceDispositionInventory,
    ExecutionMode,
    ExecutionPlan,
    ExplanationTemplate,
    MapperOutput,
    MapperRequest,
    PlanCommand,
    PlanDiff,
    PlanStep,
    RankingScope,
    ReasonCode,
    RunDecision,
    StageHandle,
    StepReceipt,
    Strategy,
    TraceEvent,
    TrustDecision,
    TrustOutcome,
    TrustScope,
    TrustStage,
    TrustState,
    UnavailableCandidate,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)
from cv_trust_agent.policy import DecisionController, ExecutionPlanner
from cv_trust_agent.release import ReleaseAuthorizer
from cv_trust_agent.retrieval import RetrievedCandidateDetail, RetrievedResume
from cv_trust_agent.telemetry import NullTelemetrySink, TelemetrySink, sanitized_attributes
from cv_trust_agent.workflow import (
    CommandHandler,
    CommandResult,
    ExecutionReport,
    StageInput,
    StageVault,
    WorkflowExecutor,
)


class StartFailure(RuntimeError):
    """Sanitized start failure carrying the already fail-closed decision."""

    def __init__(self, decision: RunDecision) -> None:
        super().__init__("source index could not cross the trusted start boundary")
        self.decision = decision


@dataclass(frozen=True)
class ExecutionMaterial:
    """Candidate material after the provider's bounded PDF parsing stage."""

    candidate_records: tuple[CandidateRecord, ...]
    mapper_requests: tuple[MapperRequest, ...]
    unavailable_candidates: tuple[UnavailableCandidate, ...] = ()


@dataclass(frozen=True)
class DetailFetchMaterial:
    retrieved_details: tuple[RetrievedCandidateDetail, ...]
    unavailable_candidates: tuple[UnavailableCandidate, ...] = ()


@dataclass(frozen=True)
class DetailValidationMaterial:
    prepared_details: tuple[PreparedCandidateDetail, ...]
    unavailable_candidates: tuple[UnavailableCandidate, ...] = ()


@dataclass(frozen=True)
class ResumeFetchMaterial:
    retrieved_resumes: tuple[RetrievedResume, ...]
    prepared_details: tuple[PreparedCandidateDetail, ...]
    unavailable_candidates: tuple[UnavailableCandidate, ...] = ()


class CandidateEvidenceProvider(Protocol):
    """Trusted adapter whose methods align one-to-one with v1 I/O/intake commands."""

    def fetch_candidate_details(self, index: BatchIndex) -> DetailFetchMaterial: ...

    def validate_candidate_details(
        self,
        index: BatchIndex,
        fetched: DetailFetchMaterial,
    ) -> DetailValidationMaterial: ...

    def fetch_candidate_resumes(
        self,
        index: BatchIndex,
        validated: DetailValidationMaterial,
    ) -> ResumeFetchMaterial: ...

    def parse_candidate_resumes(
        self,
        index: BatchIndex,
        fetched: ResumeFetchMaterial,
    ) -> ExecutionMaterial: ...


@dataclass(frozen=True)
class _MappedMaterial:
    candidate_records: tuple[CandidateRecord, ...]
    mapper_requests: tuple[MapperRequest, ...]
    unavailable_candidates: tuple[UnavailableCandidate, ...]
    bindings: Mapping[str, CandidateBindingAssessment]
    outputs: tuple[MapperOutput, ...]
    prepared_claims: Mapping[str, PreparedMapperClaims]
    failed_candidate_ids: tuple[str, ...]

    @property
    def mapping_commitment_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    evidence_id
                    for prepared in self.prepared_claims.values()
                    for evidence_id in prepared.mapping_commitment_ids
                }
            )
        )


@dataclass(frozen=True)
class _BindingValidatedMaterial:
    candidate_records: tuple[CandidateRecord, ...]
    eligible_mapper_requests: tuple[MapperRequest, ...]
    unavailable_candidates: tuple[UnavailableCandidate, ...]
    bindings: Mapping[str, CandidateBindingAssessment]


@dataclass(frozen=True)
class _ValidatedMaterial:
    assessments: Mapping[str, CandidateAssessment]
    batch: ValidatedBatchEvidence
    terminal_handles: tuple[StageHandle, ...] = ()


@dataclass(frozen=True)
class _FinalWorkflowState:
    batch: ValidatedBatchEvidence
    routes: tuple[CandidateRoute, ...] = ()
    corroboration_requests: tuple[CorroborationRequest, ...] = ()
    authorized: bool = False
    released: bool = False


@dataclass(frozen=True)
class _FinalPlanInput:
    plan: ExecutionPlan
    batch: ValidatedBatchEvidence


@dataclass(frozen=True)
class RankingCheckpoint:
    run_id: str
    initial_plan: ExecutionPlan
    index: BatchIndex
    index_valid: bool
    _owner_token: object
    _ledger: list[TrustDecision]
    _receipts: list[StepReceipt]
    _initial_plan_gate: StageHandle
    _vault: StageVault


class TrustedAgentEngine:
    def __init__(
        self,
        mapper: ClaimMapper,
        *,
        telemetry: TelemetrySink | None = None,
        controller: DecisionController | None = None,
    ) -> None:
        self._mapper = mapper
        self._telemetry = telemetry or NullTelemetrySink()
        self._controller = controller or DecisionController()
        self._planner = ExecutionPlanner()
        self._validator = CandidateEvidenceValidator()
        self._executor = WorkflowExecutor()
        self._authorizer = ReleaseAuthorizer()
        self._checkpoint_token = object()
        self._open_checkpoints: set[int] = set()
        self._stage_vaults: dict[str, StageVault] = {}

    def start(
        self,
        index: BatchIndex | Mapping[str, Any],
        *,
        run_id: str | None = None,
    ) -> RankingCheckpoint:
        selected_run_id = run_id or f"run-{uuid4().hex[:12]}"
        if selected_run_id in self._stage_vaults:
            raise ValueError("run_id is already registered")
        vault = StageVault(selected_run_id)
        self._stage_vaults[selected_run_id] = vault
        ledger: list[TrustDecision] = []
        raw_index: BatchIndex | Mapping[str, Any] = index
        retrieval_decision = self._append_decision(
            ledger,
            run_id=selected_run_id,
            stage=TrustStage.RETRIEVAL,
            scope=TrustScope.BATCH,
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reasons=(ReasonCode.FETCH_SUCCEEDED,),
            snapshot_id=index.index_id if isinstance(index, BatchIndex) else None,
        )
        retrieved = self._consume_gate(
            run_id=selected_run_id,
            value=raw_index,
            decision=retrieval_decision,
        )
        if retrieved is None:
            raise RuntimeError("usable retrieval gate unexpectedly blocked")
        try:
            parsed = parse_batch_index(retrieved)
        except SourceSchemaError:
            schema_failure = self._append_decision(
                ledger,
                run_id=selected_run_id,
                stage=TrustStage.SCHEMA,
                scope=TrustScope.BATCH,
                state=TrustState.QUARANTINED,
                outcome=TrustOutcome.HOLD,
                reasons=(ReasonCode.SCHEMA_INVALID,),
                snapshot_id="untrusted-index",
                input_gate_ids=(retrieval_decision.decision_id,),
            )
            self._create_gate(
                run_id=selected_run_id,
                value=None,
                decision=schema_failure,
            )
            raise StartFailure(
                self.fail_closed(
                    stage=TrustStage.SCHEMA,
                    reason=ReasonCode.SCHEMA_INVALID,
                    run_id=selected_run_id,
                    _prior_ledger=ledger,
                    _append_failure=False,
                )
            ) from None
        schema_decision = self._append_decision(
            ledger,
            run_id=selected_run_id,
            stage=TrustStage.SCHEMA,
            scope=TrustScope.BATCH,
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reasons=(ReasonCode.SCHEMA_VALID,),
            snapshot_id=parsed.index_id,
            input_gate_ids=(retrieval_decision.decision_id,),
        )
        schema_result = self._consume_gate(
            run_id=selected_run_id,
            value=parsed,
            decision=schema_decision,
        )
        if not isinstance(schema_result, BatchIndex):
            raise RuntimeError("usable schema gate unexpectedly blocked")
        manifest_valid = (
            compute_index_manifest_hash(schema_result.candidates) == schema_result.manifest_hash
        )
        manifest_decision = self._append_decision(
            ledger,
            run_id=selected_run_id,
            stage=TrustStage.MANIFEST,
            scope=TrustScope.BATCH,
            state=TrustState.USABLE if manifest_valid else TrustState.QUARANTINED,
            outcome=TrustOutcome.ALLOW if manifest_valid else TrustOutcome.HOLD,
            reasons=(
                ReasonCode.MANIFEST_VALID if manifest_valid else ReasonCode.MANIFEST_CONFLICT,
            ),
            snapshot_id=parsed.index_id,
            input_gate_ids=(schema_decision.decision_id,),
        )
        if manifest_valid:
            manifest_result = self._consume_gate(
                run_id=selected_run_id,
                value=schema_result,
                decision=manifest_decision,
            )
            if not isinstance(manifest_result, BatchIndex):
                raise RuntimeError("usable manifest gate unexpectedly blocked")
        else:
            self._create_gate(
                run_id=selected_run_id,
                value=None,
                decision=manifest_decision,
            )
        initial_plan = self._planner.initial_plan(manifest_valid)
        plan_state = TrustState.USABLE if manifest_valid else TrustState.QUARANTINED
        planning_decision = self._append_decision(
            ledger,
            run_id=selected_run_id,
            stage=TrustStage.PLANNING,
            scope=TrustScope.BATCH,
            # The source may be held, while the code-owned hold plan remains a
            # trusted and consumable control-plane value.
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reasons=(ReasonCode.PLAN_SELECTED,),
            snapshot_id=parsed.index_id,
            input_gate_ids=(manifest_decision.decision_id,),
        )
        initial_plan_gate = self._create_gate(
            run_id=selected_run_id,
            value=initial_plan,
            decision=planning_decision,
        )
        self._emit(
            TraceEvent(
                event_type="plan.materialized",
                run_id=selected_run_id,
                emitted_at=datetime.now(UTC),
                stage=TrustStage.PLANNING,
                snapshot_id=parsed.index_id,
                state=plan_state,
                reason_codes=(ReasonCode.PLAN_SELECTED,),
                attributes=sanitized_attributes(
                    strategy=initial_plan.strategy.value,
                    plan_version=initial_plan.version,
                    candidate_count=len(parsed.candidates),
                ),
            )
        )
        checkpoint = RankingCheckpoint(
            run_id=selected_run_id,
            initial_plan=initial_plan,
            index=parsed,
            index_valid=manifest_valid,
            _owner_token=self._checkpoint_token,
            _ledger=ledger,
            _receipts=[],
            _initial_plan_gate=initial_plan_gate,
            _vault=vault,
        )
        self._open_checkpoints.add(id(checkpoint))
        return checkpoint

    def execute(
        self,
        checkpoint: RankingCheckpoint,
        provider: CandidateEvidenceProvider,
    ) -> RunDecision:
        """Execute every advertised v1 stage, then execute the selected v2 plan."""

        if not checkpoint._vault.is_available(checkpoint._initial_plan_gate):
            raise ValueError("initial plan gate was consumed before its first command")
        validated_box: list[_ValidatedMaterial] = []

        def fetch_details(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if values != (checkpoint.initial_plan,):
                raise RuntimeError("detail fetch lacks its trusted plan gate")
            fetched = provider.fetch_candidate_details(checkpoint.index)
            return self._command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.RETRIEVAL,
                value=fetched,
                snapshot_id=checkpoint.index.index_id,
                consumed_gate_ids=gate_ids,
            )

        def validate_details(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if len(values) != 1 or not isinstance(values[0], DetailFetchMaterial):
                raise RuntimeError("detail validation dependency is invalid")
            validated = provider.validate_candidate_details(checkpoint.index, values[0])
            return self._command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.SCHEMA,
                value=validated,
                snapshot_id=checkpoint.index.index_id,
                consumed_gate_ids=gate_ids,
            )

        def fetch_resumes(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if len(values) != 1 or not isinstance(values[0], DetailValidationMaterial):
                raise RuntimeError("resume fetch dependency is invalid")
            fetched = provider.fetch_candidate_resumes(checkpoint.index, values[0])
            return self._command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.RETRIEVAL,
                value=fetched,
                snapshot_id=checkpoint.index.index_id,
                consumed_gate_ids=gate_ids,
            )

        def parse_resumes(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if len(values) != 1 or not isinstance(values[0], ResumeFetchMaterial):
                raise RuntimeError("resume parsing dependency is invalid")
            material = provider.parse_candidate_resumes(checkpoint.index, values[0])
            evidence_ids = self._material_evidence_ids(material)
            return self._command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.PARSING,
                value=material,
                snapshot_id=checkpoint.index.index_id,
                consumed_gate_ids=gate_ids,
                evidence_ids=evidence_ids,
            )

        def map_claims(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if len(values) != 1 or not isinstance(values[0], _BindingValidatedMaterial):
                raise RuntimeError("mapping dependency is invalid")
            mapped = self._map_material(checkpoint, values[0])
            return self._command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.MAPPING,
                value=mapped,
                snapshot_id=checkpoint.index.index_id,
                consumed_gate_ids=gate_ids,
                evidence_ids=mapped.mapping_commitment_ids,
            )

        def validate_bindings(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if len(values) != 1 or not isinstance(values[0], ExecutionMaterial):
                raise RuntimeError("candidate binding dependency is invalid")
            bound = self._validate_candidate_bindings(
                checkpoint,
                values[0],
                input_gate_id=gate_ids[0],
            )
            return self._deferred_fan_in_command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.IDENTITY,
                value=bound,
                snapshot_id=checkpoint.index.index_id,
                fan_in_handles=tuple(
                    binding.terminal_handle for _, binding in sorted(bound.bindings.items())
                ),
                evidence_ids=tuple(
                    sorted(
                        {
                            evidence_id
                            for binding in bound.bindings.values()
                            for evidence_id in binding.evidence_ids
                        }
                    )
                ),
            )

        def validate_evidence(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if len(values) != 1 or not isinstance(values[0], _MappedMaterial):
                raise RuntimeError("evidence validation dependency is invalid")
            validated = self._validate_mapped_material(
                checkpoint,
                values[0],
                input_gate_id=gate_ids[0],
            )
            validated_box.append(validated)
            evidence_ids = tuple(
                sorted(
                    {
                        evidence_id
                        for candidate in validated.batch.candidates
                        for evidence_id in candidate.evidence_ids
                    }
                )
            )
            return self._deferred_fan_in_command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.PROVENANCE,
                value=validated,
                snapshot_id=checkpoint.index.index_id,
                fan_in_handles=validated.terminal_handles,
                evidence_ids=evidence_ids,
            )

        def validate_index_commitments(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            values, gate_ids = self._consume_command_dependencies(
                run_id=checkpoint.run_id,
                dependencies=dependencies,
            )
            if values != (checkpoint.initial_plan,) or checkpoint.index_valid:
                raise RuntimeError("index-hold command precondition is invalid")
            assessments = {
                entry.candidate_id: CandidateAssessment(
                    evidence=self._validator.empty_candidate(
                        entry.candidate_id,
                        checkpoint.index.index_id,
                        TrustState.QUARANTINED,
                        (ReasonCode.MANIFEST_CONFLICT,),
                    ),
                    mapper_disagreement=False,
                )
                for entry in checkpoint.index.candidates
            }
            batch = ValidatedBatchEvidence(
                batch_id=checkpoint.index.batch_id,
                snapshot_id=checkpoint.index.index_id,
                candidates=tuple(item.evidence for item in assessments.values()),
                batch_integrity_valid=False,
                mapper_disagreement=False,
            )
            validated = _ValidatedMaterial(assessments, batch)
            validated_box.append(validated)
            return self._command_result(
                checkpoint._ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.MANIFEST,
                value=validated,
                snapshot_id=checkpoint.index.index_id,
                consumed_gate_ids=gate_ids,
                reasons=(ReasonCode.MANIFEST_CONFLICT,),
            )

        handlers: dict[PlanStep, CommandHandler] = {
            PlanStep.FETCH_CANDIDATE_DETAILS: fetch_details,
            PlanStep.VALIDATE_CANDIDATE_DETAILS: validate_details,
            PlanStep.FETCH_CANDIDATE_RESUMES: fetch_resumes,
            PlanStep.PARSE_CANDIDATE_RESUMES: parse_resumes,
            PlanStep.VALIDATE_CANDIDATE_BINDINGS: validate_bindings,
            PlanStep.MAP_CANDIDATE_CLAIMS: map_claims,
            PlanStep.VALIDATE_CANDIDATE_EVIDENCE: validate_evidence,
            PlanStep.VALIDATE_INDEX_COMMITMENTS: validate_index_commitments,
        }
        report = self._executor.execute(
            checkpoint.initial_plan,
            handlers,
            vault=checkpoint._vault,
            root_gate=checkpoint._initial_plan_gate,
            stop_after=(
                PlanStep.VALIDATE_CANDIDATE_EVIDENCE
                if checkpoint.index_valid
                else PlanStep.VALIDATE_INDEX_COMMITMENTS
            ),
            on_gate_consumed=lambda gate: self._emit_gate_consumed(checkpoint.run_id, gate),
        )
        checkpoint._receipts.extend(report.receipts)
        if report.selected_complete and validated_box:
            validated = validated_box[-1]
        else:
            validated = self._failed_initial_execution(checkpoint)
        mode = ExecutionMode.EXECUTED if report.selected_complete else ExecutionMode.FAILED_CLOSED
        return self._finish_validated(
            checkpoint,
            validated,
            initial_report=report,
            execution_mode=mode,
        )

    def _map_material(
        self,
        checkpoint: RankingCheckpoint,
        bound: _BindingValidatedMaterial,
    ) -> _MappedMaterial:
        outputs: list[MapperOutput] = []
        prepared_claims: dict[str, PreparedMapperClaims] = {}
        failed: list[str] = []
        records = {record.candidate_id: record for record in bound.candidate_records}
        approved_ids = {
            candidate_id for candidate_id, binding in bound.bindings.items() if binding.valid
        }
        if {request.candidate_id for request in bound.eligible_mapper_requests} != approved_ids:
            raise RuntimeError("binding boundary exposed an ineligible mapper request")
        for request in bound.eligible_mapper_requests:
            try:
                output = self._mapper.map_claims(request)
                if (
                    output.candidate_id != request.candidate_id
                    or output.snapshot_id != checkpoint.index.index_id
                ):
                    raise MapperError(
                        "mapper changed request identity",
                        code=(
                            MapperFailureCode.CANDIDATE_IDENTITY_MISMATCH
                            if output.candidate_id != request.candidate_id
                            else MapperFailureCode.SNAPSHOT_IDENTITY_MISMATCH
                        ),
                    )
            except MapperError:
                failed.append(request.candidate_id)
            else:
                record = records.get(request.candidate_id)
                if record is None:
                    failed.append(request.candidate_id)
                    continue
                try:
                    prepared = self._validator.prepare_mapper_output(record, request, output)
                except (RuntimeError, ValueError):
                    failed.append(request.candidate_id)
                    continue
                outputs.append(output)
                prepared_claims[request.candidate_id] = prepared
        return _MappedMaterial(
            candidate_records=bound.candidate_records,
            mapper_requests=bound.eligible_mapper_requests,
            unavailable_candidates=bound.unavailable_candidates,
            bindings=bound.bindings,
            outputs=tuple(outputs),
            prepared_claims=prepared_claims,
            failed_candidate_ids=tuple(sorted(set(failed))),
        )

    def _validate_candidate_bindings(
        self,
        checkpoint: RankingCheckpoint,
        material: ExecutionMaterial,
        *,
        input_gate_id: str,
    ) -> _BindingValidatedMaterial:
        records, _ = unique_by_candidate(material.candidate_records)
        requests, _ = unique_request_map(material.mapper_requests)
        record_counts = {
            candidate_id: sum(
                record.candidate_id == candidate_id for record in material.candidate_records
            )
            for candidate_id in records
        }
        request_counts = {
            candidate_id: sum(
                request.candidate_id == candidate_id for request in material.mapper_requests
            )
            for candidate_id in requests
        }
        unavailable_by_id = {item.candidate_id: item for item in material.unavailable_candidates}
        bindings: dict[str, CandidateBindingAssessment] = {}
        for entry in checkpoint.index.candidates:
            candidate_id = entry.candidate_id
            if candidate_id in unavailable_by_id:
                failure = unavailable_by_id[candidate_id]
                failure_stage = {
                    ReasonCode.RETRIEVAL_FAILED: TrustStage.RETRIEVAL,
                    ReasonCode.SCHEMA_INVALID: TrustStage.SCHEMA,
                    ReasonCode.PARSING_FAILED: TrustStage.PARSING,
                }[failure.reason]
                failure_state = (
                    TrustState.UNAVAILABLE
                    if failure_stage is TrustStage.RETRIEVAL
                    else TrustState.QUARANTINED
                )
                decision = self._append_decision(
                    checkpoint._ledger,
                    run_id=checkpoint.run_id,
                    stage=failure_stage,
                    scope=TrustScope.RECORD,
                    state=failure_state,
                    outcome=self._validator.outcome_for(failure_state),
                    reasons=(failure.reason, ReasonCode.CANDIDATE_UNAVAILABLE),
                    candidate_id=candidate_id,
                    snapshot_id=checkpoint.index.index_id,
                    input_gate_ids=(input_gate_id,),
                )
                terminal_handle = self._create_gate(
                    run_id=checkpoint.run_id, value=None, decision=decision
                )
                bindings[candidate_id] = CandidateBindingAssessment(
                    valid=False,
                    reason_codes=(failure.reason, ReasonCode.CANDIDATE_UNAVAILABLE),
                    evidence_ids=(),
                    terminal_handle=terminal_handle,
                )
                continue
            record = records.get(candidate_id)
            request = requests.get(candidate_id)
            ambiguous = (
                record_counts.get(candidate_id, 0) != 1 or request_counts.get(candidate_id, 0) != 1
            )
            if record is None or request is None or ambiguous:
                decision = self._append_decision(
                    checkpoint._ledger,
                    run_id=checkpoint.run_id,
                    stage=TrustStage.IDENTITY,
                    scope=TrustScope.RECORD,
                    state=TrustState.QUARANTINED,
                    outcome=TrustOutcome.QUARANTINE,
                    reasons=(ReasonCode.INDEX_CONFLICT,),
                    candidate_id=candidate_id,
                    snapshot_id=checkpoint.index.index_id,
                    input_gate_ids=(input_gate_id,),
                )
                terminal_handle = self._create_gate(
                    run_id=checkpoint.run_id, value=None, decision=decision
                )
                bindings[candidate_id] = CandidateBindingAssessment(
                    valid=False,
                    reason_codes=(ReasonCode.INDEX_CONFLICT,),
                    evidence_ids=(),
                    terminal_handle=terminal_handle,
                )
                continue
            bindings[candidate_id] = self._validator.validate_candidate_binding(
                checkpoint.index,
                entry,
                record,
                request,
                checkpoint.run_id,
                checkpoint._ledger,
                input_gate_id=input_gate_id,
                gate_port=self,
            )
        eligible_ids = {candidate_id for candidate_id, binding in bindings.items() if binding.valid}
        eligible_requests = tuple(
            request
            for request in material.mapper_requests
            if request.candidate_id in eligible_ids
            and request_counts.get(request.candidate_id) == 1
        )
        return _BindingValidatedMaterial(
            candidate_records=material.candidate_records,
            eligible_mapper_requests=eligible_requests,
            unavailable_candidates=material.unavailable_candidates,
            bindings=bindings,
        )

    @staticmethod
    def _material_evidence_ids(material: ExecutionMaterial) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    evidence.evidence_id
                    for request in material.mapper_requests
                    for evidence in request.evidence_catalog
                }
            )
        )

    def _failed_initial_execution(self, checkpoint: RankingCheckpoint) -> _ValidatedMaterial:
        assessments = {
            entry.candidate_id: CandidateAssessment(
                evidence=self._validator.empty_candidate(
                    entry.candidate_id,
                    checkpoint.index.index_id,
                    TrustState.UNAVAILABLE,
                    (ReasonCode.RETRIEVAL_FAILED, ReasonCode.CANDIDATE_UNAVAILABLE),
                ),
                mapper_disagreement=True,
            )
            for entry in checkpoint.index.candidates
        }
        batch = ValidatedBatchEvidence(
            batch_id=checkpoint.index.batch_id,
            snapshot_id=checkpoint.index.index_id,
            candidates=tuple(item.evidence for item in assessments.values()),
            unavailable_candidate_ids=tuple(sorted(assessments)),
            batch_integrity_valid=False,
            mapper_disagreement=True,
        )
        return _ValidatedMaterial(assessments, batch)

    def _validate_mapped_material(
        self,
        checkpoint: RankingCheckpoint,
        mapped: _MappedMaterial,
        *,
        input_gate_id: str,
    ) -> _ValidatedMaterial:
        candidate_records = mapped.candidate_records
        mapper_requests = mapped.mapper_requests
        unavailable_candidates = mapped.unavailable_candidates
        index = checkpoint.index
        ledger = checkpoint._ledger
        entries = {entry.candidate_id: entry for entry in index.candidates}
        records, duplicate_records = unique_by_candidate(candidate_records)
        unavailable, duplicate_unavailable = unique_by_candidate(unavailable_candidates)
        requests, duplicate_requests = unique_request_map(mapper_requests)
        outputs, duplicate_outputs = unique_by_candidate(mapped.outputs)
        mapping_failures = set(mapped.failed_candidate_ids)
        indexed_ids = set(entries)
        contract_valid = not any(
            (
                duplicate_records,
                duplicate_unavailable,
                duplicate_requests,
                duplicate_outputs,
                set(records).difference(indexed_ids),
                set(unavailable).difference(indexed_ids),
                set(records).intersection(unavailable),
                indexed_ids.difference(set(records).union(unavailable)),
                set(mapped.prepared_claims) != set(outputs),
            )
        )
        assessments: dict[str, CandidateAssessment] = {}
        explicit_unavailable = set(unavailable).intersection(indexed_ids)
        for candidate_id, entry in entries.items():
            if candidate_id in explicit_unavailable:
                failure = unavailable[candidate_id]
                binding = mapped.bindings.get(candidate_id)
                if binding is None or binding.valid:
                    contract_valid = False
                assessments[candidate_id] = CandidateAssessment(
                    evidence=self._validator.empty_candidate(
                        candidate_id,
                        index.index_id,
                        TrustState.UNAVAILABLE,
                        (
                            binding.reason_codes
                            if binding is not None
                            else (failure.reason, ReasonCode.CANDIDATE_UNAVAILABLE)
                        ),
                    ),
                    mapper_disagreement=False,
                )
                continue
            record = records.get(candidate_id)
            request = requests.get(candidate_id)
            binding = mapped.bindings.get(candidate_id)
            if binding is not None and not binding.valid:
                assessments[candidate_id] = CandidateAssessment(
                    evidence=self._validator.empty_candidate(
                        candidate_id,
                        index.index_id,
                        TrustState.QUARANTINED,
                        binding.reason_codes,
                    ),
                    mapper_disagreement=True,
                )
                continue
            if record is None or request is None:
                contract_valid = False
                assessments[candidate_id] = CandidateAssessment(
                    evidence=self._validator.empty_candidate(
                        candidate_id,
                        index.index_id,
                        TrustState.QUARANTINED,
                        (ReasonCode.INDEX_CONFLICT,),
                    ),
                    mapper_disagreement=True,
                )
                continue
            if binding is None:
                contract_valid = False
                assessments[candidate_id] = CandidateAssessment(
                    evidence=self._validator.empty_candidate(
                        candidate_id,
                        index.index_id,
                        TrustState.QUARANTINED,
                        (ReasonCode.INDEX_CONFLICT,),
                    ),
                    mapper_disagreement=True,
                )
                continue
            assessments[candidate_id] = self._validator.assess_candidate(
                index,
                entry,
                record,
                request,
                checkpoint.run_id,
                ledger,
                mapped_output=outputs.get(candidate_id),
                prepared_claims=mapped.prepared_claims.get(candidate_id),
                mapping_failed=candidate_id in mapping_failures,
                binding=binding,
                gate_port=self,
            )

        batch_integrity_valid = checkpoint.index_valid and contract_valid
        mapper_disagreement = any(
            assessment.mapper_disagreement for assessment in assessments.values()
        )
        validated_batch = ValidatedBatchEvidence(
            batch_id=index.batch_id,
            snapshot_id=index.index_id,
            candidates=tuple(
                assessments[candidate_id].evidence for candidate_id in sorted(assessments)
            ),
            unavailable_candidate_ids=tuple(
                candidate_id
                for candidate_id, assessment in sorted(assessments.items())
                if assessment.evidence.trust_state is TrustState.UNAVAILABLE
            ),
            batch_integrity_valid=batch_integrity_valid,
            mapper_disagreement=mapper_disagreement,
        )
        terminal_handles: list[StageHandle] = []
        for candidate_id in sorted(entries):
            assessment = assessments[candidate_id]
            record_parents = tuple(
                decision
                for decision in ledger
                if decision.scope is TrustScope.RECORD
                and decision.candidate_id == candidate_id
                and decision.stage is not TrustStage.CANDIDATE_VALIDATION
            )
            parent_gate_id = record_parents[-1].decision_id if record_parents else input_gate_id
            terminal_decision = self._append_decision(
                ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.CANDIDATE_VALIDATION,
                scope=TrustScope.RECORD,
                state=assessment.evidence.trust_state,
                outcome=self._validator.outcome_for(assessment.evidence.trust_state),
                reasons=(assessment.evidence.reason_codes or (ReasonCode.SUPPORT_GRAPH_VALID,)),
                candidate_id=candidate_id,
                snapshot_id=index.index_id,
                evidence_ids=assessment.evidence.evidence_ids,
                input_gate_ids=(parent_gate_id,),
                evidence_inventory=assessment.evidence_inventory,
            )
            terminal_handles.append(
                self._create_gate(
                    run_id=checkpoint.run_id,
                    value=(
                        assessment
                        if assessment.evidence.trust_state
                        in {TrustState.USABLE, TrustState.DEGRADED}
                        else None
                    ),
                    decision=terminal_decision,
                    provenance_ids=assessment.evidence.evidence_ids,
                )
            )
        return _ValidatedMaterial(
            assessments,
            validated_batch,
            tuple(terminal_handles),
        )

    def _finish_validated(
        self,
        checkpoint: RankingCheckpoint,
        validated: _ValidatedMaterial,
        *,
        initial_report: ExecutionReport,
        execution_mode: ExecutionMode,
    ) -> RunDecision:
        self._consume_checkpoint(checkpoint)
        index = checkpoint.index
        ledger = checkpoint._ledger
        assessments = validated.assessments
        validated_batch = validated.batch
        explicit_unavailable = set(validated_batch.unavailable_candidate_ids)
        batch_integrity_valid = validated_batch.batch_integrity_valid
        mapper_disagreement = validated_batch.mapper_disagreement
        validation_kind = (
            PlanStep.VALIDATE_CANDIDATE_EVIDENCE
            if checkpoint.index_valid
            else PlanStep.VALIDATE_INDEX_COMMITMENTS
        )
        validation_command = next(
            command
            for command in checkpoint.initial_plan.commands
            if command.kind is validation_kind
        )
        validation_gate = initial_report.stage_results.get(validation_command.command_id)
        validation_gate_id: str | None = None
        if validation_gate is None:
            # A failed acquisition prefix never authorizes ordinary ranking.
            validated_batch = validated_batch.model_copy(
                update={"batch_integrity_valid": False, "mapper_disagreement": True}
            )
            execution_failure = self._append_decision(
                ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.PROVENANCE,
                scope=TrustScope.BATCH,
                state=TrustState.QUARANTINED,
                outcome=TrustOutcome.HOLD,
                reasons=(ReasonCode.COMMAND_FAILED,),
                snapshot_id=index.index_id,
            )
            self._create_gate(
                run_id=checkpoint.run_id,
                value=None,
                decision=execution_failure,
            )
            validation_gate_id = execution_failure.decision_id
        else:
            validation_gate_id = validation_gate.decision.decision_id
            gated_validated, _consumed_validation = self._consume_stage_result(
                run_id=checkpoint.run_id,
                gate=validation_gate,
            )
            if not isinstance(gated_validated, _ValidatedMaterial):
                raise RuntimeError("strategy selection received the wrong validation gate")
            validated_batch = gated_validated.batch
            assessments = gated_validated.assessments
        strategy = self._controller.select_strategy(validated_batch)
        allowed = (
            () if strategy is Strategy.BATCH_INTEGRITY_HOLD else self._allowed_evidence(assessments)
        )
        plan, plan_diff = self._planner.build_plan(
            checkpoint.initial_plan,
            strategy,
            allowed,
            batch_integrity_valid=batch_integrity_valid,
            has_unavailable=bool(explicit_unavailable),
            mapper_disagreement=mapper_disagreement,
        )
        planning_decision = self._append_decision(
            ledger,
            run_id=checkpoint.run_id,
            stage=TrustStage.PLANNING,
            scope=TrustScope.BATCH,
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reasons=(ReasonCode.PLAN_SELECTED if plan.version == 1 else ReasonCode.PLAN_REVISED,),
            snapshot_id=index.index_id,
            evidence_ids=plan.allowed_evidence_ids,
            input_gate_ids=(validation_gate_id,),
        )
        plan_gate = self._create_gate(
            run_id=checkpoint.run_id,
            value=_FinalPlanInput(plan=plan, batch=validated_batch),
            decision=planning_decision,
            provenance_ids=plan.allowed_evidence_ids,
        )
        routes, final_report, corroboration_requests = self._execute_final_plan(
            run_id=checkpoint.run_id,
            ledger=checkpoint._ledger,
            completed_receipts=tuple(checkpoint._receipts),
            batch=validated_batch,
            plan=plan,
            plan_gate=plan_gate,
            initial_report=initial_report,
            plan_history=((plan,) if plan.version == 1 else (checkpoint.initial_plan, plan)),
        )
        plan_history: tuple[ExecutionPlan, ...] = (
            (plan,) if plan.version == 1 else (checkpoint.initial_plan, plan)
        )
        if not final_report.complete:
            # Preserve the failed attempt as execution evidence.  A revised
            # plan may remove only provisional commands that never started;
            # completed/failed commands remain in the v1 lineage.
            checkpoint._receipts.extend(final_report.receipts)
            attempted_command_ids = {receipt.command_id for receipt in final_report.receipts}
            execution_mode = ExecutionMode.FAILED_CLOSED
            strategy = Strategy.BATCH_INTEGRITY_HOLD
            rejected_plan = plan
            prior_diff = plan_diff
            if rejected_plan.version == 2:
                plan, plan_diff = self._planner.terminal_hold_plan(
                    rejected_plan,
                    cumulative_removed_command_ids=(
                        prior_diff.removed_command_ids if prior_diff is not None else ()
                    ),
                )
                plan_history = (checkpoint.initial_plan, rejected_plan, plan)
            else:
                plan, plan_diff = self._planner.build_plan(
                    checkpoint.initial_plan,
                    strategy,
                    (),
                    batch_integrity_valid=False,
                    has_unavailable=bool(explicit_unavailable),
                    mapper_disagreement=True,
                    extra_trigger=ReasonCode.PRE_RELEASE_BLOCKED,
                )
                plan_history = (checkpoint.initial_plan, plan)
            if plan_diff is not None and rejected_plan.version == 1:
                plan_diff = plan_diff.model_copy(
                    update={
                        "removed_command_ids": tuple(
                            command_id
                            for command_id in plan_diff.removed_command_ids
                            if command_id not in attempted_command_ids
                        )
                    }
                )
            validated_batch = validated_batch.model_copy(
                update={"batch_integrity_valid": False, "mapper_disagreement": True}
            )
            release_failure = self._append_decision(
                ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.PRE_RELEASE,
                scope=TrustScope.BATCH,
                state=TrustState.QUARANTINED,
                outcome=TrustOutcome.HOLD,
                reasons=(ReasonCode.PRE_RELEASE_BLOCKED,),
                snapshot_id=index.index_id,
                input_gate_ids=(validation_gate_id,),
            )
            self._create_gate(
                run_id=checkpoint.run_id,
                value=None,
                decision=release_failure,
            )
            blocked_planning = self._append_decision(
                ledger,
                run_id=checkpoint.run_id,
                stage=TrustStage.PLANNING,
                scope=TrustScope.BATCH,
                state=TrustState.USABLE,
                outcome=TrustOutcome.ALLOW,
                reasons=(ReasonCode.PLAN_REVISED, ReasonCode.PRE_RELEASE_BLOCKED),
                snapshot_id=index.index_id,
                input_gate_ids=(release_failure.decision_id,),
            )
            blocked_gate = self._create_gate(
                run_id=checkpoint.run_id,
                value=_FinalPlanInput(plan=plan, batch=validated_batch),
                decision=blocked_planning,
            )
            routes, final_report, corroboration_requests = self._execute_final_plan(
                run_id=checkpoint.run_id,
                ledger=checkpoint._ledger,
                completed_receipts=tuple(checkpoint._receipts),
                batch=validated_batch,
                plan=plan,
                plan_gate=blocked_gate,
                initial_report=initial_report,
                plan_history=plan_history,
            )
            if not final_report.complete:
                raise RuntimeError("trusted batch-hold plan could not be executed")
        checkpoint._receipts.extend(final_report.receipts)
        return self._complete_decision(
            checkpoint,
            assessments,
            strategy,
            plan,
            plan_diff,
            routes,
            ledger,
            execution_mode,
            tuple(checkpoint._receipts),
            corroboration_requests,
            plan_history,
        )

    def fail_closed(
        self,
        *,
        stage: TrustStage,
        reason: ReasonCode,
        checkpoint: RankingCheckpoint | None = None,
        run_id: str | None = None,
        failed_candidate_id: str | None = None,
        _prior_ledger: list[TrustDecision] | None = None,
        _append_failure: bool = True,
    ) -> RunDecision:
        valid = {
            TrustStage.RETRIEVAL: ReasonCode.RETRIEVAL_FAILED,
            TrustStage.SCHEMA: ReasonCode.SCHEMA_INVALID,
            TrustStage.PARSING: ReasonCode.PARSING_FAILED,
        }
        if valid.get(stage) is not reason:
            raise ValueError("fail-closed stage and reason are inconsistent")
        if checkpoint is None:
            selected_run_id = run_id or f"run-{uuid4().hex[:12]}"
            if selected_run_id not in self._stage_vaults:
                self._stage_vaults[selected_run_id] = StageVault(selected_run_id)
            batch_id = "untrusted-batch"
            snapshot_id = "untrusted-index"
            ledger = list(_prior_ledger or ())
            candidates: tuple[ValidatedCandidateEvidence, ...] = ()
            initial_plan = self._planner.hold_plan(reason)
            plan = initial_plan
            plan_diff = None
            completed_receipts: tuple[StepReceipt, ...] = ()
        else:
            if run_id is not None and run_id != checkpoint.run_id:
                raise ValueError("run_id does not match checkpoint")
            self._consume_checkpoint(checkpoint)
            selected_run_id = checkpoint.run_id
            batch_id = checkpoint.index.batch_id
            snapshot_id = checkpoint.index.index_id
            ledger = checkpoint._ledger
            candidates = tuple(
                self._validator.empty_candidate(
                    entry.candidate_id,
                    checkpoint.index.index_id,
                    TrustState.QUARANTINED,
                    (ReasonCode.BATCH_HOLD_REQUIRED,),
                )
                for entry in checkpoint.index.candidates
            )
            initial_plan = checkpoint.initial_plan
            plan, plan_diff = self._planner.build_plan(
                initial_plan,
                Strategy.BATCH_INTEGRITY_HOLD,
                (),
                batch_integrity_valid=False,
                has_unavailable=False,
                mapper_disagreement=True,
                extra_trigger=reason,
            )
            if not checkpoint._receipts:
                failed_prefix = self._executor.execute(
                    checkpoint.initial_plan,
                    {},
                    vault=checkpoint._vault,
                    root_gate=checkpoint._initial_plan_gate,
                    stop_after=(
                        PlanStep.VALIDATE_CANDIDATE_EVIDENCE
                        if checkpoint.index_valid
                        else PlanStep.VALIDATE_INDEX_COMMITMENTS
                    ),
                    on_gate_consumed=lambda gate: self._emit_gate_consumed(checkpoint.run_id, gate),
                )
                checkpoint._receipts.extend(failed_prefix.receipts)
            completed_receipts = tuple(checkpoint._receipts)
        if _append_failure:
            self._append_decision(
                ledger,
                run_id=selected_run_id,
                stage=stage,
                scope=TrustScope.RECORD if failed_candidate_id else TrustScope.BATCH,
                state=(
                    TrustState.UNAVAILABLE
                    if stage is TrustStage.RETRIEVAL
                    else TrustState.QUARANTINED
                ),
                outcome=TrustOutcome.HOLD,
                reasons=(reason,),
                candidate_id=failed_candidate_id,
                snapshot_id=snapshot_id,
            )
        batch = ValidatedBatchEvidence(
            batch_id=batch_id,
            snapshot_id=snapshot_id,
            candidates=candidates,
            unavailable_candidate_ids=(),
            batch_integrity_valid=False,
            mapper_disagreement=True,
        )
        planning_decision = self._append_decision(
            ledger,
            run_id=selected_run_id,
            stage=TrustStage.PLANNING,
            scope=TrustScope.BATCH,
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reasons=(ReasonCode.PLAN_SELECTED, reason),
            snapshot_id=snapshot_id,
            input_gate_ids=(ledger[-1].decision_id,) if ledger else (),
        )
        plan_gate = self._create_gate(
            run_id=selected_run_id,
            value=_FinalPlanInput(plan=plan, batch=batch),
            decision=planning_decision,
        )
        routes, final_report, corroboration = self._execute_final_plan(
            run_id=selected_run_id,
            ledger=ledger,
            completed_receipts=completed_receipts,
            batch=batch,
            plan=plan,
            plan_gate=plan_gate,
            initial_report=None,
            plan_history=(initial_plan,) if plan.version == 1 else (initial_plan, plan),
        )
        if not final_report.complete:
            raise RuntimeError("trusted fail-closed release plan could not execute")
        receipts = (*completed_receipts, *final_report.receipts)
        plans = (plan,) if plan.version == 1 else (initial_plan, plan)
        decision = RunDecision(
            run_id=selected_run_id,
            batch_id=batch_id,
            snapshot_id=snapshot_id,
            strategy=Strategy.BATCH_INTEGRITY_HOLD,
            ranking_scope=RankingScope.NONE,
            plans=plans,
            plan=plan,
            plan_diff=plan_diff,
            execution_mode=ExecutionMode.FAILED_CLOSED,
            step_receipts=receipts,
            corroboration_requests=corroboration,
            support_graph_hash=compute_support_graph_hash(routes),
            batch_state=TrustState.QUARANTINED,
            routes=routes,
            trust_ledger=tuple(ledger),
            explanations=(
                DecisionExplanation(
                    template=ExplanationTemplate.BATCH_HELD,
                    message=(
                        f"The run failed closed at {stage.value}; unavailable or untrusted input "
                        "was not released into an evidence ranking."
                    ),
                    candidate_id=failed_candidate_id,
                    reason_codes=(reason,),
                ),
            ),
        )
        self._emit_completion(decision)
        self._stage_vaults.pop(selected_run_id, None)
        return decision

    def _execute_final_plan(
        self,
        *,
        run_id: str,
        ledger: list[TrustDecision],
        completed_receipts: tuple[StepReceipt, ...],
        batch: ValidatedBatchEvidence,
        plan: ExecutionPlan,
        plan_gate: StageHandle,
        initial_report: ExecutionReport | None,
        plan_history: tuple[ExecutionPlan, ...],
    ) -> tuple[
        tuple[CandidateRoute, ...],
        ExecutionReport,
        tuple[CorroborationRequest, ...],
    ]:
        vault = self._stage_vaults[run_id]
        if not vault.is_available(plan_gate):
            raise ValueError("final plan gate is unavailable to the first final command")
        states: list[_FinalWorkflowState] = []

        def input_state(
            dependencies: tuple[StageInput, ...],
        ) -> tuple[_FinalWorkflowState, tuple[str, ...]]:
            if not dependencies:
                return _FinalWorkflowState(batch=batch), ()
            values, gate_ids = self._consume_command_dependencies(
                run_id=run_id,
                dependencies=dependencies,
            )
            if len(values) != 1:
                raise RuntimeError("final workflow dependency is invalid")
            value = values[0]
            if isinstance(value, _FinalPlanInput):
                if value.plan != plan or value.batch != batch:
                    raise RuntimeError("final plan input does not match selected plan")
                return _FinalWorkflowState(batch=value.batch), gate_ids
            if not isinstance(value, _FinalWorkflowState):
                raise RuntimeError("final workflow dependency is invalid")
            return value, gate_ids

        def quarantine_handler(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            state, gate_ids = input_state(dependencies)
            if not any(
                candidate.trust_state in {TrustState.QUARANTINED, TrustState.UNAVAILABLE}
                for candidate in batch.candidates
            ):
                raise RuntimeError("quarantine command has no restricted candidate")
            states.append(state)
            return self._command_result(
                ledger,
                run_id=run_id,
                stage=TrustStage.PROVENANCE,
                value=state,
                snapshot_id=batch.snapshot_id,
                consumed_gate_ids=gate_ids,
                reasons=(ReasonCode.RECORD_QUARANTINED,),
            )

        def pending_handler(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            state, gate_ids = input_state(dependencies)
            if not batch.unavailable_candidate_ids:
                raise RuntimeError("pending-evidence command has no unavailable candidate")
            states.append(state)
            return self._command_result(
                ledger,
                run_id=run_id,
                stage=TrustStage.RETRIEVAL,
                value=state,
                snapshot_id=batch.snapshot_id,
                consumed_gate_ids=gate_ids,
                reasons=(ReasonCode.CANDIDATE_UNAVAILABLE,),
            )

        def rank_handler(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            state, gate_ids = input_state(dependencies)
            routes = self._controller.rank(batch, plan.strategy)
            updated = _FinalWorkflowState(
                batch=state.batch,
                routes=routes,
                corroboration_requests=state.corroboration_requests,
            )
            states.append(updated)
            rank_reason = {
                Strategy.FULL_EVIDENCE_RANKING: ReasonCode.RANKING_ALLOWED,
                Strategy.SUPPORTED_ONLY_RANKING: ReasonCode.RANKING_RESTRICTED,
                Strategy.PARTIAL_SAFE_RANKING: ReasonCode.RANKING_PARTIAL,
                Strategy.BATCH_INTEGRITY_HOLD: ReasonCode.RANKING_HELD,
            }[plan.strategy]
            return self._command_result(
                ledger,
                run_id=run_id,
                stage=TrustStage.RANKING,
                value=updated,
                snapshot_id=batch.snapshot_id,
                consumed_gate_ids=gate_ids,
                evidence_ids=plan.allowed_evidence_ids,
                reasons=(rank_reason,),
            )

        def isolate_handler(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            state, gate_ids = input_state(dependencies)
            routes = DecisionController().rank(batch, Strategy.BATCH_INTEGRITY_HOLD)
            updated = _FinalWorkflowState(batch=state.batch, routes=routes)
            states.append(updated)
            return self._command_result(
                ledger,
                run_id=run_id,
                stage=TrustStage.RANKING,
                value=updated,
                snapshot_id=batch.snapshot_id,
                consumed_gate_ids=gate_ids,
                reasons=(ReasonCode.RANKING_HELD, ReasonCode.BATCH_HOLD_REQUIRED),
            )

        def corroboration_handler(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            state, gate_ids = input_state(dependencies)
            candidate_ids = tuple(
                sorted(
                    {
                        *batch.unavailable_candidate_ids,
                        *(
                            candidate.candidate_id
                            for candidate in batch.candidates
                            if candidate.trust_state
                            in {TrustState.QUARANTINED, TrustState.UNAVAILABLE}
                        ),
                    }
                )
            )
            request = CorroborationRequest(
                request_id=f"corroborate:{batch.snapshot_id}",
                candidate_ids=candidate_ids,
                reason_codes=(ReasonCode.CORROBORATION_REQUIRED,),
                requested_evidence_kinds=(ClaimKind.CANDIDATE_ID, ClaimKind.AP_YEARS),
            )
            updated = _FinalWorkflowState(
                batch=state.batch,
                routes=state.routes,
                corroboration_requests=(*state.corroboration_requests, request),
            )
            states.append(updated)
            return self._command_result(
                ledger,
                run_id=run_id,
                stage=TrustStage.PLANNING,
                value=updated,
                snapshot_id=batch.snapshot_id,
                consumed_gate_ids=gate_ids,
                reasons=(ReasonCode.CORROBORATION_REQUIRED,),
            )

        def authorize_handler(
            _command: PlanCommand,
            receipts_so_far: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            state, gate_ids = input_state(dependencies)
            if not state.routes and plan.strategy is not Strategy.BATCH_INTEGRITY_HOLD:
                raise RuntimeError("ranking command did not produce candidate routes")
            result = self._authorizer.authorize(
                batch,
                state.routes,
                plan,
                (*completed_receipts, *receipts_so_far),
                trust_ledger=ledger,
                plan_history=plan_history,
            )
            if not result.authorized:
                raise RuntimeError("release authorization failed")
            updated = _FinalWorkflowState(
                batch=state.batch,
                routes=state.routes,
                corroboration_requests=state.corroboration_requests,
                authorized=True,
            )
            states.append(updated)
            return self._command_result(
                ledger,
                run_id=run_id,
                stage=TrustStage.PRE_RELEASE,
                value=updated,
                snapshot_id=batch.snapshot_id,
                consumed_gate_ids=gate_ids,
                evidence_ids=plan.allowed_evidence_ids,
                reasons=result.reason_codes,
            )

        def release_handler(
            _command: PlanCommand,
            _receipts: tuple[StepReceipt, ...],
            dependencies: tuple[StageInput, ...],
        ) -> CommandResult:
            state, gate_ids = input_state(dependencies)
            if not state.authorized:
                raise RuntimeError("release command lacks authorization")
            updated = _FinalWorkflowState(
                batch=state.batch,
                routes=state.routes,
                corroboration_requests=state.corroboration_requests,
                authorized=True,
                released=True,
            )
            states.append(updated)
            return self._command_result(
                ledger,
                run_id=run_id,
                stage=TrustStage.RELEASE,
                value=updated,
                snapshot_id=batch.snapshot_id,
                consumed_gate_ids=gate_ids,
                evidence_ids=plan.allowed_evidence_ids,
                reasons=(ReasonCode.RELEASE_AUTHORIZED,),
            )

        handlers: dict[PlanStep, CommandHandler] = {
            PlanStep.QUARANTINE_UNSUPPORTED: quarantine_handler,
            PlanStep.MARK_EVIDENCE_PENDING: pending_handler,
            PlanStep.RANK_FULL_EVIDENCE: rank_handler,
            PlanStep.RANK_SUPPORTED_EVIDENCE: rank_handler,
            PlanStep.RANK_PARTIAL_EVIDENCE: rank_handler,
            PlanStep.ISOLATE_BATCH: isolate_handler,
            PlanStep.REQUEST_CORROBORATION: corroboration_handler,
            PlanStep.PRE_RELEASE_AUDIT: authorize_handler,
            PlanStep.RELEASE_OUTPUT: release_handler,
        }
        report = self._executor.execute(
            plan,
            handlers,
            vault=vault,
            start_sequence=len(completed_receipts) + 1,
            root_gate=plan_gate,
            prior_report=initial_report if plan.version == 1 else None,
            start_after=(
                PlanStep.VALIDATE_CANDIDATE_EVIDENCE
                if plan.version == 1 and initial_report is not None
                else None
            ),
            on_gate_consumed=lambda gate: self._emit_gate_consumed(run_id, gate),
        )
        final_state = states[-1] if states else _FinalWorkflowState(batch=batch)
        if report.complete and not final_state.released:
            raise RuntimeError("completed final plan did not execute the release command")
        return final_state.routes, report, final_state.corroboration_requests

    def _complete_decision(
        self,
        checkpoint: RankingCheckpoint,
        assessments: Mapping[str, CandidateAssessment],
        strategy: Strategy,
        plan: ExecutionPlan,
        plan_diff: PlanDiff | None,
        routes: tuple[CandidateRoute, ...],
        ledger: list[TrustDecision],
        execution_mode: ExecutionMode,
        step_receipts: tuple[StepReceipt, ...],
        corroboration_requests: tuple[CorroborationRequest, ...],
        plan_history: tuple[ExecutionPlan, ...],
    ) -> RunDecision:
        state, _ = self._strategy_trust(strategy)
        ranking_scope = (
            RankingScope.COMPLETE
            if strategy is Strategy.FULL_EVIDENCE_RANKING
            else RankingScope.NONE
            if strategy is Strategy.BATCH_INTEGRITY_HOLD
            else RankingScope.PARTIAL
        )
        decision = RunDecision(
            run_id=checkpoint.run_id,
            batch_id=checkpoint.index.batch_id,
            snapshot_id=checkpoint.index.index_id,
            strategy=strategy,
            ranking_scope=ranking_scope,
            plans=plan_history,
            plan=plan,
            plan_diff=plan_diff,
            execution_mode=execution_mode,
            step_receipts=step_receipts,
            corroboration_requests=corroboration_requests,
            support_graph_hash=compute_support_graph_hash(routes),
            batch_state=state,
            routes=routes,
            trust_ledger=tuple(ledger),
            explanations=self._render_explanations(assessments, strategy),
        )
        self._emit_completion(decision)
        self._stage_vaults.pop(checkpoint.run_id, None)
        return decision

    def _render_explanations(
        self,
        assessments: Mapping[str, CandidateAssessment],
        strategy: Strategy,
    ) -> tuple[DecisionExplanation, ...]:
        explanations: list[DecisionExplanation] = []
        for assessment in assessments.values():
            candidate = assessment.evidence
            if candidate.trust_state is TrustState.UNAVAILABLE:
                explanations.append(
                    DecisionExplanation(
                        template=ExplanationTemplate.CANDIDATE_UNAVAILABLE,
                        candidate_id=candidate.candidate_id,
                        message=(
                            f"{candidate.candidate_id}: detail or resume evidence was unavailable; "
                            "the candidate has no evidence rank and remains pending."
                        ),
                        reason_codes=candidate.reason_codes,
                    )
                )
            elif candidate.trust_state is TrustState.QUARANTINED:
                if assessment.conflicts:
                    conflict = assessment.conflicts[0]
                    expected = safe_conflict_value(conflict.kind, conflict.expected)
                    observed = safe_conflict_value(conflict.kind, conflict.observed)
                    source = safe_evidence_source_label(conflict.source_kinds)
                    evidence_id = conflict.evidence_ids[0][:80]
                    message = (
                        f"{candidate.candidate_id}: {conflict.snapshot_id} structured "
                        f"{conflict.kind.value}={expected} conflicts with {source} "
                        f"{evidence_id} value={observed}; the record has no evidence rank."
                    )
                else:
                    message = (
                        f"{candidate.candidate_id}: evidence provenance or an index commitment "
                        "failed; the record has no evidence rank."
                    )
                explanations.append(
                    DecisionExplanation(
                        template=ExplanationTemplate.RECORD_QUARANTINED,
                        candidate_id=candidate.candidate_id,
                        message=message,
                        reason_codes=candidate.reason_codes,
                    )
                )
            elif candidate.trust_state is TrustState.DEGRADED:
                explanations.append(
                    DecisionExplanation(
                        template=ExplanationTemplate.RECORD_DEGRADED,
                        candidate_id=candidate.candidate_id,
                        message=(
                            f"{candidate.candidate_id}: only corroborated fields contribute to "
                            "the transparent evidence-strength rank."
                        ),
                        reason_codes=candidate.reason_codes,
                    )
                )
        if strategy is Strategy.BATCH_INTEGRITY_HOLD:
            explanations.append(
                DecisionExplanation(
                    template=ExplanationTemplate.BATCH_HELD,
                    message=(
                        "The batch is isolated pending corroboration; no evidence ranking or "
                        "automated hiring outcome was released."
                    ),
                    reason_codes=(ReasonCode.BATCH_HOLD_REQUIRED,),
                )
            )
        return tuple(explanations)

    @staticmethod
    def _strategy_trust(strategy: Strategy) -> tuple[TrustState, TrustOutcome]:
        if strategy is Strategy.FULL_EVIDENCE_RANKING:
            return TrustState.USABLE, TrustOutcome.ALLOW
        if strategy is Strategy.BATCH_INTEGRITY_HOLD:
            return TrustState.QUARANTINED, TrustOutcome.HOLD
        return TrustState.DEGRADED, TrustOutcome.RESTRICT

    @staticmethod
    def _allowed_evidence(
        assessments: Mapping[str, CandidateAssessment],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    item
                    for assessment in assessments.values()
                    if assessment.evidence.trust_state
                    not in {TrustState.QUARANTINED, TrustState.UNAVAILABLE}
                    for item in assessment.evidence.evidence_ids
                }
            )
        )

    def _consume_checkpoint(self, checkpoint: RankingCheckpoint) -> None:
        if checkpoint._owner_token is not self._checkpoint_token:
            raise ValueError("checkpoint belongs to a different engine")
        checkpoint_id = id(checkpoint)
        if checkpoint_id not in self._open_checkpoints:
            raise ValueError("checkpoint was already completed")
        self._open_checkpoints.remove(checkpoint_id)

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
    ) -> TrustDecision:
        decision = TrustDecision(
            decision_id=f"td:{run_id}:{len(ledger) + 1}",
            stage=stage,
            scope=scope,
            state=state,
            outcome=outcome,
            reason_codes=reasons,
            candidate_id=candidate_id,
            snapshot_id=snapshot_id,
            evidence_ids=evidence_ids,
            input_gate_ids=input_gate_ids,
            evidence_inventory=evidence_inventory,
        )
        ledger.append(decision)
        self._emit(
            TraceEvent(
                event_type="trust.decision",
                run_id=run_id,
                emitted_at=datetime.now(UTC),
                stage=stage,
                candidate_id=candidate_id,
                snapshot_id=snapshot_id,
                state=state,
                reason_codes=reasons,
            )
        )
        return decision

    def _consume_gate(
        self,
        *,
        run_id: str,
        value: Any,
        decision: TrustDecision,
        provenance_ids: tuple[str, ...] = (),
    ) -> Any | None:
        gate = self._create_gate(
            run_id=run_id,
            value=(
                value if decision.outcome in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT} else None
            ),
            provenance_ids=provenance_ids,
            decision=decision,
        )
        if decision.outcome not in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}:
            return None
        consumed_value, _handle = self._consume_stage_result(run_id=run_id, gate=gate)
        return consumed_value

    def _create_gate(
        self,
        *,
        run_id: str,
        value: Any,
        decision: TrustDecision,
        provenance_ids: tuple[str, ...] = (),
    ) -> StageHandle:
        vault = self._stage_vaults.get(run_id)
        if vault is None:
            raise ValueError("run has no stage vault")
        gate = vault.create(decision=decision, value=value, provenance_ids=provenance_ids)
        self._emit(
            TraceEvent(
                event_type="gate.created",
                run_id=run_id,
                emitted_at=datetime.now(UTC),
                stage=decision.stage,
                candidate_id=decision.candidate_id,
                snapshot_id=decision.snapshot_id,
                gate_id=decision.decision_id,
                state=decision.state,
                reason_codes=decision.reason_codes,
            )
        )
        return gate

    def _consume_stage_result(
        self,
        *,
        run_id: str,
        gate: StageHandle,
    ) -> tuple[Any, StageHandle]:
        vault = self._stage_vaults.get(run_id)
        if vault is None:
            raise ValueError("run has no stage vault")
        consumed_value = vault.consume(gate).value
        self._emit_gate_consumed(run_id, gate)
        return consumed_value, gate

    def _emit_gate_consumed(self, run_id: str, gate: StageHandle) -> None:
        self._emit(
            TraceEvent(
                event_type="gate.consumed",
                run_id=run_id,
                emitted_at=datetime.now(UTC),
                stage=gate.decision.stage,
                candidate_id=gate.decision.candidate_id,
                snapshot_id=gate.decision.snapshot_id,
                gate_id=gate.decision.decision_id,
                state=gate.decision.state,
                reason_codes=gate.decision.reason_codes,
            )
        )

    def _consume_command_dependencies(
        self,
        *,
        run_id: str,
        dependencies: tuple[StageInput, ...],
    ) -> tuple[tuple[Any, ...], tuple[str, ...]]:
        values: list[Any] = []
        gate_ids: list[str] = []
        for dependency in dependencies:
            gate = dependency.handle
            values.append(dependency.value)
            gate_ids.append(gate.handle_id)
        return tuple(values), tuple(gate_ids)

    def _command_result(
        self,
        ledger: list[TrustDecision],
        *,
        run_id: str,
        stage: TrustStage,
        value: Any,
        snapshot_id: str,
        consumed_gate_ids: tuple[str, ...] = (),
        evidence_ids: tuple[str, ...] = (),
        reasons: tuple[ReasonCode, ...] = (ReasonCode.COMMAND_COMPLETED,),
    ) -> CommandResult:
        decision = self._append_decision(
            ledger,
            run_id=run_id,
            stage=stage,
            scope=TrustScope.BATCH,
            state=TrustState.USABLE,
            outcome=TrustOutcome.ALLOW,
            reasons=reasons,
            snapshot_id=snapshot_id,
            evidence_ids=evidence_ids,
            input_gate_ids=consumed_gate_ids,
        )
        return CommandResult(
            stage_handle=self._create_gate(
                run_id=run_id,
                value=value,
                decision=decision,
                provenance_ids=evidence_ids,
            ),
            evidence_ids=evidence_ids,
            reason_codes=reasons,
        )

    def _deferred_fan_in_command_result(
        self,
        ledger: list[TrustDecision],
        *,
        run_id: str,
        stage: TrustStage,
        value: Any,
        snapshot_id: str,
        fan_in_handles: tuple[StageHandle, ...],
        evidence_ids: tuple[str, ...] = (),
        reasons: tuple[ReasonCode, ...] = (ReasonCode.COMMAND_COMPLETED,),
    ) -> CommandResult:
        """Create a batch gate only after the executor closes the exact fan-in."""

        def create_stage(consumed_gate_ids: tuple[str, ...]) -> StageHandle:
            decision = self._append_decision(
                ledger,
                run_id=run_id,
                stage=stage,
                scope=TrustScope.BATCH,
                state=TrustState.USABLE,
                outcome=TrustOutcome.ALLOW,
                reasons=reasons,
                snapshot_id=snapshot_id,
                evidence_ids=evidence_ids,
                input_gate_ids=consumed_gate_ids,
            )
            return self._create_gate(
                run_id=run_id,
                value=value,
                decision=decision,
                provenance_ids=evidence_ids,
            )

        return CommandResult(
            deferred_stage_factory=create_stage,
            fan_in_handles=fan_in_handles,
            evidence_ids=evidence_ids,
            reason_codes=reasons,
        )

    def _emit_completion(self, decision: RunDecision) -> None:
        self._emit(
            TraceEvent(
                event_type="plan.selected",
                run_id=decision.run_id,
                emitted_at=datetime.now(UTC),
                stage=TrustStage.PLANNING,
                snapshot_id=decision.snapshot_id,
                state=decision.batch_state,
                attributes=sanitized_attributes(
                    strategy=decision.strategy.value,
                    plan_version=decision.plan.version,
                    ranking_scope=decision.ranking_scope.value,
                ),
            )
        )
        self._emit(
            TraceEvent(
                event_type="run.completed",
                run_id=decision.run_id,
                emitted_at=datetime.now(UTC),
                snapshot_id=decision.snapshot_id,
                state=decision.batch_state,
                attributes=sanitized_attributes(
                    strategy=decision.strategy.value,
                    ranked_count=sum(route.evidence_rank is not None for route in decision.routes),
                    excluded_count=sum(route.evidence_rank is None for route in decision.routes),
                ),
            )
        )

    def _emit(self, event: TraceEvent) -> None:
        self._telemetry.emit(event)
