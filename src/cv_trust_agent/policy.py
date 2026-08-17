"""Trusted ranking and finite-plan policy over validated evidence only.

This module is deliberately a leaf: policy consumes typed models and cannot
retrieve source content, invoke a mapper, execute commands, or authorize its
own output release.
"""

from __future__ import annotations

from collections.abc import Sequence

from cv_trust_agent.models import (
    CandidateRoute,
    EvidenceRankKey,
    ExecutionPlan,
    PlanCommand,
    PlanDiff,
    PlanObjective,
    PlanStep,
    ProhibitedAction,
    ReasonCode,
    ReviewBand,
    ReviewQueue,
    Strategy,
    TrustState,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)

BASE_PROHIBITIONS = (
    ProhibitedAction.AUTOMATED_HIRE,
    ProhibitedAction.AUTOMATED_REJECT,
    ProhibitedAction.EXECUTE_SOURCE_INSTRUCTIONS,
    ProhibitedAction.USE_RAW_SOURCE_TEXT,
    ProhibitedAction.USE_PROTECTED_ATTRIBUTES,
    ProhibitedAction.RANK_QUARANTINED_EVIDENCE,
    ProhibitedAction.RANK_UNAVAILABLE_CANDIDATE,
)


class DecisionController:
    """Finite ranking policy over validated evidence only."""

    def select_strategy(self, batch: ValidatedBatchEvidence) -> Strategy:
        states = {candidate.trust_state for candidate in batch.candidates}
        rankable = [
            candidate
            for candidate in batch.candidates
            if candidate.trust_state not in {TrustState.QUARANTINED, TrustState.UNAVAILABLE}
        ]
        has_unavailable = bool(batch.unavailable_candidate_ids)
        local_restriction = batch.mapper_disagreement or bool(
            states.intersection(
                {TrustState.DEGRADED, TrustState.QUARANTINED, TrustState.UNAVAILABLE}
            )
        )
        if (
            not batch.batch_integrity_valid
            or not rankable
            or (has_unavailable and batch.mapper_disagreement)
        ):
            return Strategy.BATCH_INTEGRITY_HOLD
        if has_unavailable:
            return Strategy.PARTIAL_SAFE_RANKING
        if local_restriction:
            return Strategy.SUPPORTED_ONLY_RANKING
        return Strategy.FULL_EVIDENCE_RANKING

    def rank(
        self,
        batch: ValidatedBatchEvidence,
        strategy: Strategy,
    ) -> tuple[CandidateRoute, ...]:
        if strategy is Strategy.BATCH_INTEGRITY_HOLD:
            return tuple(
                CandidateRoute(
                    candidate_id=candidate.candidate_id,
                    snapshot_id=batch.snapshot_id,
                    band=ReviewBand.INTEGRITY_HOLD,
                    queue=ReviewQueue.BATCH_INTEGRITY_HOLD,
                    reason_codes=(ReasonCode.BATCH_HOLD_REQUIRED,),
                )
                for candidate in sorted(batch.candidates, key=lambda item: item.candidate_id)
            )

        ranked: list[
            tuple[ValidatedCandidateEvidence, ReviewBand, ReviewQueue, EvidenceRankKey]
        ] = []
        excluded: list[CandidateRoute] = []
        unavailable_ids = set(batch.unavailable_candidate_ids)
        for candidate in batch.candidates:
            if candidate.trust_state is TrustState.UNAVAILABLE or (
                candidate.candidate_id in unavailable_ids
            ):
                excluded.append(
                    CandidateRoute(
                        candidate_id=candidate.candidate_id,
                        snapshot_id=batch.snapshot_id,
                        band=ReviewBand.EVIDENCE_UNAVAILABLE,
                        queue=ReviewQueue.EVIDENCE_PENDING,
                        reason_codes=candidate.reason_codes or (ReasonCode.CANDIDATE_UNAVAILABLE,),
                    )
                )
                continue
            if candidate.trust_state is TrustState.QUARANTINED:
                excluded.append(
                    CandidateRoute(
                        candidate_id=candidate.candidate_id,
                        snapshot_id=batch.snapshot_id,
                        band=ReviewBand.INTEGRITY_HOLD,
                        queue=ReviewQueue.INTEGRITY_REVIEW,
                        reason_codes=candidate.reason_codes or (ReasonCode.RECORD_QUARANTINED,),
                    )
                )
                continue
            band, queue = self._evidence_band(candidate)
            ranked.append((candidate, band, queue, self._rank_key(candidate, band)))

        ranked.sort(
            key=lambda item: (
                -item[3].band_priority,
                -item[3].essentials_count,
                -item[3].preferred_count,
                -item[3].corroborated_claim_count,
                item[0].candidate_id,
            )
        )
        routes: list[CandidateRoute] = []
        dense_rank = 0
        previous_key: tuple[int, int, int, int] | None = None
        for position, (candidate, band, queue, rank_key) in enumerate(ranked, start=1):
            key = rank_key.as_tuple()
            if key != previous_key:
                dense_rank += 1
                previous_key = key
            routes.append(
                CandidateRoute(
                    candidate_id=candidate.candidate_id,
                    snapshot_id=batch.snapshot_id,
                    band=band,
                    queue=queue,
                    evidence_rank=dense_rank,
                    display_position=position,
                    rank_key=rank_key,
                    reason_codes=candidate.reason_codes,
                    evidence_ids=candidate.evidence_ids,
                    support_graph=candidate.support_graph,
                )
            )
        return tuple((*routes, *sorted(excluded, key=lambda item: item.candidate_id)))

    @staticmethod
    def _evidence_band(
        candidate: ValidatedCandidateEvidence,
    ) -> tuple[ReviewBand, ReviewQueue]:
        essentials = DecisionController._essentials_count(candidate)
        preferred = DecisionController._preferred_count(candidate) > 0
        if essentials == 4 and preferred:
            return ReviewBand.STRONG_EVIDENCE_MATCH, ReviewQueue.PRIORITY_HUMAN_REVIEW
        if essentials == 3 or (essentials == 4 and not preferred):
            return ReviewBand.POTENTIAL_EVIDENCE_MATCH, ReviewQueue.STANDARD_HUMAN_REVIEW
        return ReviewBand.INSUFFICIENT_SUPPORTED_EVIDENCE, ReviewQueue.EVIDENCE_CHECK

    @staticmethod
    def _rank_key(candidate: ValidatedCandidateEvidence, band: ReviewBand) -> EvidenceRankKey:
        band_priority = {
            ReviewBand.STRONG_EVIDENCE_MATCH: 2,
            ReviewBand.POTENTIAL_EVIDENCE_MATCH: 1,
            ReviewBand.INSUFFICIENT_SUPPORTED_EVIDENCE: 0,
        }[band]
        return EvidenceRankKey(
            band_priority=band_priority,
            essentials_count=DecisionController._essentials_count(candidate),
            preferred_count=DecisionController._preferred_count(candidate),
            corroborated_claim_count=len(candidate.corroborated_claim_kinds),
        )

    @staticmethod
    def _essentials_count(candidate: ValidatedCandidateEvidence) -> int:
        return sum(
            (
                candidate.invoice_processing is True,
                candidate.reconciliation is True,
                candidate.spreadsheet_supported,
                candidate.accounting_platform_supported,
            )
        )

    @staticmethod
    def _preferred_count(candidate: ValidatedCandidateEvidence) -> int:
        return sum(
            (
                candidate.ap_years is not None and candidate.ap_years >= 2.0,
                candidate.monthly_invoice_volume is not None
                and candidate.monthly_invoice_volume >= 300,
                candidate.qualification_supported,
            )
        )


class ExecutionPlanner:
    """Materialize only the repository's closed, trusted command graphs."""

    @staticmethod
    def initial_plan(index_valid: bool) -> ExecutionPlan:
        if not index_valid:
            return ExecutionPlan(
                version=1,
                objective=PlanObjective.HOLD_BATCH_FOR_INTEGRITY_REVIEW,
                strategy=Strategy.BATCH_INTEGRITY_HOLD,
                commands=ExecutionPlanner._commands(
                    1,
                    (PlanStep.VALIDATE_INDEX_COMMITMENTS,),
                ),
                trigger_codes=(ReasonCode.MANIFEST_CONFLICT,),
                prohibited_actions=(
                    *BASE_PROHIBITIONS,
                    ProhibitedAction.RELEASE_FINAL_QUALIFICATION_DECISION,
                ),
            )
        return ExecutionPlan(
            version=1,
            objective=PlanObjective.RANK_FULL_CORROBORATED_EVIDENCE,
            strategy=Strategy.FULL_EVIDENCE_RANKING,
            commands=ExecutionPlanner._commands(
                1,
                (
                    PlanStep.FETCH_CANDIDATE_DETAILS,
                    PlanStep.VALIDATE_CANDIDATE_DETAILS,
                    PlanStep.FETCH_CANDIDATE_RESUMES,
                    PlanStep.PARSE_CANDIDATE_RESUMES,
                    PlanStep.VALIDATE_CANDIDATE_BINDINGS,
                    PlanStep.MAP_CANDIDATE_CLAIMS,
                    PlanStep.VALIDATE_CANDIDATE_EVIDENCE,
                    PlanStep.RANK_FULL_EVIDENCE,
                    PlanStep.PRE_RELEASE_AUDIT,
                    PlanStep.RELEASE_OUTPUT,
                ),
            ),
            trigger_codes=(ReasonCode.INDEX_VALID,),
            prohibited_actions=BASE_PROHIBITIONS,
        )

    @staticmethod
    def hold_plan(reason: ReasonCode) -> ExecutionPlan:
        return ExecutionPlan(
            version=1,
            objective=PlanObjective.HOLD_BATCH_FOR_INTEGRITY_REVIEW,
            strategy=Strategy.BATCH_INTEGRITY_HOLD,
            commands=ExecutionPlanner._commands(
                1,
                (
                    PlanStep.ISOLATE_BATCH,
                    PlanStep.REQUEST_CORROBORATION,
                    PlanStep.PRE_RELEASE_AUDIT,
                    PlanStep.RELEASE_OUTPUT,
                ),
            ),
            trigger_codes=(reason,),
            prohibited_actions=(
                *BASE_PROHIBITIONS,
                ProhibitedAction.RELEASE_FINAL_QUALIFICATION_DECISION,
            ),
        )

    def build_plan(
        self,
        initial: ExecutionPlan,
        strategy: Strategy,
        allowed: tuple[str, ...],
        *,
        batch_integrity_valid: bool,
        has_unavailable: bool,
        mapper_disagreement: bool,
        extra_trigger: ReasonCode | None = None,
    ) -> tuple[ExecutionPlan, PlanDiff | None]:
        objective, steps, prohibitions = self._plan_policy(strategy)
        commands = self._commands(2, steps)
        triggers: set[ReasonCode] = set()
        if not batch_integrity_valid:
            triggers.add(ReasonCode.INDEX_CONFLICT)
        if has_unavailable:
            triggers.add(ReasonCode.CANDIDATE_UNAVAILABLE)
        if mapper_disagreement:
            triggers.add(ReasonCode.MAPPER_DISAGREEMENT)
        if extra_trigger is not None:
            triggers.add(extra_trigger)
        if not triggers:
            triggers.add(ReasonCode.EVIDENCE_ADMISSIBLE)
        if (
            initial.strategy is Strategy.FULL_EVIDENCE_RANKING
            and strategy is Strategy.FULL_EVIDENCE_RANKING
            and batch_integrity_valid
            and not has_unavailable
            and not mapper_disagreement
            and extra_trigger is None
        ):
            return initial.model_copy(update={"allowed_evidence_ids": allowed}), None
        plan = ExecutionPlan(
            version=2,
            objective=objective,
            strategy=strategy,
            commands=commands,
            trigger_codes=tuple(sorted(triggers, key=str)),
            allowed_evidence_ids=allowed,
            prohibited_actions=prohibitions,
        )
        diff = PlanDiff(
            from_version=1,
            to_version=2,
            strategy_before=initial.strategy,
            strategy_after=strategy,
            objective_before=initial.objective,
            objective_after=objective,
            trigger_codes=plan.trigger_codes,
            removed_command_ids=tuple(
                command.command_id
                for command in initial.commands
                if command.kind
                in {
                    PlanStep.RANK_FULL_EVIDENCE,
                    PlanStep.PRE_RELEASE_AUDIT,
                    PlanStep.RELEASE_OUTPUT,
                }
            ),
            added_commands=plan.commands,
            revoked_evidence_ids=tuple(
                sorted(set(initial.allowed_evidence_ids).difference(allowed))
            ),
            granted_evidence_ids=tuple(
                sorted(set(allowed).difference(initial.allowed_evidence_ids))
            ),
            added_prohibitions=tuple(
                item for item in plan.prohibited_actions if item not in initial.prohibited_actions
            ),
        )
        return plan, diff

    @staticmethod
    def terminal_hold_plan(
        rejected: ExecutionPlan,
        *,
        cumulative_removed_command_ids: tuple[str, ...],
    ) -> tuple[ExecutionPlan, PlanDiff]:
        """Create the one permitted terminal transition after a rejected v2 release."""

        if rejected.version != 2:
            raise ValueError("terminal hold is defined only for a rejected v2 plan")
        objective, steps, prohibitions = ExecutionPlanner._plan_policy(
            Strategy.BATCH_INTEGRITY_HOLD
        )
        plan = ExecutionPlan(
            version=3,
            objective=objective,
            strategy=Strategy.BATCH_INTEGRITY_HOLD,
            commands=ExecutionPlanner._commands(3, steps),
            trigger_codes=(ReasonCode.PRE_RELEASE_BLOCKED,),
            prohibited_actions=prohibitions,
        )
        diff = PlanDiff(
            from_version=2,
            to_version=3,
            strategy_before=rejected.strategy,
            strategy_after=Strategy.BATCH_INTEGRITY_HOLD,
            objective_before=rejected.objective,
            objective_after=objective,
            trigger_codes=plan.trigger_codes,
            # RunDecision keeps one public terminal diff. Preserve the earlier
            # v1 removals in that cumulative audit set so absent v1 commands
            # remain explicitly accounted for alongside the retained v2 receipts.
            removed_command_ids=cumulative_removed_command_ids,
            added_commands=plan.commands,
            revoked_evidence_ids=rejected.allowed_evidence_ids,
            added_prohibitions=tuple(
                item for item in plan.prohibited_actions if item not in rejected.prohibited_actions
            ),
        )
        return plan, diff

    @staticmethod
    def _plan_policy(
        strategy: Strategy,
    ) -> tuple[PlanObjective, tuple[PlanStep, ...], tuple[ProhibitedAction, ...]]:
        if strategy is Strategy.FULL_EVIDENCE_RANKING:
            return (
                PlanObjective.RANK_FULL_CORROBORATED_EVIDENCE,
                (
                    PlanStep.RANK_FULL_EVIDENCE,
                    PlanStep.PRE_RELEASE_AUDIT,
                    PlanStep.RELEASE_OUTPUT,
                ),
                BASE_PROHIBITIONS,
            )
        if strategy is Strategy.SUPPORTED_ONLY_RANKING:
            return (
                PlanObjective.RANK_SUPPORTED_EVIDENCE_ONLY,
                (
                    PlanStep.QUARANTINE_UNSUPPORTED,
                    PlanStep.RANK_SUPPORTED_EVIDENCE,
                    PlanStep.PRE_RELEASE_AUDIT,
                    PlanStep.RELEASE_OUTPUT,
                ),
                BASE_PROHIBITIONS,
            )
        if strategy is Strategy.PARTIAL_SAFE_RANKING:
            return (
                PlanObjective.RANK_AVAILABLE_EVIDENCE_SAFELY,
                (
                    PlanStep.MARK_EVIDENCE_PENDING,
                    PlanStep.RANK_PARTIAL_EVIDENCE,
                    PlanStep.REQUEST_CORROBORATION,
                    PlanStep.PRE_RELEASE_AUDIT,
                    PlanStep.RELEASE_OUTPUT,
                ),
                BASE_PROHIBITIONS,
            )
        return (
            PlanObjective.HOLD_BATCH_FOR_INTEGRITY_REVIEW,
            (
                PlanStep.ISOLATE_BATCH,
                PlanStep.REQUEST_CORROBORATION,
                PlanStep.PRE_RELEASE_AUDIT,
                PlanStep.RELEASE_OUTPUT,
            ),
            (*BASE_PROHIBITIONS, ProhibitedAction.RELEASE_FINAL_QUALIFICATION_DECISION),
        )

    @staticmethod
    def _commands(version: int, steps: Sequence[PlanStep]) -> tuple[PlanCommand, ...]:
        commands: list[PlanCommand] = []
        previous_id: str | None = None
        for step in steps:
            command_id = f"p{version}:{step.value}"
            commands.append(
                PlanCommand(
                    command_id=command_id,
                    kind=step,
                    dependency_ids=() if previous_id is None else (previous_id,),
                )
            )
            previous_id = command_id
        return tuple(commands)
