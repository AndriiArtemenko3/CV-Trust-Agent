"""Closed execution of trusted plan commands with single-use stage capabilities."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from threading import Lock
from typing import Any

from cv_trust_agent.models import (
    ExecutionPlan,
    PlanCommand,
    PlanStep,
    ReasonCode,
    StageHandle,
    StepReceipt,
    StepStatus,
    TrustDecision,
    TrustOutcome,
)

_FAN_IN_COMMANDS = frozenset(
    {
        PlanStep.VALIDATE_CANDIDATE_BINDINGS,
        PlanStep.VALIDATE_CANDIDATE_EVIDENCE,
    }
)


class StageCapabilityError(ValueError):
    """A stage capability was invalid, foreign, copied, blocked, or already used."""


@dataclass(frozen=True)
class StageInput:
    """Ephemeral value yielded only after the vault consumes its capability."""

    value: Any
    handle: StageHandle


@dataclass
class _VaultEntry:
    handle: StageHandle
    value: Any | None
    consumed: bool = False


class StageVault:
    """Run-scoped, atomic, single-use store for stage values.

    Values never live on serializable handles. Object-identity checks make a
    copied handle invalid even when every public field is identical. The lock
    covers validation and consumption of the complete dependency set, so two
    threads cannot both cross the same trust gate.
    """

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self._entries: dict[str, _VaultEntry] = {}
        self._lock = Lock()

    def create(
        self,
        *,
        decision: TrustDecision,
        value: Any | None,
        provenance_ids: tuple[str, ...] = (),
    ) -> StageHandle:
        consumable = decision.outcome in {TrustOutcome.ALLOW, TrustOutcome.RESTRICT}
        if consumable is not (value is not None):
            raise StageCapabilityError(
                "only ALLOW/RESTRICT decisions may place a value in the stage vault"
            )
        handle = StageHandle(
            handle_id=decision.decision_id,
            run_id=self.run_id,
            provenance_ids=provenance_ids,
            decision=decision,
            consumable=consumable,
        )
        with self._lock:
            if handle.handle_id in self._entries:
                raise StageCapabilityError("stage handle ID is already registered")
            self._entries[handle.handle_id] = _VaultEntry(handle=handle, value=value)
        return handle

    def consume(self, handle: StageHandle) -> StageInput:
        return self.consume_many((handle,))[0]

    def consume_many(self, handles: Sequence[StageHandle]) -> tuple[StageInput, ...]:
        with self._lock:
            entries: list[_VaultEntry] = []
            seen: set[str] = set()
            for handle in handles:
                if handle.run_id != self.run_id:
                    raise StageCapabilityError("stage handle belongs to another run")
                if handle.handle_id in seen:
                    raise StageCapabilityError("dependency set contains a duplicate stage handle")
                seen.add(handle.handle_id)
                entry = self._entries.get(handle.handle_id)
                if entry is None or entry.handle is not handle:
                    raise StageCapabilityError("stage handle is unknown or was copied")
                if not handle.consumable or entry.value is None:
                    raise StageCapabilityError("blocked stage handle has no consumable value")
                if entry.consumed:
                    raise StageCapabilityError("stage handle was already consumed")
                entries.append(entry)
            values = tuple(entry.value for entry in entries)
            for entry in entries:
                entry.consumed = True
                entry.value = None
            return tuple(
                StageInput(value=value, handle=entry.handle)
                for value, entry in zip(values, entries, strict=True)
            )

    def close_fan_in(self, handles: Sequence[StageHandle]) -> tuple[StageHandle, ...]:
        """Atomically close exact terminal handles, including blocked terminals."""

        with self._lock:
            entries: list[_VaultEntry] = []
            seen: set[str] = set()
            for handle in handles:
                if handle.run_id != self.run_id:
                    raise StageCapabilityError("fan-in handle belongs to another run")
                if handle.handle_id in seen:
                    raise StageCapabilityError("fan-in contains a duplicate handle")
                seen.add(handle.handle_id)
                entry = self._entries.get(handle.handle_id)
                if entry is None or entry.handle is not handle:
                    raise StageCapabilityError("fan-in handle is unknown or was copied")
                if entry.consumed:
                    raise StageCapabilityError("fan-in handle was already closed")
                if handle.consumable is not (entry.value is not None):
                    raise StageCapabilityError("fan-in handle/value state is inconsistent")
                entries.append(entry)
            for entry in entries:
                entry.consumed = True
                entry.value = None
            return tuple(entry.handle for entry in entries)

    def owns(self, handle: StageHandle) -> bool:
        with self._lock:
            entry = self._entries.get(handle.handle_id)
            return handle.run_id == self.run_id and entry is not None and entry.handle is handle

    def is_available(self, handle: StageHandle) -> bool:
        with self._lock:
            entry = self._entries.get(handle.handle_id)
            return bool(
                handle.run_id == self.run_id
                and entry is not None
                and entry.handle is handle
                and handle.consumable
                and entry.value is not None
                and not entry.consumed
            )


@dataclass(frozen=True)
class CommandResult:
    """Opaque output capability plus sanitized receipt metadata."""

    stage_handle: StageHandle | None = None
    deferred_stage_factory: Callable[[tuple[str, ...]], StageHandle] | None = None
    fan_in_handles: tuple[StageHandle, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    reason_codes: tuple[ReasonCode, ...] = (ReasonCode.COMMAND_COMPLETED,)

    def __post_init__(self) -> None:
        if (self.stage_handle is None) is (self.deferred_stage_factory is None):
            raise ValueError("command result requires exactly one stage output mechanism")


CommandHandler = Callable[
    [PlanCommand, tuple[StepReceipt, ...], tuple[StageInput, ...]],
    CommandResult,
]


@dataclass(frozen=True)
class ExecutionReport:
    receipts: tuple[StepReceipt, ...]
    complete: bool
    selected_complete: bool
    stage_results: Mapping[str, StageHandle]
    terminal_statuses: Mapping[str, StepStatus]
    consumed_gate_ids: frozenset[str]


class WorkflowExecutor:
    """Execute a closed plan; the executor, not handlers, consumes dependencies."""

    def execute(
        self,
        plan: ExecutionPlan,
        handlers: Mapping[PlanStep, CommandHandler],
        *,
        vault: StageVault,
        start_sequence: int = 1,
        root_gate: StageHandle | None = None,
        prior_report: ExecutionReport | None = None,
        start_after: PlanStep | None = None,
        stop_after: PlanStep | None = None,
        on_gate_consumed: Callable[[StageHandle], None] | None = None,
    ) -> ExecutionReport:
        receipts: list[StepReceipt] = []
        terminal_by_command = dict(prior_report.terminal_statuses) if prior_report else {}
        stage_by_command = dict(prior_report.stage_results) if prior_report else {}
        produced_gate_ids = {gate.handle_id for gate in stage_by_command.values()}
        if root_gate is not None:
            produced_gate_ids.add(root_gate.handle_id)
        consumed_gate_ids = set(prior_report.consumed_gate_ids) if prior_report else set()
        sequence = start_sequence
        started = start_after is None
        first_selected = True
        selected_command_ids: list[str] = []

        for command in plan.commands:
            if not started:
                if command.kind is start_after:
                    started = True
                continue
            receipts.append(
                self._receipt(
                    plan,
                    command,
                    sequence,
                    StepStatus.STARTED,
                    (ReasonCode.COMMAND_STARTED,),
                )
            )
            selected_command_ids.append(command.command_id)
            sequence += 1

            dependency_failed = any(
                terminal_by_command.get(dependency) is not StepStatus.COMPLETED
                for dependency in command.dependency_ids
            )
            dependency_handles: tuple[StageHandle, ...]
            if first_selected and root_gate is not None:
                dependency_handles = (root_gate,)
            else:
                dependency_handles = tuple(
                    stage_by_command[dependency]
                    for dependency in command.dependency_ids
                    if dependency in stage_by_command
                )
            evidence_ids: tuple[str, ...] = ()
            produced_gate_id: str | None = None
            consumed_ids: tuple[str, ...] = ()
            reasons: tuple[ReasonCode, ...]
            if dependency_failed:
                terminal = StepStatus.RESTRICTED
                reasons = (ReasonCode.COMMAND_RESTRICTED,)
            elif len(dependency_handles) != (
                1 if first_selected and root_gate is not None else len(command.dependency_ids)
            ):
                terminal = StepStatus.FAILED
                reasons = (ReasonCode.COMMAND_FAILED,)
            else:
                handler = handlers.get(command.kind)
                if handler is None:
                    terminal = StepStatus.FAILED
                    reasons = (ReasonCode.COMMAND_FAILED,)
                else:
                    try:
                        inputs = vault.consume_many(dependency_handles)
                        if on_gate_consumed is not None:
                            for item in inputs:
                                on_gate_consumed(item.handle)
                        consumed_ids = tuple(item.handle.handle_id for item in inputs)
                        result = handler(command, tuple(receipts), inputs)
                        closed_fan_in = vault.close_fan_in(result.fan_in_handles)
                        if on_gate_consumed is not None:
                            for handle in closed_fan_in:
                                on_gate_consumed(handle)
                        consumed_ids = (
                            *consumed_ids,
                            *(handle.handle_id for handle in closed_fan_in),
                        )
                        if result.deferred_stage_factory is not None:
                            result_handle = result.deferred_stage_factory(consumed_ids)
                        elif result.stage_handle is not None:
                            result_handle = result.stage_handle
                        else:  # pragma: no cover - guarded by CommandResult
                            raise StageCapabilityError("command result has no stage output")
                    except Exception:
                        terminal = StepStatus.FAILED
                        reasons = (ReasonCode.COMMAND_FAILED,)
                        consumed_gate_ids.update(consumed_ids)
                    else:
                        produced_gate_id = result_handle.handle_id
                        decision_inputs = result_handle.decision.input_gate_ids
                        input_binding_valid = (
                            decision_inputs == consumed_ids
                            and (bool(result.fan_in_handles) is (command.kind in _FAN_IN_COMMANDS))
                            and (
                                (result.deferred_stage_factory is not None)
                                is bool(result.fan_in_handles)
                            )
                        )
                        valid_transition = (
                            bool(consumed_ids)
                            and not set(consumed_ids).intersection(consumed_gate_ids)
                            and produced_gate_id not in produced_gate_ids
                            and vault.owns(result_handle)
                            and vault.is_available(result_handle)
                            and input_binding_valid
                        )
                        if not valid_transition:
                            terminal = StepStatus.FAILED
                            reasons = (ReasonCode.COMMAND_FAILED,)
                            produced_gate_id = None
                            consumed_gate_ids.update(consumed_ids)
                        else:
                            terminal = StepStatus.COMPLETED
                            reasons = tuple(
                                dict.fromkeys((ReasonCode.COMMAND_COMPLETED, *result.reason_codes))
                            )
                            evidence_ids = result.evidence_ids
                            consumed_gate_ids.update(consumed_ids)
                            produced_gate_ids.add(produced_gate_id)
                            stage_by_command[command.command_id] = result_handle

            receipts.append(
                self._receipt(
                    plan,
                    command,
                    sequence,
                    terminal,
                    reasons,
                    evidence_ids,
                    produced_gate_id,
                    consumed_ids,
                )
            )
            sequence += 1
            terminal_by_command[command.command_id] = terminal
            first_selected = False
            if command.kind is stop_after:
                break

        return ExecutionReport(
            receipts=tuple(receipts),
            complete=all(
                terminal_by_command.get(command.command_id) is StepStatus.COMPLETED
                for command in plan.commands
            ),
            selected_complete=bool(selected_command_ids)
            and all(
                terminal_by_command.get(command_id) is StepStatus.COMPLETED
                for command_id in selected_command_ids
            ),
            stage_results=stage_by_command,
            terminal_statuses=terminal_by_command,
            consumed_gate_ids=frozenset(consumed_gate_ids),
        )

    @staticmethod
    def _receipt(
        plan: ExecutionPlan,
        command: PlanCommand,
        sequence: int,
        status: StepStatus,
        reasons: tuple[ReasonCode, ...],
        evidence_ids: tuple[str, ...] = (),
        produced_gate_id: str | None = None,
        consumed_gate_ids: tuple[str, ...] = (),
    ) -> StepReceipt:
        return StepReceipt(
            receipt_id=f"receipt:{plan.version}:{sequence}:{command.kind.value}",
            sequence=sequence,
            plan_version=plan.version,
            command_id=command.command_id,
            command_kind=command.kind,
            status=status,
            reason_codes=reasons,
            candidate_id=command.candidate_id,
            evidence_ids=evidence_ids,
            produced_gate_id=produced_gate_id,
            consumed_gate_ids=consumed_gate_ids,
        )
