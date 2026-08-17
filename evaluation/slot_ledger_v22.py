"""Independent validation for V2.2 provider-call slot ledgers.

The capture writer is deliberately not imported here.  This module rebuilds
the frozen secure and naïve schedules from the retained attempt artifacts,
recomputes every observation hash and every chain link, and requires an exact
one-start/one-terminal lifecycle for all 116 preregistered provider slots.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeAlias, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evaluation.naive_protocol_v22 import LATIN_SQUARE_SCHEDULE_V22, NAIVE_SEEDS_V22
from evaluation.protocol_v22 import (
    CANONICAL_PROVIDER_CANDIDATE_IDS_V22,
    CANONICAL_PROVIDER_SNAPSHOT_ID_V22,
    FROZEN_RUN_ID_V22,
    HELDOUT_CLEAN_SNAPSHOT_ID_V22,
    HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22,
    HELDOUT_PROVIDER_CANDIDATE_IDS_V22,
    NAIVE_LEDGER_FILENAME_V22,
    NAIVE_SLOT_COUNT_V22,
    PROTOCOL_VERSION_V22,
    SCHEMA_VERSION_V22,
    SECURE_CANONICAL_SLOT_COUNT_V22,
    SECURE_HELDOUT_SLOT_COUNT_V22,
    SECURE_LEDGER_FILENAME_V22,
    SECURE_SLOT_COUNT_V22,
)
from evaluation.release_spec_v2 import (
    Digest,
    JsonObject,
    canonical_json_bytes,
    decode_strict_json_object_v2,
)

LedgerKindV22: TypeAlias = Literal["secure", "naive"]
SlotStateV22: TypeAlias = Literal["completed", "failed", "unobserved"]

SLOT_CHAIN_DOMAIN_V22 = b"cv-trust-agent/provider-slot-chain/v3\0"
SLOT_ABSENCE_DOMAIN_V22 = b"cv-trust-agent/provider-slot-unobserved/v3\0"
_MAX_LEDGER_BYTES = 4 * 1024 * 1024
_MAX_LEDGER_LINE_BYTES = 32 * 1024
_MAX_ATTEMPT_BYTES = 32 * 1024 * 1024
_MAX_ATTEMPT_LINE_BYTES = 2 * 1024 * 1024
_PAIR_ORDERS = (
    ("clean", "directive"),
    ("directive", "clean"),
    ("clean", "directive"),
)


class SlotLedgerV22Error(ValueError):
    """A provider-call ledger is not an exact V2.2 protocol receipt."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _ChainedRecordV22(_StrictModel):
    schema_version: Literal[3]
    protocol_version: Literal["2.2"]
    run_id: Literal["v24-20260817-r1"]
    ledger_kind: LedgerKindV22
    prev_chain_sha256: Digest
    chain_sha256: Digest


class LedgerGenesisV22(_ChainedRecordV22):
    event: Literal["ledger_genesis_v22"]
    expected_slot_count: int = Field(ge=1, le=116)
    canonical_slot_count: int = Field(ge=0, le=60)
    heldout_slot_count: int = Field(ge=0, le=24)
    naive_slot_count: int = Field(ge=0, le=32)

    @model_validator(mode="after")
    def counts_match_kind(self) -> LedgerGenesisV22:
        expected = (
            (
                SECURE_SLOT_COUNT_V22,
                SECURE_CANONICAL_SLOT_COUNT_V22,
                SECURE_HELDOUT_SLOT_COUNT_V22,
                0,
            )
            if self.ledger_kind == "secure"
            else (NAIVE_SLOT_COUNT_V22, 0, 0, NAIVE_SLOT_COUNT_V22)
        )
        if (
            self.expected_slot_count,
            self.canonical_slot_count,
            self.heldout_slot_count,
            self.naive_slot_count,
        ) != expected:
            raise ValueError("ledger genesis counts differ from the frozen protocol")
        return self


class SlotStartedV22(_ChainedRecordV22):
    event: Literal["slot_started_v22"]
    slot_index: int = Field(ge=1, le=116)
    arm: Literal["canonical", "heldout", "naive"]
    repetition: int | None = Field(default=None, ge=1, le=3)
    condition: Literal["clean", "directive"] | None = None
    condition_order_index: int | None = Field(default=None, ge=1, le=2)
    call_index: int = Field(ge=1, le=10)
    block_id: int | None = Field(default=None, ge=1, le=8)
    call_role: (
        Literal["attack_clean", "attack_directive", "control_first", "control_second"] | None
    ) = None
    call_position: int | None = Field(default=None, ge=1, le=4)
    candidate_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    snapshot_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

    @model_validator(mode="after")
    def coordinates_match_arm(self) -> SlotStartedV22:
        secure = self.arm in {"canonical", "heldout"}
        if secure:
            if (
                self.ledger_kind != "secure"
                or self.repetition is None
                or self.condition is None
                or self.condition_order_index is None
                or self.block_id is not None
                or self.call_role is not None
                or self.call_position is not None
                or self.candidate_id is None
                or self.snapshot_id is None
                or (self.arm == "canonical" and self.call_index > 10)
                or (self.arm == "heldout" and self.call_index > 4)
            ):
                raise ValueError("secure slot coordinates are invalid")
        elif (
            self.ledger_kind != "naive"
            or self.repetition is not None
            or self.condition is not None
            or self.condition_order_index is not None
            or self.call_index != 1
            or self.block_id is None
            or self.call_role is None
            or self.call_position is None
            or self.candidate_id is not None
            or self.snapshot_id is not None
        ):
            raise ValueError("naïve slot coordinates are invalid")
        return self

    def descriptor(self) -> JsonObject:
        return cast(
            JsonObject,
            self.model_dump(
                mode="json",
                include={
                    "arm",
                    "repetition",
                    "condition",
                    "condition_order_index",
                    "call_index",
                    "block_id",
                    "call_role",
                    "call_position",
                    "candidate_id",
                    "snapshot_id",
                },
                exclude_none=True,
            ),
        )


class SlotTerminalV22(_ChainedRecordV22):
    event: Literal["slot_terminal_v22"]
    slot_index: int = Field(ge=1, le=116)
    state: SlotStateV22
    row_sha256: Digest


class LedgerFinalV22(_ChainedRecordV22):
    event: Literal["ledger_final_v22"]
    slot_count: int = Field(ge=1, le=116)
    completed_count: int = Field(ge=0, le=116)
    failed_count: int = Field(ge=0, le=116)
    unobserved_count: int = Field(ge=0, le=116)

    @model_validator(mode="after")
    def terminal_counts_close(self) -> LedgerFinalV22:
        if self.completed_count + self.failed_count + self.unobserved_count != self.slot_count:
            raise ValueError("ledger final counts do not close")
        return self


LedgerRecordV22: TypeAlias = LedgerGenesisV22 | SlotStartedV22 | SlotTerminalV22 | LedgerFinalV22


@dataclass(frozen=True, slots=True)
class ValidatedSlotLedgerV22:
    run_id: str
    ledger_kind: str
    artifact_sha256: str
    final_chain_sha256: str
    slot_count: int
    completed_count: int
    failed_count: int
    unobserved_count: int


@dataclass(frozen=True, slots=True)
class _ExpectedSlotV22:
    descriptor: JsonObject
    state: SlotStateV22
    row_sha256: str


def initial_slot_chain_v22(ledger_kind: LedgerKindV22, run_id: str) -> str:
    """Return the domain-separated chain seed used before the genesis record."""

    return hashlib.sha256(
        SLOT_CHAIN_DOMAIN_V22 + ledger_kind.encode("ascii") + b"\0" + run_id.encode("ascii")
    ).hexdigest()


def unobserved_slot_sha256_v22(
    *,
    ledger_kind: LedgerKindV22,
    run_id: str,
    slot_index: int,
    descriptor: Mapping[str, object],
) -> str:
    """Hash an explicit absence marker; it is not a fabricated provider row."""

    return hashlib.sha256(
        SLOT_ABSENCE_DOMAIN_V22
        + canonical_json_bytes(
            {
                "kind": "unobserved",
                "ledger_kind": ledger_kind,
                "run_id": run_id,
                "slot_index": slot_index,
                "descriptor": dict(descriptor),
            }
        )
    ).hexdigest()


def validate_slot_ledger_v22(
    ledger_path: Path,
    *,
    artifact_path: Path,
    ledger_kind: LedgerKindV22,
    expected_run_id: str = FROZEN_RUN_ID_V22,
) -> ValidatedSlotLedgerV22:
    """Validate a ledger independently against its exact attempt artifact."""

    if expected_run_id != FROZEN_RUN_ID_V22:
        raise SlotLedgerV22Error("alternate V2.2 run IDs are not admissible")
    expected_names = (
        (SECURE_LEDGER_FILENAME_V22, "secure-v22.jsonl")
        if ledger_kind == "secure"
        else (NAIVE_LEDGER_FILENAME_V22, "naive-v22.jsonl")
    )
    if (
        ledger_path.name != expected_names[0]
        or artifact_path.name != expected_names[1]
        or ledger_path.resolve().parent != artifact_path.resolve().parent
    ):
        raise SlotLedgerV22Error("slot ledger is not colocated with its exact attempt artifact")

    records, raw_records, ledger_bytes = _load_ledger(ledger_path)
    if not records or not isinstance(records[0], LedgerGenesisV22):
        raise SlotLedgerV22Error("slot ledger is missing its genesis")
    if not isinstance(records[-1], LedgerFinalV22):
        raise SlotLedgerV22Error("slot ledger is missing its final closure")
    if any(
        record.run_id != expected_run_id or record.ledger_kind != ledger_kind for record in records
    ):
        raise SlotLedgerV22Error("slot ledger uses a mixed, replayed, or alternate run identity")
    _validate_chain(records, raw_records, ledger_kind=ledger_kind, run_id=expected_run_id)

    artifact_rows = _load_attempt_rows(artifact_path)
    expected_slots = (
        _expected_secure_slots(artifact_rows, expected_run_id)
        if ledger_kind == "secure"
        else _expected_naive_slots(artifact_rows, expected_run_id)
    )
    expected_record_count = 2 + 2 * len(expected_slots)
    if len(records) != expected_record_count:
        raise SlotLedgerV22Error("slot ledger has missing, extra, or replayed lifecycle records")
    genesis = records[0]
    final = records[-1]
    if genesis.expected_slot_count != len(expected_slots) or final.slot_count != len(
        expected_slots
    ):
        raise SlotLedgerV22Error("slot ledger count differs from the rebuilt schedule")

    lifecycle = records[1:-1]
    cursor = 0
    slot_index = 1
    expected_terminals: list[_ExpectedSlotV22] = []
    while slot_index <= len(expected_slots):
        arm = cast(str, expected_slots[slot_index - 1].descriptor["arm"])
        group_size = 10 if arm == "canonical" else 1
        group = expected_slots[slot_index - 1 : slot_index - 1 + group_size]
        starts = lifecycle[cursor : cursor + group_size]
        cursor += group_size
        if len(starts) != group_size or any(
            not isinstance(item, SlotStartedV22) for item in starts
        ):
            raise SlotLedgerV22Error("slot starts do not follow the frozen call schedule")
        for offset, (record, expected) in enumerate(zip(starts, group, strict=True)):
            start = cast(SlotStartedV22, record)
            expected_index = slot_index + offset
            if start.slot_index != expected_index or start.descriptor() != expected.descriptor:
                raise SlotLedgerV22Error("slot start coordinates differ from the frozen schedule")
        terminals = lifecycle[cursor : cursor + group_size]
        cursor += group_size
        if len(terminals) != group_size or any(
            not isinstance(item, SlotTerminalV22) for item in terminals
        ):
            raise SlotLedgerV22Error("started slot is missing exactly one terminal response")
        for offset, (record, expected) in enumerate(zip(terminals, group, strict=True)):
            terminal = cast(SlotTerminalV22, record)
            expected_index = slot_index + offset
            if (
                terminal.slot_index != expected_index
                or terminal.state != expected.state
                or terminal.row_sha256 != expected.row_sha256
            ):
                raise SlotLedgerV22Error(
                    "slot terminal is duplicated, unmatched, or row-mismatched"
                )
            expected_terminals.append(expected)
        slot_index += group_size
    if cursor != len(lifecycle):
        raise SlotLedgerV22Error("slot ledger contains replayed trailing records")

    counts = {
        state: sum(item.state == state for item in expected_terminals)
        for state in ("completed", "failed", "unobserved")
    }
    if (
        final.completed_count != counts["completed"]
        or final.failed_count != counts["failed"]
        or final.unobserved_count != counts["unobserved"]
    ):
        raise SlotLedgerV22Error("ledger final state counts differ from terminal records")
    return ValidatedSlotLedgerV22(
        run_id=expected_run_id,
        ledger_kind=ledger_kind,
        artifact_sha256=hashlib.sha256(ledger_bytes).hexdigest(),
        final_chain_sha256=final.chain_sha256,
        slot_count=len(expected_slots),
        completed_count=counts["completed"],
        failed_count=counts["failed"],
        unobserved_count=counts["unobserved"],
    )


def _load_ledger(
    path: Path,
) -> tuple[tuple[LedgerRecordV22, ...], tuple[JsonObject, ...], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SlotLedgerV22Error("slot ledger could not be read") from exc
    if not raw or len(raw) > _MAX_LEDGER_BYTES:
        raise SlotLedgerV22Error("slot ledger has an invalid byte length")
    records: list[LedgerRecordV22] = []
    raw_records: list[JsonObject] = []
    for line in raw.splitlines():
        if not line or len(line) > _MAX_LEDGER_LINE_BYTES:
            raise SlotLedgerV22Error("slot ledger row is empty or oversized")
        try:
            value = decode_strict_json_object_v2(line, maximum_bytes=_MAX_LEDGER_LINE_BYTES)
        except Exception as exc:
            raise SlotLedgerV22Error("slot ledger row is not strict JSON") from exc
        if line != canonical_json_bytes(value):
            raise SlotLedgerV22Error("slot ledger row is not canonical JSON")
        model: type[LedgerRecordV22]
        event = value.get("event")
        if event == "ledger_genesis_v22":
            model = LedgerGenesisV22
        elif event == "slot_started_v22":
            model = SlotStartedV22
        elif event == "slot_terminal_v22":
            model = SlotTerminalV22
        elif event == "ledger_final_v22":
            model = LedgerFinalV22
        else:
            raise SlotLedgerV22Error("slot ledger event is outside the closed vocabulary")
        try:
            records.append(model.model_validate_json(line))
        except Exception as exc:
            raise SlotLedgerV22Error("slot ledger row schema is invalid") from exc
        raw_records.append(value)
    return tuple(records), tuple(raw_records), raw


def _validate_chain(
    records: tuple[LedgerRecordV22, ...],
    raw_records: tuple[JsonObject, ...],
    *,
    ledger_kind: LedgerKindV22,
    run_id: str,
) -> None:
    chain = initial_slot_chain_v22(ledger_kind, run_id)
    for record, raw in zip(records, raw_records, strict=True):
        if record.prev_chain_sha256 != chain:
            raise SlotLedgerV22Error("slot ledger predecessor hash is invalid")
        payload = dict(raw)
        observed_chain = cast(str, payload.pop("chain_sha256"))
        expected_chain = hashlib.sha256(
            SLOT_CHAIN_DOMAIN_V22 + bytes.fromhex(chain) + canonical_json_bytes(payload)
        ).hexdigest()
        if observed_chain != expected_chain:
            raise SlotLedgerV22Error("slot ledger chain hash is invalid")
        chain = expected_chain


def _load_attempt_rows(path: Path) -> tuple[JsonObject, ...]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SlotLedgerV22Error("attempt artifact could not be read") from exc
    if not raw or len(raw) > _MAX_ATTEMPT_BYTES:
        raise SlotLedgerV22Error("attempt artifact has an invalid byte length")
    rows: list[JsonObject] = []
    for line in raw.splitlines():
        if not line or len(line) > _MAX_ATTEMPT_LINE_BYTES:
            raise SlotLedgerV22Error("attempt artifact row is empty or oversized")
        try:
            value = decode_strict_json_object_v2(line, maximum_bytes=_MAX_ATTEMPT_LINE_BYTES)
        except Exception as exc:
            raise SlotLedgerV22Error("attempt artifact row is not strict JSON") from exc
        rows.append(value)
    return tuple(rows)


def _secure_coordinates() -> tuple[tuple[str, int, str, int], ...]:
    coordinates: list[tuple[str, int, str, int]] = []
    for arm in ("canonical", "heldout"):
        for repetition, order in enumerate(_PAIR_ORDERS, start=1):
            for order_index, condition in enumerate(order, start=1):
                coordinates.append((arm, repetition, condition, order_index))
    return tuple(coordinates)


def _expected_secure_slots(
    rows: tuple[JsonObject, ...], run_id: str
) -> tuple[_ExpectedSlotV22, ...]:
    coordinates = _secure_coordinates()
    if len(rows) != len(coordinates):
        raise SlotLedgerV22Error("secure artifact does not contain the twelve-call schedule")
    expected: list[_ExpectedSlotV22] = []
    next_slot = 1
    for row, (arm, repetition, condition, order_index) in zip(rows, coordinates, strict=True):
        if (
            row.get("schema_version") != SCHEMA_VERSION_V22
            or row.get("protocol_version") != PROTOCOL_VERSION_V22
            or row.get("run_id") != run_id
            or row.get("arm") != arm
            or row.get("repetition") != repetition
            or row.get("condition") != condition
            or row.get("condition_order_index") != order_index
            or row.get("condition_order") != list(_PAIR_ORDERS[repetition - 1])
        ):
            raise SlotLedgerV22Error("secure artifact schedule or run identity is invalid")
        identities = (
            tuple(
                (candidate_id, CANONICAL_PROVIDER_SNAPSHOT_ID_V22)
                for candidate_id in CANONICAL_PROVIDER_CANDIDATE_IDS_V22
            )
            if arm == "canonical"
            else tuple(
                (
                    candidate_id,
                    (
                        HELDOUT_CLEAN_SNAPSHOT_ID_V22
                        if condition == "clean"
                        else HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22
                    ),
                )
                for candidate_id in HELDOUT_PROVIDER_CANDIDATE_IDS_V22
            )
        )
        call_count = len(identities)
        field = "provider_calls" if arm == "canonical" else "provider_candidates"
        observed = row.get(field)
        if (
            not isinstance(observed, list)
            or len(observed) > call_count
            or any(not isinstance(item, dict) for item in observed)
        ):
            raise SlotLedgerV22Error("secure provider observations are malformed")
        observed_rows = cast(list[JsonObject], observed)
        observed_identity_items: list[tuple[str, str]] = []
        for item in observed_rows:
            candidate_id = item.get("candidate_id")
            snapshot_id = item.get("snapshot_id")
            if not isinstance(candidate_id, str) or not isinstance(snapshot_id, str):
                raise SlotLedgerV22Error("secure provider identities are malformed")
            observed_identity_items.append((candidate_id, snapshot_id))
        observed_identities = tuple(observed_identity_items)
        if (
            len(observed_identities) != len(set(observed_identities))
            or not set(observed_identities).issubset(identities)
            or observed_identities
            != tuple(identity for identity in identities if identity in set(observed_identities))
        ):
            raise SlotLedgerV22Error("secure provider identities differ from the frozen cohort")
        observations_by_identity = dict(zip(observed_identities, observed_rows, strict=True))
        result = row.get("result")
        if arm == "canonical" and isinstance(result, dict) and result.get("kind") == "decision":
            projection_value = result.get("projection")
            if not isinstance(projection_value, dict):
                raise SlotLedgerV22Error("canonical retained projection is malformed")
            projection = cast(JsonObject, projection_value)
            routes = projection.get("routes")
            if (
                projection.get("snapshot_id") != CANONICAL_PROVIDER_SNAPSHOT_ID_V22
                or not isinstance(routes, list)
                or any(not isinstance(item, dict) for item in routes)
                or {cast(JsonObject, item).get("candidate_id") for item in routes}
                != set(CANONICAL_PROVIDER_CANDIDATE_IDS_V22)
            ):
                raise SlotLedgerV22Error(
                    "canonical provider identities differ from the retained projection"
                )
        for call_index, (candidate_id, snapshot_id) in enumerate(identities, start=1):
            descriptor: JsonObject = {
                "arm": arm,
                "repetition": repetition,
                "condition": condition,
                "condition_order_index": order_index,
                "call_index": call_index,
                "candidate_id": candidate_id,
                "snapshot_id": snapshot_id,
            }
            observation = observations_by_identity.get((candidate_id, snapshot_id))
            if observation is not None:
                outcome = observation.get("outcome")
                state: SlotStateV22 = "completed" if outcome in {"success", "mapped"} else "failed"
                row_sha256 = hashlib.sha256(canonical_json_bytes(observation)).hexdigest()
            else:
                state = "unobserved"
                row_sha256 = unobserved_slot_sha256_v22(
                    ledger_kind="secure",
                    run_id=run_id,
                    slot_index=next_slot,
                    descriptor=descriptor,
                )
            expected.append(
                _ExpectedSlotV22(
                    descriptor=descriptor,
                    state=state,
                    row_sha256=row_sha256,
                )
            )
            next_slot += 1
    if len(expected) != SECURE_SLOT_COUNT_V22:
        raise SlotLedgerV22Error("secure slot schedule is not 60 canonical plus 24 held-out")
    return tuple(expected)


def _expected_naive_slots(
    rows: tuple[JsonObject, ...], run_id: str
) -> tuple[_ExpectedSlotV22, ...]:
    if len(rows) != NAIVE_SLOT_COUNT_V22:
        raise SlotLedgerV22Error("naïve artifact does not contain exactly 32 calls")
    expected: list[_ExpectedSlotV22] = []
    for slot_index, row in enumerate(rows, start=1):
        block_id = (slot_index - 1) // 4 + 1
        call_position = (slot_index - 1) % 4 + 1
        role = LATIN_SQUARE_SCHEDULE_V22[block_id - 1][call_position - 1]
        if (
            row.get("schema_version") != SCHEMA_VERSION_V22
            or row.get("protocol_version") != PROTOCOL_VERSION_V22
            or row.get("run_id") != run_id
            or row.get("block_id") != block_id
            or row.get("seed") != NAIVE_SEEDS_V22[block_id - 1]
            or row.get("call_role") != role
            or row.get("call_position") != call_position
        ):
            raise SlotLedgerV22Error("naïve artifact schedule or run identity is invalid")
        descriptor: JsonObject = {
            "arm": "naive",
            "call_index": 1,
            "block_id": block_id,
            "call_role": role,
            "call_position": call_position,
        }
        result = row.get("result")
        state: SlotStateV22 = (
            "completed"
            if isinstance(result, dict) and result.get("status") == "valid"
            else "failed"
        )
        expected.append(
            _ExpectedSlotV22(
                descriptor=descriptor,
                state=state,
                row_sha256=hashlib.sha256(canonical_json_bytes(row)).hexdigest(),
            )
        )
    return tuple(expected)


__all__ = [
    "SLOT_ABSENCE_DOMAIN_V22",
    "SLOT_CHAIN_DOMAIN_V22",
    "LedgerFinalV22",
    "LedgerGenesisV22",
    "LedgerKindV22",
    "SlotLedgerV22Error",
    "SlotStartedV22",
    "SlotStateV22",
    "SlotTerminalV22",
    "ValidatedSlotLedgerV22",
    "initial_slot_chain_v22",
    "unobserved_slot_sha256_v22",
    "validate_slot_ledger_v22",
]
