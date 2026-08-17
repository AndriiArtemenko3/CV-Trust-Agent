"""Hostile boundary tests for the independently validated V2.2 slot ledger."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from evaluation.capture_v22 import SecureSlotLedgerV22
from evaluation.naive_protocol_v22 import LATIN_SQUARE_SCHEDULE_V22, NAIVE_SEEDS_V22
from evaluation.release_spec_v2 import canonical_json_bytes
from evaluation.slot_ledger_v22 import (
    SLOT_CHAIN_DOMAIN_V22,
    LedgerFinalV22,
    LedgerGenesisV22,
    SlotLedgerV22Error,
    SlotStartedV22,
    initial_slot_chain_v22,
    validate_slot_ledger_v22,
)

Json = dict[str, Any]
RUN_ID = "v24-20260817-r1"


def _naive_rows() -> list[Json]:
    rows: list[Json] = []
    for block_id, (seed, schedule) in enumerate(
        zip(NAIVE_SEEDS_V22, LATIN_SQUARE_SCHEDULE_V22, strict=True), start=1
    ):
        for call_position, role in enumerate(schedule, start=1):
            rows.append(
                {
                    "schema_version": 3,
                    "protocol_version": "2.2",
                    "run_id": RUN_ID,
                    "block_id": block_id,
                    "seed": seed,
                    "call_role": role,
                    "call_position": call_position,
                    "result": {"status": "valid"},
                }
            )
    return rows


def _write_jsonl(path: Path, rows: list[Json]) -> None:
    path.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))


def _bundle(tmp_path: Path) -> tuple[Path, Path]:
    artifact = tmp_path / "naive-v22.jsonl"
    ledger_path = tmp_path / "naive-slots-v22.jsonl"
    rows = _naive_rows()
    _write_jsonl(artifact, rows)
    ledger = SecureSlotLedgerV22(ledger_path, ledger_kind="naive")
    for row in rows:
        descriptor = {
            "arm": "naive",
            "call_index": 1,
            "block_id": row["block_id"],
            "call_role": row["call_role"],
            "call_position": row["call_position"],
        }
        slot = ledger.start_slot(descriptor)
        ledger.terminalize_slot(
            slot,
            state="completed",
            row_sha256=hashlib.sha256(canonical_json_bytes(row)).hexdigest(),
        )
    ledger.close(expected_slot_count=32)
    return artifact, ledger_path


def _ledger_rows(path: Path) -> list[Json]:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def _write_rechained(path: Path, rows: list[Json]) -> None:
    chain = initial_slot_chain_v22("naive", RUN_ID)
    rechained: list[Json] = []
    for original in rows:
        payload = {key: value for key, value in original.items() if key != "chain_sha256"}
        payload["prev_chain_sha256"] = chain
        chain = hashlib.sha256(
            SLOT_CHAIN_DOMAIN_V22 + bytes.fromhex(chain) + canonical_json_bytes(payload)
        ).hexdigest()
        rechained.append({**payload, "chain_sha256": chain})
    _write_jsonl(path, rechained)


def _validate(artifact: Path, ledger: Path) -> None:
    validate_slot_ledger_v22(ledger, artifact_path=artifact, ledger_kind="naive")


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            LedgerGenesisV22,
            {
                "event": "ledger_genesis_v22",
                "expected_slot_count": 84,
                "canonical_slot_count": 60,
                "heldout_slot_count": 24,
                "naive_slot_count": 0,
            },
        ),
        (
            SlotStartedV22,
            {
                "event": "slot_started_v22",
                "slot_index": 1,
                "arm": "canonical",
                "call_index": 1,
            },
        ),
        (
            SlotStartedV22,
            {
                "event": "slot_started_v22",
                "slot_index": 1,
                "arm": "naive",
                "call_index": 2,
                "block_id": 1,
                "call_role": "attack_clean",
                "call_position": 1,
            },
        ),
        (
            LedgerFinalV22,
            {
                "event": "ledger_final_v22",
                "slot_count": 32,
                "completed_count": 31,
                "failed_count": 0,
                "unobserved_count": 0,
            },
        ),
    ],
)
def test_closed_record_models_reject_incoherent_coordinates(
    model: type[LedgerGenesisV22 | SlotStartedV22 | LedgerFinalV22], payload: Json
) -> None:
    base: Json = {
        "schema_version": 3,
        "protocol_version": "2.2",
        "run_id": RUN_ID,
        "ledger_kind": "naive",
        "prev_chain_sha256": "0" * 64,
        "chain_sha256": "1" * 64,
    }
    with pytest.raises(ValidationError):
        model.model_validate({**base, **payload})


def test_alternate_run_id_is_rejected_before_file_access(tmp_path: Path) -> None:
    with pytest.raises(SlotLedgerV22Error, match=r"alternate V2\.2 run IDs"):
        validate_slot_ledger_v22(
            tmp_path / "naive-slots-v22.jsonl",
            artifact_path=tmp_path / "naive-v22.jsonl",
            ledger_kind="naive",
            expected_run_id="v22-replay",
        )


def test_ledger_and_artifact_must_be_exactly_colocated(tmp_path: Path) -> None:
    with pytest.raises(SlotLedgerV22Error, match="colocated"):
        validate_slot_ledger_v22(
            tmp_path / "wrong-name.jsonl",
            artifact_path=tmp_path / "naive-v22.jsonl",
            ledger_kind="naive",
        )


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (b"", "invalid byte length"),
        (b"\n", "empty or oversized"),
        (b"{", "not strict JSON"),
        (b'{ "event": "outside"}\n', "not canonical JSON"),
        (canonical_json_bytes({"event": "outside"}) + b"\n", "closed vocabulary"),
        (canonical_json_bytes({"event": "ledger_genesis_v22"}) + b"\n", "schema is invalid"),
    ],
)
def test_ledger_framing_is_strict(tmp_path: Path, contents: bytes, message: str) -> None:
    ledger = tmp_path / "naive-slots-v22.jsonl"
    ledger.write_bytes(contents)
    with pytest.raises(SlotLedgerV22Error, match=message):
        _validate(tmp_path / "naive-v22.jsonl", ledger)


def test_missing_ledger_is_a_sanitized_local_failure(tmp_path: Path) -> None:
    with pytest.raises(SlotLedgerV22Error, match="could not be read"):
        _validate(tmp_path / "naive-v22.jsonl", tmp_path / "naive-slots-v22.jsonl")


def test_lifecycle_without_genesis_is_rejected(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)[1:]
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="missing its genesis"):
        _validate(artifact, ledger)


def test_mixed_ledger_kind_is_rejected_even_with_a_valid_chain(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[-1]["ledger_kind"] = "secure"
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="mixed, replayed, or alternate"):
        _validate(artifact, ledger)


def test_extra_lifecycle_record_is_rejected(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows.insert(-1, dict(rows[-2]))
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="missing, extra, or replayed"):
        _validate(artifact, ledger)


def test_final_slot_count_must_match_rebuilt_schedule(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[-1].update(
        slot_count=31,
        completed_count=31,
        failed_count=0,
        unobserved_count=0,
    )
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="count differs"):
        _validate(artifact, ledger)


def test_terminal_in_a_start_position_is_rejected(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[1], rows[2] = rows[2], rows[1]
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="starts do not follow"):
        _validate(artifact, ledger)


def test_started_coordinates_must_match_frozen_schedule(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[1]["block_id"] = 2
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="coordinates differ"):
        _validate(artifact, ledger)


def test_two_starts_before_terminal_are_rejected(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[2], rows[3] = rows[3], rows[2]
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="missing exactly one terminal"):
        _validate(artifact, ledger)


def test_final_state_counts_are_independently_recomputed(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[-1].update(completed_count=31, failed_count=1)
    _write_rechained(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="state counts differ"):
        _validate(artifact, ledger)


def test_predecessor_hash_tampering_is_rejected(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[0]["prev_chain_sha256"] = "0" * 64
    _write_jsonl(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="predecessor hash"):
        _validate(artifact, ledger)


def test_chain_hash_tampering_is_rejected(tmp_path: Path) -> None:
    artifact, ledger = _bundle(tmp_path)
    rows = _ledger_rows(ledger)
    rows[0]["chain_sha256"] = "0" * 64
    _write_jsonl(ledger, rows)
    with pytest.raises(SlotLedgerV22Error, match="chain hash"):
        _validate(artifact, ledger)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (None, "could not be read"),
        (b"", "invalid byte length"),
        (b"\n", "empty or oversized"),
        (b"{", "not strict JSON"),
        (canonical_json_bytes({"schema_version": 3}) + b"\n", "exactly 32 calls"),
    ],
)
def test_attempt_artifact_framing_and_cardinality_are_strict(
    tmp_path: Path, contents: bytes | None, message: str
) -> None:
    artifact, ledger = _bundle(tmp_path)
    if contents is None:
        artifact.unlink()
    else:
        artifact.write_bytes(contents)
    with pytest.raises(SlotLedgerV22Error, match=message):
        _validate(artifact, ledger)
