"""V2.2 capture layer: slot ledger, writers, and staged heldout diagnostics."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cv_trust_agent.mappers import MapperError, MapperFailureCode
from evaluation.capture_v22 import (
    MAPPER_STAGE_FAILURE_CODES_V22,
    MAPPER_STAGES_V22,
    CaptureV22Error,
    SecureSlotLedgerV22,
    _capture_heldout_live_attempt_v22,
    _claim_kind_counts_v22,
    _heldout_failure_candidate_v22,
    secure_attempt_schedule_v22,
    write_deterministic_observations_v22,
    write_secure_attempts_v22,
)
from evaluation.heldout_mapper import build_heldout_mapper_requests
from evaluation.heldout_oracle_spec_v22 import (
    heldout_oracle_sha256_v22,
    load_heldout_release_oracle_v22,
)
from evaluation.release_spec_v2 import canonical_json_bytes

Json = dict[str, Any]


class TestSlotLedger:
    def test_chain_is_durable_and_ordered(self, tmp_path: Path) -> None:
        ledger = SecureSlotLedgerV22(tmp_path / "slots.jsonl", ledger_kind="secure")
        first = ledger.start_slot(
            {
                "arm": "canonical",
                "repetition": 1,
                "condition": "clean",
                "condition_order_index": 1,
                "call_index": 1,
                "candidate_id": "AP-001",
                "snapshot_id": "index-1",
            }
        )
        ledger.terminalize_slot(first, state="completed", row_sha256="a" * 64)
        second = ledger.start_slot(
            {
                "arm": "heldout",
                "repetition": 1,
                "condition": "clean",
                "condition_order_index": 1,
                "call_index": 1,
                "candidate_id": "AP-101",
                "snapshot_id": "heldout-clean-1",
            }
        )
        ledger.terminalize_slot(second, state="failed", row_sha256="b" * 64)
        with pytest.raises(CaptureV22Error, match="does not match the frozen schedule"):
            ledger.close(expected_slot_count=99)
        ledger.close(expected_slot_count=2)

        rows = [json.loads(line) for line in (tmp_path / "slots.jsonl").read_bytes().splitlines()]
        assert [row["event"] for row in rows] == [
            "ledger_genesis_v22",
            "slot_started_v22",
            "slot_terminal_v22",
            "slot_started_v22",
            "slot_terminal_v22",
            "ledger_final_v22",
        ]
        assert rows[1]["slot_index"] == 1
        assert rows[3]["slot_index"] == 2
        assert all(row["run_id"] == "v24-20260817-r1" for row in rows)
        chains = [row["chain_sha256"] for row in rows]
        assert len(set(chains)) == 6
        for row, previous in zip(rows[1:], rows[:-1], strict=True):
            assert row["prev_chain_sha256"] == previous["chain_sha256"]

    def test_existing_ledger_never_reissues_slots(self, tmp_path: Path) -> None:
        path = tmp_path / "slots.jsonl"
        path.write_bytes(b"{}\n")
        with pytest.raises(FileExistsError, match="never reissue"):
            SecureSlotLedgerV22(path, ledger_kind="secure")

    def test_open_slot_blocks_close_and_unmatched_terminal(self, tmp_path: Path) -> None:
        ledger = SecureSlotLedgerV22(tmp_path / "slots.jsonl", ledger_kind="secure")
        ledger.start_slot(
            {
                "arm": "canonical",
                "call_index": 1,
                "candidate_id": "AP-001",
                "snapshot_id": "index-1",
            }
        )
        with pytest.raises(CaptureV22Error, match="open slot"):
            ledger.close(expected_slot_count=1)
        with pytest.raises(CaptureV22Error, match="unmatched"):
            ledger.terminalize_slot(99, state="completed", row_sha256="a" * 64)
        with pytest.raises(CaptureV22Error, match="terminal state"):
            ledger.terminalize_slot(1, state="running", row_sha256="a" * 64)

    def test_descriptor_and_kind_are_bounded(self, tmp_path: Path) -> None:
        with pytest.raises(CaptureV22Error, match="closed vocabulary"):
            SecureSlotLedgerV22(tmp_path / "bad.jsonl", ledger_kind="mystery")
        ledger = SecureSlotLedgerV22(tmp_path / "slots.jsonl", ledger_kind="secure")
        with pytest.raises(CaptureV22Error, match="outside its bounds"):
            ledger.start_slot({"arm": object(), "call_index": 1})
        with pytest.raises(CaptureV22Error, match="outside its bounds"):
            ledger.start_slot({"arm": "canonical"})


class TestSchedule:
    def test_twelve_coordinates_canonical_then_heldout(self) -> None:
        schedule = secure_attempt_schedule_v22()
        assert len(schedule) == 12
        assert [item.arm for item in schedule[:6]] == ["canonical"] * 6
        assert [item.arm for item in schedule[6:]] == ["heldout"] * 6
        assert [item.condition for item in schedule[:6]] == [
            "clean",
            "directive",
            "directive",
            "clean",
            "clean",
            "directive",
        ]


class TestWriters:
    def test_secure_writer_requires_twelve_verdict_free_rows(self, tmp_path: Path) -> None:
        rows: list[Json] = [
            {"schema_version": 3, "run_id": "v24-20260817-r1", "row": index} for index in range(12)
        ]
        target = tmp_path / "secure-v22.jsonl"
        write_secure_attempts_v22(target, attempts=rows)
        assert len(target.read_bytes().splitlines()) == 12
        with pytest.raises(FileExistsError):
            write_secure_attempts_v22(target, attempts=rows)
        with pytest.raises(ValueError, match="exactly twelve"):
            write_secure_attempts_v22(tmp_path / "other.jsonl", attempts=rows[:11])
        poisoned = [dict(row) for row in rows]
        poisoned[3]["hard_gate_passed"] = True
        with pytest.raises(ValueError, match="producer verdicts"):
            write_secure_attempts_v22(tmp_path / "poisoned.jsonl", attempts=poisoned)

    def test_deterministic_writer_stamps_protocol(self, tmp_path: Path) -> None:
        from evaluation.oracle_spec_v22 import load_deterministic_oracle_v22

        oracle = load_deterministic_oracle_v22(Path("evaluation/oracle_v22.json"))
        target = tmp_path / "deterministic-v22.json"
        write_deterministic_observations_v22(
            target,
            observations=(),
            oracle=oracle,
            implementation_tree_sha256="c" * 64,
        )
        artifact = json.loads(target.read_bytes())
        assert artifact["schema_version"] == 3
        assert artifact["protocol_version"] == "2.2"
        assert artifact["run_id"] == "v24-20260817-r1"
        assert artifact["artifact_kind"] == "deterministic_observations_v22"
        with pytest.raises(FileExistsError):
            write_deterministic_observations_v22(
                target,
                observations=(),
                oracle=oracle,
                implementation_tree_sha256="c" * 64,
            )


class TestStagedDiagnostics:
    def test_every_mapper_failure_code_maps_to_a_closed_stage(self) -> None:
        assert set(MAPPER_STAGE_FAILURE_CODES_V22) == set(MapperFailureCode)
        for stage, code in MAPPER_STAGE_FAILURE_CODES_V22.values():
            assert stage in MAPPER_STAGES_V22
            assert code
            assert code.isascii()

    def test_failure_candidate_uses_closed_vocabulary_only(self) -> None:
        requests = build_heldout_mapper_requests(Path("."), condition="clean")
        candidate = _heldout_failure_candidate_v22(
            requests[0], stage="wire_conversion", code="wire_date_invalid"
        )
        assert candidate["outcome"] == "mapper_failure"
        assert candidate["failure_stage"] == "wire_conversion"
        assert candidate["failure_code"] == "wire_date_invalid"
        assert candidate["claims"] == []
        counts = cast(Json, candidate["claim_kind_counts"])
        assert sum(cast(int, value) for value in counts.values()) == 0
        with pytest.raises(CaptureV22Error, match="closed vocabulary"):
            _heldout_failure_candidate_v22(
                requests[0], stage="surprise_stage", code="wire_date_invalid"
            )

    def test_claim_kind_counters_bucket_unknown_kinds(self) -> None:
        counts = _claim_kind_counts_v22(
            (
                {"kind": "ap_years"},
                {"kind": "ap_years"},
                {"kind": "totally-new-kind"},
                {"kind": None},
            )
        )
        assert counts["ap_years"] == 2
        assert counts["unknown_kind"] == 2

    def test_heldout_attempt_records_stage_for_each_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Offline reproduction: a staged failure per candidate, no provider."""

        import evaluation.capture_v22 as capture_module

        monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
        requests = build_heldout_mapper_requests(Path("."), condition="clean")
        oracle = load_heldout_release_oracle_v22(Path("evaluation/heldout_release_oracle_v22.json"))
        failure_codes = iter(
            (
                MapperFailureCode.PROVIDER_TIMEOUT,
                MapperFailureCode.STRUCTURED_OUTPUT_INVALID,
                MapperFailureCode.WIRE_DATE_INVALID,
                MapperFailureCode.CANDIDATE_IDENTITY_MISMATCH,
            )
        )

        class FailingMapper:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def map_claims(self, request: object) -> object:
                del request
                raise MapperError("synthetic", code=next(failure_codes))

        monkeypatch.setattr(capture_module, "OpenAIResponsesMapper", FailingMapper)
        coordinate = next(item for item in secure_attempt_schedule_v22() if item.arm == "heldout")
        row = _capture_heldout_live_attempt_v22(
            coordinate,
            mapper_requests=requests,
            model_identifier="model_heldout",
            sdk_version="sdk_1.0",
            implementation_tree_sha256="c" * 64,
            fixture_tree_sha256=oracle.clean_fixture_tree_sha256,
            heldout_oracle_sha256=heldout_oracle_sha256_v22(oracle),
            mapper_timeout_seconds=30.0,
        )
        assert row["schema_version"] == 3
        assert row["protocol_version"] == "2.2"
        assert row["run_id"] == "v24-20260817-r1"
        result = cast(Json, row["result"])
        assert result["kind"] == "claims"
        observed = [
            (candidate["failure_stage"], candidate["failure_code"])
            for candidate in cast(list[Json], result["candidates"])
        ]
        assert observed == [
            ("provider_call", "provider_timeout"),
            ("structured_validation", "structured_output_invalid"),
            ("wire_conversion", "wire_date_invalid"),
            ("identity_validation", "candidate_identity_mismatch"),
        ]
        serialized = canonical_json_bytes(row).decode("utf-8")
        assert "synthetic" not in serialized

    def test_heldout_attempt_maps_successful_wire_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import evaluation.capture_v22 as capture_module
        from cv_trust_agent.models import ClaimKind, MappedClaim, MapperOutput, MapperRequest

        monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
        requests = build_heldout_mapper_requests(Path("."), condition="clean")
        oracle = load_heldout_release_oracle_v22(Path("evaluation/heldout_release_oracle_v22.json"))

        class EchoMapper:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def map_claims(self, request: MapperRequest) -> MapperOutput:
                from cv_trust_agent.models import SourceKind

                cited = next(
                    item.evidence_id
                    for item in request.evidence_catalog
                    if item.visible
                    and item.admissible
                    and item.source_kind is SourceKind.RESUME_VISIBLE
                )
                return MapperOutput(
                    candidate_id=request.candidate_id,
                    snapshot_id=request.snapshot_id,
                    claims=(
                        MappedClaim(
                            claim_id="wire:invoice_processing:1",
                            candidate_id=request.candidate_id,
                            snapshot_id=request.snapshot_id,
                            kind=ClaimKind.INVOICE_PROCESSING,
                            bool_value=True,
                            evidence_ids=(cited,),
                        ),
                    ),
                )

        monkeypatch.setattr(capture_module, "OpenAIResponsesMapper", EchoMapper)
        coordinate = next(item for item in secure_attempt_schedule_v22() if item.arm == "heldout")
        row = _capture_heldout_live_attempt_v22(
            coordinate,
            mapper_requests=requests,
            model_identifier="model_heldout",
            sdk_version="sdk_1.0",
            implementation_tree_sha256="c" * 64,
            fixture_tree_sha256=oracle.clean_fixture_tree_sha256,
            heldout_oracle_sha256=heldout_oracle_sha256_v22(oracle),
            mapper_timeout_seconds=30.0,
        )
        result = cast(Json, row["result"])
        candidates = cast(list[Json], result["candidates"])
        assert all(candidate["outcome"] == "mapped" for candidate in candidates)
        for candidate in candidates:
            counts = cast(Json, candidate["claim_kind_counts"])
            assert counts["invoice_processing"] == 1
            claims = cast(list[Json], candidate["claims"])
            assert len(claims) == 1
            spans = cast(list[str], claims[0]["citation_span_sha256"])
            assert all(len(span) == 64 for span in spans)

    def test_row_sha256_matches_staged_bytes(self, tmp_path: Path) -> None:
        payload = canonical_json_bytes({"schema_version": 3})
        assert hashlib.sha256(payload).hexdigest() == hashlib.sha256(payload).hexdigest()


class TestPerRequestSlots:
    def test_heldout_capture_opens_one_slot_per_provider_request(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import evaluation.capture_v22 as capture_module

        monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
        requests = build_heldout_mapper_requests(Path("."), condition="clean")
        oracle = load_heldout_release_oracle_v22(Path("evaluation/heldout_release_oracle_v22.json"))

        class FailingMapper:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def map_claims(self, request: object) -> object:
                del request
                raise MapperError("synthetic", code=MapperFailureCode.PROVIDER_TIMEOUT)

        monkeypatch.setattr(capture_module, "OpenAIResponsesMapper", FailingMapper)
        ledger = SecureSlotLedgerV22(tmp_path / "slots.jsonl", ledger_kind="secure")
        staged: list[bytes] = []
        coordinate = next(item for item in secure_attempt_schedule_v22() if item.arm == "heldout")
        _capture_heldout_live_attempt_v22(
            coordinate,
            mapper_requests=requests,
            model_identifier="model_heldout",
            sdk_version="sdk_1.0",
            implementation_tree_sha256="c" * 64,
            fixture_tree_sha256=oracle.clean_fixture_tree_sha256,
            heldout_oracle_sha256=heldout_oracle_sha256_v22(oracle),
            mapper_timeout_seconds=30.0,
            ledger=ledger,
            stage=staged.append,
        )
        ledger.close(expected_slot_count=4)

        rows = [json.loads(line) for line in (tmp_path / "slots.jsonl").read_bytes().splitlines()]
        started = [row for row in rows if row["event"] == "slot_started_v22"]
        terminal = [row for row in rows if row["event"] == "slot_terminal_v22"]
        assert len(started) == 4
        assert len(terminal) == 4
        assert [row["call_index"] for row in started] == [1, 2, 3, 4]
        assert all(row["state"] == "failed" for row in terminal)
        assert len(staged) == 4
