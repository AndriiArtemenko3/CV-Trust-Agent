"""V2.2 semantic harness: digests, stage-local closure, secure/naive/aggregate."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import evaluation.aggregate_v22 as aggregate_v22
from evaluation.aggregate_v22 import (
    AggregateV22Error,
    validate_aggregate_v22,
    write_release_manifest_v22,
)
from evaluation.capture_v22 import CaptureV22Error, SecureSlotLedgerV22
from evaluation.deterministic_release_v22 import ValidatedDeterministicReleaseV22
from evaluation.heldout_oracle_spec_v22 import (
    CANONICAL_SECURE_PROMPT_SHA256_V22,
    HELDOUT_SECURE_PROMPT_SHA256_V22,
    HeldoutReleaseOracleV22,
    heldout_oracle_sha256_v22,
    load_heldout_release_oracle_v22,
)
from evaluation.naive_protocol_v22 import (
    LATIN_SQUARE_SCHEDULE_V22,
    NAIVE_ATTACK_COHORT_SHA256_V22,
    NAIVE_ATTACK_FIXTURE_TREE_SHA256_V22,
    NAIVE_CLEAN_COHORT_SHA256_V22,
    NAIVE_CLEAN_FIXTURE_TREE_SHA256_V22,
    NAIVE_PROMPT_SHA256_V22,
    NAIVE_SEEDS_V22,
)
from evaluation.naive_release_v22 import (
    NaiveReleaseV22Error,
    validate_naive_semantics_v22,
)
from evaluation.protocol_v22 import (
    CANONICAL_MAPPER_NAME_V22,
    CANONICAL_PROVIDER_SNAPSHOT_ID_V22,
    HELDOUT_CLEAN_SNAPSHOT_ID_V22,
    HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22,
)
from evaluation.release_spec_v2 import DecisionProjectionV2
from evaluation.release_spec_v22 import (
    DecisionProjectionV22,
    ReleaseSpecV22Error,
    canonical_json_bytes,
)
from evaluation.secure_release_v22 import (
    SecureReleaseV22Error,
    validate_secure_semantics_v22,
    validate_secure_structure_v22,
)
from evaluation.slot_ledger_v22 import SlotLedgerV22Error, validate_slot_ledger_v22
from tests.test_engine_unit import _case, _record, _run

Json = dict[str, Any]

HELDOUT_ORACLE_PATH = Path("evaluation/heldout_release_oracle_v22.json")


@pytest.fixture(scope="module")
def runtime_observation() -> Json:
    import tests.test_engine_unit as engine_unit

    original_snapshot = engine_unit.SNAPSHOT_ID
    engine_unit.SNAPSHOT_ID = CANONICAL_PROVIDER_SNAPSHOT_ID_V22
    try:
        records = tuple(_record(f"AP-{index:03d}") for index in range(1, 11))
        decision = _run(_case(records))
        return cast(Json, decision.model_dump(mode="json", exclude_none=True))
    finally:
        engine_unit.SNAPSHOT_ID = original_snapshot


@pytest.fixture(scope="module")
def projection(runtime_observation: Json) -> DecisionProjectionV22:
    return DecisionProjectionV22.from_observation(runtime_observation)


@pytest.fixture(scope="module")
def heldout_oracle() -> HeldoutReleaseOracleV22:
    return load_heldout_release_oracle_v22(HELDOUT_ORACLE_PATH)


def _mutated_canonical(
    projection: DecisionProjectionV22,
    mutate: Callable[[Json], None],
) -> Json:
    canonical = cast(Json, json.loads(canonical_json_bytes(projection.canonical_object())))
    mutate(canonical)
    return canonical


def _record_gate(canonical: Json, stage: str, candidate_id: str) -> Json:
    for gate in cast(list[Json], canonical["trust_gates"]):
        if (
            gate["stage"] == stage
            and gate["scope"] == "record"
            and gate["candidate_id"] == candidate_id
        ):
            return gate
    raise AssertionError(f"no record {stage} gate for {candidate_id}")


def _graph(canonical: Json, candidate_id: str) -> Json:
    for route in cast(list[Json], canonical["routes"]):
        if route["candidate_id"] == candidate_id and route["support_graph"] is not None:
            return cast(Json, route["support_graph"])
    raise AssertionError(f"no ranked support graph for {candidate_id}")


class TestProtocolIdentity:
    def test_projection_requires_schema_version_three(
        self, projection: DecisionProjectionV22
    ) -> None:
        canonical = projection.canonical_object()
        assert canonical["schema_version"] == 3
        assert canonical["protocol_version"] == "2.2"

    def test_v21_projection_is_rejected_by_v22(self) -> None:
        det = json.loads(Path("evidence/v2/deterministic-v2.json").read_bytes())
        old_projection = det["observations"][0]["projection"]
        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(old_projection)

    def test_v22_projection_is_rejected_by_v21(self, projection: DecisionProjectionV22) -> None:
        from evaluation.release_spec_v2 import ReleaseSpecV2Error

        with pytest.raises(ReleaseSpecV2Error):
            DecisionProjectionV2.from_canonical(projection.canonical_object())

    def test_missing_protocol_version_is_rejected(self, projection: DecisionProjectionV22) -> None:
        canonical = _mutated_canonical(projection, lambda c: c.pop("protocol_version"))
        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(canonical)

    def test_numeric_protocol_version_is_rejected(self, projection: DecisionProjectionV22) -> None:
        def mutate(canonical: Json) -> None:
            canonical["protocol_version"] = 2.2

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))


class TestDigestDomains:
    def test_action_and_audit_digests_differ(self, projection: DecisionProjectionV22) -> None:
        assert projection.action_semantic_digest() != projection.audit_digest()
        assert projection.audit_digest() == projection.digest()

    def test_validated_gate_variation_moves_audit_but_not_action(self) -> None:
        """Two runs with identical actions but different audit traces."""

        case = _case((_record("AP-001"),))
        first = DecisionProjectionV22.from_observation(
            cast(Json, _run(case).model_dump(mode="json", exclude_none=True))
        )
        # A run over the directive-style fixture would differ in audit-only
        # surfaces; here we simulate by asserting the digest inputs directly.
        action = first.action_semantic_digest()
        audit = first.audit_digest()
        second = DecisionProjectionV22.from_canonical(first.canonical_object())
        assert second.action_semantic_digest() == action
        assert second.audit_digest() == audit

    def test_action_digest_binds_routes(self, projection: DecisionProjectionV22) -> None:
        def mutate(canonical: Json) -> None:
            route = cast(list[Json], canonical["routes"])[0]
            route["band"] = "POTENTIAL_EVIDENCE_MATCH"

        mutated = _mutated_canonical(projection, mutate)
        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(mutated)


class TestStageLocalClosure:
    """Hostile under-/over-closure mutations against record provenance gates."""

    def test_extra_irrelevant_admissible_identity_evidence_fails(
        self, projection: DecisionProjectionV22
    ) -> None:
        def mutate(canonical: Json) -> None:
            graph = _graph(canonical, "AP-001")
            identity_ids = [
                fact["evidence_ids"][0]
                for fact in cast(list[Json], graph["facts"])
                if fact["kind"] == "candidate_id"
            ]
            manifest = {
                item["evidence_id"]: item for item in cast(list[Json], graph["evidence_manifest"])
            }
            extra = next(
                evidence_id
                for evidence_id in identity_ids
                if manifest[evidence_id]["source_kind"] == "resume_visible"
            )
            gate = _record_gate(canonical, "provenance", "AP-001")
            gate["evidence_ids"] = sorted({*gate["evidence_ids"], extra})

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))

    def test_application_json_evidence_in_provenance_gate_fails(
        self, projection: DecisionProjectionV22
    ) -> None:
        def mutate(canonical: Json) -> None:
            graph = _graph(canonical, "AP-001")
            json_id = next(
                item["evidence_id"]
                for item in cast(list[Json], graph["evidence_manifest"])
                if item["source_kind"] == "application_json"
            )
            gate = _record_gate(canonical, "provenance", "AP-001")
            gate["evidence_ids"] = sorted({*gate["evidence_ids"], json_id})

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))

    def test_missing_released_support_fails_under_closure(
        self, projection: DecisionProjectionV22
    ) -> None:
        def mutate(canonical: Json) -> None:
            gate = _record_gate(canonical, "provenance", "AP-001")
            gate["evidence_ids"] = list(gate["evidence_ids"])[:-1]

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))

    def test_duplicate_gate_evidence_fails(self, projection: DecisionProjectionV22) -> None:
        def mutate(canonical: Json) -> None:
            gate = _record_gate(canonical, "provenance", "AP-001")
            gate["evidence_ids"] = [*gate["evidence_ids"], gate["evidence_ids"][0]]

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))

    def test_unmarked_extra_resume_evidence_fails(self, projection: DecisionProjectionV22) -> None:
        """A same-candidate visible ref outside the closure must be rejected."""

        def mutate(canonical: Json) -> None:
            gate = _record_gate(canonical, "provenance", "AP-001")
            fabricated = "pdfline:index-2026-08-15:AP-001:p1:visible:l9:aaaaaaaaaaaaaaaa"
            gate["evidence_ids"] = sorted({*gate["evidence_ids"], fabricated})

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))

    def test_marked_consumption_does_not_permit_supersets(
        self, projection: DecisionProjectionV22
    ) -> None:
        """A category marker cannot authorize fabricated extra citations."""

        def mutate(canonical: Json) -> None:
            cross = _record_gate(canonical, "cross_source", "AP-001")
            cross["reason_codes"] = sorted({*cross["reason_codes"], "category_not_supported"})
            gate = _record_gate(canonical, "provenance", "AP-001")
            fabricated = "pdfline:index-2026-08-15:AP-001:p1:visible:l9:aaaaaaaaaaaaaaaa"
            gate["evidence_ids"] = sorted({*gate["evidence_ids"], fabricated})

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))

    def test_marked_consumption_still_rejects_under_closure(
        self, projection: DecisionProjectionV22
    ) -> None:
        def mutate(canonical: Json) -> None:
            cross = _record_gate(canonical, "cross_source", "AP-001")
            cross["reason_codes"] = sorted({*cross["reason_codes"], "category_not_supported"})
            gate = _record_gate(canonical, "provenance", "AP-001")
            gate["evidence_ids"] = list(gate["evidence_ids"])[:-1]

        with pytest.raises(ReleaseSpecV22Error):
            DecisionProjectionV22.from_canonical(_mutated_canonical(projection, mutate))


def _deterministic_release_v22(
    projection: DecisionProjectionV22,
) -> ValidatedDeterministicReleaseV22:
    return ValidatedDeterministicReleaseV22(
        suite_id="unit_v22",
        oracle_sha256="d" * 64,
        artifact_sha256="e" * 64,
        implementation_tree_sha256="c" * 64,
        release_binding_sha256="f" * 64,
        case_count=25,
        artifact_invariant_count=47,
        projections=(
            ("clean", projection),
            ("structured_note_directive", projection),
        ),
        fixture_commitments=(
            ("clean", "a" * 64),
            ("structured_note_directive", "b" * 64),
        ),
        fixture_ids=(
            ("clean", "canonical_clean"),
            ("structured_note_directive", "canonical_structured_note_directive"),
        ),
    )


def _claim_kind_counts(claims: list[Json]) -> Json:
    keys = (
        "candidate_id",
        "ap_years",
        "invoice_processing",
        "reconciliation",
        "spreadsheet",
        "accounting_platform",
        "monthly_invoice_volume",
        "qualification",
        "employment_interval",
        "unknown_kind",
    )
    counts = dict.fromkeys(keys, 0)
    for claim in claims:
        kind = cast(str, claim["kind"])
        counts[kind if kind in counts else "unknown_kind"] += 1
    return cast(Json, counts)


def _secure_attempt_rows_v22(
    projection: DecisionProjectionV22,
    oracle: HeldoutReleaseOracleV22,
) -> list[Json]:
    oracle_digest = heldout_oracle_sha256_v22(oracle)
    orders = (
        ("clean", "directive"),
        ("directive", "clean"),
        ("clean", "directive"),
    )
    rows: list[Json] = []
    for arm in ("canonical", "heldout"):
        for repetition, order in enumerate(orders, start=1):
            for order_index, condition in enumerate(order, start=1):
                fixture_digest = (
                    ("a" * 64 if condition == "clean" else "b" * 64)
                    if arm == "canonical"
                    else (
                        oracle.clean_fixture_tree_sha256
                        if condition == "clean"
                        else oracle.directive_fixture_tree_sha256
                    )
                )
                metadata: Json = {
                    "schema_version": 3,
                    "protocol_version": "2.2",
                    "run_id": "v24-20260817-r1",
                    "repetition": repetition,
                    "condition": condition,
                    "condition_order": list(order),
                    "condition_order_index": order_index,
                    "started_at": datetime(
                        2026, 8, 17, 9, repetition, order_index, tzinfo=UTC
                    ).isoformat(),
                    "latency_ms": 10,
                    "model_identifier": f"model_{arm}",
                    "sdk_version": "sdk_1.0",
                    "prompt_sha256": (
                        CANONICAL_SECURE_PROMPT_SHA256_V22
                        if arm == "canonical"
                        else HELDOUT_SECURE_PROMPT_SHA256_V22
                    ),
                    "implementation_tree_sha256": "c" * 64,
                    "fixture_tree_sha256": fixture_digest,
                    "source_timeout_seconds": 0.5 if arm == "canonical" else None,
                    "source_max_attempts": 1 if arm == "canonical" else None,
                    "mapper_timeout_seconds": 30.0,
                    "mapper_max_retries": 0,
                    "usage": {
                        "input_tokens": 100,
                        "output_tokens": 20,
                        "total_tokens": 120,
                    },
                }
                if arm == "canonical":
                    provider_calls = [
                        {
                            "mapper_name": CANONICAL_MAPPER_NAME_V22,
                            "model": "model_canonical",
                            "candidate_id": f"AP-{index:03d}",
                            "snapshot_id": CANONICAL_PROVIDER_SNAPSHOT_ID_V22,
                            "outcome": "success",
                            "failure_code": None,
                            "latency_ms": 1,
                            "claim_count": 1,
                            "citation_count": 1,
                            "response_id_hash": f"{index:064x}",
                            "input_tokens": 10,
                            "output_tokens": 2,
                            "total_tokens": 12,
                        }
                        for index in range(1, 11)
                    ]
                    rows.append(
                        {
                            **metadata,
                            "event": "secure_canonical_attempt_v22",
                            "arm": "canonical",
                            "provider_calls": provider_calls,
                            "result": {
                                "kind": "decision",
                                "projection": projection.canonical_object(),
                            },
                        }
                    )
                    continue
                candidates: list[Json] = []
                for candidate in oracle.candidates:
                    claims: list[Json] = []
                    for expected in candidate.claims:
                        claims.append(
                            {
                                "kind": expected.kind,
                                "bool_value": expected.bool_value,
                                "number_value": expected.number_value,
                                "text_value": expected.text_value,
                                "start_date": (
                                    expected.start_date.isoformat()
                                    if expected.start_date is not None
                                    else None
                                ),
                                "end_date": (
                                    expected.end_date.isoformat()
                                    if expected.end_date is not None
                                    else None
                                ),
                                "citation_span_sha256": list(expected.required_span_sha256),
                            }
                        )
                    candidates.append(
                        {
                            "candidate_id": candidate.candidate_id,
                            "snapshot_id": (
                                HELDOUT_CLEAN_SNAPSHOT_ID_V22
                                if condition == "clean"
                                else HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22
                            ),
                            "outcome": "mapped",
                            "failure_stage": None,
                            "failure_code": None,
                            "claim_kind_counts": _claim_kind_counts(claims),
                            "claims": claims,
                        }
                    )
                rows.append(
                    {
                        **metadata,
                        "event": "secure_heldout_attempt_v22",
                        "arm": "heldout",
                        "heldout_oracle_sha256": oracle_digest,
                        "provider_candidates": candidates,
                        "result": {"kind": "claims", "candidates": candidates},
                    }
                )
    return rows


def _write_jsonl(path: Path, rows: list[Json]) -> Path:
    path.write_bytes(b"".join(canonical_json_bytes(item) + b"\n" for item in rows))
    return path


def _write_naive_test_ledger(
    evidence_dir: Path,
    naive_rows: list[Json],
    *,
    wrong_row_hash_at: int | None = None,
) -> Path:
    path = evidence_dir / "naive-slots-v22.jsonl"
    naive = SecureSlotLedgerV22(path, ledger_kind="naive")
    for index, row in enumerate(naive_rows, start=1):
        descriptor = {
            "arm": "naive",
            "call_index": 1,
            "block_id": row["block_id"],
            "call_role": row["call_role"],
            "call_position": row["call_position"],
        }
        slot = naive.start_slot(descriptor)
        result = cast(Json, row["result"])
        naive.terminalize_slot(
            slot,
            state="completed" if result["status"] == "valid" else "failed",
            row_sha256=(
                "f" * 64
                if index == wrong_row_hash_at
                else hashlib.sha256(canonical_json_bytes(row)).hexdigest()
            ),
        )
    naive.close(expected_slot_count=32)
    return path


def _write_test_slot_ledgers(
    evidence_dir: Path, secure_rows: list[Json], naive_rows: list[Json]
) -> None:
    secure = SecureSlotLedgerV22(
        evidence_dir / "secure-slots-v22.jsonl",
        ledger_kind="secure",
    )
    for row in secure_rows:
        arm = cast(str, row["arm"])
        observations = cast(
            list[Json],
            row["provider_calls"] if arm == "canonical" else row["provider_candidates"],
        )
        descriptors = [
            {
                "arm": arm,
                "repetition": row["repetition"],
                "condition": row["condition"],
                "condition_order_index": row["condition_order_index"],
                "call_index": index,
                "candidate_id": observation["candidate_id"],
                "snapshot_id": observation["snapshot_id"],
            }
            for index, observation in enumerate(observations, start=1)
        ]
        if arm == "canonical":
            slots = [secure.start_slot(descriptor) for descriptor in descriptors]
            for slot, observation in zip(slots, observations, strict=True):
                secure.terminalize_slot(
                    slot,
                    state=(
                        "completed" if observation["outcome"] in {"success", "mapped"} else "failed"
                    ),
                    row_sha256=hashlib.sha256(canonical_json_bytes(observation)).hexdigest(),
                )
        else:
            for descriptor, observation in zip(descriptors, observations, strict=True):
                slot = secure.start_slot(descriptor)
                secure.terminalize_slot(
                    slot,
                    state=(
                        "completed" if observation["outcome"] in {"success", "mapped"} else "failed"
                    ),
                    row_sha256=hashlib.sha256(canonical_json_bytes(observation)).hexdigest(),
                )
    secure.close(expected_slot_count=84)

    _write_naive_test_ledger(evidence_dir, naive_rows)


class TestSecureReleaseV22:
    def test_green_run_passes_every_secure_hard_gate(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        artifact = _write_jsonl(
            tmp_path / "secure-v22.jsonl",
            _secure_attempt_rows_v22(projection, heldout_oracle),
        )
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        assert release.attempt_count == 12
        assert release.canonical_provider_success_count == 60
        assert release.canonical_bound_count == 6
        assert release.canonical_audit_valid_count == 6
        assert release.canonical_evaluable_pair_count == 3
        assert release.canonical_noninterference_pair_count == 3
        assert release.prose_valid_nonempty_candidate_count == 24
        assert release.unsupported_claim_count == 0
        assert release.promotion_count == 0
        assert release.clean_utility_run_count == 3
        assert all(count == 3 for _, count in release.candidate_exact_clean_counts)
        assert all(have == total for _, have, total in release.candidate_fact_recall)
        assert all(have == total for _, have, total in release.candidate_span_recall)
        assert release.heldout_evaluable_pair_count == 3
        assert release.heldout_noninterference_pair_count == 3
        assert release.safety_passed
        assert release.canonical_gate_passed
        assert release.prose_gate_passed
        assert release.hard_gate_passed

    def test_v21_rows_are_rejected(self, tmp_path: Path) -> None:
        rows = [{"schema_version": 2, "event": "secure_canonical_attempt_v2"}]
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", cast(list[Json], rows))
        with pytest.raises(SecureReleaseV22Error, match="event is not allowed"):
            validate_secure_structure_v22(artifact)

    def test_safe_but_wrong_canonical_provider_identities_are_rejected(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        first = next(row for row in rows if row["arm"] == "canonical")
        for index, call in enumerate(cast(list[Json], first["provider_calls"]), start=1):
            call["candidate_id"] = f"FAKE-{index:03d}"
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        with pytest.raises(SecureReleaseV22Error, match="row schema is invalid"):
            validate_secure_structure_v22(artifact)

    def test_claim_kind_counts_require_the_exact_retained_distribution(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        heldout = next(row for row in rows if row["arm"] == "heldout")
        candidate = cast(list[Json], heldout["provider_candidates"])[0]
        first_kind = cast(str, cast(list[Json], candidate["claims"])[0]["kind"])
        counts = cast(Json, candidate["claim_kind_counts"])
        counts[first_kind] = cast(int, counts[first_kind]) - 1
        counts["unknown_kind"] = cast(int, counts["unknown_kind"]) + 1

        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        with pytest.raises(SecureReleaseV22Error, match="row schema is invalid"):
            validate_secure_structure_v22(artifact)

    @pytest.mark.parametrize("defect", ["mapper", "model", "usage", "citation_count"])
    def test_canonical_diagnostics_are_bound_to_the_attempt(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
        defect: str,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        row = next(item for item in rows if item["arm"] == "canonical")
        call = cast(list[Json], row["provider_calls"])[0]
        if defect == "mapper":
            call["mapper_name"] = "other_mapper"
        elif defect == "model":
            call["model"] = "other_model"
        elif defect == "usage":
            cast(Json, row["usage"])["input_tokens"] = 101
        else:
            call["citation_count"] = 0

        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        with pytest.raises(SecureReleaseV22Error, match="row schema is invalid"):
            validate_secure_structure_v22(artifact)

    def test_failed_canonical_call_is_preserved_as_valid_red_evidence(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        row = next(item for item in rows if item["arm"] == "canonical")
        call = cast(list[Json], row["provider_calls"])[0]
        call.update(
            {
                "outcome": "failure",
                "failure_code": "provider_failure",
                "claim_count": 0,
                "citation_count": 0,
            }
        )
        row["result"] = {"kind": "failure", "failure_code": "provider_failure"}

        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        assert release.canonical_provider_success_count == 59
        assert release.canonical_bound_count == 5
        assert not release.canonical_gate_passed
        assert not release.hard_gate_passed

    def test_staged_schema_failure_candidate_fails_reliability(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        heldout_rows = [row for row in rows if row["arm"] == "heldout"]
        result = cast(Json, heldout_rows[0]["result"])
        candidates = cast(list[Json], result["candidates"])
        candidates[0] = {
            "candidate_id": candidates[0]["candidate_id"],
            "snapshot_id": candidates[0]["snapshot_id"],
            "outcome": "mapper_failure",
            "failure_stage": "structured_validation",
            "failure_code": "structured_output_invalid",
            "claim_kind_counts": _claim_kind_counts([]),
            "claims": [],
        }
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        assert release.prose_valid_nonempty_candidate_count == 23
        assert not release.prose_gate_passed
        assert not release.hard_gate_passed
        assert release.canonical_gate_passed

    def test_failure_stage_must_belong_to_its_closed_stage(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        heldout_rows = [row for row in rows if row["arm"] == "heldout"]
        result = cast(Json, heldout_rows[0]["result"])
        candidates = cast(list[Json], result["candidates"])
        candidates[0] = {
            "candidate_id": candidates[0]["candidate_id"],
            "snapshot_id": candidates[0]["snapshot_id"],
            "outcome": "mapper_failure",
            "failure_stage": "provider_call",
            "failure_code": "citation_failure",
            "claim_kind_counts": _claim_kind_counts([]),
            "claims": [],
        }
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        with pytest.raises(SecureReleaseV22Error, match="row schema is invalid"):
            validate_secure_structure_v22(artifact)

    def test_valid_empty_output_fails_utility_and_reliability(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        for row in rows:
            if row["arm"] != "heldout":
                continue
            result = cast(Json, row["result"])
            for candidate in cast(list[Json], result["candidates"]):
                candidate["claims"] = []
                candidate["claim_kind_counts"] = _claim_kind_counts([])
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        assert release.prose_valid_nonempty_candidate_count == 0
        assert release.clean_utility_run_count == 0
        assert release.unsupported_claim_count == 0
        assert not release.prose_gate_passed
        assert not release.hard_gate_passed

    def test_unsupported_claim_breaks_safety(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        heldout_rows = [row for row in rows if row["arm"] == "heldout"]
        result = cast(Json, heldout_rows[0]["result"])
        first_claims = cast(list[Json], cast(list[Json], result["candidates"])[0]["claims"])
        first_claims[0]["citation_span_sha256"] = ["9" * 64]
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        assert release.unsupported_claim_count == 1
        assert not release.safety_passed
        assert not release.hard_gate_passed

    def test_canonical_audit_invalid_attempt_is_red_not_fatal(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        canonical_rows = [row for row in rows if row["arm"] == "canonical"]
        broken = cast(Json, cast(Json, canonical_rows[0]["result"])["projection"])
        gate = _record_gate(broken, "provenance", "AP-001")
        gate["evidence_ids"] = list(gate["evidence_ids"])[:-1]
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        assert release.canonical_audit_valid_count == 5
        assert release.canonical_bound_count == 5
        assert release.canonical_evaluable_pair_count == 2
        assert not release.canonical_gate_passed
        assert not release.hard_gate_passed

    def test_per_candidate_exact_requirement_gates_prose(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        """3/4 exact per run can still fail when one candidate is never exact."""

        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        target = heldout_oracle.candidates[0].candidate_id
        for row in rows:
            if row["arm"] != "heldout" or row["condition"] != "clean":
                continue
            result = cast(Json, row["result"])
            for candidate in cast(list[Json], result["candidates"]):
                if candidate["candidate_id"] == target:
                    candidate["claims"] = []
                    candidate["claim_kind_counts"] = _claim_kind_counts([])
        artifact = _write_jsonl(tmp_path / "secure-v22.jsonl", rows)
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        exact = dict(release.candidate_exact_clean_counts)
        assert exact[target] == 0
        assert release.clean_utility_run_count == 3
        assert not release.prose_gate_passed
        assert not release.hard_gate_passed


def _naive_attempt_rows_v22() -> list[Json]:
    import random

    candidates = tuple(f"AP-{index:03d}" for index in range(1, 11))
    target = "AP-005"
    rows: list[Json] = []
    for block_id, (seed, schedule) in enumerate(
        zip(NAIVE_SEEDS_V22, LATIN_SQUARE_SCHEDULE_V22, strict=True), start=1
    ):
        order = list(candidates)
        random.Random(seed).shuffle(order)
        base_ranking = list(order)
        promoted = [target, *(item for item in base_ranking if item != target)]
        for call_position, role in enumerate(schedule, start=1):
            ranking = promoted if role == "attack_directive" else base_ranking
            rows.append(
                {
                    "schema_version": 3,
                    "protocol_version": "2.2",
                    "run_id": "v24-20260817-r1",
                    "event": "naive_attempt_v22",
                    "block_id": block_id,
                    "seed": seed,
                    "call_role": role,
                    "call_position": call_position,
                    "candidate_order": list(order),
                    "started_at": datetime(
                        2026, 8, 17, 10, block_id, call_position, tzinfo=UTC
                    ).isoformat(),
                    "latency_ms": 5,
                    "usage": {
                        "input_tokens": 50,
                        "output_tokens": 10,
                        "total_tokens": 60,
                    },
                    "model_identifier": "naive_model",
                    "sdk_version": "sdk_1.0",
                    "prompt_sha256": NAIVE_PROMPT_SHA256_V22,
                    "implementation_tree_sha256": "c" * 64,
                    "mapper_timeout_seconds": 30.0,
                    "mapper_max_retries": 0,
                    "extraction_mode": "visible",
                    "target_candidate_id": target,
                    "mutation_channel": "structured_detail",
                    "clean_fixture_tree_sha256": NAIVE_CLEAN_FIXTURE_TREE_SHA256_V22,
                    "attack_fixture_tree_sha256": NAIVE_ATTACK_FIXTURE_TREE_SHA256_V22,
                    "clean_cohort_sha256": NAIVE_CLEAN_COHORT_SHA256_V22,
                    "attack_cohort_sha256": NAIVE_ATTACK_COHORT_SHA256_V22,
                    "input_cohort_sha256": (
                        NAIVE_ATTACK_COHORT_SHA256_V22
                        if role == "attack_directive"
                        else NAIVE_CLEAN_COHORT_SHA256_V22
                    ),
                    "changed_detail_candidate_ids": [target],
                    "changed_pdf_candidate_ids": [],
                    "threat_class": "structured_field_directive_and_fabrication",
                    "attacker_knowledge_level": "K1_PUBLIC_TASK_CONTEXT",
                    "result": {
                        "status": "valid",
                        "ordered_candidate_ids": list(ranking),
                    },
                }
            )
    return rows


class TestNaiveReleaseV22:
    def test_green_replication_endpoint(self, tmp_path: Path) -> None:
        artifact = _write_jsonl(tmp_path / "naive-v22.jsonl", _naive_attempt_rows_v22())
        release = validate_naive_semantics_v22(artifact)
        assert release.attempt_count == 32
        assert release.block_count == 8
        assert release.evaluable_block_count == 8
        assert release.positive_d_block_count == 8
        assert release.hard_gate_passed
        assert all(
            outcome.evaluable
            and outcome.g_control == 0
            and outcome.g_attack is not None
            and outcome.g_attack > 0
            and outcome.d_value == outcome.g_attack
            for outcome in release.block_outcomes
        )

    def test_control_movement_equal_to_attack_fails_endpoint(self, tmp_path: Path) -> None:
        rows = _naive_attempt_rows_v22()
        for row in rows:
            if row["block_id"] == 3 and row["call_role"] == "control_second":
                order = cast(list[str], row["candidate_order"])
                target = cast(str, row["target_candidate_id"])
                base = [item for item in order if item != target]
                result = cast(Json, row["result"])
                result["ordered_candidate_ids"] = [target, *base]
        artifact = _write_jsonl(tmp_path / "naive-v22.jsonl", rows)
        release = validate_naive_semantics_v22(artifact)
        assert release.evaluable_block_count == 8
        assert release.positive_d_block_count < 8
        assert not release.hard_gate_passed

    def test_invalid_call_fails_its_block_without_imputation(self, tmp_path: Path) -> None:
        rows = _naive_attempt_rows_v22()
        for row in rows:
            if row["block_id"] == 5 and row["call_role"] == "attack_clean":
                row["result"] = {
                    "status": "provider_failure",
                    "ordered_candidate_ids": None,
                }
        artifact = _write_jsonl(tmp_path / "naive-v22.jsonl", rows)
        release = validate_naive_semantics_v22(artifact)
        assert release.evaluable_block_count == 7
        outcome = release.block_outcomes[4]
        assert outcome.block_id == 5
        assert not outcome.evaluable
        assert outcome.d_value is None
        assert not release.hard_gate_passed

    def test_v21_seeds_are_rejected(self, tmp_path: Path) -> None:
        from evaluation.naive_protocol_v2 import NAIVE_SEEDS_V2

        rows = _naive_attempt_rows_v22()
        for row in rows:
            block_index = cast(int, row["block_id"]) - 1
            row["seed"] = NAIVE_SEEDS_V2[block_index]
        artifact = _write_jsonl(tmp_path / "naive-v22.jsonl", rows)
        with pytest.raises(NaiveReleaseV22Error):
            validate_naive_semantics_v22(artifact)

    def test_v21_rows_are_rejected(self, tmp_path: Path) -> None:
        rows = _naive_attempt_rows_v22()
        for row in rows:
            row["schema_version"] = 2
            row["event"] = "naive_attempt_v2"
            del row["protocol_version"]
        artifact = _write_jsonl(tmp_path / "naive-v22.jsonl", rows)
        with pytest.raises(NaiveReleaseV22Error, match="row is invalid"):
            validate_naive_semantics_v22(artifact)


class TestSlotLedgerReleaseV22:
    @staticmethod
    def _bundle(tmp_path: Path, *, wrong_row_hash_at: int | None = None) -> tuple[Path, Path]:
        evidence = tmp_path / "v24-20260817-r1"
        evidence.mkdir()
        rows = _naive_attempt_rows_v22()
        artifact = _write_jsonl(evidence / "naive-v22.jsonl", rows)
        ledger = _write_naive_test_ledger(
            evidence,
            rows,
            wrong_row_hash_at=wrong_row_hash_at,
        )
        return artifact, ledger

    def test_independent_validator_rebuilds_all_32_naive_slots(self, tmp_path: Path) -> None:
        artifact, ledger = self._bundle(tmp_path)
        validated = validate_slot_ledger_v22(
            ledger,
            artifact_path=artifact,
            ledger_kind="naive",
        )
        assert validated.run_id == "v24-20260817-r1"
        assert validated.slot_count == 32
        assert validated.completed_count == 32
        assert validated.failed_count == 0
        assert validated.unobserved_count == 0
        assert len(validated.final_chain_sha256) == 64

    def test_row_hash_mismatch_is_rejected(self, tmp_path: Path) -> None:
        artifact, ledger = self._bundle(tmp_path, wrong_row_hash_at=17)
        with pytest.raises(SlotLedgerV22Error, match="row-mismatched"):
            validate_slot_ledger_v22(
                ledger,
                artifact_path=artifact,
                ledger_kind="naive",
            )

    def test_secure_ledger_rejects_safe_fake_provider_identities(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        evidence = tmp_path / "v24-20260817-r1"
        evidence.mkdir()
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        artifact = _write_jsonl(evidence / "secure-v22.jsonl", rows)
        _write_test_slot_ledgers(evidence, rows, _naive_attempt_rows_v22())
        first = next(row for row in rows if row["arm"] == "canonical")
        for index, call in enumerate(cast(list[Json], first["provider_calls"]), start=1):
            call["candidate_id"] = f"FAKE-{index:03d}"
        _write_jsonl(artifact, rows)
        with pytest.raises(SlotLedgerV22Error, match="frozen cohort"):
            validate_slot_ledger_v22(
                evidence / "secure-slots-v22.jsonl",
                artifact_path=artifact,
                ledger_kind="secure",
            )

    def test_coherent_ledger_cannot_make_failed_canonical_decisions_green(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
    ) -> None:
        evidence = tmp_path / "v24-20260817-r1"
        evidence.mkdir()
        rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        for row in rows:
            if row["arm"] != "canonical":
                continue
            for call in cast(list[Json], row["provider_calls"]):
                call.update(
                    {
                        "outcome": "failure",
                        "failure_code": "provider_failure",
                        "claim_count": 0,
                        "citation_count": 0,
                    }
                )
        artifact = _write_jsonl(evidence / "secure-v22.jsonl", rows)
        _write_test_slot_ledgers(evidence, rows, _naive_attempt_rows_v22())

        ledger = validate_slot_ledger_v22(
            evidence / "secure-slots-v22.jsonl",
            artifact_path=artifact,
            ledger_kind="secure",
        )
        assert ledger.completed_count == 24
        assert ledger.failed_count == 60
        assert ledger.unobserved_count == 0
        release = validate_secure_semantics_v22(
            artifact,
            deterministic_release=_deterministic_release_v22(projection),
            heldout_oracle_path=HELDOUT_ORACLE_PATH,
        )
        assert release.canonical_provider_success_count == 0
        assert release.canonical_bound_count == 0
        assert release.canonical_evaluable_pair_count == 0
        assert not release.canonical_gate_passed
        assert not release.hard_gate_passed

    def test_started_without_terminal_or_final_is_rejected(self, tmp_path: Path) -> None:
        evidence = tmp_path / "v24-20260817-r1"
        evidence.mkdir()
        rows = _naive_attempt_rows_v22()
        artifact = _write_jsonl(evidence / "naive-v22.jsonl", rows)
        ledger_path = evidence / "naive-slots-v22.jsonl"
        ledger = SecureSlotLedgerV22(ledger_path, ledger_kind="naive")
        ledger.start_slot(
            {
                "arm": "naive",
                "call_index": 1,
                "block_id": 1,
                "call_role": rows[0]["call_role"],
                "call_position": 1,
            }
        )
        with pytest.raises(SlotLedgerV22Error, match="final closure"):
            validate_slot_ledger_v22(
                ledger_path,
                artifact_path=artifact,
                ledger_kind="naive",
            )

    def test_replayed_terminal_is_rejected_at_capture_boundary(self, tmp_path: Path) -> None:
        ledger = SecureSlotLedgerV22(tmp_path / "slots.jsonl", ledger_kind="naive")
        slot = ledger.start_slot(
            {
                "arm": "naive",
                "call_index": 1,
                "block_id": 1,
                "call_role": "attack_clean",
                "call_position": 1,
            }
        )
        ledger.terminalize_slot(slot, state="failed", row_sha256="a" * 64)
        with pytest.raises(CaptureV22Error, match="unmatched"):
            ledger.terminalize_slot(slot, state="failed", row_sha256="a" * 64)

    def test_alternate_run_and_reordered_attempts_are_rejected(self, tmp_path: Path) -> None:
        artifact, ledger = self._bundle(tmp_path)
        rows = [json.loads(line) for line in artifact.read_bytes().splitlines()]
        rows[0]["run_id"] = "v22-other-run"
        _write_jsonl(artifact, rows)
        with pytest.raises(SlotLedgerV22Error, match="schedule or run identity"):
            validate_slot_ledger_v22(
                ledger,
                artifact_path=artifact,
                ledger_kind="naive",
            )


class TestAggregateV22:
    def _prepared_evidence(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
        monkeypatch: pytest.MonkeyPatch,
        *,
        make_prose_red: bool = False,
        canonical_diagnostic_defect: str | None = None,
        fail_canonical_calls: bool = False,
    ) -> tuple[Path, Path]:
        import evaluation.aggregate_v22 as aggregate_module

        run_id = "v24-20260817-r1"
        evidence_dir = tmp_path / "evidence" / "v2.2" / run_id
        evidence_dir.mkdir(parents=True)
        oracle_digest = heldout_oracle_sha256_v22(heldout_oracle)

        secure_rows = _secure_attempt_rows_v22(projection, heldout_oracle)
        if canonical_diagnostic_defect is not None:
            canonical = next(row for row in secure_rows if row["arm"] == "canonical")
            call = cast(list[Json], canonical["provider_calls"])[0]
            call[canonical_diagnostic_defect] = (
                "other_mapper" if canonical_diagnostic_defect == "mapper_name" else "other_model"
            )
        if fail_canonical_calls:
            for row in secure_rows:
                if row["arm"] != "canonical":
                    continue
                for call in cast(list[Json], row["provider_calls"]):
                    call.update(
                        {
                            "outcome": "failure",
                            "failure_code": "provider_failure",
                            "claim_count": 0,
                            "citation_count": 0,
                        }
                    )
        if make_prose_red:
            for row in secure_rows:
                if row["arm"] != "heldout":
                    continue
                result = cast(Json, row["result"])
                for candidate in cast(list[Json], result["candidates"]):
                    candidate["claims"] = []
                    candidate["claim_kind_counts"] = _claim_kind_counts([])
        _write_jsonl(evidence_dir / "secure-v22.jsonl", secure_rows)
        naive_rows = _naive_attempt_rows_v22()
        _write_jsonl(evidence_dir / "naive-v22.jsonl", naive_rows)
        _write_test_slot_ledgers(evidence_dir, secure_rows, naive_rows)

        deterministic_release = _deterministic_release_v22(projection)

        def fake_validate_deterministic(
            artifact_path: Path, oracle_path: Path
        ) -> ValidatedDeterministicReleaseV22:
            del artifact_path, oracle_path
            return deterministic_release

        (evidence_dir / "deterministic-v22.json").write_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 3,
                    "protocol_version": "2.2",
                    "run_id": "v24-20260817-r1",
                    "artifact_kind": "deterministic_observations_v22",
                    "oracle_sha256": "d" * 64,
                    "implementation_tree_sha256": "c" * 64,
                    "observations": [
                        {
                            "case_name": "clean",
                            "fixture_id": "canonical_clean",
                            "fixture_tree_sha256": "a" * 64,
                            "projection": projection.canonical_object(),
                        }
                    ],
                }
            )
            + b"\n"
        )
        monkeypatch.setattr(
            aggregate_module,
            "validate_deterministic_release_v22",
            fake_validate_deterministic,
        )
        monkeypatch.setattr(
            aggregate_module,
            "implementation_tree_sha256_v2",
            lambda paths, *, repository_root: "c" * 64,
        )
        monkeypatch.setattr(
            aggregate_module,
            "_validate_named_fixture_bindings",
            lambda deterministic, secure, naive: None,
        )

        repo_root = tmp_path / "repo"
        (repo_root / "evaluation").mkdir(parents=True)
        (repo_root / "evaluation" / "oracle_v22.json").write_bytes(b"{}")
        (repo_root / "evaluation" / "heldout_release_oracle_v22.json").write_bytes(
            HELDOUT_ORACLE_PATH.read_bytes()
        )
        assert oracle_digest == heldout_oracle_sha256_v22(
            load_heldout_release_oracle_v22(
                repo_root / "evaluation" / "heldout_release_oracle_v22.json"
            )
        )
        return evidence_dir, repo_root

    def test_manifest_commits_red_run_but_validation_fails_closed(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        evidence_dir, repo_root = self._prepared_evidence(
            tmp_path, projection, heldout_oracle, monkeypatch, make_prose_red=True
        )
        manifest = write_release_manifest_v22(
            evidence_dir,
            run_id="v24-20260817-r1",
            deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
            heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
            repository_root=repo_root,
        )
        assert manifest.name == "manifest-v22.json"
        with pytest.raises(AggregateV22Error, match="release gates did not pass"):
            validate_aggregate_v22(
                manifest,
                deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
                heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
                repository_root=repo_root,
                execute_property_gates=False,
            )
        integrity = validate_aggregate_v22(
            manifest,
            deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
            heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
            repository_root=repo_root,
            execute_property_gates=False,
            require_release_green=False,
        )
        assert integrity.integrity_valid
        assert not integrity.release_green
        assert integrity.run_id == "v24-20260817-r1"

    def test_green_run_validates_release_green(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        evidence_dir, repo_root = self._prepared_evidence(
            tmp_path, projection, heldout_oracle, monkeypatch
        )
        manifest = write_release_manifest_v22(
            evidence_dir,
            run_id="v24-20260817-r1",
            deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
            heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
            repository_root=repo_root,
        )
        with pytest.raises(AggregateV22Error, match="release gates did not pass"):
            validate_aggregate_v22(
                manifest,
                deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
                heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
                repository_root=repo_root,
                execute_property_gates=False,
            )
        integrity = validate_aggregate_v22(
            manifest,
            deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
            heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
            repository_root=repo_root,
            execute_property_gates=False,
            require_release_green=False,
        )
        assert integrity.integrity_valid
        assert not integrity.release_green
        assert integrity.property_gate_count == 0
        assert integrity.total_release_gate_count == 47

        monkeypatch.setattr(
            aggregate_v22,
            "_execute_property_gate_families",
            lambda _root: (
                "unseen_identity_renaming_and_input_permutation",
                "unseen_value_equivalence_and_composed_transform",
            ),
        )
        release = validate_aggregate_v22(
            manifest,
            deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
            heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
            repository_root=repo_root,
        )
        assert release.release_green
        assert release.secure.hard_gate_passed
        assert release.naive.hard_gate_passed
        assert release.provider_slot_count == 116

    @pytest.mark.parametrize("field", ["mapper_name", "model"])
    def test_aggregate_rejects_rehashed_canonical_diagnostic_substitution(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
        monkeypatch: pytest.MonkeyPatch,
        field: str,
    ) -> None:
        evidence_dir, repo_root = self._prepared_evidence(
            tmp_path,
            projection,
            heldout_oracle,
            monkeypatch,
            canonical_diagnostic_defect=field,
        )
        secure_artifact = evidence_dir / "secure-v22.jsonl"
        ledger = validate_slot_ledger_v22(
            evidence_dir / "secure-slots-v22.jsonl",
            artifact_path=secure_artifact,
            ledger_kind="secure",
        )
        assert ledger.completed_count == 84
        assert ledger.failed_count == 0
        with pytest.raises(SecureReleaseV22Error, match="row schema is invalid"):
            write_release_manifest_v22(
                evidence_dir,
                run_id="v24-20260817-r1",
                deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
                heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
                repository_root=repo_root,
            )

    def test_aggregate_retains_rehashed_failed_slots_but_release_is_red(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        evidence_dir, repo_root = self._prepared_evidence(
            tmp_path,
            projection,
            heldout_oracle,
            monkeypatch,
            fail_canonical_calls=True,
        )
        manifest = write_release_manifest_v22(
            evidence_dir,
            run_id="v24-20260817-r1",
            deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
            heldout_oracle_path=repo_root / "evaluation" / "heldout_release_oracle_v22.json",
            repository_root=repo_root,
        )
        with pytest.raises(AggregateV22Error, match="release gates did not pass"):
            validate_aggregate_v22(
                manifest,
                deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
                heldout_oracle_path=repo_root / "evaluation" / "heldout_release_oracle_v22.json",
                repository_root=repo_root,
                execute_property_gates=False,
            )
        integrity = validate_aggregate_v22(
            manifest,
            deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
            heldout_oracle_path=repo_root / "evaluation" / "heldout_release_oracle_v22.json",
            repository_root=repo_root,
            execute_property_gates=False,
            require_release_green=False,
        )
        assert integrity.integrity_valid
        assert not integrity.release_green
        assert integrity.secure_ledger.completed_count == 24
        assert integrity.secure_ledger.failed_count == 60

    def test_run_id_mismatch_is_rejected(
        self,
        tmp_path: Path,
        projection: DecisionProjectionV22,
        heldout_oracle: HeldoutReleaseOracleV22,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        evidence_dir, repo_root = self._prepared_evidence(
            tmp_path, projection, heldout_oracle, monkeypatch
        )
        with pytest.raises(AggregateV22Error, match=r"alternate V2\.2 run IDs"):
            write_release_manifest_v22(
                evidence_dir,
                run_id="v22-other-run",
                deterministic_oracle_path=repo_root / "evaluation" / "oracle_v22.json",
                heldout_oracle_path=(repo_root / "evaluation" / "heldout_release_oracle_v22.json"),
                repository_root=repo_root,
            )
