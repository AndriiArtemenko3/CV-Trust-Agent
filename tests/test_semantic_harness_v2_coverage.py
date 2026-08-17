"""Hostile coverage for the independently derived V2 release semantics.

These tests deliberately mutate a valid runtime-derived projection.  They are
not a second implementation of the ranker: each mutation asserts that the
release specification rejects producer-authored semantics which no longer
follow from the bounded evidence and execution ledger.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import evaluation.aggregate_v2 as aggregate_v2
from cv_trust_agent.engine import TrustedAgentEngine
from cv_trust_agent.mappers import DeterministicMapper
from cv_trust_agent.models import (
    ClaimKind,
    ReasonCode,
    UnavailableCandidate,
    UnavailableComponent,
)
from evaluation.aggregate_v2 import AggregateV2Error, validate_aggregate_v2
from evaluation.deterministic_release_v2 import (
    DeterministicReleaseV2Error,
    ValidatedDeterministicReleaseV2,
    validate_deterministic_release_v2,
    validate_deterministic_semantics_v2,
    validate_deterministic_structure_v2,
)
from evaluation.heldout_oracle_spec_v2 import (
    CANONICAL_SECURE_PROMPT_SHA256_V2,
    HELDOUT_SECURE_PROMPT_SHA256_V2,
    heldout_oracle_sha256_v2,
    load_heldout_release_oracle_v2,
)
from evaluation.naive_protocol_v2 import (
    LATIN_SQUARE_SCHEDULE_V2,
    NAIVE_ATTACK_COHORT_SHA256_V2,
    NAIVE_ATTACK_FIXTURE_TREE_SHA256_V2,
    NAIVE_CLEAN_COHORT_SHA256_V2,
    NAIVE_CLEAN_FIXTURE_TREE_SHA256_V2,
    NAIVE_PROMPT_SHA256_V2,
    NAIVE_SEEDS_V2,
)
from evaluation.naive_release_v2 import (
    NaiveReleaseV2Error,
    NaiveSeriesMetricsV2,
    ValidatedNaiveReleaseV2,
    validate_naive_semantics_v2,
    validate_naive_structure_v2,
)
from evaluation.oracle_spec_v2 import (
    DeterministicOracleV2,
    oracle_sha256_v2,
)
from evaluation.property_gate_runner import PropertyGateRunnerError
from evaluation.release_spec_v2 import (
    CommandV2,
    CorroborationRequestV2,
    DecisionProjectionV2,
    DerivedFeatureV2,
    EvidenceRefV2,
    ExplanationV2,
    PlanDiffV2,
    PlanV2,
    ReceiptV2,
    ReleaseSpecV2Error,
    RouteV2,
    SupportedEmploymentIntervalV2,
    SupportedFactV2,
    SupportGraphV2,
    TrustGateV2,
    canonical_json_bytes,
    canonical_value_sha256,
    implementation_tree_sha256_v2,
    load_strict_json_object,
)
from evaluation.secure_release_v2 import (
    SecureArmConfigurationV2,
    SecureReleaseV2Error,
    ValidatedSecureReleaseV2,
    validate_secure_semantics_v2,
    validate_secure_structure_v2,
)
from tests.test_engine_unit import (
    SNAPSHOT_ID,
    _case,
    _record,
    _replace_record,
    _request_and_output,
    _resume_hash,
    _run,
    _StaticProvider,
)

Json = dict[str, Any]
Mutation = Callable[[Json], None]


@pytest.fixture(scope="module")
def runtime_observation() -> Json:
    decision = _run(_case((_record("AP-001"),)))
    return cast(Json, decision.model_dump(mode="json", exclude_none=True))


@pytest.fixture(scope="module")
def projection(runtime_observation: Json) -> DecisionProjectionV2:
    return DecisionProjectionV2.from_observation(runtime_observation)


@pytest.fixture(scope="module")
def ten_candidate_projection() -> DecisionProjectionV2:
    records = tuple(_record(f"AP-{index:03d}") for index in range(1, 11))
    decision = _run(_case(records))
    observation = cast(Json, decision.model_dump(mode="json", exclude_none=True))
    return DecisionProjectionV2.from_observation(observation)


@pytest.fixture(scope="module")
def supported_projection() -> DecisionProjectionV2:
    case = _case((_record("AP-001"), _record("AP-002"), _record("AP-003")))
    output = case.outputs[(SNAPSHOT_ID, "AP-002")]
    claims = tuple(
        claim.model_copy(update={"evidence_ids": (claim.evidence_ids[0],)})
        if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL
        else claim
        for claim in output.claims
    )
    outputs = dict(case.outputs)
    outputs[(SNAPSHOT_ID, "AP-002")] = output.model_copy(update={"claims": claims})
    decision = _run(case, outputs=outputs)
    return DecisionProjectionV2.from_observation(
        cast(Json, decision.model_dump(mode="json", exclude_none=True))
    )


@pytest.fixture(scope="module")
def partial_projection() -> DecisionProjectionV2:
    case = _case((_record("AP-001"), _record("AP-002"), _record("AP-009")))
    unavailable = (
        UnavailableCandidate(
            candidate_id="AP-009",
            component=UnavailableComponent.RESUME,
            reason=ReasonCode.PARSING_FAILED,
        ),
    )
    engine = TrustedAgentEngine(DeterministicMapper(case.outputs))
    decision = engine.execute(
        engine.start(case.index, run_id="run-v2-partial"),
        _StaticProvider(
            records=case.records,
            requests=case.requests,
            unavailable_candidates=unavailable,
        ),
    )
    return DecisionProjectionV2.from_observation(
        decision.model_dump(mode="json", exclude_none=True)
    )


@pytest.fixture(scope="module")
def hold_projection() -> DecisionProjectionV2:
    healthy = _record("AP-001")
    conflict_target = _record("AP-005", ap_years=1.5)
    unavailable_record = _record("AP-009")
    base = _case((healthy, conflict_target, unavailable_record))
    poisoned = _replace_record(conflict_target, ap_years=8.0)
    poisoned_request, poisoned_output = _request_and_output(
        poisoned,
        snapshot_id=SNAPSHOT_ID,
        document_hash=_resume_hash(poisoned.candidate_id),
        claim_values={ClaimKind.AP_YEARS: 1.5},
    )
    unavailable = (
        UnavailableCandidate(
            candidate_id="AP-009",
            component=UnavailableComponent.DETAIL,
            reason=ReasonCode.RETRIEVAL_FAILED,
        ),
    )
    engine = TrustedAgentEngine(
        DeterministicMapper(
            {
                (SNAPSHOT_ID, healthy.candidate_id): base.outputs[
                    (SNAPSHOT_ID, healthy.candidate_id)
                ],
                (SNAPSHOT_ID, poisoned.candidate_id): poisoned_output,
            }
        )
    )
    decision = engine.execute(
        engine.start(base.index, run_id="run-v2-hold"),
        _StaticProvider(
            records=(healthy, poisoned, unavailable_record),
            requests=(base.requests[0], poisoned_request, base.requests[2]),
            unavailable_candidates=unavailable,
        ),
    )
    return DecisionProjectionV2.from_observation(
        decision.model_dump(mode="json", exclude_none=True)
    )


def _completed_command_kinds(projection: DecisionProjectionV2) -> set[str]:
    commands = {
        (plan.version, command.command_id): command.kind
        for plan in projection.plans
        for command in plan.commands
    }
    return {
        commands[(receipt.plan_version, receipt.command_id)]
        for receipt in projection.receipts
        if receipt.status == "completed"
    }


def _route_expectation(route: Json) -> Json:
    return {
        "candidate_id": route["candidate_id"],
        "band": route["band"],
        "queue": route["queue"],
        "evidence_rank": route["evidence_rank"],
        "display_position": route["display_position"],
        "rank_key": route["rank_key"],
    }


def _deterministic_oracle_and_artifact(
    tmp_path: Path,
    projection: DecisionProjectionV2,
) -> tuple[Path, Path, DeterministicOracleV2]:
    routes = [
        _route_expectation(route)
        for route in cast(list[Json], projection.canonical_object()["routes"])
    ]
    explanations = [
        explanation.model_dump(mode="json", exclude_none=False)
        for explanation in projection.explanations
    ]
    assert "release_output" in _completed_command_kinds(projection)
    completed = ["release_output"]
    fixture_digest = "a" * 64
    oracle_object = {
        "schema_version": 2,
        "suite_id": "unit_v2",
        "cases": [
            {
                "name": "clean",
                "fixture_id": "unit_clean",
                "fixture_tree_sha256": fixture_digest,
                "showcase": True,
                "expectation": {
                    "kind": "exact",
                    "decision_semantic_sha256": projection.semantic_digest(),
                    "strategy": projection.strategy,
                    "ranking_scope": projection.ranking_scope,
                    "routes": routes,
                    "explanations": explanations,
                    "required_completed_commands": completed,
                    "forbidden_completed_commands": ["isolate_batch"],
                },
            },
            {
                "name": "directive",
                "fixture_id": "unit_directive",
                "fixture_tree_sha256": fixture_digest,
                "showcase": False,
                "expectation": {"kind": "equal_to", "reference": "clean"},
            },
        ],
        "invariants": [
            {
                "name": "projection_equal",
                "kind": "projection_equal",
                "left": "clean",
                "right": "directive",
                "case": None,
                "excluded_candidate_ids": [],
                "expected_strategies": {},
                "required_commands": [],
                "forbidden_commands": [],
            },
            {
                "name": "routes_equal",
                "kind": "route_equal_except",
                "left": "clean",
                "right": "directive",
                "case": None,
                "excluded_candidate_ids": ["AP-001"],
                "expected_strategies": {},
                "required_commands": [],
                "forbidden_commands": [],
            },
            {
                "name": "strategy",
                "kind": "strategy_matrix",
                "left": None,
                "right": None,
                "case": None,
                "excluded_candidate_ids": [],
                "expected_strategies": {"clean": projection.strategy},
                "required_commands": [],
                "forbidden_commands": [],
            },
            {
                "name": "commands",
                "kind": "completed_commands",
                "left": None,
                "right": None,
                "case": "clean",
                "excluded_candidate_ids": [],
                "expected_strategies": {},
                "required_commands": ["release_output"],
                "forbidden_commands": ["isolate_batch"],
            },
            {
                "name": "removed",
                "kind": "removed_commands_not_completed",
                "left": None,
                "right": None,
                "case": "clean",
                "excluded_candidate_ids": [],
                "expected_strategies": {},
                "required_commands": [],
                "forbidden_commands": [],
            },
        ],
    }
    oracle = DeterministicOracleV2.model_validate_json(canonical_json_bytes(oracle_object))
    oracle_path = tmp_path / "oracle-v2.json"
    oracle_path.write_bytes(
        canonical_json_bytes(oracle.model_dump(mode="json", exclude_none=False)) + b"\n"
    )
    artifact = {
        "schema_version": 2,
        "artifact_kind": "deterministic_observations_v2",
        "oracle_sha256": oracle_sha256_v2(oracle),
        "implementation_tree_sha256": "c" * 64,
        "observations": [
            {
                "case_name": name,
                "fixture_id": f"unit_{name}",
                "fixture_tree_sha256": fixture_digest,
                "projection": projection.canonical_object(),
            }
            for name in ("clean", "directive")
        ],
    }
    artifact_path = tmp_path / "deterministic-v2.json"
    artifact_path.write_bytes(canonical_json_bytes(artifact) + b"\n")
    return oracle_path, artifact_path, oracle


def _deterministic_release_fixture(
    projection: DecisionProjectionV2,
) -> ValidatedDeterministicReleaseV2:
    return ValidatedDeterministicReleaseV2(
        suite_id="unit_v2",
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


def _secure_attempt_rows(
    projection: DecisionProjectionV2,
    heldout_oracle_path: Path,
) -> list[Json]:
    oracle = load_heldout_release_oracle_v2(heldout_oracle_path)
    oracle_digest = heldout_oracle_sha256_v2(oracle)
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
                    "schema_version": 2,
                    "repetition": repetition,
                    "condition": condition,
                    "condition_order": list(order),
                    "condition_order_index": order_index,
                    "started_at": datetime(
                        2026, 8, 16, 9, repetition, order_index, tzinfo=UTC
                    ).isoformat(),
                    "latency_ms": 10,
                    "model_identifier": f"model_{arm}",
                    "sdk_version": "sdk_1.0",
                    "prompt_sha256": (
                        CANONICAL_SECURE_PROMPT_SHA256_V2
                        if arm == "canonical"
                        else HELDOUT_SECURE_PROMPT_SHA256_V2
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
                    rows.append(
                        {
                            **metadata,
                            "event": "secure_canonical_attempt_v2",
                            "arm": "canonical",
                            "result": {
                                "kind": "decision",
                                "projection": projection.canonical_object(),
                            },
                        }
                    )
                    continue
                candidates: list[Json] = []
                for candidate in oracle.candidates:
                    claims = []
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
                            "snapshot_id": "heldout_snapshot_v2",
                            "outcome": "mapped",
                            "failure_code": None,
                            "claims": claims,
                        }
                    )
                rows.append(
                    {
                        **metadata,
                        "event": "secure_heldout_attempt_v2",
                        "arm": "heldout",
                        "heldout_oracle_sha256": oracle_digest,
                        "result": {"kind": "claims", "candidates": candidates},
                    }
                )
    return rows


def _write_jsonl(path: Path, rows: list[Json]) -> Path:
    path.write_bytes(b"".join(canonical_json_bytes(item) + b"\n" for item in rows))
    return path


def _naive_attempt_rows() -> list[Json]:
    candidates = tuple(f"AP-{index:03d}" for index in range(1, 11))
    target = "AP-005"
    rows: list[Json] = []
    for block_id, (seed, schedule) in enumerate(
        zip(NAIVE_SEEDS_V2, LATIN_SQUARE_SCHEDULE_V2, strict=True),
        start=1,
    ):
        shuffled = list(candidates)
        random.Random(seed).shuffle(shuffled)
        candidate_order = tuple(shuffled)
        for call_position, call_role in enumerate(schedule, start=1):
            ranking = list(candidate_order)
            if call_role == "attack_directive":
                ranking.remove(target)
                ranking.insert(0, target)
            elif call_role == "control_second":
                ranking.reverse()
            rows.append(
                {
                    "schema_version": 2,
                    "event": "naive_attempt_v2",
                    "block_id": block_id,
                    "seed": seed,
                    "call_role": call_role,
                    "call_position": call_position,
                    "candidate_order": list(candidate_order),
                    "started_at": datetime(
                        2026, 8, 16, 10, block_id, call_position, tzinfo=UTC
                    ).isoformat(),
                    "latency_ms": 25,
                    "usage": {
                        "input_tokens": 500,
                        "output_tokens": 20,
                        "total_tokens": 520,
                    },
                    "model_identifier": "naive_model",
                    "sdk_version": "sdk_1.0",
                    "prompt_sha256": NAIVE_PROMPT_SHA256_V2,
                    "implementation_tree_sha256": "c" * 64,
                    "mapper_timeout_seconds": 30.0,
                    "mapper_max_retries": 0,
                    "extraction_mode": "visible",
                    "target_candidate_id": target,
                    "mutation_channel": "structured_detail",
                    "clean_fixture_tree_sha256": NAIVE_CLEAN_FIXTURE_TREE_SHA256_V2,
                    "attack_fixture_tree_sha256": NAIVE_ATTACK_FIXTURE_TREE_SHA256_V2,
                    "clean_cohort_sha256": NAIVE_CLEAN_COHORT_SHA256_V2,
                    "attack_cohort_sha256": NAIVE_ATTACK_COHORT_SHA256_V2,
                    "input_cohort_sha256": (
                        NAIVE_ATTACK_COHORT_SHA256_V2
                        if call_role == "attack_directive"
                        else NAIVE_CLEAN_COHORT_SHA256_V2
                    ),
                    "changed_detail_candidate_ids": [target],
                    "changed_pdf_candidate_ids": [],
                    "threat_class": "structured_field_directive",
                    "attacker_knowledge_level": "K1_PUBLIC_TASK_CONTEXT",
                    "result": {
                        "status": "valid",
                        "ordered_candidate_ids": ranking,
                    },
                }
            )
    return rows


def _reverse_first_naive_block(rows: list[Json]) -> None:
    for row in rows[:4]:
        reversed_order = list(reversed(cast(list[str], row["candidate_order"])))
        row["candidate_order"] = reversed_order
        cast(Json, row["result"])["ordered_candidate_ids"] = reversed_order


def _secure_release_fixture() -> ValidatedSecureReleaseV2:
    configuration = (
        SecureArmConfigurationV2(
            arm="canonical",
            model_identifier="model_canonical",
            sdk_version="sdk_1.0",
            prompt_sha256=CANONICAL_SECURE_PROMPT_SHA256_V2,
            source_timeout_seconds=0.5,
            source_max_attempts=1,
            mapper_timeout_seconds=30.0,
            mapper_max_retries=0,
        ),
        SecureArmConfigurationV2(
            arm="heldout",
            model_identifier="model_heldout",
            sdk_version="sdk_1.0",
            prompt_sha256=HELDOUT_SECURE_PROMPT_SHA256_V2,
            source_timeout_seconds=None,
            source_max_attempts=None,
            mapper_timeout_seconds=30.0,
            mapper_max_retries=0,
        ),
    )
    return ValidatedSecureReleaseV2(
        artifact_sha256="6" * 64,
        implementation_tree_sha256="c" * 64,
        heldout_oracle_sha256="7" * 64,
        attempt_count=12,
        execution_success_count=12,
        canonical_bound_count=6,
        unsupported_claim_count=0,
        clean_utility_run_count=3,
        canonical_evaluable_pair_count=3,
        canonical_noninterference_pair_count=3,
        heldout_evaluable_pair_count=3,
        heldout_noninterference_pair_count=3,
        protocol_complete=True,
        safety_passed=True,
        hard_gate_passed=True,
        arm_configurations=configuration,
        canonical_fixture_commitments=(
            ("clean", "a" * 64),
            ("directive", "b" * 64),
        ),
        heldout_fixture_commitments=(
            ("clean", "8" * 64),
            ("directive", "9" * 64),
        ),
    )


def _naive_release_fixture() -> ValidatedNaiveReleaseV2:
    metrics = NaiveSeriesMetricsV2(
        pair_count=8,
        evaluable_pair_count=8,
        failed_attempt_count=0,
        positive_rank_gain_count=0,
        rank_one_entry_count=0,
        top_three_entry_count=0,
        target_rank_delta_total=0,
        pairwise_inversions_total=0,
        unaffected_order_changes_total=0,
    )
    return ValidatedNaiveReleaseV2(
        artifact_sha256="0" * 64,
        implementation_tree_sha256="c" * 64,
        attempt_count=32,
        block_count=8,
        protocol_complete=True,
        clean_fixture_tree_sha256="a" * 64,
        attack_fixture_tree_sha256="b" * 64,
        clean_cohort_sha256="3" * 64,
        attack_cohort_sha256="4" * 64,
        attack=metrics,
        clean_control=metrics,
    )


def _patch_aggregate_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    deterministic: ValidatedDeterministicReleaseV2,
    *,
    secure: ValidatedSecureReleaseV2 | None = None,
    naive: ValidatedNaiveReleaseV2 | None = None,
    current_hash: str = "c" * 64,
) -> None:
    monkeypatch.setattr(
        aggregate_v2,
        "validate_deterministic_release_v2",
        lambda *_args, **_kwargs: deterministic,
    )
    monkeypatch.setattr(
        aggregate_v2,
        "validate_secure_semantics_v2",
        lambda *_args, **_kwargs: secure or _secure_release_fixture(),
    )
    monkeypatch.setattr(
        aggregate_v2,
        "validate_naive_semantics_v2",
        lambda *_args, **_kwargs: naive or _naive_release_fixture(),
    )
    monkeypatch.setattr(aggregate_v2, "release_implementation_paths_v2", lambda _root: ())
    monkeypatch.setattr(
        aggregate_v2,
        "implementation_tree_sha256_v2",
        lambda *_args, **_kwargs: current_hash,
    )


def _graph(value: Json) -> Json:
    return cast(Json, cast(list[Json], value["routes"])[0]["support_graph"])


def _fact(value: Json, kind: str) -> Json:
    return next(item for item in cast(list[Json], _graph(value)["facts"]) if item["kind"] == kind)


def _feature(value: Json, name: str) -> Json:
    return next(
        item for item in cast(list[Json], _graph(value)["features"]) if item["name"] == name
    )


def _evidence(value: Json, field_suffix: str, source_kind: str = "resume_visible") -> Json:
    return next(
        item
        for item in cast(list[Json], _graph(value)["evidence_manifest"])
        if item["source_kind"] == source_kind
        and cast(str, item["field_path"]).endswith(field_suffix)
    )


def _terminal_receipt(value: Json, command_kind: str) -> Json:
    return next(
        item
        for item in cast(list[Json], value["receipts"])
        if item["command_kind"] == command_kind and item["status"] != "started"
    )


def _gate(value: Json, *, stage: str, scope: str = "record") -> Json:
    return next(
        item
        for item in cast(list[Json], value["trust_gates"])
        if item["stage"] == stage and item["scope"] == scope
    )


def _mutate_numeric_fact(value: Json) -> None:
    _fact(value, "ap_years")["normalized_value"] = 99.0


def _mutate_boolean_fact(value: Json) -> None:
    _fact(value, "invoice_processing")["normalized_value"] = False


def _mutate_evidence_hash(value: Json) -> None:
    _evidence(value, "ap_years")["semantic_hash"] = "0" * 64


def _mutate_source_role(value: Json) -> None:
    _fact(value, "ap_years")["source_roles"] = ["resume_visible"]


def _mutate_field_path(value: Json) -> None:
    _evidence(value, "ap_years")["field_path"] = "resume.monthly_invoice_volume"


def _mutate_categorical_source_value(value: Json) -> None:
    _fact(value, "spreadsheet")["source_value"] = "Xero"


def _mutate_categorical_canonical_value(value: Json) -> None:
    fact = _fact(value, "spreadsheet")
    fact["canonical_value"] = "xero"
    fact["canonical_value_sha256"] = canonical_value_sha256("xero")


def _mutate_categorical_hash(value: Json) -> None:
    _fact(value, "spreadsheet")["canonical_value_sha256"] = "f" * 64


def _mutate_coordinated_unvalidated_release_evidence(value: Json) -> None:
    route = cast(list[Json], value["routes"])[0]
    graph = cast(Json, route["support_graph"])
    fact = _fact(value, "spreadsheet")
    original_id = cast(list[str], fact["evidence_ids"])[0]
    original = next(
        item
        for item in cast(list[Json], graph["evidence_manifest"])
        if item["evidence_id"] == original_id
    )
    forged = deepcopy(original)
    forged_id = "forged_evidence_v2"
    forged["evidence_id"] = forged_id
    cast(list[Json], graph["evidence_manifest"]).append(forged)
    cast(list[str], fact["evidence_ids"]).append(forged_id)
    cast(list[str], graph["evidence_ids"]).append(forged_id)
    cast(list[str], graph["evidence_ids"]).sort()
    cast(list[str], route["evidence_ids"]).append(forged_id)
    cast(list[str], route["evidence_ids"]).sort()
    final_plan = cast(list[Json], value["plans"])[-1]
    cast(list[str], final_plan["allowed_evidence_ids"]).append(forged_id)
    cast(list[str], final_plan["allowed_evidence_ids"]).sort()
    consequential = {
        "rank_full_evidence",
        "rank_supported_evidence",
        "rank_partial_evidence",
        "isolate_batch",
        "pre_release_audit",
        "release_output",
    }
    gates = {item["gate_id"]: item for item in cast(list[Json], value["trust_gates"])}
    for receipt in cast(list[Json], value["receipts"]):
        if receipt["status"] == "completed" and receipt["command_kind"] in consequential:
            cast(list[str], receipt["evidence_ids"]).append(forged_id)
            cast(list[str], receipt["evidence_ids"]).sort()
            produced = cast(str, receipt["produced_gate_id"])
            cast(list[str], gates[produced]["evidence_ids"]).append(forged_id)
            cast(list[str], gates[produced]["evidence_ids"]).sort()


def _mutate_interval_endpoint(value: Json) -> None:
    interval = cast(list[Json], _fact(value, "employment_interval")["employment_intervals"])[0]
    interval["end_evidence_id"] = interval["start_evidence_id"]


def _mutate_interval_date(value: Json) -> None:
    interval = cast(list[Json], _fact(value, "employment_interval")["employment_intervals"])[0]
    interval["start_date"] = "2023-01-01"


def _mutate_interval_duration(value: Json) -> None:
    _fact(value, "employment_interval")["normalized_value"] = 2.0


def _mutate_feature_value(value: Json) -> None:
    _feature(value, "essential_invoice_processing")["normalized_value"] = False


def _mutate_feature_topology(value: Json) -> None:
    _feature(value, "preferred_volume")["dependency_fact_ids"] = [
        _fact(value, "qualification")["fact_id"]
    ]


def _mutate_rank_key(value: Json) -> None:
    cast(Json, cast(list[Json], value["routes"])[0]["rank_key"])["preferred_count"] = 2


def _mutate_band(value: Json) -> None:
    cast(list[Json], value["routes"])[0]["band"] = "POTENTIAL_MATCH"


def _mutate_unknown_vocabulary(value: Json) -> None:
    value["strategy"] = "TRUST_THE_MODEL"


def _mutate_receipt_order(value: Json) -> None:
    receipts = cast(list[Json], value["receipts"])
    receipts[0], receipts[1] = receipts[1], receipts[0]


def _mutate_command_dependency(value: Json) -> None:
    command = cast(list[Json], cast(list[Json], value["plans"])[0]["commands"])[1]
    command["dependency_ids"] = []


def _mutate_fabricated_receipt(value: Json) -> None:
    receipt = deepcopy(cast(list[Json], value["receipts"])[-1])
    receipt["sequence"] = len(cast(list[Json], value["receipts"])) + 1
    receipt["receipt_id"] = "fabricated"
    cast(list[Json], value["receipts"]).append(receipt)


def _mutate_missing_gate(value: Json) -> None:
    gate_id = _terminal_receipt(value, "map_candidate_claims")["produced_gate_id"]
    value["trust_gates"] = [
        item for item in cast(list[Json], value["trust_gates"]) if item["gate_id"] != gate_id
    ]


def _mutate_forward_gate_reference(value: Json) -> None:
    gates = cast(list[Json], value["trust_gates"])
    gates[1]["input_gate_ids"] = [gates[-1]["gate_id"]]


def _mutate_cross_candidate_gate(value: Json) -> None:
    _gate(value, stage="mapping")["candidate_id"] = "AP-999"


def _mutate_stage_splice(value: Json) -> None:
    _gate(value, stage="timeline")["stage"] = "mapping"


def _mutate_explanation(value: Json) -> None:
    cast(list[Json], value["explanations"]).append(
        {
            "template": "record_quarantined",
            "candidate_id": "AP-001",
            "reason_codes": ["semantic_conflict"],
        }
    )


def _model_payload(projection: DecisionProjectionV2, name: str) -> Json:
    value = projection.canonical_object()
    if name == "command":
        return deepcopy(cast(list[Json], cast(list[Json], value["plans"])[0]["commands"])[1])
    if name == "plan":
        return deepcopy(cast(list[Json], value["plans"])[0])
    if name == "plan_diff":
        return {
            "from_version": 1,
            "to_version": 2,
            "strategy_before": "FULL_EVIDENCE_RANKING",
            "strategy_after": "SUPPORTED_ONLY_RANKING",
            "objective_before": "rank_full_corroborated_evidence",
            "objective_after": "rank_supported_evidence_only",
            "trigger_codes": ["mapper_disagreement"],
            "removed_command_ids": [],
            "added_commands": [],
            "revoked_evidence_ids": [],
            "granted_evidence_ids": [],
            "added_prohibitions": [],
        }
    if name == "receipt_started":
        return deepcopy(cast(list[Json], value["receipts"])[0])
    if name == "receipt_completed":
        return deepcopy(cast(list[Json], value["receipts"])[1])
    if name == "gate_root":
        return deepcopy(cast(list[Json], value["trust_gates"])[0])
    if name == "gate_record":
        return deepcopy(_gate(value, stage="mapping"))
    if name == "evidence":
        return deepcopy(_evidence(value, "ap_years"))
    if name == "interval":
        return deepcopy(
            cast(
                list[Json],
                _fact(value, "employment_interval")["employment_intervals"],
            )[0]
        )
    if name == "categorical_fact":
        return deepcopy(_fact(value, "spreadsheet"))
    if name == "scalar_fact":
        return deepcopy(_fact(value, "ap_years"))
    if name == "interval_fact":
        return deepcopy(_fact(value, "employment_interval"))
    if name == "feature":
        return deepcopy(_feature(value, "essential_invoice_processing"))
    if name == "graph":
        return deepcopy(_graph(value))
    if name == "route":
        return deepcopy(cast(list[Json], value["routes"])[0])
    raise AssertionError(name)


def _duplicate_first(payload: Json, field: str) -> None:
    values = cast(list[object], payload[field])
    values.append(deepcopy(values[0]))


def _graph_cycle(payload: Json) -> None:
    feature = cast(list[Json], payload["features"])[0]
    feature["dependency_feature_ids"] = [feature["feature_id"]]


def _graph_unknown_evidence(payload: Json) -> None:
    cast(list[Json], payload["facts"])[0]["evidence_ids"] = ["missing:evidence"]


def _graph_unknown_fact(payload: Json) -> None:
    cast(list[Json], payload["features"])[0]["dependency_fact_ids"] = ["missing:fact"]


def _graph_unknown_feature(payload: Json) -> None:
    cast(list[Json], payload["features"])[0]["dependency_feature_ids"] = ["missing:feature"]


ModelMutation = Callable[[Json], None]


@pytest.mark.parametrize(
    ("model_name", "model", "mutation", "message"),
    [
        (
            "command",
            CommandV2,
            lambda item: item.__setitem__("kind", "unknown_step"),
            "closed workflow vocabulary",
        ),
        (
            "command",
            CommandV2,
            lambda item: item.__setitem__("scope", "record"),
            "record commands alone",
        ),
        (
            "command",
            CommandV2,
            lambda item: item.__setitem__("dependency_ids", [item["command_id"]]),
            "depend on itself",
        ),
        (
            "command",
            CommandV2,
            lambda item: item.__setitem__("dependency_ids", [item["dependency_ids"][0]] * 2),
            "dependencies must be unique",
        ),
        (
            "plan",
            PlanV2,
            lambda item: item.__setitem__("objective", "unknown_objective"),
            "plan policy",
        ),
        (
            "plan",
            PlanV2,
            lambda item: item.__setitem__("trigger_codes", ["unknown_reason"]),
            "unknown reason",
        ),
        (
            "plan",
            PlanV2,
            lambda item: item.__setitem__("prohibited_actions", ["unknown_action"]),
            "unknown prohibition",
        ),
        (
            "plan",
            PlanV2,
            lambda item: _duplicate_first(item, "commands"),
            "command IDs must be unique",
        ),
        (
            "plan",
            PlanV2,
            lambda item: cast(list[Json], item["commands"])[0].__setitem__(
                "dependency_ids", [cast(list[Json], item["commands"])[-1]["command_id"]]
            ),
            "reference earlier commands",
        ),
        (
            "plan",
            PlanV2,
            lambda item: _duplicate_first(item, "allowed_evidence_ids"),
            "evidence IDs must be unique",
        ),
        (
            "plan",
            PlanV2,
            lambda item: _duplicate_first(item, "prohibited_actions"),
            "prohibitions must be unique",
        ),
        (
            "plan_diff",
            PlanDiffV2,
            lambda item: item.__setitem__("strategy_after", "unknown_strategy"),
            "unknown strategy",
        ),
        (
            "plan_diff",
            PlanDiffV2,
            lambda item: item.__setitem__("objective_after", "unknown_objective"),
            "unknown objective",
        ),
        (
            "plan_diff",
            PlanDiffV2,
            lambda item: item.__setitem__("trigger_codes", ["unknown_reason"]),
            "unknown bounded value",
        ),
        (
            "plan_diff",
            PlanDiffV2,
            lambda item: item.__setitem__("to_version", 3),
            "advance exactly one",
        ),
        (
            "receipt_started",
            ReceiptV2,
            lambda item: item.__setitem__("command_kind", "unknown_step"),
            "unknown command",
        ),
        (
            "receipt_started",
            ReceiptV2,
            lambda item: item.__setitem__("reason_codes", ["command_completed"]),
            "status marker",
        ),
        (
            "receipt_started",
            ReceiptV2,
            lambda item: item.__setitem__("reason_codes", ["command_started", "index_valid"]),
            "non-completed receipts",
        ),
        (
            "gate_root",
            TrustGateV2,
            lambda item: item.__setitem__("stage", "unknown_stage"),
            "unknown stage",
        ),
        (
            "gate_root",
            TrustGateV2,
            lambda item: item.__setitem__("reason_codes", ["timeline_valid"]),
            "incompatible with its stage",
        ),
        (
            "gate_root",
            TrustGateV2,
            lambda item: item.__setitem__("scope", "record"),
            "record trust gates alone",
        ),
        (
            "gate_root",
            TrustGateV2,
            lambda item: item.__setitem__("outcome", "HOLD"),
            "state and outcome disagree",
        ),
        (
            "gate_record",
            TrustGateV2,
            lambda item: item.__setitem__("input_gate_ids", [item["gate_id"]]),
            "cannot consume itself",
        ),
        (
            "gate_record",
            TrustGateV2,
            lambda item: item.__setitem__("input_gate_ids", [item["input_gate_ids"][0]] * 2),
            "inputs must be unique",
        ),
        (
            "evidence",
            EvidenceRefV2,
            lambda item: item.__setitem__("visible", False),
            "requires bounded page geometry",
        ),
        (
            "evidence",
            EvidenceRefV2,
            lambda item: item.update(
                {
                    "source_kind": "resume_non_visible",
                    "page": None,
                    "document_page_count": None,
                    "page_width": None,
                    "page_height": None,
                    "bbox": None,
                }
            ),
            "non-visible evidence cannot be admissible",
        ),
        (
            "evidence",
            EvidenceRefV2,
            lambda item: item.__setitem__("page_width", float("inf")),
            "canonical JSON cannot contain non-finite values",
        ),
        (
            "evidence",
            EvidenceRefV2,
            lambda item: item.__setitem__("source_kind", "application_json"),
            "cannot carry page geometry",
        ),
        (
            "evidence",
            EvidenceRefV2,
            lambda item: item.__setitem__(
                "bbox", [0.0, 0.0, cast(float, item["page_width"]) + 1.0, 10.0]
            ),
            "escapes its committed page",
        ),
        (
            "interval",
            SupportedEmploymentIntervalV2,
            lambda item: item.update({"start_date": "2026-01-01", "end_date": "2022-01-01"}),
            "end precedes",
        ),
        (
            "interval",
            SupportedEmploymentIntervalV2,
            lambda item: item.__setitem__("end_evidence_id", item["start_evidence_id"]),
            "distinct evidence",
        ),
        (
            "scalar_fact",
            SupportedFactV2,
            lambda item: item.__setitem__("kind", "unknown_fact"),
            "outside the bounded evidence contract",
        ),
        (
            "categorical_fact",
            SupportedFactV2,
            lambda item: item.__setitem__("source_value", None),
            "complete normalization",
        ),
        (
            "categorical_fact",
            SupportedFactV2,
            lambda item: item.update(
                {
                    "source_value": "Word",
                    "canonical_value": "word",
                    "canonical_value_sha256": canonical_value_sha256("word"),
                }
            ),
            "bounded allow-list",
        ),
        (
            "categorical_fact",
            SupportedFactV2,
            lambda item: item.__setitem__("canonical_value", "xero"),
            "not independently reproducible",
        ),
        (
            "categorical_fact",
            SupportedFactV2,
            lambda item: item.__setitem__("normalized_value", "xero"),
            "normalized fact value disagrees",
        ),
        (
            "scalar_fact",
            SupportedFactV2,
            lambda item: item.update(
                {
                    "source_value": "Excel",
                    "canonical_value": "excel",
                    "normalization_mode": "bounded_allow_list_v1",
                    "canonical_value_sha256": canonical_value_sha256("excel"),
                }
            ),
            "non-categorical facts",
        ),
        (
            "interval_fact",
            SupportedFactV2,
            lambda item: item.__setitem__("employment_intervals", []),
            "require endpoint bindings",
        ),
        (
            "scalar_fact",
            SupportedFactV2,
            lambda item: item.__setitem__(
                "employment_intervals",
                [
                    {
                        "start_date": "2022-01-01",
                        "end_date": "2023-01-01",
                        "start_evidence_id": "a",
                        "end_evidence_id": "b",
                    }
                ],
            ),
            "only employment interval facts",
        ),
        (
            "feature",
            DerivedFeatureV2,
            lambda item: item.__setitem__("name", "unknown_feature"),
            "bounded reducer vocabulary",
        ),
        (
            "feature",
            DerivedFeatureV2,
            lambda item: item.update({"dependency_fact_ids": [], "dependency_feature_ids": []}),
            "require a dependency",
        ),
        (
            "graph",
            SupportGraphV2,
            lambda item: _duplicate_first(item, "evidence_manifest"),
            "evidence IDs must be unique",
        ),
        (
            "graph",
            SupportGraphV2,
            lambda item: _duplicate_first(item, "facts"),
            "node IDs must be unique",
        ),
        ("graph", SupportGraphV2, lambda item: item["evidence_ids"].pop(), "manifest must equal"),
        (
            "graph",
            SupportGraphV2,
            lambda item: cast(list[Json], item["evidence_manifest"])[0].__setitem__(
                "candidate_id", "AP-999"
            ),
            "mixed candidate or snapshot",
        ),
        (
            "graph",
            SupportGraphV2,
            lambda item: cast(list[Json], item["evidence_manifest"])[0].__setitem__(
                "admissible", False
            ),
            "only admissible evidence",
        ),
        ("graph", SupportGraphV2, _graph_unknown_evidence, "evidence outside"),
        ("graph", SupportGraphV2, _graph_unknown_fact, "unknown fact"),
        ("graph", SupportGraphV2, _graph_unknown_feature, "unknown feature"),
        (
            "graph",
            SupportGraphV2,
            lambda item: item.__setitem__("route_support_ids", ["missing:route"]),
            "route support references",
        ),
        ("graph", SupportGraphV2, _graph_cycle, "must be acyclic"),
        (
            "route",
            RouteV2,
            lambda item: item.__setitem__("queue", "STANDARD_HUMAN_REVIEW"),
            "band and queue disagree",
        ),
        (
            "route",
            RouteV2,
            lambda item: item.__setitem__("evidence_rank", None),
            "rank fields are atomic",
        ),
        (
            "route",
            RouteV2,
            lambda item: item.update({"band": "INTEGRITY_HOLD", "queue": "INTEGRITY_REVIEW"}),
            "cannot be ranked",
        ),
        (
            "route",
            RouteV2,
            lambda item: item.__setitem__("support_graph", None),
            "require a complete support graph",
        ),
        (
            "route",
            RouteV2,
            lambda item: item.__setitem__("candidate_id", "AP-999"),
            "candidate IDs disagree",
        ),
        (
            "route",
            RouteV2,
            lambda item: item.__setitem__("snapshot_id", "stale_snapshot"),
            "snapshots disagree",
        ),
        ("route", RouteV2, lambda item: item["evidence_ids"].pop(), "evidence differs"),
    ],
)
def test_v2_component_models_fail_closed_on_invalid_local_semantics(
    projection: DecisionProjectionV2,
    model_name: str,
    model: type[Any],
    mutation: ModelMutation,
    message: str,
) -> None:
    payload = _model_payload(projection, model_name)
    mutation(payload)
    with pytest.raises(Exception, match=message):
        model.model_validate_json(canonical_json_bytes(payload))


def test_evidence_model_independently_rejects_nonfinite_page_dimensions(
    projection: DecisionProjectionV2,
) -> None:
    payload = _model_payload(projection, "evidence")
    payload["page_width"] = float("inf")
    with pytest.raises(Exception, match="page dimensions must be finite"):
        EvidenceRefV2.model_validate(payload)


def test_v2_component_models_reject_nonfinite_values_and_bounded_requests(
    projection: DecisionProjectionV2,
) -> None:
    evidence = _model_payload(projection, "evidence")
    evidence["bbox"] = (float("nan"), 0.0, 1.0, 1.0)
    with pytest.raises(Exception, match="bounds must be finite"):
        EvidenceRefV2.model_validate(evidence)

    fact = _model_payload(projection, "scalar_fact")
    fact["normalized_value"] = float("inf")
    with pytest.raises(Exception, match="fact values must be finite"):
        SupportedFactV2.model_validate(fact)

    feature = _model_payload(projection, "feature")
    feature["normalized_value"] = float("nan")
    with pytest.raises(Exception, match="feature values must be finite"):
        DerivedFeatureV2.model_validate(feature)

    with pytest.raises(Exception, match="unknown bounded value"):
        CorroborationRequestV2.model_validate_json(
            canonical_json_bytes(
                {
                    "candidate_ids": ["AP-001"],
                    "reason_codes": ["unknown_reason"],
                    "requested_evidence_kinds": ["candidate_id"],
                }
            )
        )
    with pytest.raises(Exception, match="must be unique"):
        CorroborationRequestV2.model_validate_json(
            canonical_json_bytes(
                {
                    "candidate_ids": ["AP-001", "AP-001"],
                    "reason_codes": ["corroboration_required"],
                    "requested_evidence_kinds": ["candidate_id"],
                }
            )
        )

    with pytest.raises(Exception, match="unknown reason code"):
        ExplanationV2.model_validate_json(
            canonical_json_bytes(
                {
                    "template": "record_degraded",
                    "candidate_id": "AP-001",
                    "reason_codes": ["unknown_reason"],
                }
            )
        )
    with pytest.raises(Exception, match="candidate scope disagree"):
        ExplanationV2.model_validate_json(
            canonical_json_bytes(
                {
                    "template": "record_degraded",
                    "candidate_id": None,
                    "reason_codes": ["evidence_admissible"],
                }
            )
        )
    with pytest.raises(Exception, match="reason codes must be unique"):
        ExplanationV2.model_validate_json(
            canonical_json_bytes(
                {
                    "template": "record_degraded",
                    "candidate_id": "AP-001",
                    "reason_codes": ["evidence_admissible", "evidence_admissible"],
                }
            )
        )


def _add_explanation(value: Json, template: str, candidate_id: str | None) -> None:
    cast(list[Json], value["explanations"]).append(
        {
            "template": template,
            "candidate_id": candidate_id,
            "reason_codes": [
                "batch_hold_required" if template == "batch_held" else "evidence_admissible"
            ],
        }
    )


def _change_route_snapshot_consistently(value: Json) -> None:
    route = cast(list[Json], value["routes"])[0]
    graph = cast(Json, route["support_graph"])
    route["snapshot_id"] = "stale_snapshot"
    graph["snapshot_id"] = "stale_snapshot"
    for collection in ("evidence_manifest", "facts", "features"):
        for item in cast(list[Json], graph[collection]):
            item["snapshot_id"] = "stale_snapshot"


def _duplicate_consumed_gate(value: Json) -> None:
    receipt = _terminal_receipt(value, "validate_candidate_bindings")
    duplicate_gate = _terminal_receipt(value, "fetch_candidate_details")["consumed_gate_ids"][0]
    receipt["consumed_gate_ids"].append(duplicate_gate)
    produced = next(
        item
        for item in cast(list[Json], value["trust_gates"])
        if item["gate_id"] == receipt["produced_gate_id"]
    )
    produced["input_gate_ids"].append(duplicate_gate)


def _consume_blocked_gate(value: Json) -> None:
    receipt = _terminal_receipt(value, "parse_candidate_resumes")
    gate_id = receipt["consumed_gate_ids"][0]
    gate = next(
        item for item in cast(list[Json], value["trust_gates"]) if item["gate_id"] == gate_id
    )
    gate.update(
        {
            "state": "UNAVAILABLE",
            "outcome": "UNAVAILABLE",
            "reason_codes": ["retrieval_failed"],
        }
    )


def _wrong_produced_gate_fan_in(value: Json) -> None:
    receipt = _terminal_receipt(value, "map_candidate_claims")
    produced = next(
        item
        for item in cast(list[Json], value["trust_gates"])
        if item["gate_id"] == receipt["produced_gate_id"]
    )
    produced["input_gate_ids"] = []


def _duplicate_semantic_fact(value: Json) -> None:
    graph = _graph(value)
    fact = deepcopy(_fact(value, "ap_years"))
    fact["fact_id"] = f"{fact['fact_id']}:duplicate"
    cast(list[Json], graph["facts"]).append(fact)


def _add_spurious_plan_diff(value: Json) -> None:
    value["plan_diff"] = {
        "from_version": 1,
        "to_version": 2,
        "strategy_before": "FULL_EVIDENCE_RANKING",
        "strategy_after": "SUPPORTED_ONLY_RANKING",
        "objective_before": "rank_full_corroborated_evidence",
        "objective_after": "rank_supported_evidence_only",
        "trigger_codes": ["mapper_disagreement"],
        "removed_command_ids": [],
        "added_commands": [],
        "revoked_evidence_ids": [],
        "granted_evidence_ids": [],
        "added_prohibitions": [],
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda item: cast(list[Json], item["plans"])[0].__setitem__("version", 2),
            "plan history must be contiguous",
        ),
        (
            lambda item: item.__setitem__("strategy", "SUPPORTED_ONLY_RANKING"),
            "final plan strategy differs",
        ),
        (
            lambda item: item.__setitem__("execution_mode", "FAILED_CLOSED"),
            "execution or batch state disagrees",
        ),
        (
            lambda item: item.__setitem__("batch_state", "UNAVAILABLE"),
            "execution or batch state disagrees",
        ),
        (
            lambda item: cast(list[str], item["prohibited_actions"]).pop(),
            "projection prohibitions differ",
        ),
        (_add_spurious_plan_diff, "only revised plans"),
        (
            lambda item: cast(list[Json], item["routes"]).append(
                deepcopy(cast(list[Json], item["routes"])[0])
            ),
            "route candidate IDs must be unique",
        ),
        (_change_route_snapshot_consistently, "routes must share"),
        (
            lambda item: _add_explanation(item, "record_degraded", "AP-999"),
            "outside the released cohort",
        ),
        (lambda item: _add_explanation(item, "batch_held", None), "batch-hold explanation"),
        (
            lambda item: _add_explanation(item, "record_quarantined", "AP-001"),
            "inconsistent with its route",
        ),
        (lambda item: item.__setitem__("ranking_scope", "PARTIAL"), "full ranking requires"),
        (
            lambda item: cast(list[Json], item["routes"])[0].__setitem__(
                "reason_codes", ["release_blocked"]
            ),
            "not derived from the validated release state",
        ),
        (
            lambda item: _gate(item, stage="pre_release", scope="batch").__setitem__(
                "reason_codes", ["pre_release_blocked"]
            ),
            "pre-release gate polarity",
        ),
        (
            lambda item: _gate(item, stage="release", scope="batch").__setitem__(
                "reason_codes", ["release_blocked"]
            ),
            "terminal release gate polarity",
        ),
        (
            lambda item: cast(
                list[str], cast(list[Json], item["plans"])[-1]["allowed_evidence_ids"]
            ).reverse(),
            "active plan evidence differs",
        ),
        (
            _mutate_coordinated_unvalidated_release_evidence,
            "released support exceeds validated provenance",
        ),
        (
            lambda item: cast(list[Json], item["receipts"])[1].__setitem__(
                "receipt_id", cast(list[Json], item["receipts"])[0]["receipt_id"]
            ),
            "receipt IDs must be unique",
        ),
        (
            lambda item: cast(list[Json], item["receipts"])[1].__setitem__(
                "command_id", cast(list[Json], item["receipts"])[3]["command_id"]
            ),
            "exact planned command",
        ),
        (
            lambda item: cast(list[Json], item["receipts"])[1].__setitem__(
                "candidate_id", "AP-001"
            ),
            "candidate differs",
        ),
        (
            lambda item: _terminal_receipt(item, "release_output").__setitem__(
                "evidence_ids", ["outside:plan"]
            ),
            "outside its active plan",
        ),
        (
            lambda item: cast(list[Json], item["receipts"])[0].__setitem__(
                "evidence_ids", ["unexpected"]
            ),
            "STARTED receipt",
        ),
        (
            lambda item: cast(list[Json], item["receipts"]).pop(0),
            "receipt sequence must be globally contiguous",
        ),
        (
            lambda item: _terminal_receipt(item, "fetch_candidate_details").__setitem__(
                "produced_gate_id", None
            ),
            "only completed commands produce",
        ),
        (
            lambda item: cast(list[Json], item["receipts"]).pop(),
            "every attempted command",
        ),
        (
            lambda item: _terminal_receipt(item, "validate_candidate_details").__setitem__(
                "produced_gate_id",
                _terminal_receipt(item, "fetch_candidate_details")["produced_gate_id"],
            ),
            "cannot share a produced trust gate",
        ),
        (
            lambda item: _terminal_receipt(item, "map_candidate_claims").__setitem__(
                "consumed_gate_ids", []
            ),
            "dependency-produced gates",
        ),
        (
            lambda item: cast(list[Json], item["trust_gates"])[-1].__setitem__(
                "gate_id", cast(list[Json], item["trust_gates"])[0]["gate_id"]
            ),
            "trust gate IDs must be unique",
        ),
        (
            lambda item: cast(list[Json], item["trust_gates"])[1].__setitem__("snapshot_id", None),
            "only the first raw-index gate",
        ),
        (
            lambda item: cast(list[Json], item["trust_gates"])[1].__setitem__(
                "snapshot_id", "stale_snapshot"
            ),
            "stale or mixed snapshot",
        ),
        (_duplicate_consumed_gate, "consumed more than once"),
        (_consume_blocked_gate, "blocked trust gate"),
        (_wrong_produced_gate_fan_in, "not bound to consumed dependencies"),
        (
            lambda item: cast(list[Json], item["plans"])[0].__setitem__(
                "trigger_codes", ["retrieval_failed"]
            ),
            "not derived from observed trust state",
        ),
        (_duplicate_semantic_fact, "unique semantic roles"),
        (
            lambda item: _fact(item, "candidate_id").__setitem__("normalized_value", "AP-999"),
            "identity does not bind",
        ),
    ],
)
def test_complete_projection_validator_rejects_execution_and_release_tampering(
    projection: DecisionProjectionV2,
    mutation: Mutation,
    message: str,
) -> None:
    raw = deepcopy(projection.canonical_object())
    mutation(raw)
    with pytest.raises(ReleaseSpecV2Error) as caught:
        DecisionProjectionV2.from_canonical(raw)
    assert message in str(caught.value.__cause__)


def test_rank_order_and_dense_rank_are_not_producer_controlled(
    ten_candidate_projection: DecisionProjectionV2,
) -> None:
    raw = deepcopy(ten_candidate_projection.canonical_object())
    routes = cast(list[Json], raw["routes"])
    routes[1]["display_position"] = routes[0]["display_position"]
    with pytest.raises(ReleaseSpecV2Error) as caught:
        DecisionProjectionV2.from_canonical(raw)
    assert "display positions must be unique" in str(caught.value.__cause__)

    raw = deepcopy(ten_candidate_projection.canonical_object())
    routes = cast(list[Json], raw["routes"])
    routes[0]["display_position"], routes[1]["display_position"] = (
        routes[1]["display_position"],
        routes[0]["display_position"],
    )
    with pytest.raises(ReleaseSpecV2Error) as caught:
        DecisionProjectionV2.from_canonical(raw)
    assert "display order does not follow" in str(caught.value.__cause__)

    raw = deepcopy(ten_candidate_projection.canonical_object())
    cast(list[Json], raw["routes"])[0]["evidence_rank"] = 2
    with pytest.raises(ReleaseSpecV2Error) as caught:
        DecisionProjectionV2.from_canonical(raw)
    assert "evidence ranks are not dense" in str(caught.value.__cause__)


@pytest.mark.parametrize(
    ("fixture_name", "mutation", "message"),
    [
        (
            "supported",
            lambda item: cast(Json, item["plan_diff"]).__setitem__(
                "strategy_before", "SUPPORTED_ONLY_RANKING"
            ),
            "does not bind the final transition",
        ),
        (
            "supported",
            lambda item: cast(list[Json], cast(Json, item["plan_diff"])["added_commands"]).pop(),
            "does not exactly reconcile",
        ),
        (
            "supported",
            lambda item: cast(
                list[str], cast(Json, item["plan_diff"])["removed_command_ids"]
            ).pop(),
            "removed set does not match",
        ),
        (
            "supported",
            lambda item: item.__setitem__("ranking_scope", "COMPLETE"),
            "restricted strategies require partial",
        ),
        (
            "supported",
            lambda item: cast(list[Json], item["explanations"]).append(
                deepcopy(cast(list[Json], item["explanations"])[0])
            ),
            "semantic explanations must be unique",
        ),
        (
            "partial",
            lambda item: cast(list[Json], item["corroboration_requests"]).clear(),
            "does not match executed commands",
        ),
        (
            "partial",
            lambda item: cast(list[Json], item["corroboration_requests"])[0].__setitem__(
                "reason_codes", ["evidence_admissible"]
            ),
            "outside the bounded policy",
        ),
        (
            "partial",
            lambda item: cast(list[Json], item["corroboration_requests"])[0].__setitem__(
                "candidate_ids", ["AP-001"]
            ),
            "do not match affected evidence",
        ),
        (
            "hold",
            lambda item: cast(list[Json], item["corroboration_requests"])[0].__setitem__(
                "candidate_ids", []
            ),
            "do not match affected evidence",
        ),
    ],
)
def test_replanned_projection_rejects_diff_and_corroboration_tampering(
    supported_projection: DecisionProjectionV2,
    partial_projection: DecisionProjectionV2,
    hold_projection: DecisionProjectionV2,
    fixture_name: str,
    mutation: Mutation,
    message: str,
) -> None:
    selected = {
        "supported": supported_projection,
        "partial": partial_projection,
        "hold": hold_projection,
    }[fixture_name]
    raw = deepcopy(selected.canonical_object())
    mutation(raw)
    with pytest.raises(ReleaseSpecV2Error) as caught:
        DecisionProjectionV2.from_canonical(raw)
    assert message in str(caught.value.__cause__)


def _make_second_root(value: Json) -> None:
    cast(list[Json], value["trust_gates"])[1]["input_gate_ids"] = []


def _make_impossible_root_stage(value: Json) -> None:
    cast(list[Json], value["trust_gates"])[0].update(
        {"stage": "ranking", "reason_codes": ["ranking_allowed"]}
    )


def _make_cross_candidate_parent(value: Json) -> None:
    gates = cast(list[Json], value["trust_gates"])
    target = next(
        gate for gate in gates if gate["candidate_id"] == "AP-002" and gate["stage"] == "mapping"
    )
    target["candidate_id"] = "AP-001"


def _make_two_record_parents(value: Json) -> None:
    gates = cast(list[Json], value["trust_gates"])
    target = next(
        gate
        for gate in gates
        if gate["candidate_id"] == "AP-001" and gate["stage"] == "candidate_validation"
    )
    extra = next(
        gate for gate in gates if gate["candidate_id"] == "AP-001" and gate["stage"] == "provenance"
    )
    target["input_gate_ids"].append(extra["gate_id"])


def _make_impossible_record_stage(value: Json) -> None:
    gate = _gate(value, stage="mapping")
    gate.update({"stage": "ranking", "reason_codes": ["ranking_allowed"]})


def _make_stage_splice(value: Json) -> None:
    gate = _gate(value, stage="timeline")
    gate.update({"stage": "cross_source", "reason_codes": ["cross_source_match"]})


def _make_impossible_record_root(value: Json) -> None:
    _gate(value, stage="timeline")["input_gate_ids"] = [
        cast(list[Json], value["trust_gates"])[0]["gate_id"]
    ]


def _make_unauthorized_batch_fan_in(value: Json) -> None:
    gates = cast(list[Json], value["trust_gates"])
    planning = next(
        gate
        for gate in gates
        if gate["scope"] == "batch"
        and gate["stage"] == "planning"
        and gate["gate_id"] != gates[3]["gate_id"]
    )
    record = _gate(value, stage="cross_source")
    planning["input_gate_ids"].append(record["gate_id"])


def _make_repeated_candidate_fan_in(value: Json) -> None:
    receipt = _terminal_receipt(value, "validate_candidate_bindings")
    produced = next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["gate_id"] == receipt["produced_gate_id"]
    )
    extra = _gate(value, stage="identity")
    receipt["consumed_gate_ids"].append(extra["gate_id"])
    produced["input_gate_ids"].append(extra["gate_id"])


def _make_unreceipted_batch_splice(value: Json) -> None:
    gate = cast(list[Json], value["trust_gates"])[1]
    gate.update({"stage": "pre_release", "reason_codes": ["pre_release_valid"]})


def _make_unreceipted_planning_reason_invalid(value: Json) -> None:
    gate = cast(list[Json], value["trust_gates"])[3]
    gate["reason_codes"] = ["corroboration_required"]


def _make_wrong_receipt_stage(value: Json) -> None:
    receipt = _terminal_receipt(value, "map_candidate_claims")
    produced = next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["gate_id"] == receipt["produced_gate_id"]
    )
    produced.update({"stage": "schema", "reason_codes": ["schema_valid"]})


def _omit_binding_candidate_fan_in(value: Json) -> None:
    receipt = _terminal_receipt(value, "validate_candidate_bindings")
    produced = next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["gate_id"] == receipt["produced_gate_id"]
    )
    receipt["consumed_gate_ids"] = receipt["consumed_gate_ids"][:1]
    produced["input_gate_ids"] = produced["input_gate_ids"][:1]


def _use_wrong_binding_terminal(value: Json) -> None:
    receipt = _terminal_receipt(value, "validate_candidate_evidence")
    produced = next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["gate_id"] == receipt["produced_gate_id"]
    )
    cross_source = _gate(value, stage="cross_source")
    receipt["consumed_gate_ids"][-1] = cross_source["gate_id"]
    produced["input_gate_ids"][-1] = cross_source["gate_id"]


def _remove_release_receipts_and_gate(value: Json) -> None:
    receipts = cast(list[Json], value["receipts"])
    receipts[:] = [item for item in receipts if item["command_kind"] != "release_output"]
    gate_id = cast(list[Json], value["trust_gates"])[-1]["gate_id"]
    value["trust_gates"] = [
        item for item in cast(list[Json], value["trust_gates"]) if item["gate_id"] != gate_id
    ]


@pytest.mark.parametrize(
    ("projection_name", "mutation", "message"),
    [
        (
            "clean",
            lambda item: item.update({"receipts": [], "trust_gates": []}),
            "requires a trust ledger",
        ),
        ("clean", _make_second_root, "exactly one leading batch root"),
        ("clean", _make_impossible_root_stage, "root uses an impossible stage"),
        ("ten", _make_cross_candidate_parent, "cross-candidate parentage"),
        ("clean", _make_two_record_parents, "single record lineage"),
        ("clean", _make_impossible_record_stage, "impossible validation stage"),
        ("clean", _make_stage_splice, "splices incompatible validation stages"),
        ("clean", _make_impossible_record_root, "starts at an impossible stage"),
        ("clean", _make_unauthorized_batch_fan_in, "unauthorized record fan-in"),
        ("ten", _make_repeated_candidate_fan_in, "repeats a candidate lineage"),
        ("clean", _make_unreceipted_batch_splice, "splices incompatible stages"),
        ("clean", _make_unreceipted_planning_reason_invalid, "lacks a bounded planning reason"),
        ("clean", _make_wrong_receipt_stage, "wrong workflow stage"),
        ("clean", _omit_binding_candidate_fan_in, "does not cover every record lineage"),
        ("clean", _use_wrong_binding_terminal, "required terminal stage"),
        ("clean", _remove_release_receipts_and_gate, "exactly one completed release command"),
    ],
)
def test_trust_causality_rejects_spliced_or_incomplete_ledgers(
    projection: DecisionProjectionV2,
    ten_candidate_projection: DecisionProjectionV2,
    projection_name: str,
    mutation: Mutation,
    message: str,
) -> None:
    selected = projection if projection_name == "clean" else ten_candidate_projection
    raw = deepcopy(selected.canonical_object())
    mutation(raw)
    with pytest.raises(ReleaseSpecV2Error) as caught:
        DecisionProjectionV2.from_canonical(raw)
    assert message in str(caught.value.__cause__)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(_mutate_numeric_fact, id="numeric-fact"),
        pytest.param(_mutate_boolean_fact, id="boolean-fact"),
        pytest.param(_mutate_evidence_hash, id="evidence-hash"),
        pytest.param(_mutate_source_role, id="source-role"),
        pytest.param(_mutate_field_path, id="field-path"),
        pytest.param(_mutate_categorical_source_value, id="categorical-source"),
        pytest.param(_mutate_categorical_canonical_value, id="categorical-value"),
        pytest.param(_mutate_categorical_hash, id="categorical-hash"),
        pytest.param(_mutate_interval_endpoint, id="interval-endpoint"),
        pytest.param(_mutate_interval_date, id="interval-date"),
        pytest.param(_mutate_interval_duration, id="interval-duration"),
        pytest.param(_mutate_feature_value, id="feature-value"),
        pytest.param(_mutate_feature_topology, id="feature-topology"),
        pytest.param(_mutate_rank_key, id="rank-key"),
        pytest.param(_mutate_band, id="route-band"),
        pytest.param(_mutate_unknown_vocabulary, id="unknown-vocabulary"),
        pytest.param(_mutate_receipt_order, id="receipt-order"),
        pytest.param(_mutate_command_dependency, id="command-dependency"),
        pytest.param(_mutate_fabricated_receipt, id="fabricated-receipt"),
        pytest.param(_mutate_missing_gate, id="missing-gate"),
        pytest.param(_mutate_forward_gate_reference, id="forward-gate"),
        pytest.param(_mutate_cross_candidate_gate, id="cross-candidate-gate"),
        pytest.param(_mutate_stage_splice, id="stage-splice"),
        pytest.param(_mutate_explanation, id="explanation"),
    ],
)
def test_projection_rejects_hostile_semantic_mutations(
    projection: DecisionProjectionV2,
    mutation: Mutation,
) -> None:
    raw = deepcopy(projection.canonical_object())
    mutation(raw)

    with pytest.raises(ReleaseSpecV2Error):
        DecisionProjectionV2.from_canonical(raw)


def test_projection_round_trip_and_digest_are_release_derived(
    runtime_observation: Json,
    projection: DecisionProjectionV2,
) -> None:
    stored = projection.canonical_object()
    assert DecisionProjectionV2.from_canonical(stored).digest() == projection.digest()
    assert (
        projection.digest()
        == hashlib.sha256(
            b"cv-trust-agent/decision-projection/v2\0" + canonical_json_bytes(stored)
        ).hexdigest()
    )

    producer_claims = deepcopy(runtime_observation)
    producer_claims["decision_fingerprint"] = "f" * 64
    producer_claims["passed"] = True
    assert DecisionProjectionV2.from_observation(producer_claims).digest() == projection.digest()


def test_all_four_runtime_strategies_have_independently_valid_release_projections(
    projection: DecisionProjectionV2,
    supported_projection: DecisionProjectionV2,
    partial_projection: DecisionProjectionV2,
    hold_projection: DecisionProjectionV2,
) -> None:
    projections = (
        projection,
        supported_projection,
        partial_projection,
        hold_projection,
    )
    assert {item.strategy for item in projections} == {
        "FULL_EVIDENCE_RANKING",
        "SUPPORTED_ONLY_RANKING",
        "PARTIAL_SAFE_RANKING",
        "BATCH_INTEGRITY_HOLD",
    }
    assert {item.ranking_scope for item in projections} == {
        "COMPLETE",
        "PARTIAL",
        "NONE",
    }
    for item in projections:
        assert (
            DecisionProjectionV2.from_canonical(item.canonical_object()).digest() == item.digest()
        )


def test_deterministic_semantics_rederive_exact_equal_and_invariant_results(
    tmp_path: Path,
    ten_candidate_projection: DecisionProjectionV2,
) -> None:
    oracle_path, artifact_path, _ = _deterministic_oracle_and_artifact(
        tmp_path, ten_candidate_projection
    )

    release = validate_deterministic_semantics_v2(artifact_path, oracle_path)

    assert release.case_count == 2
    assert release.artifact_invariant_count == 5
    assert release.projection("clean").digest() == ten_candidate_projection.digest()
    assert release.fixture_tree_sha256("directive") == "a" * 64
    assert len(release.release_binding_sha256) == 64
    with pytest.raises(KeyError):
        release.projection("missing")
    with pytest.raises(KeyError):
        release.fixture_tree_sha256("missing")
    with pytest.raises(DeterministicReleaseV2Error, match="25 cases"):
        validate_deterministic_release_v2(artifact_path, oracle_path)


def test_fixed_exact_commitment_rejects_coordinated_self_consistent_graph_relabel(
    tmp_path: Path,
    ten_candidate_projection: DecisionProjectionV2,
) -> None:
    oracle_path, artifact_path, _ = _deterministic_oracle_and_artifact(
        tmp_path,
        ten_candidate_projection,
    )
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    for observation in cast(list[Json], artifact["observations"]):
        projection = cast(Json, observation["projection"])
        graph = _graph(projection)
        fact = _fact(projection, "spreadsheet")
        fact["source_value"] = "Google Sheets"
        fact["canonical_value"] = "google sheets"
        fact["normalized_value"] = "Google Sheets"
        fact["canonical_value_sha256"] = canonical_value_sha256("google sheets")
        evidence_hash = hashlib.sha256(canonical_json_bytes("Google Sheets")).hexdigest()
        evidence_ids = set(cast(list[str], fact["evidence_ids"]))
        for reference in cast(list[Json], graph["evidence_manifest"]):
            if reference["evidence_id"] in evidence_ids:
                reference["semantic_hash"] = evidence_hash
    artifact_path.write_bytes(canonical_json_bytes(artifact) + b"\n")

    with pytest.raises(DeterministicReleaseV2Error, match="semantic decision differs"):
        validate_deterministic_semantics_v2(artifact_path, oracle_path)


@pytest.mark.parametrize(
    ("target", "replacement", "message"),
    [
        ("artifact.oracle_sha256", "b" * 64, "not bound"),
        ("artifact.observations.0.fixture_tree_sha256", "b" * 64, "fixture bytes"),
        (
            "oracle.cases.0.expectation.strategy_scope",
            "SUPPORTED_ONLY_RANKING",
            "strategy or scope",
        ),
        (
            "oracle.cases.0.expectation.routes.0.band_queue",
            "POTENTIAL_EVIDENCE_MATCH",
            "routes differ",
        ),
        (
            "oracle.cases.0.expectation.required_completed_commands",
            ["request_corroboration"],
            "omitted a required command",
        ),
        (
            "oracle.cases.0.expectation.forbidden_completed_commands",
            ["rank_full_evidence"],
            "completed a forbidden command",
        ),
        (
            "oracle.invariants.2.expected_strategies",
            {"clean": "SUPPORTED_ONLY_RANKING"},
            "invariant failed",
        ),
    ],
)
def test_deterministic_semantics_rejects_oracle_and_artifact_tampering(
    tmp_path: Path,
    ten_candidate_projection: DecisionProjectionV2,
    target: str,
    replacement: object,
    message: str,
) -> None:
    oracle_path, artifact_path, _ = _deterministic_oracle_and_artifact(
        tmp_path, ten_candidate_projection
    )
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    root_name, *segments = target.split(".")
    current: Any = artifact if root_name == "artifact" else oracle
    for segment in segments[:-1]:
        current = current[int(segment)] if segment.isdigit() else current[segment]
    if segments[-1] == "strategy_scope":
        current["strategy"] = replacement
        current["ranking_scope"] = "PARTIAL"
    elif segments[-1] == "band_queue":
        current["band"] = replacement
        current["queue"] = "STANDARD_HUMAN_REVIEW"
    else:
        current[segments[-1]] = replacement
    if root_name == "oracle":
        validated_oracle = DeterministicOracleV2.model_validate_json(canonical_json_bytes(oracle))
        artifact["oracle_sha256"] = oracle_sha256_v2(validated_oracle)
        oracle_path.write_bytes(canonical_json_bytes(oracle) + b"\n")
    artifact_path.write_bytes(canonical_json_bytes(artifact) + b"\n")

    with pytest.raises(DeterministicReleaseV2Error, match=message):
        validate_deterministic_semantics_v2(artifact_path, oracle_path)


def test_deterministic_structure_rejects_duplicate_cases_and_bad_projection(
    tmp_path: Path,
    ten_candidate_projection: DecisionProjectionV2,
) -> None:
    _oracle_path, artifact_path, _ = _deterministic_oracle_and_artifact(
        tmp_path, ten_candidate_projection
    )
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["observations"][1]["case_name"] = "clean"
    artifact_path.write_bytes(canonical_json_bytes(artifact) + b"\n")
    with pytest.raises(DeterministicReleaseV2Error, match="repeat a case"):
        validate_deterministic_structure_v2(artifact_path)

    artifact["observations"][1]["case_name"] = "directive"
    artifact["observations"][1]["projection"]["strategy"] = "TRUST_MODEL"
    artifact_path.write_bytes(canonical_json_bytes(artifact) + b"\n")
    with pytest.raises(DeterministicReleaseV2Error, match="invalid decision projection"):
        validate_deterministic_structure_v2(artifact_path)


def test_secure_semantics_derive_safety_utility_and_pair_evaluability(
    tmp_path: Path,
    projection: DecisionProjectionV2,
) -> None:
    heldout_oracle_path = Path("evaluation/heldout_release_oracle_v2.json")
    artifact = _write_jsonl(
        tmp_path / "secure-v2.jsonl",
        _secure_attempt_rows(projection, heldout_oracle_path),
    )

    release = validate_secure_semantics_v2(
        artifact,
        deterministic_release=_deterministic_release_fixture(projection),
        heldout_oracle_path=heldout_oracle_path,
    )

    assert release.attempt_count == 12
    assert release.execution_success_count == 12
    assert release.canonical_bound_count == 6
    assert release.unsupported_claim_count == 0
    assert release.clean_utility_run_count == 3
    assert release.canonical_evaluable_pair_count == 3
    assert release.canonical_noninterference_pair_count == 3
    assert release.heldout_evaluable_pair_count == 3
    assert release.heldout_noninterference_pair_count == 3
    assert release.protocol_complete
    assert release.safety_passed
    assert release.hard_gate_passed
    configurations = {item.arm: item for item in release.arm_configurations}
    assert configurations["canonical"].source_timeout_seconds == 0.5
    assert configurations["canonical"].source_max_attempts == 1
    assert configurations["heldout"].source_timeout_seconds is None
    assert configurations["heldout"].source_max_attempts is None


def test_secure_and_naive_jsonl_reject_duplicate_keys(
    tmp_path: Path,
    projection: DecisionProjectionV2,
) -> None:
    heldout_oracle_path = Path("evaluation/heldout_release_oracle_v2.json")
    secure_rows = _secure_attempt_rows(projection, heldout_oracle_path)
    secure_lines = [canonical_json_bytes(item) for item in secure_rows]
    secure_lines[0] = secure_lines[0].replace(
        b'{"arm":',
        b'{"arm":"heldout","arm":',
        1,
    )
    secure_artifact = tmp_path / "secure-v2.jsonl"
    secure_artifact.write_bytes(b"\n".join(secure_lines) + b"\n")
    with pytest.raises(SecureReleaseV2Error, match="not strict JSON"):
        validate_secure_structure_v2(secure_artifact)

    naive_rows = _naive_attempt_rows()
    naive_lines = [canonical_json_bytes(item) for item in naive_rows]
    naive_lines[0] = naive_lines[0].replace(
        b'{"attack_cohort_sha256":',
        b'{"attack_cohort_sha256":"0","attack_cohort_sha256":',
        1,
    )
    naive_artifact = tmp_path / "naive-v2.jsonl"
    naive_artifact.write_bytes(b"\n".join(naive_lines) + b"\n")
    with pytest.raises(NaiveReleaseV2Error, match="row is invalid"):
        validate_naive_structure_v2(naive_artifact)


def test_secure_semantics_retain_failures_without_calling_them_invariant(
    tmp_path: Path,
    projection: DecisionProjectionV2,
) -> None:
    heldout_oracle_path = Path("evaluation/heldout_release_oracle_v2.json")
    rows = _secure_attempt_rows(projection, heldout_oracle_path)
    for row in rows:
        row["result"] = {"kind": "failure", "failure_code": "provider_failure"}
    artifact = _write_jsonl(tmp_path / "secure-v2.jsonl", rows)

    release = validate_secure_semantics_v2(
        artifact,
        deterministic_release=_deterministic_release_fixture(projection),
        heldout_oracle_path=heldout_oracle_path,
    )

    assert release.execution_success_count == 0
    assert release.canonical_evaluable_pair_count == 0
    assert release.heldout_evaluable_pair_count == 0
    assert release.unsupported_claim_count == 0
    assert not release.hard_gate_passed


def test_secure_semantics_counts_unsupported_claims_and_mapper_failures(
    tmp_path: Path,
    projection: DecisionProjectionV2,
) -> None:
    heldout_oracle_path = Path("evaluation/heldout_release_oracle_v2.json")
    rows = _secure_attempt_rows(projection, heldout_oracle_path)
    heldout_rows = [row for row in rows if row["arm"] == "heldout"]
    result = cast(Json, heldout_rows[0]["result"])
    candidates = cast(list[Json], result["candidates"])
    first_claim = cast(list[Json], candidates[0]["claims"])[0]
    first_claim["citation_span_sha256"] = ["9" * 64]
    candidates[1] = {
        "candidate_id": candidates[1]["candidate_id"],
        "snapshot_id": candidates[1]["snapshot_id"],
        "outcome": "mapper_failure",
        "failure_code": "provider_failure",
        "claims": [],
    }
    artifact = _write_jsonl(tmp_path / "secure-v2.jsonl", rows)

    release = validate_secure_semantics_v2(
        artifact,
        deterministic_release=_deterministic_release_fixture(projection),
        heldout_oracle_path=heldout_oracle_path,
    )

    assert release.unsupported_claim_count == 1
    assert release.heldout_evaluable_pair_count == 2
    assert not release.safety_passed
    assert not release.hard_gate_passed


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda rows: rows.__setitem__(0, {**rows[0], "model_identifier": "different_model"}),
            "changes frozen execution metadata",
        ),
        (
            lambda rows: [
                row.__setitem__("prompt_sha256", "9" * 64)
                for row in rows
                if row["arm"] == "canonical"
            ],
            "frozen prompt or mapper deadline",
        ),
        (
            lambda rows: [
                row.__setitem__("mapper_timeout_seconds", 31.0)
                for row in rows
                if row["arm"] == "heldout"
            ],
            "frozen prompt or mapper deadline",
        ),
        (
            lambda rows: rows[0].__setitem__("fixture_tree_sha256", "9" * 64),
            "uncommitted fixture bytes",
        ),
        (
            lambda rows: rows[0].__setitem__("condition_order_index", 2),
            "row schema is invalid",
        ),
        (
            lambda rows: rows[0].pop("source_timeout_seconds"),
            "row schema is invalid",
        ),
        (
            lambda rows: rows[0].__setitem__("source_timeout_seconds", 0.6),
            "row schema is invalid",
        ),
        (
            lambda rows: rows[-1].update({"source_timeout_seconds": 0.5, "source_max_attempts": 1}),
            "row schema is invalid",
        ),
        (
            lambda rows: rows[-1].__setitem__("heldout_oracle_sha256", "9" * 64),
            "not bound to the frozen oracle",
        ),
        (
            lambda rows: rows[-1].__setitem__("implementation_tree_sha256", "9" * 64),
            "changes frozen execution metadata",
        ),
        (
            lambda rows: cast(Json, rows[0]["result"]).__setitem__(
                "projection", {"schema_version": 2}
            ),
            "canonical attempt projection is invalid",
        ),
        (
            lambda rows: cast(list[Json], cast(Json, rows[-1]["result"])["candidates"])[
                0
            ].__setitem__("candidate_id", "AP-999"),
            "candidate set differs",
        ),
        (
            lambda rows: cast(list[Json], cast(Json, rows[-1]["result"])["candidates"])[
                0
            ].__setitem__("snapshot_id", "other_snapshot"),
            "mixes snapshots",
        ),
    ],
)
def test_secure_semantics_rejects_protocol_and_result_tampering(
    tmp_path: Path,
    projection: DecisionProjectionV2,
    mutation: Callable[[list[Json]], None],
    message: str,
) -> None:
    heldout_oracle_path = Path("evaluation/heldout_release_oracle_v2.json")
    rows = _secure_attempt_rows(projection, heldout_oracle_path)
    mutation(rows)
    artifact = _write_jsonl(tmp_path / "secure-v2.jsonl", rows)
    with pytest.raises(SecureReleaseV2Error, match=message):
        validate_secure_semantics_v2(
            artifact,
            deterministic_release=_deterministic_release_fixture(projection),
            heldout_oracle_path=heldout_oracle_path,
        )


def test_naive_semantics_rederive_counterbalanced_rank_effect_metrics(
    tmp_path: Path,
) -> None:
    artifact = _write_jsonl(tmp_path / "naive-v2.jsonl", _naive_attempt_rows())

    release = validate_naive_semantics_v2(artifact)

    assert release.attempt_count == 32
    assert release.block_count == 8
    assert release.protocol_complete
    assert release.attack.pair_count == 8
    assert release.attack.evaluable_pair_count == 8
    assert release.attack.positive_rank_gain_count > 0
    assert release.attack.rank_one_entry_count > 0
    assert release.attack.top_three_entry_count > 0
    assert release.attack.target_rank_delta_total > 0
    assert release.clean_control.evaluable_pair_count == 8
    assert release.clean_control.pairwise_inversions_total > 0
    assert release.clean_control.unaffected_order_changes_total > 0


def test_naive_semantics_retains_failed_denominators(tmp_path: Path) -> None:
    rows = _naive_attempt_rows()
    rows[0]["result"] = {
        "status": "provider_failure",
        "ordered_candidate_ids": None,
    }
    rows[2]["result"] = {
        "status": "no_parsed_ranking",
        "ordered_candidate_ids": None,
    }
    artifact = _write_jsonl(tmp_path / "naive-v2.jsonl", rows)

    release = validate_naive_semantics_v2(artifact)

    assert release.attack.evaluable_pair_count == 7
    assert release.attack.failed_attempt_count == 1
    assert release.clean_control.evaluable_pair_count == 7
    assert release.clean_control.failed_attempt_count == 1


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda rows: rows[-1].__setitem__("model_identifier", "other_model"),
            "share one preregistration",
        ),
        (
            lambda rows: [
                row.__setitem__("attack_cohort_sha256", NAIVE_CLEAN_COHORT_SHA256_V2)
                or row.__setitem__(
                    "input_cohort_sha256",
                    NAIVE_CLEAN_COHORT_SHA256_V2,
                )
                for row in rows
            ],
            "attack and clean cohorts are identical",
        ),
        (
            lambda rows: [row.__setitem__("target_candidate_id", "AP-004") for row in rows],
            "frozen preregistration",
        ),
        (
            lambda rows: [row.__setitem__("prompt_sha256", "9" * 64) for row in rows],
            "frozen preregistration",
        ),
        (
            lambda rows: [row.__setitem__("changed_detail_candidate_ids", []) for row in rows],
            "mutation is not target-only",
        ),
        (
            lambda rows: [row.__setitem__("mutation_channel", "pdf") for row in rows],
            "frozen preregistration",
        ),
        (
            lambda rows: rows[0].__setitem__("block_id", 2),
            "Latin-square schedule is incomplete",
        ),
        (
            lambda rows: rows[0].__setitem__(
                "candidate_order", list(reversed(cast(list[str], rows[0]["candidate_order"])))
            ),
            "different candidate orders",
        ),
        (_reverse_first_naive_block, "preregistered seeded permutation"),
    ],
)
def test_naive_semantics_rejects_protocol_tampering(
    tmp_path: Path,
    mutation: Callable[[list[Json]], object],
    message: str,
) -> None:
    rows = _naive_attempt_rows()
    mutation(rows)
    artifact = _write_jsonl(tmp_path / "naive-v2.jsonl", rows)
    with pytest.raises(NaiveReleaseV2Error, match=message):
        validate_naive_semantics_v2(artifact)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row.__setitem__("candidate_order", ["AP-001"] * 10),
        lambda row: row.__setitem__("input_cohort_sha256", "9" * 64),
        lambda row: cast(Json, row["result"]).__setitem__("ordered_candidate_ids", ["AP-001"] * 10),
    ],
)
def test_naive_structure_rejects_self_inconsistent_rows(
    tmp_path: Path,
    mutation: Callable[[Json], None],
) -> None:
    rows = _naive_attempt_rows()
    mutation(rows[0])
    artifact = _write_jsonl(tmp_path / "naive-v2.jsonl", rows)
    with pytest.raises(NaiveReleaseV2Error, match="row is invalid"):
        validate_naive_structure_v2(artifact)


def _write_placeholder_v2_artifacts(evidence_directory: Path) -> None:
    evidence_directory.mkdir(parents=True)
    (evidence_directory / "deterministic-v2.json").write_bytes(b"deterministic\n")
    (evidence_directory / "secure-v2.jsonl").write_bytes(b"secure\n")
    (evidence_directory / "naive-v2.jsonl").write_bytes(b"naive\n")


@pytest.mark.parametrize("substituted", ["deterministic", "heldout"])
@pytest.mark.parametrize("operation", ["write", "validate"])
def test_public_aggregate_rejects_substitute_oracle_paths(
    tmp_path: Path,
    substituted: str,
    operation: str,
) -> None:
    deterministic = tmp_path / "evaluation" / "oracle_v2.json"
    heldout = tmp_path / "evaluation" / "heldout_release_oracle_v2.json"
    if substituted == "deterministic":
        deterministic = tmp_path / "substitute-deterministic.json"
    else:
        heldout = tmp_path / "substitute-heldout.json"

    with pytest.raises(AggregateV2Error, match="canonical repository oracles"):
        if operation == "write":
            aggregate_v2.write_release_manifest_v2(
                tmp_path / "evidence",
                deterministic_oracle_path=deterministic,
                heldout_oracle_path=heldout,
                repository_root=tmp_path,
            )
        else:
            validate_aggregate_v2(
                tmp_path / "evidence" / "manifest-v2.json",
                deterministic_oracle_path=deterministic,
                heldout_oracle_path=heldout,
                repository_root=tmp_path,
            )


def test_aggregate_writer_and_validator_bind_all_transitive_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: DecisionProjectionV2,
) -> None:
    evidence_directory = tmp_path / "evidence"
    _write_placeholder_v2_artifacts(evidence_directory)
    deterministic = _deterministic_release_fixture(projection)
    _patch_aggregate_dependencies(monkeypatch, deterministic)
    generated_at = datetime(2026, 8, 16, 12, tzinfo=UTC)

    manifest = aggregate_v2.write_release_manifest_v2(
        evidence_directory,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
        repository_root=tmp_path,
        generated_at=generated_at,
    )
    monkeypatch.setattr(
        aggregate_v2,
        "_execute_property_gate_families",
        lambda _root: (
            "unseen_identity_renaming_and_input_permutation",
            "unseen_value_equivalence_and_composed_transform",
        ),
    )

    release = validate_aggregate_v2(
        manifest,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
        repository_root=tmp_path,
    )

    assert release.artifact_invariant_count == 47
    assert release.property_gate_count == 2
    assert release.total_release_gate_count == 49
    assert release.implementation_tree_sha256 == "c" * 64
    with pytest.raises(FileExistsError):
        aggregate_v2.write_release_manifest_v2(
            evidence_directory,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            generated_at=generated_at,
        )


def test_v2_aggregate_rejects_implementation_drift_during_property_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: DecisionProjectionV2,
) -> None:
    implementation = tmp_path / "synthetic" / "implementation.py"
    implementation.parent.mkdir()
    implementation.write_text("before = True\n", encoding="utf-8")
    expected_hash = implementation_tree_sha256_v2(
        (implementation,),
        repository_root=tmp_path,
    )
    deterministic = replace(
        _deterministic_release_fixture(projection),
        implementation_tree_sha256=expected_hash,
    )
    secure = replace(
        _secure_release_fixture(),
        implementation_tree_sha256=expected_hash,
    )
    naive = replace(
        _naive_release_fixture(),
        implementation_tree_sha256=expected_hash,
    )
    _patch_aggregate_dependencies(
        monkeypatch,
        deterministic,
        secure=secure,
        naive=naive,
        current_hash=expected_hash,
    )
    monkeypatch.setattr(
        aggregate_v2,
        "release_implementation_paths_v2",
        lambda _root: (implementation,),
    )
    monkeypatch.setattr(
        aggregate_v2,
        "implementation_tree_sha256_v2",
        implementation_tree_sha256_v2,
    )
    evidence_directory = tmp_path / "evidence"
    _write_placeholder_v2_artifacts(evidence_directory)
    manifest = aggregate_v2.write_release_manifest_v2(
        evidence_directory,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
        repository_root=tmp_path,
    )

    def mutate_tree(_root: Path) -> tuple[str, str]:
        implementation.write_text("after = True\n", encoding="utf-8")
        return (
            "unseen_identity_renaming_and_input_permutation",
            "unseen_value_equivalence_and_composed_transform",
        )

    monkeypatch.setattr(aggregate_v2, "_execute_property_gate_families", mutate_tree)
    with pytest.raises(AggregateV2Error, match="changed during property-gate execution"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
        )


def test_integrity_manifest_can_record_but_release_rejects_failed_secure_hard_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: DecisionProjectionV2,
) -> None:
    evidence_directory = tmp_path / "evidence"
    _write_placeholder_v2_artifacts(evidence_directory)
    deterministic = _deterministic_release_fixture(projection)
    failed_secure = replace(_secure_release_fixture(), hard_gate_passed=False)
    _patch_aggregate_dependencies(monkeypatch, deterministic, secure=failed_secure)
    manifest = aggregate_v2.write_release_manifest_v2(
        evidence_directory,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=(tmp_path / "evaluation" / "heldout_release_oracle_v2.json"),
        repository_root=tmp_path,
    )

    with pytest.raises(AggregateV2Error, match="secure release hard gate"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=(tmp_path / "evaluation" / "heldout_release_oracle_v2.json"),
            repository_root=tmp_path,
            execute_property_gates=False,
        )
    integrity_only = validate_aggregate_v2(
        manifest,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
        repository_root=tmp_path,
        execute_property_gates=False,
        require_secure_hard_gate=False,
    )
    assert not integrity_only.secure.hard_gate_passed


def test_aggregate_writer_rejects_missing_stale_and_unbound_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: DecisionProjectionV2,
) -> None:
    deterministic = _deterministic_release_fixture(projection)
    _patch_aggregate_dependencies(monkeypatch, deterministic)
    with pytest.raises(AggregateV2Error, match="exact three artifacts"):
        aggregate_v2.write_release_manifest_v2(
            tmp_path / "missing",
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
        )

    evidence_directory = tmp_path / "stale"
    _write_placeholder_v2_artifacts(evidence_directory)
    _patch_aggregate_dependencies(
        monkeypatch,
        replace(deterministic, implementation_tree_sha256="9" * 64),
    )
    with pytest.raises(AggregateV2Error, match="stale or use mixed"):
        aggregate_v2.write_release_manifest_v2(
            evidence_directory,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
        )

    _patch_aggregate_dependencies(
        monkeypatch,
        deterministic,
        naive=replace(_naive_release_fixture(), clean_fixture_tree_sha256="9" * 64),
    )
    with pytest.raises(AggregateV2Error, match="naïve fixtures"):
        aggregate_v2.write_release_manifest_v2(
            evidence_directory,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
        )

    _patch_aggregate_dependencies(monkeypatch, deterministic)
    with pytest.raises(AggregateV2Error, match="timezone aware"):
        aggregate_v2.write_release_manifest_v2(
            evidence_directory,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            generated_at=datetime(2026, 8, 16, 12),
        )


def test_aggregate_validator_rejects_hash_or_commitment_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: DecisionProjectionV2,
) -> None:
    evidence_directory = tmp_path / "evidence"
    _write_placeholder_v2_artifacts(evidence_directory)
    deterministic = _deterministic_release_fixture(projection)
    _patch_aggregate_dependencies(monkeypatch, deterministic)
    manifest = aggregate_v2.write_release_manifest_v2(
        evidence_directory,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
        repository_root=tmp_path,
    )
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["artifacts"][0]["sha256"] = "0" * 64
    manifest.write_bytes(canonical_json_bytes(raw) + b"\n")
    with pytest.raises(AggregateV2Error, match="hash differs"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            execute_property_gates=False,
        )


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("deterministic_oracle_sha256", "deterministic oracle commitment"),
        ("heldout_oracle_sha256", "held-out oracle commitment"),
        ("implementation_tree_sha256", "different implementation trees"),
    ],
)
def test_aggregate_validator_rejects_manifest_binding_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: DecisionProjectionV2,
    field: str,
    message: str,
) -> None:
    evidence_directory = tmp_path / "evidence"
    _write_placeholder_v2_artifacts(evidence_directory)
    deterministic = _deterministic_release_fixture(projection)
    _patch_aggregate_dependencies(monkeypatch, deterministic)
    manifest = aggregate_v2.write_release_manifest_v2(
        evidence_directory,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
        repository_root=tmp_path,
    )
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw[field] = "9" * 64
    manifest.write_bytes(canonical_json_bytes(raw) + b"\n")
    with pytest.raises(AggregateV2Error, match=message):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            execute_property_gates=False,
        )


def test_aggregate_validator_rejects_configuration_gate_and_freshness_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: DecisionProjectionV2,
) -> None:
    evidence_directory = tmp_path / "evidence"
    _write_placeholder_v2_artifacts(evidence_directory)
    deterministic = _deterministic_release_fixture(projection)
    _patch_aggregate_dependencies(monkeypatch, deterministic)
    manifest = aggregate_v2.write_release_manifest_v2(
        evidence_directory,
        deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
        heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
        repository_root=tmp_path,
    )
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["secure_arm_configurations"][0]["sdk_version"] = "sdk_2.0"
    manifest.write_bytes(canonical_json_bytes(raw) + b"\n")
    with pytest.raises(AggregateV2Error, match="configuration differs"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            execute_property_gates=False,
        )

    raw["secure_arm_configurations"][0]["sdk_version"] = "sdk_1.0"
    manifest.write_bytes(canonical_json_bytes(raw) + b"\n")
    _patch_aggregate_dependencies(monkeypatch, deterministic, current_hash="9" * 64)
    with pytest.raises(AggregateV2Error, match="stale relative"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            execute_property_gates=False,
        )

    _patch_aggregate_dependencies(monkeypatch, deterministic)
    monkeypatch.setattr(
        aggregate_v2, "_execute_property_gate_families", lambda _root: ("only_one",)
    )
    with pytest.raises(AggregateV2Error, match="not completely executed"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
        )

    _patch_aggregate_dependencies(
        monkeypatch,
        replace(deterministic, artifact_invariant_count=46),
    )
    with pytest.raises(AggregateV2Error, match="invariant count is incomplete"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            execute_property_gates=False,
        )


def test_property_gate_runner_accounts_for_success_and_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(aggregate_v2, "execute_property_gate_nodes", lambda *_args: ())
    assert aggregate_v2._execute_property_gate_families(tmp_path) == (
        "unseen_identity_renaming_and_input_permutation",
        "unseen_value_equivalence_and_composed_transform",
    )

    def fail(*_args: object) -> tuple[str, ...]:
        raise PropertyGateRunnerError("controlled failure")

    monkeypatch.setattr(aggregate_v2, "execute_property_gate_nodes", fail)
    with pytest.raises(AggregateV2Error, match="family failed"):
        aggregate_v2._execute_property_gate_families(tmp_path)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"[]",
        b'{"duplicate":1,"duplicate":2}',
        b'{"not_finite":NaN}',
        b'{"too_deep":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}',
    ],
)
def test_strict_json_loader_rejects_ambiguous_or_unbounded_json(
    tmp_path: Path, payload: bytes
) -> None:
    path = tmp_path / "artifact.json"
    path.write_bytes(payload)
    with pytest.raises(ReleaseSpecV2Error):
        load_strict_json_object(path, maximum_bytes=1024)


def test_strict_json_loader_accepts_one_bounded_object(tmp_path: Path) -> None:
    path = tmp_path / "artifact.json"
    path.write_bytes(b'{"answer":42}')
    assert load_strict_json_object(path, maximum_bytes=1024) == {"answer": 42}


@pytest.mark.parametrize(
    ("validator", "error"),
    [
        (validate_deterministic_structure_v2, DeterministicReleaseV2Error),
        (validate_secure_structure_v2, SecureReleaseV2Error),
        (validate_naive_structure_v2, NaiveReleaseV2Error),
    ],
)
def test_v2_artifact_readers_reject_missing_empty_and_malformed_inputs(
    tmp_path: Path,
    validator: Callable[[Path], object],
    error: type[ValueError],
) -> None:
    with pytest.raises(error):
        validator(tmp_path / "missing")

    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    with pytest.raises(error):
        validator(empty)

    malformed = tmp_path / "malformed"
    malformed.write_bytes(b"not-json\n")
    with pytest.raises(error):
        validator(malformed)


def test_structural_readers_reject_unknown_or_incomplete_records(tmp_path: Path) -> None:
    deterministic = tmp_path / "deterministic.json"
    deterministic.write_text("{}", encoding="utf-8")
    with pytest.raises(DeterministicReleaseV2Error):
        validate_deterministic_structure_v2(deterministic)

    secure = tmp_path / "secure.jsonl"
    secure.write_text('{"event":"not_allowed"}\n', encoding="utf-8")
    with pytest.raises(SecureReleaseV2Error, match="event is not allowed"):
        validate_secure_structure_v2(secure)

    naive = tmp_path / "naive.jsonl"
    naive.write_text("{}\n", encoding="utf-8")
    with pytest.raises(NaiveReleaseV2Error, match="row is invalid"):
        validate_naive_structure_v2(naive)


def test_aggregate_rejects_manifest_without_exact_release_schema(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest-v2.json"
    manifest.write_text("{}", encoding="utf-8")
    with pytest.raises(AggregateV2Error, match="manifest is invalid"):
        validate_aggregate_v2(
            manifest,
            deterministic_oracle_path=tmp_path / "evaluation" / "oracle_v2.json",
            heldout_oracle_path=tmp_path / "evaluation" / "heldout_release_oracle_v2.json",
            repository_root=tmp_path,
            execute_property_gates=False,
        )


def test_implementation_tree_hash_is_stable_and_path_bound(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    (source / "b.pyc").write_bytes(b"ignored")
    first = implementation_tree_sha256_v2((source,), repository_root=tmp_path)
    second = implementation_tree_sha256_v2((source,), repository_root=tmp_path)
    assert first == second
    (source / "a.py").write_text("x = 2\n", encoding="utf-8")
    assert implementation_tree_sha256_v2((source,), repository_root=tmp_path) != first
