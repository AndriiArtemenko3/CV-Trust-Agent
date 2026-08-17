"""Deterministic V2.2 validator: dual-digest oracle binding and invariants."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from evaluation.deterministic_release_v22 import (
    DeterministicReleaseV22Error,
    validate_deterministic_release_v22,
    validate_deterministic_semantics_v22,
    validate_deterministic_structure_v22,
)
from evaluation.oracle_spec_v22 import (
    DeterministicOracleV22,
    load_deterministic_oracle_v22,
    oracle_sha256_v22,
)
from evaluation.oracle_v22_source import frozen_release_oracle_matches_v22
from evaluation.release_spec_v22 import DecisionProjectionV22, canonical_json_bytes
from tests.test_engine_unit import _case, _record, _run

Json = dict[str, Any]


@pytest.fixture(scope="module")
def ten_candidate_projection() -> DecisionProjectionV22:
    records = tuple(_record(f"AP-{index:03d}") for index in range(1, 11))
    decision = _run(_case(records))
    return DecisionProjectionV22.from_observation(
        cast(Json, decision.model_dump(mode="json", exclude_none=True))
    )


def _route_expectation(route: Json) -> Json:
    return {
        "candidate_id": route["candidate_id"],
        "band": route["band"],
        "queue": route["queue"],
        "evidence_rank": route["evidence_rank"],
        "display_position": route["display_position"],
        "rank_key": route["rank_key"],
    }


def _completed_command_kinds(projection: DecisionProjectionV22) -> set[str]:
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


def _oracle_and_artifact_v22(
    tmp_path: Path,
    projection: DecisionProjectionV22,
) -> tuple[Path, Path, DeterministicOracleV22]:
    routes = [
        _route_expectation(route)
        for route in cast(list[Json], projection.canonical_object()["routes"])
    ]
    explanations = [
        explanation.model_dump(mode="json", exclude_none=False)
        for explanation in projection.explanations
    ]
    assert "release_output" in _completed_command_kinds(projection)
    fixture_digest = "a" * 64
    oracle_object: Json = {
        "schema_version": 3,
        "protocol_version": "2.2",
        "suite_id": "unit_v22",
        "cases": [
            {
                "name": "clean",
                "fixture_id": "unit_clean",
                "fixture_tree_sha256": fixture_digest,
                "showcase": True,
                "expectation": {
                    "kind": "exact",
                    "decision_action_sha256": projection.action_semantic_digest(),
                    "decision_audit_sha256": projection.audit_digest(),
                    "strategy": projection.strategy,
                    "ranking_scope": projection.ranking_scope,
                    "routes": routes,
                    "explanations": explanations,
                    "required_completed_commands": ["release_output"],
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
        ],
    }
    oracle = DeterministicOracleV22.model_validate_json(canonical_json_bytes(oracle_object))
    oracle_path = tmp_path / "oracle-v22.json"
    oracle_path.write_bytes(
        canonical_json_bytes(oracle.model_dump(mode="json", exclude_none=False)) + b"\n"
    )
    artifact: Json = {
        "schema_version": 3,
        "protocol_version": "2.2",
        "run_id": "v24-20260817-r1",
        "artifact_kind": "deterministic_observations_v22",
        "oracle_sha256": oracle_sha256_v22(oracle),
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
    artifact_path = tmp_path / "deterministic-v22.json"
    artifact_path.write_bytes(canonical_json_bytes(artifact) + b"\n")
    return oracle_path, artifact_path, oracle


def _rewrite_artifact(artifact_path: Path, mutate: Any) -> None:
    artifact = json.loads(artifact_path.read_bytes())
    mutate(artifact)
    artifact_path.write_bytes(canonical_json_bytes(artifact) + b"\n")


def test_dual_digest_semantics_validate_green(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)
    release = validate_deterministic_semantics_v22(artifact_path, oracle_path)
    assert release.case_count == 2
    assert release.artifact_invariant_count == 2
    assert release.projection("clean").audit_digest() == (ten_candidate_projection.audit_digest())
    with pytest.raises(DeterministicReleaseV22Error, match="25 cases"):
        validate_deterministic_release_v22(artifact_path, oracle_path)


def test_action_digest_mismatch_is_detected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)
    raw = json.loads(oracle_path.read_bytes())
    raw["cases"][0]["expectation"]["decision_action_sha256"] = "9" * 64
    mutated = DeterministicOracleV22.model_validate_json(canonical_json_bytes(raw))
    oracle_path.write_bytes(
        canonical_json_bytes(mutated.model_dump(mode="json", exclude_none=False)) + b"\n"
    )
    _rewrite_artifact(
        artifact_path,
        lambda artifact: artifact.__setitem__("oracle_sha256", oracle_sha256_v22(mutated)),
    )
    with pytest.raises(DeterministicReleaseV22Error, match="action semantics differ"):
        validate_deterministic_semantics_v22(artifact_path, oracle_path)


def test_audit_digest_mismatch_is_detected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)
    raw = json.loads(oracle_path.read_bytes())
    raw["cases"][0]["expectation"]["decision_audit_sha256"] = "9" * 64
    mutated = DeterministicOracleV22.model_validate_json(canonical_json_bytes(raw))
    oracle_path.write_bytes(
        canonical_json_bytes(mutated.model_dump(mode="json", exclude_none=False)) + b"\n"
    )
    _rewrite_artifact(
        artifact_path,
        lambda artifact: artifact.__setitem__("oracle_sha256", oracle_sha256_v22(mutated)),
    )
    with pytest.raises(DeterministicReleaseV22Error, match="audit trace differs"):
        validate_deterministic_semantics_v22(artifact_path, oracle_path)


def test_v21_artifact_shape_is_rejected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    _, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)

    def downgrade(artifact: Json) -> None:
        artifact["schema_version"] = 2
        artifact["artifact_kind"] = "deterministic_observations_v2"
        del artifact["protocol_version"]

    _rewrite_artifact(artifact_path, downgrade)
    with pytest.raises(DeterministicReleaseV22Error, match="artifact is invalid"):
        validate_deterministic_structure_v22(artifact_path)


def test_unbound_oracle_and_reordered_suite_are_rejected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)
    _rewrite_artifact(
        artifact_path,
        lambda artifact: artifact.__setitem__("oracle_sha256", "9" * 64),
    )
    with pytest.raises(DeterministicReleaseV22Error, match="not bound"):
        validate_deterministic_semantics_v22(artifact_path, oracle_path)

    (tmp_path / "second").mkdir()
    oracle_path2, artifact_path2, _ = _oracle_and_artifact_v22(
        tmp_path / "second", ten_candidate_projection
    )

    def reorder(artifact: Json) -> None:
        artifact["observations"] = list(reversed(artifact["observations"]))

    _rewrite_artifact(artifact_path2, reorder)
    with pytest.raises(DeterministicReleaseV22Error, match="ordered complete oracle suite"):
        validate_deterministic_semantics_v22(artifact_path2, oracle_path2)


def test_fixture_commitment_mismatch_is_rejected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)

    def poison(artifact: Json) -> None:
        artifact["observations"][0]["fixture_tree_sha256"] = "9" * 64

    _rewrite_artifact(artifact_path, poison)
    with pytest.raises(DeterministicReleaseV22Error, match="fixture bytes differ"):
        validate_deterministic_semantics_v22(artifact_path, oracle_path)


class TestFrozenOracle:
    def test_frozen_oracle_v22_matches_its_mechanical_derivation(self) -> None:
        assert frozen_release_oracle_matches_v22(
            Path("evaluation/oracle_v22.json"),
            Path("evaluation/oracle_v2.json"),
        )

    def test_frozen_oracle_v22_loads_with_25_cases_and_47_invariants(self) -> None:
        oracle = load_deterministic_oracle_v22(Path("evaluation/oracle_v22.json"))
        assert oracle.suite_id == "release_v22"
        assert len(oracle.cases) == 25
        assert len(oracle.invariants) == 47
        assert oracle.schema_version == 3
        assert oracle.protocol_version == "2.2"

    def test_v21_oracle_is_rejected_by_v22_loader(self) -> None:
        from evaluation.oracle_spec_v22 import OracleSpecV22Error

        with pytest.raises(OracleSpecV22Error):
            load_deterministic_oracle_v22(Path("evaluation/oracle_v2.json"))


def _second_projection(records_variation: float) -> DecisionProjectionV22:
    records = tuple(
        _record(f"AP-{index:03d}", ap_years=records_variation if index == 10 else 4.0)
        for index in range(1, 11)
    )
    decision = _run(_case(records))
    return DecisionProjectionV22.from_observation(
        cast(Json, decision.model_dump(mode="json", exclude_none=True))
    )


def test_equal_case_action_divergence_is_detected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)
    divergent = _second_projection(1.0)
    assert divergent.action_semantic_digest() != ten_candidate_projection.action_semantic_digest()

    def swap_directive(artifact: Json) -> None:
        artifact["observations"][1]["projection"] = divergent.canonical_object()

    _rewrite_artifact(artifact_path, swap_directive)
    with pytest.raises(DeterministicReleaseV22Error, match="action-semantic reference"):
        validate_deterministic_semantics_v22(artifact_path, oracle_path)


def test_fixture_identity_mismatch_is_detected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)

    def poison(artifact: Json) -> None:
        artifact["observations"][0]["fixture_id"] = "unexpected_fixture"

    _rewrite_artifact(artifact_path, poison)
    with pytest.raises(DeterministicReleaseV22Error, match="fixture identity differs"):
        validate_deterministic_semantics_v22(artifact_path, oracle_path)


def test_invalid_oracle_file_is_rejected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    _, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)
    broken = tmp_path / "broken-oracle.json"
    broken.write_bytes(b'{"schema_version": 2}')
    with pytest.raises(DeterministicReleaseV22Error, match="oracle is invalid"):
        validate_deterministic_semantics_v22(artifact_path, broken)


def test_forbidden_completed_command_is_detected(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    (tmp_path / "forbidden").mkdir()
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(
        tmp_path / "forbidden", ten_candidate_projection
    )
    raw = json.loads(oracle_path.read_bytes())
    raw["cases"][0]["expectation"]["forbidden_completed_commands"] = ["release_output"]
    raw["cases"][0]["expectation"]["required_completed_commands"] = ["fetch_candidate_details"]
    mutated = DeterministicOracleV22.model_validate_json(canonical_json_bytes(raw))
    oracle_path.write_bytes(
        canonical_json_bytes(mutated.model_dump(mode="json", exclude_none=False)) + b"\n"
    )
    _rewrite_artifact(
        artifact_path,
        lambda artifact: artifact.__setitem__("oracle_sha256", oracle_sha256_v22(mutated)),
    )
    with pytest.raises(DeterministicReleaseV22Error, match="completed a forbidden command"):
        validate_deterministic_semantics_v22(artifact_path, oracle_path)


def test_remaining_invariant_kinds_and_helpers(
    ten_candidate_projection: DecisionProjectionV22,
) -> None:
    from evaluation.deterministic_release_v22 import (
        _evaluate_invariant,
        _explanation_summary,
    )
    from evaluation.oracle_spec_v22 import InvariantOracleV22

    projections = {"clean": ten_candidate_projection}
    removed = InvariantOracleV22.model_validate(
        {
            "name": "removed",
            "kind": "removed_commands_not_completed",
            "case": "clean",
        }
    )
    assert _evaluate_invariant(removed, projections)
    no_rank = InvariantOracleV22.model_validate(
        {
            "name": "no_rank",
            "kind": "no_ranking_commands_completed",
            "case": "clean",
        }
    )
    assert not _evaluate_invariant(no_rank, projections)

    summary = _explanation_summary(
        {"template": "strategy_selected", "candidate_id": None, "reason_codes": ["b", "a"]}
    )
    assert summary["reason_codes"] == ["a", "b"]
    with pytest.raises(DeterministicReleaseV22Error, match="not canonical JSON"):
        _explanation_summary({"template": "strategy_selected", "reason_codes": "oops"})


def test_release_lookup_helpers_and_invariant_count(
    tmp_path: Path, ten_candidate_projection: DecisionProjectionV22
) -> None:
    oracle_path, artifact_path, _ = _oracle_and_artifact_v22(tmp_path, ten_candidate_projection)
    release = validate_deterministic_semantics_v22(artifact_path, oracle_path)
    assert release.invariant_count == release.artifact_invariant_count
    with pytest.raises(KeyError):
        release.projection("missing")
    with pytest.raises(KeyError):
        release.fixture_tree_sha256("missing")
