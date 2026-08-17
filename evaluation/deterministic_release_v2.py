"""Independent semantic release validation for deterministic V2 observations.

Capture artifacts contain projections, not verdicts.  This module reconstructs
every projection, applies the frozen oracle, and derives all case and invariant
results in memory.  It intentionally imports neither capture code nor any
runtime/ranker/release module.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from evaluation.oracle_spec_v2 import (
    EqualExpectationV2,
    ExactExpectationV2,
    InvariantOracleV2,
    OracleSpecV2Error,
    load_deterministic_oracle_v2,
    oracle_sha256_v2,
)
from evaluation.release_spec_v2 import (
    DecisionProjectionV2,
    Digest,
    JsonObject,
    ReleaseSpecV2Error,
    RouteV2,
    Token,
    canonical_json_bytes,
    load_strict_json_object,
)

DETERMINISTIC_RELEASE_DOMAIN_V2 = b"cv-trust-agent/deterministic-release/v2\0"
RELEASE_CASE_COUNT_V2 = 25
RELEASE_ARTIFACT_INVARIANT_COUNT_V2 = 47
RELEASE_PROPERTY_GATE_COUNT_V2 = 2
RELEASE_TOTAL_GATE_COUNT_V2 = RELEASE_ARTIFACT_INVARIANT_COUNT_V2 + RELEASE_PROPERTY_GATE_COUNT_V2

_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_RANK_COMMANDS = frozenset(
    {"rank_full_evidence", "rank_supported_evidence", "rank_partial_evidence"}
)


class DeterministicReleaseV2Error(ValueError):
    """A deterministic V2 suite is not semantically release-valid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CaseObservationV2(_StrictModel):
    case_name: Token
    fixture_id: Token
    fixture_tree_sha256: Digest
    projection: JsonObject


class DeterministicArtifactV2(_StrictModel):
    schema_version: Literal[2]
    artifact_kind: Literal["deterministic_observations_v2"]
    oracle_sha256: Digest
    implementation_tree_sha256: Digest
    observations: tuple[CaseObservationV2, ...] = Field(min_length=1, max_length=64)


@dataclass(frozen=True, slots=True)
class StructuredDeterministicArtifactV2:
    oracle_sha256: str
    implementation_tree_sha256: str
    observations: tuple[tuple[str, str, str, DecisionProjectionV2], ...]
    artifact_sha256: str


@dataclass(frozen=True, slots=True)
class ValidatedDeterministicReleaseV2:
    suite_id: str
    oracle_sha256: str
    artifact_sha256: str
    implementation_tree_sha256: str
    release_binding_sha256: str
    case_count: int
    artifact_invariant_count: int
    projections: tuple[tuple[str, DecisionProjectionV2], ...]
    fixture_commitments: tuple[tuple[str, str], ...]
    fixture_ids: tuple[tuple[str, str], ...]

    def projection(self, case_name: str) -> DecisionProjectionV2:
        for name, projection in self.projections:
            if name == case_name:
                return projection
        raise KeyError(case_name)

    def fixture_tree_sha256(self, case_name: str) -> str:
        for name, digest in self.fixture_commitments:
            if name == case_name:
                return digest
        raise KeyError(case_name)

    @property
    def invariant_count(self) -> int:
        """Compatibility spelling; this count is artifact-derived only."""

        return self.artifact_invariant_count


def validate_deterministic_structure_v2(path: Path) -> StructuredDeterministicArtifactV2:
    """Validate artifact structure and each projection, without applying an oracle."""

    try:
        raw = load_strict_json_object(path, maximum_bytes=_MAX_ARTIFACT_BYTES)
        artifact = DeterministicArtifactV2.model_validate_json(canonical_json_bytes(raw))
    except Exception as exc:
        raise DeterministicReleaseV2Error("deterministic V2 artifact is invalid") from exc
    observations: list[tuple[str, str, str, DecisionProjectionV2]] = []
    names: set[str] = set()
    for observation in artifact.observations:
        if observation.case_name in names:
            raise DeterministicReleaseV2Error("deterministic observations repeat a case")
        names.add(observation.case_name)
        try:
            projection = DecisionProjectionV2.from_canonical(observation.projection)
        except ReleaseSpecV2Error as exc:
            raise DeterministicReleaseV2Error(
                "deterministic observation contains an invalid decision projection"
            ) from exc
        observations.append(
            (
                observation.case_name,
                observation.fixture_id,
                observation.fixture_tree_sha256,
                projection,
            )
        )
    return StructuredDeterministicArtifactV2(
        oracle_sha256=artifact.oracle_sha256,
        implementation_tree_sha256=artifact.implementation_tree_sha256,
        observations=tuple(observations),
        artifact_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def validate_deterministic_semantics_v2(
    artifact_path: Path,
    oracle_path: Path,
    *,
    require_release_suite: bool = False,
) -> ValidatedDeterministicReleaseV2:
    """Apply the fixed oracle to observations and derive every verdict."""

    artifact = validate_deterministic_structure_v2(artifact_path)
    try:
        oracle = load_deterministic_oracle_v2(oracle_path)
    except OracleSpecV2Error as exc:
        raise DeterministicReleaseV2Error("deterministic V2 oracle is invalid") from exc
    oracle_digest = oracle_sha256_v2(oracle)
    if artifact.oracle_sha256 != oracle_digest:
        raise DeterministicReleaseV2Error("artifact is not bound to the supplied oracle")
    if require_release_suite and (
        len(oracle.cases) != RELEASE_CASE_COUNT_V2
        or len(oracle.invariants) != RELEASE_ARTIFACT_INVARIANT_COUNT_V2
    ):
        raise DeterministicReleaseV2Error(
            "V2 artifact release requires 25 cases and 47 semantic invariants"
        )

    observed_names = [name for name, _, _, _ in artifact.observations]
    expected_names = [case.name for case in oracle.cases]
    if observed_names != expected_names:
        raise DeterministicReleaseV2Error(
            "deterministic observations are not the ordered complete oracle suite"
        )
    projections = {name: projection for name, _, _, projection in artifact.observations}
    observed_fixture_ids = {name: fixture_id for name, fixture_id, _, _ in artifact.observations}
    observed_fixture_hashes = {
        name: fixture_hash for name, _, fixture_hash, _ in artifact.observations
    }
    for case in oracle.cases:
        if observed_fixture_ids[case.name] != case.fixture_id:
            raise DeterministicReleaseV2Error(
                f"case {case.name} fixture identity differs from the frozen oracle"
            )
        if observed_fixture_hashes[case.name] != case.fixture_tree_sha256:
            raise DeterministicReleaseV2Error(
                f"case {case.name} fixture bytes differ from the frozen commitment"
            )
        projection = projections[case.name]
        expectation = case.expectation
        if isinstance(expectation, EqualExpectationV2):
            if projection.semantic_digest() != projections[expectation.reference].semantic_digest():
                raise DeterministicReleaseV2Error(
                    f"case {case.name} differs from its semantic reference"
                )
        else:
            _validate_exact_case(case.name, projection, expectation)
    for invariant in oracle.invariants:
        if not _evaluate_invariant(invariant, projections):
            raise DeterministicReleaseV2Error(f"V2 invariant failed: {invariant.name}")

    release_binding = hashlib.sha256(
        DETERMINISTIC_RELEASE_DOMAIN_V2
        + canonical_json_bytes(
            {
                "artifact_sha256": artifact.artifact_sha256,
                "implementation_tree_sha256": artifact.implementation_tree_sha256,
                "oracle_sha256": oracle_digest,
                "suite_id": oracle.suite_id,
            }
        )
    ).hexdigest()
    return ValidatedDeterministicReleaseV2(
        suite_id=oracle.suite_id,
        oracle_sha256=oracle_digest,
        artifact_sha256=artifact.artifact_sha256,
        implementation_tree_sha256=artifact.implementation_tree_sha256,
        release_binding_sha256=release_binding,
        case_count=len(oracle.cases),
        artifact_invariant_count=len(oracle.invariants),
        projections=tuple((name, projections[name]) for name in expected_names),
        fixture_commitments=tuple((case.name, case.fixture_tree_sha256) for case in oracle.cases),
        fixture_ids=tuple((case.name, case.fixture_id) for case in oracle.cases),
    )


def validate_deterministic_release_v2(
    artifact_path: Path,
    oracle_path: Path,
) -> ValidatedDeterministicReleaseV2:
    return validate_deterministic_semantics_v2(
        artifact_path,
        oracle_path,
        require_release_suite=True,
    )


def _validate_exact_case(
    case_name: str,
    projection: DecisionProjectionV2,
    expectation: ExactExpectationV2,
) -> None:
    if projection.semantic_digest() != expectation.decision_semantic_sha256:
        raise DeterministicReleaseV2Error(
            f"case {case_name} semantic decision differs from the frozen oracle"
        )
    if (
        projection.strategy != expectation.strategy
        or projection.ranking_scope != expectation.ranking_scope
    ):
        raise DeterministicReleaseV2Error(f"case {case_name} strategy or scope differs")
    observed_routes = sorted(
        (_route_summary(item) for item in projection.routes),
        key=lambda item: cast(str, item["candidate_id"]),
    )
    expected_routes = sorted(
        (
            cast(JsonObject, item.model_dump(mode="json", exclude_none=False))
            for item in expectation.routes
        ),
        key=lambda item: cast(str, item["candidate_id"]),
    )
    if observed_routes != expected_routes:
        raise DeterministicReleaseV2Error(f"case {case_name} routes differ from the oracle")
    observed_explanations = sorted(
        (_explanation_summary(item.model_dump(mode="json")) for item in projection.explanations),
        key=canonical_json_bytes,
    )
    expected_explanations = sorted(
        (_explanation_summary(item.model_dump(mode="json")) for item in expectation.explanations),
        key=canonical_json_bytes,
    )
    if observed_explanations != expected_explanations:
        raise DeterministicReleaseV2Error(f"case {case_name} explanations differ from the oracle")
    completed = _completed_command_kinds(projection)
    if not set(expectation.required_completed_commands).issubset(completed):
        raise DeterministicReleaseV2Error(f"case {case_name} omitted a required command")
    if set(expectation.forbidden_completed_commands) & completed:
        raise DeterministicReleaseV2Error(f"case {case_name} completed a forbidden command")


def _evaluate_invariant(
    invariant: InvariantOracleV2,
    projections: dict[str, DecisionProjectionV2],
) -> bool:
    if invariant.kind == "projection_equal":
        assert invariant.left is not None and invariant.right is not None
        return (
            projections[invariant.left].semantic_digest()
            == projections[invariant.right].semantic_digest()
        )
    if invariant.kind == "route_equal_except":
        assert invariant.left is not None and invariant.right is not None
        excluded = set(invariant.excluded_candidate_ids)
        return _routes_except(projections[invariant.left], excluded) == _routes_except(
            projections[invariant.right], excluded
        )
    if invariant.kind == "strategy_matrix":
        return all(
            projections[name].strategy == strategy
            for name, strategy in invariant.expected_strategies.items()
        ) and len(set(invariant.expected_strategies.values())) == len(invariant.expected_strategies)
    if invariant.kind == "completed_commands":
        assert invariant.case is not None
        completed = _completed_command_kinds(projections[invariant.case])
        return set(invariant.required_commands).issubset(completed) and not (
            set(invariant.forbidden_commands) & completed
        )
    if invariant.kind == "removed_commands_not_completed":
        assert invariant.case is not None
        projection = projections[invariant.case]
        if projection.plan_diff is None:
            return True
        completed_receipts = {
            (item.plan_version, item.command_id)
            for item in projection.receipts
            if item.status == "completed"
        }
        return all(
            (projection.plan_diff.from_version, command_id) not in completed_receipts
            for command_id in projection.plan_diff.removed_command_ids
        )
    if invariant.kind == "no_ranking_commands_completed":
        assert invariant.case is not None
        return not (_completed_command_kinds(projections[invariant.case]) & _RANK_COMMANDS)
    raise AssertionError("unreachable invariant kind")


def _route_summary(route: RouteV2) -> JsonObject:
    raw = cast(JsonObject, route.model_dump(mode="json", exclude_none=False))
    return {
        "candidate_id": raw["candidate_id"],
        "band": raw["band"],
        "queue": raw["queue"],
        "evidence_rank": raw["evidence_rank"],
        "display_position": raw["display_position"],
        "rank_key": raw["rank_key"],
    }


def _explanation_summary(value: dict[str, object]) -> JsonObject:
    """Canonicalize the reason set; tuple order has no explanatory meaning."""

    raw = cast(JsonObject, dict(value))
    reason_codes = raw.get("reason_codes")
    if not isinstance(reason_codes, list):
        raise DeterministicReleaseV2Error("explanation reason codes are not canonical JSON")
    raw["reason_codes"] = sorted(cast(list[str], reason_codes))
    return raw


def _routes_except(
    projection: DecisionProjectionV2,
    excluded: set[str],
) -> tuple[JsonObject, ...]:
    """Compare route semantics while allowing display compaction after quarantine."""

    raw_routes = cast(list[object], projection.canonical_object()["routes"])
    return tuple(
        {key: value for key, value in cast(JsonObject, route).items() if key != "display_position"}
        for route in raw_routes
        if cast(JsonObject, route).get("candidate_id") not in excluded
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
