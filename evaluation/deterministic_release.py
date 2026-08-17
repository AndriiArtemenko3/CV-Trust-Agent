"""Fail-closed validation for deterministic release evidence.

The evaluator deliberately permits custom or showcase-only diagnostic runs.
This module is a separate release boundary: it accepts only the complete
default deterministic suite and returns a bounded, hash-bound description of
the accepted artifact.  It does not import or execute the evaluator runtime.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

JsonObject: TypeAlias = dict[str, object]

DEFAULT_ORACLE_PATH = Path(__file__).with_name("oracle.json")
RELEASE_VALIDATOR_SCHEMA_VERSION = 1

_MAX_ARTIFACT_BYTES = 1_048_576
_MAX_ORACLE_BYTES = 262_144
_MAX_CASES = 64
_MAX_RECEIPTS_PER_CASE = 64
_PUBLIC_CANDIDATE_IDS = frozenset(f"AP-{number:03d}" for number in range(1, 11))

_DIGEST = re.compile(r"[0-9a-f]{64}")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]*")
_LOWER_TOKEN = re.compile(r"[a-z][a-z0-9_]*")
_UPPER_TOKEN = re.compile(r"[A-Z][A-Z0-9_]*")

_REPORT_KEYS = frozenset(
    {"schema_version", "passed", "case_count", "passed_case_count", "invariants", "cases"}
)
_CASE_RESULT_KEYS = frozenset(
    {
        "name",
        "passed",
        "checks",
        "fingerprint",
        "strategy",
        "ranking_scope",
        "support_graph_hash",
        "semantic_support_graph_hash",
        "input_fixture_tree_sha256",
        "routes",
        "receipts",
    }
)
_ROUTE_KEYS = frozenset(
    {
        "candidate_id",
        "band",
        "queue",
        "evidence_rank",
        "display_position",
        "rank_key",
        "support_graph_hash",
    }
)
_RANK_KEY_KEYS = frozenset(
    {"band_priority", "essentials_count", "preferred_count", "corroborated_claim_count"}
)
_RECEIPT_KEYS = frozenset({"command_id", "command_kind", "status"})

_ORACLE_KEYS = frozenset({"schema_version", "cases"})
_ORACLE_CASE_REQUIRED_KEYS = frozenset(
    {
        "name",
        "scenario",
        "showcase",
        "expected_strategy",
        "expected_ranking_scope",
        "expected_detail_count",
        "expected_resume_count",
        "expected_http_count",
        "expected_routes",
    }
)
_ORACLE_CASE_OPTIONAL_KEYS = frozenset(
    {"mapper_fault", "fault_candidate", "fault_claim", "equal_fingerprint_to"}
)
_ORACLE_ROUTE_REQUIRED_KEYS = frozenset({"candidate_id", "band", "queue"})
_ORACLE_ROUTE_OPTIONAL_KEYS = frozenset({"evidence_rank", "display_position", "rank_key"})

_BASE_CHECKS = frozenset(
    {
        "strategy",
        "ranking_scope",
        "candidate_details_parsed",
        "resumes_parsed",
        "http_request_count",
        "step_receipts_present",
        "support_graph_hash_present",
        "input_fixture_tree_hash_present",
    }
)
_ALLOWED_ROUTE_PAIRS = frozenset(
    {
        ("STRONG_EVIDENCE_MATCH", "PRIORITY_HUMAN_REVIEW"),
        ("POTENTIAL_EVIDENCE_MATCH", "STANDARD_HUMAN_REVIEW"),
        ("INSUFFICIENT_SUPPORTED_EVIDENCE", "EVIDENCE_CHECK"),
        ("INTEGRITY_HOLD", "INTEGRITY_REVIEW"),
        ("INTEGRITY_HOLD", "BATCH_INTEGRITY_HOLD"),
        ("EVIDENCE_UNAVAILABLE", "EVIDENCE_PENDING"),
    }
)
_UNRANKED_BANDS = frozenset({"INTEGRITY_HOLD", "EVIDENCE_UNAVAILABLE"})
_ALLOWED_COMMAND_KINDS = frozenset(
    {
        "fetch_candidate_details",
        "validate_candidate_details",
        "fetch_candidate_resumes",
        "parse_candidate_resumes",
        "map_candidate_claims",
        "validate_candidate_evidence",
        "validate_index_commitments",
        "rank_full_evidence",
        "quarantine_unsupported",
        "mark_evidence_pending",
        "rank_supported_evidence",
        "rank_partial_evidence",
        "isolate_batch",
        "request_corroboration",
        "pre_release_audit",
        "release_output",
    }
)


class DeterministicReleaseError(ValueError):
    """A deterministic artifact or its expected oracle is not release-valid."""


@dataclass(frozen=True, slots=True)
class DeterministicReleaseMetadata:
    """Bounded provenance returned only after complete release validation."""

    suite_id: str
    oracle_sha256: str
    artifact_sha256: str
    release_binding_sha256: str
    schema_version: int
    case_count: int
    invariant_count: int
    passed: bool = True


@dataclass(frozen=True, slots=True)
class _RouteExpectation:
    candidate_id: str
    band: str
    queue: str
    evidence_rank: int | None
    display_position: int | None
    rank_key: tuple[int, int, int, int] | None


@dataclass(frozen=True, slots=True)
class _CaseSpec:
    name: str
    expected_strategy: str
    expected_ranking_scope: str
    expected_routes: tuple[_RouteExpectation, ...]
    equal_fingerprint_to: str | None


@dataclass(frozen=True, slots=True)
class _OracleSpec:
    schema_version: int
    cases: tuple[_CaseSpec, ...]


def validate_deterministic_release_artifact(
    artifact_path: Path,
    expected_oracle_path: Path | None = None,
) -> DeterministicReleaseMetadata:
    """Validate one full-suite ``EvaluationReport.public_json`` artifact.

    ``expected_oracle_path`` may identify the repository oracle or a byte-for-
    byte/semantically identical copy used by a release system.  A custom,
    reduced, or otherwise modified oracle is rejected even when explicitly
    supplied; custom evaluator runs remain diagnostic artifacts only.
    """

    default_oracle_bytes = _read_bounded(
        DEFAULT_ORACLE_PATH,
        limit=_MAX_ORACLE_BYTES,
        description="default release oracle",
    )
    default_oracle = _load_json_object(default_oracle_bytes, "default release oracle")
    default_spec = _parse_oracle(default_oracle)

    if expected_oracle_path is None:
        oracle_bytes = default_oracle_bytes
        oracle = default_oracle
        oracle_spec = default_spec
    else:
        oracle_bytes = _read_bounded(
            expected_oracle_path,
            limit=_MAX_ORACLE_BYTES,
            description="expected release oracle",
        )
        oracle = _load_json_object(oracle_bytes, "expected release oracle")
        oracle_spec = _parse_oracle(oracle)
        if oracle != default_oracle or oracle_spec != default_spec:
            raise DeterministicReleaseError(
                "expected release oracle does not define the complete default suite"
            )

    artifact_bytes = _read_bounded(
        artifact_path,
        limit=_MAX_ARTIFACT_BYTES,
        description="deterministic release artifact",
    )
    report = _load_json_object(artifact_bytes, "deterministic release artifact")
    invariant_names = _expected_invariant_names(oracle_spec)
    _validate_report(report, oracle_spec, invariant_names)

    artifact_sha256 = _sha256(artifact_bytes)
    oracle_sha256 = _sha256(oracle_bytes)
    suite_id = _suite_id(default_oracle)
    release_binding_sha256 = _sha256(
        _canonical_json(
            {
                "artifact_sha256": artifact_sha256,
                "oracle_sha256": oracle_sha256,
                "suite_id": suite_id,
            }
        )
    )
    return DeterministicReleaseMetadata(
        suite_id=suite_id,
        oracle_sha256=oracle_sha256,
        artifact_sha256=artifact_sha256,
        release_binding_sha256=release_binding_sha256,
        schema_version=oracle_spec.schema_version,
        case_count=len(oracle_spec.cases),
        invariant_count=len(invariant_names),
    )


def _parse_oracle(root: JsonObject) -> _OracleSpec:
    _require_exact_keys(root, _ORACLE_KEYS, "release oracle")
    schema_version = _required_int(
        root.get("schema_version"), "release oracle schema version", minimum=1, maximum=100
    )
    raw_cases = _required_array(
        root.get("cases"), "release oracle cases", minimum=1, maximum=_MAX_CASES
    )
    cases: list[_CaseSpec] = []
    for raw_case in raw_cases:
        case = _required_object(raw_case, "release oracle case")
        if not case.keys() >= _ORACLE_CASE_REQUIRED_KEYS or not case.keys() <= (
            _ORACLE_CASE_REQUIRED_KEYS | _ORACLE_CASE_OPTIONAL_KEYS
        ):
            raise DeterministicReleaseError("release oracle case has an invalid schema")
        name = _required_token(case.get("name"), "release oracle case name", _LOWER_TOKEN, 64)
        _required_token(case.get("scenario"), "release oracle scenario", _LOWER_TOKEN, 64)
        _required_bool(case.get("showcase"), "release oracle showcase flag")
        strategy = _required_token(
            case.get("expected_strategy"), "release oracle strategy", _UPPER_TOKEN, 64
        )
        ranking_scope = _required_token(
            case.get("expected_ranking_scope"),
            "release oracle ranking scope",
            _UPPER_TOKEN,
            32,
        )
        for field in (
            "expected_detail_count",
            "expected_resume_count",
            "expected_http_count",
        ):
            _required_int(case.get(field), "release oracle count", minimum=0, maximum=10_000)
        routes = _parse_route_expectations(case.get("expected_routes"))
        if "mapper_fault" in case:
            _required_token(
                case.get("mapper_fault"), "release oracle mapper fault", _LOWER_TOKEN, 64
            )
        if "fault_candidate" in case:
            fault_candidate = _required_token(
                case.get("fault_candidate"),
                "release oracle fault candidate",
                _SAFE_ID,
                16,
            )
            if fault_candidate not in _PUBLIC_CANDIDATE_IDS:
                raise DeterministicReleaseError("release oracle fault candidate is invalid")
        if "fault_claim" in case:
            _required_token(case.get("fault_claim"), "release oracle fault claim", _LOWER_TOKEN, 64)
        equal_fingerprint_to = None
        if "equal_fingerprint_to" in case:
            equal_fingerprint_to = _required_token(
                case.get("equal_fingerprint_to"),
                "release oracle fingerprint reference",
                _LOWER_TOKEN,
                64,
            )
        cases.append(
            _CaseSpec(
                name=name,
                expected_strategy=strategy,
                expected_ranking_scope=ranking_scope,
                expected_routes=routes,
                equal_fingerprint_to=equal_fingerprint_to,
            )
        )

    names = tuple(case.name for case in cases)
    if len(set(names)) != len(names):
        raise DeterministicReleaseError("release oracle case names must be unique")
    known_names = set(names)
    if any(
        case.equal_fingerprint_to is not None and case.equal_fingerprint_to not in known_names
        for case in cases
    ):
        raise DeterministicReleaseError("release oracle fingerprint reference is invalid")
    return _OracleSpec(schema_version=schema_version, cases=tuple(cases))


def _parse_route_expectations(value: object) -> tuple[_RouteExpectation, ...]:
    raw_routes = _required_array(
        value,
        "release oracle route expectations",
        minimum=0,
        maximum=len(_PUBLIC_CANDIDATE_IDS),
    )
    routes: list[_RouteExpectation] = []
    for raw_route in raw_routes:
        route = _required_object(raw_route, "release oracle route expectation")
        if not route.keys() >= _ORACLE_ROUTE_REQUIRED_KEYS or not route.keys() <= (
            _ORACLE_ROUTE_REQUIRED_KEYS | _ORACLE_ROUTE_OPTIONAL_KEYS
        ):
            raise DeterministicReleaseError("release oracle route has an invalid schema")
        candidate_id = _required_token(
            route.get("candidate_id"), "release oracle candidate", _SAFE_ID, 16
        )
        if candidate_id not in _PUBLIC_CANDIDATE_IDS:
            raise DeterministicReleaseError("release oracle route candidate is invalid")
        band = _required_token(route.get("band"), "release oracle band", _UPPER_TOKEN, 64)
        queue = _required_token(route.get("queue"), "release oracle queue", _UPPER_TOKEN, 64)
        if (band, queue) not in _ALLOWED_ROUTE_PAIRS:
            raise DeterministicReleaseError("release oracle route pair is invalid")
        evidence_rank = _optional_int(
            route.get("evidence_rank"),
            "release oracle evidence rank",
            minimum=1,
            maximum=10,
        )
        display_position = _optional_int(
            route.get("display_position"),
            "release oracle display position",
            minimum=1,
            maximum=10,
        )
        rank_key = _optional_oracle_rank_key(route.get("rank_key"))
        routes.append(
            _RouteExpectation(
                candidate_id=candidate_id,
                band=band,
                queue=queue,
                evidence_rank=evidence_rank,
                display_position=display_position,
                rank_key=rank_key,
            )
        )
    candidate_ids = [route.candidate_id for route in routes]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise DeterministicReleaseError("release oracle route candidates must be unique")
    return tuple(routes)


def _validate_report(
    report: JsonObject,
    oracle: _OracleSpec,
    invariant_names: frozenset[str],
) -> None:
    _require_exact_keys(report, _REPORT_KEYS, "deterministic release report")
    if (
        _required_int(
            report.get("schema_version"),
            "deterministic release schema version",
            minimum=1,
            maximum=100,
        )
        != oracle.schema_version
    ):
        raise DeterministicReleaseError("deterministic release schema version is unexpected")
    if _required_bool(report.get("passed"), "deterministic release result") is not True:
        raise DeterministicReleaseError("deterministic release report did not pass")

    expected_count = len(oracle.cases)
    case_count = _required_int(
        report.get("case_count"), "deterministic release case count", minimum=0, maximum=_MAX_CASES
    )
    passed_case_count = _required_int(
        report.get("passed_case_count"),
        "deterministic release passed case count",
        minimum=0,
        maximum=_MAX_CASES,
    )
    if case_count != expected_count or passed_case_count != expected_count:
        raise DeterministicReleaseError(
            "deterministic release report is not the full passing suite"
        )

    invariants = _required_object(report.get("invariants"), "deterministic invariants")
    _require_true_map(invariants, invariant_names, "deterministic invariants")
    raw_cases = _required_array(
        report.get("cases"),
        "deterministic release cases",
        minimum=expected_count,
        maximum=expected_count,
    )
    parsed_cases = [
        _required_object(raw_case, "deterministic release case") for raw_case in raw_cases
    ]
    actual_names = tuple(
        _required_token(case.get("name"), "deterministic case name", _LOWER_TOKEN, 64)
        for case in parsed_cases
    )
    expected_names = tuple(case.name for case in oracle.cases)
    if actual_names != expected_names:
        raise DeterministicReleaseError(
            "deterministic release cases do not match the ordered default suite"
        )

    fingerprints: dict[str, str] = {}
    for case, expected in zip(parsed_cases, oracle.cases, strict=True):
        fingerprints[expected.name] = _validate_case(case, expected)
    for expected in oracle.cases:
        reference = expected.equal_fingerprint_to
        if reference is not None and fingerprints[expected.name] != fingerprints[reference]:
            raise DeterministicReleaseError(
                "deterministic release fingerprint invariant is inconsistent"
            )


def _validate_case(case: JsonObject, expected: _CaseSpec) -> str:
    _require_exact_keys(case, _CASE_RESULT_KEYS, "deterministic release case")
    if case.get("name") != expected.name:
        raise DeterministicReleaseError("deterministic release case name is unexpected")
    if _required_bool(case.get("passed"), "deterministic case result") is not True:
        raise DeterministicReleaseError("deterministic release case did not pass")

    checks = _required_object(case.get("checks"), "deterministic case checks")
    _require_true_map(checks, _expected_check_names(expected), "deterministic case checks")
    fingerprint = _required_digest(case.get("fingerprint"), "deterministic fingerprint")
    strategy = _required_token(case.get("strategy"), "deterministic strategy", _UPPER_TOKEN, 64)
    ranking_scope = _required_token(
        case.get("ranking_scope"), "deterministic ranking scope", _UPPER_TOKEN, 32
    )
    if strategy != expected.expected_strategy or ranking_scope != expected.expected_ranking_scope:
        raise DeterministicReleaseError("deterministic case outcome disagrees with the oracle")
    _required_digest(case.get("support_graph_hash"), "deterministic support graph hash")
    _required_digest(
        case.get("semantic_support_graph_hash"), "deterministic semantic support graph hash"
    )
    _required_digest(case.get("input_fixture_tree_sha256"), "deterministic input fixture hash")
    _validate_routes(case.get("routes"), expected.expected_routes)
    _validate_receipts(case.get("receipts"))
    return fingerprint


def _validate_routes(value: object, expectations: tuple[_RouteExpectation, ...]) -> None:
    raw_routes = _required_array(
        value,
        "deterministic routes",
        minimum=len(_PUBLIC_CANDIDATE_IDS),
        maximum=len(_PUBLIC_CANDIDATE_IDS),
    )
    routes_by_id: dict[str, JsonObject] = {}
    display_positions: list[int] = []
    for raw_route in raw_routes:
        route = _required_object(raw_route, "deterministic route")
        _require_exact_keys(route, _ROUTE_KEYS, "deterministic route")
        candidate_id = _required_token(
            route.get("candidate_id"), "deterministic candidate id", _SAFE_ID, 16
        )
        if candidate_id not in _PUBLIC_CANDIDATE_IDS or candidate_id in routes_by_id:
            raise DeterministicReleaseError("deterministic route candidates are invalid")
        band = _required_token(route.get("band"), "deterministic route band", _UPPER_TOKEN, 64)
        queue = _required_token(route.get("queue"), "deterministic route queue", _UPPER_TOKEN, 64)
        if (band, queue) not in _ALLOWED_ROUTE_PAIRS:
            raise DeterministicReleaseError("deterministic route band and queue are invalid")

        evidence_rank = _optional_int(
            route.get("evidence_rank"),
            "deterministic evidence rank",
            minimum=1,
            maximum=10,
        )
        display_position = _optional_int(
            route.get("display_position"),
            "deterministic display position",
            minimum=1,
            maximum=10,
        )
        rank_key = _optional_public_rank_key(route.get("rank_key"))
        is_unranked = band in _UNRANKED_BANDS
        if is_unranked is not (
            evidence_rank is None and display_position is None and rank_key is None
        ):
            raise DeterministicReleaseError("deterministic route ranking state is inconsistent")
        if display_position is not None:
            display_positions.append(display_position)

        support_hash = route.get("support_graph_hash")
        if support_hash is not None:
            _required_digest(support_hash, "deterministic route support graph hash")
        routes_by_id[candidate_id] = route

    if set(routes_by_id) != _PUBLIC_CANDIDATE_IDS:
        raise DeterministicReleaseError("deterministic routes are not the full public cohort")
    if display_positions != list(range(1, len(display_positions) + 1)):
        raise DeterministicReleaseError("deterministic route display order is invalid")

    for expectation in expectations:
        route = routes_by_id[expectation.candidate_id]
        if route.get("band") != expectation.band or route.get("queue") != expectation.queue:
            raise DeterministicReleaseError("deterministic route disagrees with the oracle")
        if (
            expectation.evidence_rank is not None
            and route.get("evidence_rank") != expectation.evidence_rank
        ):
            raise DeterministicReleaseError("deterministic evidence rank disagrees with the oracle")
        if (
            expectation.display_position is not None
            and route.get("display_position") != expectation.display_position
        ):
            raise DeterministicReleaseError(
                "deterministic display position disagrees with the oracle"
            )
        if (
            expectation.rank_key is not None
            and _optional_public_rank_key(route.get("rank_key")) != expectation.rank_key
        ):
            raise DeterministicReleaseError("deterministic rank key disagrees with the oracle")


def _validate_receipts(value: object) -> None:
    raw_receipts = _required_array(
        value,
        "deterministic receipts",
        minimum=2,
        maximum=_MAX_RECEIPTS_PER_CASE,
    )
    if len(raw_receipts) % 2:
        raise DeterministicReleaseError("deterministic receipts are not complete command pairs")
    seen_command_ids: set[str] = set()
    for index in range(0, len(raw_receipts), 2):
        started = _parse_receipt(raw_receipts[index])
        completed = _parse_receipt(raw_receipts[index + 1])
        if (
            started[0] in seen_command_ids
            or started[0] != completed[0]
            or started[1] != completed[1]
            or started[2] != "started"
            or completed[2] != "completed"
        ):
            raise DeterministicReleaseError("deterministic receipt command pair is invalid")
        seen_command_ids.add(started[0])


def _parse_receipt(value: object) -> tuple[str, str, str]:
    receipt = _required_object(value, "deterministic receipt")
    _require_exact_keys(receipt, _RECEIPT_KEYS, "deterministic receipt")
    command_id = _required_token(
        receipt.get("command_id"), "deterministic command id", _SAFE_ID, 128
    )
    command_kind = _required_token(
        receipt.get("command_kind"), "deterministic command kind", _LOWER_TOKEN, 64
    )
    if command_kind not in _ALLOWED_COMMAND_KINDS:
        raise DeterministicReleaseError("deterministic command kind is invalid")
    status = _required_token(
        receipt.get("status"), "deterministic command status", _LOWER_TOKEN, 16
    )
    return command_id, command_kind, status


def _expected_check_names(case: _CaseSpec) -> frozenset[str]:
    names = set(_BASE_CHECKS)
    for route in case.expected_routes:
        prefix = f"route_{route.candidate_id}"
        names.update({f"{prefix}_present", f"{prefix}_band", f"{prefix}_queue"})
        if route.band in _UNRANKED_BANDS:
            names.add(f"{prefix}_unranked")
        if route.evidence_rank is not None:
            names.add(f"{prefix}_evidence_rank")
        if route.display_position is not None:
            names.add(f"{prefix}_display_position")
        if route.rank_key is not None:
            names.add(f"{prefix}_rank_key")
    return frozenset(names)


def _expected_invariant_names(oracle: _OracleSpec) -> frozenset[str]:
    case_names = {case.name for case in oracle.cases}
    names = {f"{case.name}_removed_commands_not_completed" for case in oracle.cases}
    names.update(
        f"{case.name}_equals_{case.equal_fingerprint_to}"
        for case in oracle.cases
        if case.equal_fingerprint_to is not None
    )
    if {
        "clean",
        "mapper_disagreement_only",
        "detail_timeout",
        "compound",
    } <= case_names:
        names.add("failure_matrix_distinct")
    if {"clean", "semantic_no_directive"} <= case_names:
        names.add("semantic_conflict_locally_contained")
    if {"semantic_no_directive", "structured_note_poisoned"} <= case_names:
        names.add("directive_does_not_change_conflict_outcome")
    if "compound" in case_names:
        names.update(
            {
                "compound_executes_isolation",
                "compound_executes_corroboration",
                "compound_releases_no_rank",
                "compound_replan_has_real_command_transition",
            }
        )
    return frozenset(names)


def _optional_oracle_rank_key(value: object) -> tuple[int, int, int, int] | None:
    if value is None:
        return None
    raw = _required_array(value, "release oracle rank key", minimum=4, maximum=4)
    parsed = tuple(
        _required_int(item, "release oracle rank key item", minimum=0, maximum=100) for item in raw
    )
    return cast(tuple[int, int, int, int], parsed)


def _optional_public_rank_key(value: object) -> tuple[int, int, int, int] | None:
    if value is None:
        return None
    rank_key = _required_object(value, "deterministic rank key")
    _require_exact_keys(rank_key, _RANK_KEY_KEYS, "deterministic rank key")
    return (
        _required_int(
            rank_key.get("band_priority"), "rank key band priority", minimum=0, maximum=100
        ),
        _required_int(
            rank_key.get("essentials_count"),
            "rank key essentials count",
            minimum=0,
            maximum=100,
        ),
        _required_int(
            rank_key.get("preferred_count"),
            "rank key preferred count",
            minimum=0,
            maximum=100,
        ),
        _required_int(
            rank_key.get("corroborated_claim_count"),
            "rank key corroborated claim count",
            minimum=0,
            maximum=100,
        ),
    )


def _require_true_map(
    value: JsonObject,
    expected_keys: frozenset[str],
    description: str,
) -> None:
    _require_exact_keys(value, expected_keys, description)
    if any(_required_bool(item, description) is not True for item in value.values()):
        raise DeterministicReleaseError(f"{description} must all pass")


def _read_bounded(path: Path, *, limit: int, description: str) -> bytes:
    if not isinstance(path, Path):
        raise DeterministicReleaseError(f"{description} path must be a Path")
    try:
        with path.open("rb") as handle:
            content = handle.read(limit + 1)
    except OSError as exc:
        raise DeterministicReleaseError(f"{description} could not be read") from exc
    if not content or len(content) > limit:
        raise DeterministicReleaseError(f"{description} has an invalid byte length")
    return content


class _InvalidJson(ValueError):
    pass


def _load_json_object(content: bytes, description: str) -> JsonObject:
    try:
        text = content.decode("utf-8")
        raw = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise DeterministicReleaseError(f"{description} is not strict JSON") from exc
    return _required_object(cast(object, raw), description)


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJson("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> object:
    raise _InvalidJson("non-finite JSON number")


def _required_object(value: object, description: str) -> JsonObject:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise DeterministicReleaseError(f"{description} must be an object")
    return cast(JsonObject, value)


def _required_array(
    value: object,
    description: str,
    *,
    minimum: int,
    maximum: int,
) -> list[object]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise DeterministicReleaseError(f"{description} has an invalid array length")
    return cast(list[object], value)


def _required_bool(value: object, description: str) -> bool:
    if type(value) is not bool:
        raise DeterministicReleaseError(f"{description} must be a boolean")
    return value


def _required_int(
    value: object,
    description: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DeterministicReleaseError(f"{description} must be a bounded integer")
    return value


def _optional_int(
    value: object,
    description: str,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    return _required_int(value, description, minimum=minimum, maximum=maximum)


def _required_token(
    value: object,
    description: str,
    pattern: re.Pattern[str],
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or pattern.fullmatch(value) is None
    ):
        raise DeterministicReleaseError(f"{description} must be a bounded token")
    return value


def _required_digest(value: object, description: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DeterministicReleaseError(f"{description} must be a SHA-256 digest")
    return value


def _require_exact_keys(value: JsonObject, expected: frozenset[str], description: str) -> None:
    if value.keys() != expected:
        raise DeterministicReleaseError(f"{description} has an invalid schema")


def _suite_id(oracle: JsonObject) -> str:
    digest = _sha256(
        _canonical_json(
            {
                "oracle": oracle,
                "release_validator_schema_version": RELEASE_VALIDATOR_SCHEMA_VERSION,
            }
        )
    )
    return f"cv-trust-agent/deterministic-release/v1:{digest}"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


__all__ = (
    "DEFAULT_ORACLE_PATH",
    "RELEASE_VALIDATOR_SCHEMA_VERSION",
    "DeterministicReleaseError",
    "DeterministicReleaseMetadata",
    "validate_deterministic_release_artifact",
)
