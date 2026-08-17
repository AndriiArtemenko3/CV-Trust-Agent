"""Strict external scoring over sanitized ``cv-trust run`` JSON.

The scorer launches only public execution commands through a runner. It
materializes deterministic source inputs into an evaluator-owned directory,
but never calls the engine, ranker, or private CLI helpers. The oracle remains
outside the production import graph.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypeAlias, TypeVar, cast

from cv_trust_agent.dataset import materialize_fixture_root
from evaluation.fixture_commitment import normalized_fixture_tree_hash

JsonObject: TypeAlias = dict[str, object]
CaseRunner: TypeAlias = Callable[["CaseSpec"], JsonObject]
Value = TypeVar("Value")
_PUBLIC_CANDIDATE_IDS = frozenset(f"AP-{number:03d}" for number in range(1, 11))


class EvaluationError(RuntimeError):
    """An oracle, process, or sanitized-output contract was invalid."""


@dataclass(frozen=True)
class RouteExpectation:
    candidate_id: str
    band: str
    queue: str
    evidence_rank: int | None = None
    display_position: int | None = None
    rank_key: tuple[int, int, int, int] | None = None


@dataclass(frozen=True)
class CaseSpec:
    name: str
    scenario: str
    showcase: bool
    expected_strategy: str
    expected_ranking_scope: str
    expected_detail_count: int
    expected_resume_count: int
    expected_http_count: int
    expected_routes: tuple[RouteExpectation, ...]
    mapper_fault: str | None = None
    fault_candidate: str | None = None
    fault_claim: str | None = None
    equal_fingerprint_to: str | None = None


@dataclass(frozen=True)
class Oracle:
    schema_version: int
    cases: tuple[CaseSpec, ...]


@dataclass(frozen=True)
class CaseResult:
    name: str
    passed: bool
    checks: Mapping[str, bool]
    fingerprint: str | None
    payload: JsonObject


@dataclass(frozen=True)
class EvaluationReport:
    schema_version: int
    passed: bool
    case_results: tuple[CaseResult, ...]
    invariant_checks: Mapping[str, bool]

    def public_json(self) -> JsonObject:
        """Return a prose-free, synthetic-only summary suitable for evidence."""

        return {
            "schema_version": self.schema_version,
            "passed": self.passed,
            "case_count": len(self.case_results),
            "passed_case_count": sum(item.passed for item in self.case_results),
            "invariants": dict(sorted(self.invariant_checks.items())),
            "cases": [
                {
                    "name": item.name,
                    "passed": item.passed,
                    "checks": dict(sorted(item.checks.items())),
                    "fingerprint": item.fingerprint,
                    "strategy": item.payload.get("strategy"),
                    "ranking_scope": item.payload.get("ranking_scope"),
                    "support_graph_hash": _support_graph_hash(item.payload),
                    "semantic_support_graph_hash": _semantic_support_graph_hash(item.payload),
                    "input_fixture_tree_sha256": item.payload.get(
                        "_evaluation_fixture_tree_sha256"
                    ),
                    "routes": _public_routes(item.payload),
                    "receipts": _public_receipts(item.payload),
                }
                for item in self.case_results
            ],
        }


def load_oracle(path: Path | None = None) -> Oracle:
    selected = path or Path(__file__).with_name("oracle.json")
    try:
        raw = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationError("evaluation oracle could not be loaded") from exc
    root = _object(raw, "oracle")
    schema_version = _integer(root.get("schema_version"), "schema_version")
    raw_cases = _array(root.get("cases"), "cases")
    cases = tuple(_parse_case(_object(item, "case")) for item in raw_cases)
    names = [item.name for item in cases]
    if not cases or len(names) != len(set(names)):
        raise EvaluationError("oracle cases must be non-empty and uniquely named")
    known = set(names)
    for case in cases:
        if case.equal_fingerprint_to is not None and case.equal_fingerprint_to not in known:
            raise EvaluationError("fingerprint reference names an unknown case")
    return Oracle(schema_version=schema_version, cases=cases)


def evaluate_cases(
    oracle: Oracle,
    runner: CaseRunner,
    *,
    showcase_only: bool,
) -> EvaluationReport:
    selected = tuple(case for case in oracle.cases if case.showcase or not showcase_only)
    results: list[CaseResult] = []
    for case in selected:
        try:
            payload = runner(case)
            checks, fingerprint = _score_case(case, payload)
        except Exception:
            # Evaluation output is deliberately bounded. Provider/source prose
            # belongs in local diagnostics, never the evidence artifact.
            payload = {}
            checks = {"case_execution": False}
            fingerprint = None
        results.append(
            CaseResult(
                name=case.name,
                passed=all(checks.values()),
                checks=checks,
                fingerprint=fingerprint,
                payload=payload,
            )
        )

    by_name = {item.name: item for item in results}
    invariants = _cross_case_invariants(selected, by_name)
    return EvaluationReport(
        schema_version=oracle.schema_version,
        passed=all(item.passed for item in results) and all(invariants.values()),
        case_results=tuple(results),
        invariant_checks=invariants,
    )


def canonical_decision_fingerprint(payload: Mapping[str, object]) -> str:
    """Hash every trusted release semantic required by the acceptance oracle."""

    routes = _routes(payload)
    receipts = _receipts(payload)
    plan = _object(payload.get("plan"), "plan")
    plans_raw = payload.get("plans", [plan])
    plans = [_object(item, "plan history item") for item in _array(plans_raw, "plans")]
    raw_support_hash = _support_graph_hash(payload)
    if raw_support_hash is None:
        raise EvaluationError("decision omitted support_graph_hash")
    semantic_support_hash = _semantic_support_graph_hash(payload)
    if any(
        route.get("rank_key") is not None
        and (
            "evidence_rank" not in route
            or "display_position" not in route
            or route.get("support_graph") is None
        )
        for route in routes
    ):
        raise EvaluationError("ranked route omitted rank fields or support graph")

    canonical = {
        "strategy": _string(payload.get("strategy"), "strategy"),
        "ranking_scope": _string(payload.get("ranking_scope"), "ranking_scope"),
        "routes": [
            {
                "candidate_id": _string(route.get("candidate_id"), "candidate_id"),
                "band": _string(route.get("band"), "band"),
                "queue": _string(route.get("queue"), "queue"),
                "evidence_rank": _optional_integer(route.get("evidence_rank"), "evidence_rank"),
                "display_position": _optional_integer(
                    route.get("display_position"), "display_position"
                ),
                "rank_key": route.get("rank_key"),
            }
            for route in sorted(
                routes,
                key=lambda item: _string(item.get("candidate_id"), "candidate_id"),
            )
        ],
        "plans": [_canonical_plan(item) for item in plans],
        "plan": _canonical_plan(plan),
        "plan_diff": _canonical_plan_diff(payload.get("plan_diff")),
        "step_receipts": [
            _canonical_receipt(receipt)
            for receipt in sorted(
                receipts,
                key=lambda item: (
                    _string(item.get("command_id"), "receipt.command_id"),
                    _string(item.get("status"), "receipt.status"),
                ),
            )
        ],
        "support_graph_hash": raw_support_hash,
        "semantic_support_graph_hash": semantic_support_hash,
        "unavailable_candidates": sorted(
            _string(route.get("candidate_id"), "candidate_id")
            for route in routes
            if route.get("band") == "EVIDENCE_UNAVAILABLE"
        ),
        "corroboration_requests": _canonical_corroboration_requests(
            payload.get("corroboration_requests", [])
        ),
    }
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class PublicCommandRunner:
    """Run one oracle case through public ``serve`` and ``run`` commands."""

    def __init__(
        self,
        *,
        executable: str = "cv-trust",
        source_timeout_seconds: float = 0.5,
        process_timeout_seconds: float = 45.0,
    ) -> None:
        resolved = shutil.which(executable)
        if resolved is None:
            raise EvaluationError("cv-trust executable was not found")
        self._executable = resolved
        self._source_timeout = source_timeout_seconds
        self._process_timeout = process_timeout_seconds

    def __call__(self, case: CaseSpec) -> JsonObject:
        port = _ephemeral_port()
        source_url = f"http://127.0.0.1:{port}"
        with TemporaryDirectory(prefix=f"cv-trust-eval-{case.name}-") as temporary:
            fixture_root = Path(temporary)
            materialize_fixture_root(
                fixture_root,
                case.scenario,
                source_base_url=source_url,
            )
            fixture_hash = normalized_fixture_tree_hash(fixture_root)
            server = subprocess.Popen(
                (
                    self._executable,
                    "serve",
                    "--scenario",
                    case.scenario,
                    "--fixture-root",
                    fixture_root.as_posix(),
                    "--port",
                    str(port),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                _wait_for_source(server, source_url)
                command = [
                    self._executable,
                    "run",
                    "--source-url",
                    source_url,
                    "--mapper",
                    "deterministic",
                    "--source-timeout",
                    str(self._source_timeout),
                ]
                if case.mapper_fault is not None:
                    command.extend(("--mapper-fault", case.mapper_fault))
                if case.fault_candidate is not None:
                    command.extend(("--fault-candidate", case.fault_candidate))
                if case.fault_claim is not None:
                    command.extend(("--fault-claim", case.fault_claim))
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self._process_timeout,
                )
                if completed.returncode != 0:
                    raise EvaluationError("cv-trust run returned a non-zero status")
                try:
                    payload = _object(json.loads(completed.stdout), "run output")
                except json.JSONDecodeError as exc:
                    raise EvaluationError("cv-trust run did not emit one JSON object") from exc
                payload["_evaluation_fixture_tree_sha256"] = fixture_hash
                return payload
            finally:
                _stop_process(server)


def _score_case(case: CaseSpec, payload: JsonObject) -> tuple[dict[str, bool], str]:
    routes = _routes(payload)
    by_id = {_string(item.get("candidate_id"), "candidate_id"): item for item in routes}
    checks = {
        "strategy": payload.get("strategy") == case.expected_strategy,
        "ranking_scope": payload.get("ranking_scope") == case.expected_ranking_scope,
        "candidate_details_parsed": (
            payload.get("candidate_details_parsed") == case.expected_detail_count
        ),
        "resumes_parsed": payload.get("resumes_parsed") == case.expected_resume_count,
        "http_request_count": payload.get("http_request_count") == case.expected_http_count,
        "step_receipts_present": bool(_receipts(payload)),
        "support_graph_hash_present": _support_graph_hash(payload) is not None,
        "input_fixture_tree_hash_present": isinstance(
            payload.get("_evaluation_fixture_tree_sha256"), str
        )
        and len(cast(str, payload.get("_evaluation_fixture_tree_sha256"))) == 64,
    }
    for expected in case.expected_routes:
        actual = by_id.get(expected.candidate_id)
        prefix = f"route_{expected.candidate_id}"
        checks[f"{prefix}_present"] = actual is not None
        if actual is None:
            continue
        checks[f"{prefix}_band"] = actual.get("band") == expected.band
        checks[f"{prefix}_queue"] = actual.get("queue") == expected.queue
        if expected.band in {"INTEGRITY_HOLD", "EVIDENCE_UNAVAILABLE"}:
            checks[f"{prefix}_unranked"] = (
                actual.get("evidence_rank") is None
                and actual.get("display_position") is None
                and actual.get("rank_key") is None
            )
        if expected.evidence_rank is not None:
            checks[f"{prefix}_evidence_rank"] = (
                actual.get("evidence_rank") == expected.evidence_rank
            )
        if expected.display_position is not None:
            checks[f"{prefix}_display_position"] = (
                actual.get("display_position") == expected.display_position
            )
        if expected.rank_key is not None:
            checks[f"{prefix}_rank_key"] = _rank_key(actual.get("rank_key")) == expected.rank_key
    fingerprint = canonical_decision_fingerprint(payload)
    return checks, fingerprint


def _cross_case_invariants(
    specs: Sequence[CaseSpec],
    results: Mapping[str, CaseResult],
) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for name, result in results.items():
        checks[f"{name}_removed_commands_not_completed"] = _bounded_check(
            partial(_removed_commands_not_completed, result.payload)
        )
    for spec in specs:
        if spec.equal_fingerprint_to is None:
            continue
        actual = results.get(spec.name)
        reference = results.get(spec.equal_fingerprint_to)
        checks[f"{spec.name}_equals_{spec.equal_fingerprint_to}"] = bool(
            actual
            and reference
            and actual.fingerprint is not None
            and actual.fingerprint == reference.fingerprint
        )

    required_matrix = {
        "clean": "FULL_EVIDENCE_RANKING",
        "mapper_disagreement_only": "SUPPORTED_ONLY_RANKING",
        "detail_timeout": "PARTIAL_SAFE_RANKING",
        "compound": "BATCH_INTEGRITY_HOLD",
    }
    if required_matrix.keys() <= results.keys():
        checks["failure_matrix_distinct"] = (
            all(
                results[name].payload.get("strategy") == strategy
                for name, strategy in required_matrix.items()
            )
            and len({results[name].payload.get("strategy") for name in required_matrix}) == 4
        )

    if "clean" in results and "semantic_no_directive" in results:
        checks["semantic_conflict_locally_contained"] = _bounded_check(
            lambda: _unaffected_routes_equal(
                results["clean"].payload,
                results["semantic_no_directive"].payload,
                excluded=frozenset({"AP-005"}),
            )
        )
    if "semantic_no_directive" in results and "structured_note_poisoned" in results:
        checks["directive_does_not_change_conflict_outcome"] = _bounded_check(
            lambda: (
                _route_release_fingerprint(
                    results["semantic_no_directive"].payload,
                    "AP-005",
                )
                == _route_release_fingerprint(
                    results["structured_note_poisoned"].payload,
                    "AP-005",
                )
            )
        )
    if "compound" in results:
        receipts: list[JsonObject] = _bounded_value(
            lambda: _receipts(results["compound"].payload),
            cast(list[JsonObject], []),
        )
        completed = {_receipt_kind(item) for item in receipts if item.get("status") == "completed"}
        checks["compound_executes_isolation"] = "isolate_batch" in completed
        checks["compound_executes_corroboration"] = "request_corroboration" in completed
        checks["compound_releases_no_rank"] = _bounded_check(
            lambda: all(
                route.get("evidence_rank") is None for route in _routes(results["compound"].payload)
            )
        )
        checks["compound_replan_has_real_command_transition"] = _bounded_check(
            lambda: _compound_command_transition(results["compound"].payload)
        )
    return checks


def _removed_commands_not_completed(payload: Mapping[str, object]) -> bool:
    raw_diff = payload.get("plan_diff")
    if raw_diff is None:
        return True
    diff = _object(raw_diff, "plan_diff")
    removed = set(_string_array(diff.get("removed_command_ids", [])))
    completed = {
        _string(receipt.get("command_id"), "receipt.command_id")
        for receipt in _receipts(payload)
        if receipt.get("status") == "completed"
    }
    # A plan diff is allowed to be additive-only.  The invariant is universal:
    # every command that *was* removed must be absent from the completed
    # receipt set, which is vacuously true when the removed set is empty.
    return removed.isdisjoint(completed)


def _compound_command_transition(payload: Mapping[str, object]) -> bool:
    plans = [_object(item, "plan") for item in _array(payload.get("plans", []), "plans")]
    if len(plans) != 2:
        return False
    first_commands = [
        _object(item, "command") for item in _array(plans[0].get("commands"), "commands")
    ]
    final_commands = [
        _object(item, "command") for item in _array(plans[1].get("commands"), "commands")
    ]
    first_kinds = {_string(item.get("kind"), "command.kind") for item in first_commands}
    final_kinds = {_string(item.get("kind"), "command.kind") for item in final_commands}
    diff = _object(payload.get("plan_diff"), "plan_diff")
    removed = set(_string_array(diff.get("removed_command_ids", [])))
    first_rank_release_ids = {
        _string(item.get("command_id"), "command.command_id")
        for item in first_commands
        if item.get("kind") in {"rank_full_evidence", "release_output"}
    }
    completed_final = {
        _receipt_kind(item)
        for item in _receipts(payload)
        if item.get("status") == "completed" and item.get("plan_version") == 2
    }
    return (
        {"rank_full_evidence", "release_output"} <= first_kinds
        and "rank_full_evidence" not in final_kinds
        and first_rank_release_ids <= removed
        and {
            "isolate_batch",
            "request_corroboration",
            "pre_release_audit",
            "release_output",
        }
        <= completed_final
    )


def _bounded_check(check: Callable[[], bool]) -> bool:
    try:
        return check()
    except (EvaluationError, KeyError, TypeError, ValueError):
        return False


def _bounded_value(supplier: Callable[[], Value], default: Value) -> Value:
    try:
        return supplier()
    except (EvaluationError, KeyError, TypeError, ValueError):
        return default


def _unaffected_routes_equal(
    left: Mapping[str, object],
    right: Mapping[str, object],
    *,
    excluded: frozenset[str],
) -> bool:
    def selected(payload: Mapping[str, object]) -> dict[str, tuple[object, ...]]:
        return {
            candidate_id: _route_release_fingerprint(payload, candidate_id)
            for candidate_id in (
                _string(item.get("candidate_id"), "candidate_id") for item in _routes(payload)
            )
            if candidate_id not in excluded
        }

    return selected(left) == selected(right)


def _route_release_fingerprint(
    payload: Mapping[str, object], candidate_id: str
) -> tuple[object, ...]:
    route = next(
        (item for item in _routes(payload) if item.get("candidate_id") == candidate_id),
        None,
    )
    if route is None:
        return ()
    return (
        route.get("band"),
        route.get("queue"),
        route.get("evidence_rank"),
        route.get("rank_key"),
        _semantic_route_graph(route),
    )


def _public_routes(payload: Mapping[str, object]) -> list[JsonObject]:
    routes: list[JsonObject] = _bounded_value(
        lambda: _routes(payload),
        cast(list[JsonObject], []),
    )
    return [
        {
            "candidate_id": route.get("candidate_id"),
            "band": route.get("band"),
            "queue": route.get("queue"),
            "evidence_rank": route.get("evidence_rank"),
            "display_position": route.get("display_position"),
            "rank_key": route.get("rank_key"),
            "support_graph_hash": route.get("support_graph_hash"),
        }
        for route in routes
        if route.get("candidate_id") in _PUBLIC_CANDIDATE_IDS
    ]


def _public_receipts(payload: Mapping[str, object]) -> list[JsonObject]:
    receipts: list[JsonObject] = _bounded_value(
        lambda: _receipts(payload),
        cast(list[JsonObject], []),
    )
    return [
        {
            "command_id": item.get("command_id"),
            "command_kind": _receipt_kind(item),
            "status": item.get("status"),
        }
        for item in receipts
    ]


def _canonical_command(command: JsonObject) -> JsonObject:
    return {
        "command_id": _string(command.get("command_id"), "command.command_id"),
        "kind": _string(command.get("kind"), "command.kind"),
        "scope": command.get("scope"),
        "candidate_id": command.get("candidate_id"),
        "dependency_ids": sorted(_string_array(command.get("dependency_ids", []))),
    }


def _canonical_plan(plan: JsonObject) -> JsonObject:
    commands = _array(plan.get("commands"), "plan.commands")
    return {
        "version": _integer(plan.get("version"), "plan.version"),
        "objective": _string(plan.get("objective"), "plan.objective"),
        "strategy": _string(plan.get("strategy"), "plan.strategy"),
        "commands": [_canonical_command(_object(item, "command")) for item in commands],
        "allowed_evidence_count": len(_string_array(plan.get("allowed_evidence_ids", []))),
        "trigger_codes": sorted(_string_array(plan.get("trigger_codes", []))),
        "prohibited_actions": sorted(_string_array(plan.get("prohibited_actions", []))),
    }


def _canonical_receipt(receipt: JsonObject) -> JsonObject:
    return {
        "sequence": receipt.get("sequence"),
        "plan_version": receipt.get("plan_version"),
        "command_id": _string(receipt.get("command_id"), "receipt.command_id"),
        "command_kind": _receipt_kind(receipt),
        "status": _string(receipt.get("status"), "receipt.status"),
        "candidate_id": receipt.get("candidate_id"),
        "reason_codes": sorted(_string_array(receipt.get("reason_codes", []))),
    }


def _canonical_plan_diff(value: object) -> JsonObject | None:
    if value is None:
        return None
    diff = _object(value, "plan_diff")
    return {
        "from_version": diff.get("from_version"),
        "to_version": diff.get("to_version"),
        "strategy_before": diff.get("strategy_before"),
        "strategy_after": diff.get("strategy_after"),
        "objective_before": diff.get("objective_before"),
        "objective_after": diff.get("objective_after"),
        "trigger_codes": sorted(_string_array(diff.get("trigger_codes", []))),
        "removed_command_ids": sorted(_string_array(diff.get("removed_command_ids", []))),
        "added_commands": [
            _canonical_command(_object(item, "added command"))
            for item in _array(diff.get("added_commands", []), "added_commands")
        ],
        "revoked_evidence_count": len(_string_array(diff.get("revoked_evidence_ids", []))),
        "granted_evidence_count": len(_string_array(diff.get("granted_evidence_ids", []))),
        "added_prohibitions": sorted(_string_array(diff.get("added_prohibitions", []))),
    }


def _canonical_corroboration_requests(value: object) -> list[JsonObject]:
    requests = [_object(item, "corroboration request") for item in _array(value, "requests")]
    return sorted(
        (
            {
                "candidate_ids": sorted(_string_array(request.get("candidate_ids", []))),
                "reason_codes": sorted(_string_array(request.get("reason_codes", []))),
                "requested_evidence_kinds": sorted(
                    _string_array(request.get("requested_evidence_kinds", []))
                ),
            }
            for request in requests
        ),
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
    )


def _receipt_kind(receipt: Mapping[str, object]) -> str:
    value = receipt.get("command_kind", receipt.get("kind"))
    return _string(value, "receipt.command_kind")


def _support_graph_hash(payload: Mapping[str, object]) -> str | None:
    direct = payload.get("support_graph_hash")
    if isinstance(direct, str) and len(direct) == 64:
        return direct
    graph = payload.get("decision_support_graph")
    if isinstance(graph, dict):
        nested = graph.get("graph_hash")
        if isinstance(nested, str) and len(nested) == 64:
            return nested
    return None


def _semantic_support_graph_hash(payload: Mapping[str, object]) -> str | None:
    routes = _bounded_value(lambda: _routes(payload), cast(list[JsonObject], []))
    if not routes:
        return None
    normalized = [
        {
            "candidate_id": route.get("candidate_id"),
            "graph": _semantic_route_graph(route),
        }
        for route in sorted(routes, key=lambda item: str(item.get("candidate_id")))
    ]
    encoded = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _semantic_route_graph(route: Mapping[str, object]) -> object:
    raw_graph = route.get("support_graph")
    if raw_graph is None:
        return None
    graph = _object(raw_graph, "support_graph")
    facts = [_object(item, "supported fact") for item in _array(graph.get("facts"), "facts")]
    fact_nodes = {
        _string(item.get("fact_id"), "fact_id"): {
            "kind": _string(item.get("kind"), "fact kind"),
            "normalized_value": item.get("normalized_value"),
            "source_roles": sorted(_string_array(item.get("source_roles", []))),
        }
        for item in facts
    }
    features = [
        _object(item, "derived feature") for item in _array(graph.get("features"), "features")
    ]
    feature_nodes = {
        _string(item.get("feature_id"), "feature_id"): {
            "name": _string(item.get("name"), "feature name"),
            "normalized_value": item.get("normalized_value"),
        }
        for item in features
    }
    normalized_features = []
    for feature in features:
        feature_id = _string(feature.get("feature_id"), "feature_id")
        normalized_features.append(
            {
                **feature_nodes[feature_id],
                "fact_dependencies": sorted(
                    (
                        fact_nodes[item]
                        for item in _string_array(feature.get("dependency_fact_ids", []))
                    ),
                    key=_canonical_sort_key,
                ),
                "feature_dependencies": sorted(
                    (
                        feature_nodes[item]
                        for item in _string_array(feature.get("dependency_feature_ids", []))
                    ),
                    key=_canonical_sort_key,
                ),
            }
        )
    return {
        "facts": sorted(fact_nodes.values(), key=_canonical_sort_key),
        "features": sorted(normalized_features, key=_canonical_sort_key),
        "route_support": sorted(
            (feature_nodes[item] for item in _string_array(graph.get("route_support_ids", []))),
            key=_canonical_sort_key,
        ),
    }


def _canonical_sort_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _routes(payload: Mapping[str, object]) -> list[JsonObject]:
    return [_object(item, "route") for item in _array(payload.get("routes"), "routes")]


def _receipts(payload: Mapping[str, object]) -> list[JsonObject]:
    return [
        _object(item, "step receipt")
        for item in _array(payload.get("step_receipts"), "step_receipts")
    ]


def _rank_key(value: object) -> tuple[int, int, int, int] | None:
    if value is None:
        return None
    item = _object(value, "rank_key")
    return (
        _integer(item.get("band_priority"), "band_priority"),
        _integer(item.get("essentials_count"), "essentials_count"),
        _integer(item.get("preferred_count"), "preferred_count"),
        _integer(item.get("corroborated_claim_count"), "corroborated_claim_count"),
    )


def _parse_case(raw: JsonObject) -> CaseSpec:
    expected_routes = tuple(
        _parse_route_expectation(_object(item, "route expectation"))
        for item in _array(raw.get("expected_routes", []), "expected_routes")
    )
    return CaseSpec(
        name=_string(raw.get("name"), "case.name"),
        scenario=_string(raw.get("scenario"), "case.scenario"),
        showcase=bool(raw.get("showcase", False)),
        expected_strategy=_string(raw.get("expected_strategy"), "expected_strategy"),
        expected_ranking_scope=_string(raw.get("expected_ranking_scope"), "expected_ranking_scope"),
        expected_detail_count=_integer(raw.get("expected_detail_count"), "detail_count"),
        expected_resume_count=_integer(raw.get("expected_resume_count"), "resume_count"),
        expected_http_count=_integer(raw.get("expected_http_count"), "http_count"),
        expected_routes=expected_routes,
        mapper_fault=_optional_string(raw.get("mapper_fault"), "mapper_fault"),
        fault_candidate=_optional_string(raw.get("fault_candidate"), "fault_candidate"),
        fault_claim=_optional_string(raw.get("fault_claim"), "fault_claim"),
        equal_fingerprint_to=_optional_string(
            raw.get("equal_fingerprint_to"), "equal_fingerprint_to"
        ),
    )


def _parse_route_expectation(raw: JsonObject) -> RouteExpectation:
    rank_key = raw.get("rank_key")
    parsed_key: tuple[int, int, int, int] | None = None
    if rank_key is not None:
        values = _array(rank_key, "rank_key")
        if len(values) != 4:
            raise EvaluationError("rank key expectation must contain four integers")
        parsed_key = cast(
            tuple[int, int, int, int],
            tuple(_integer(item, "rank key item") for item in values),
        )
    return RouteExpectation(
        candidate_id=_string(raw.get("candidate_id"), "candidate_id"),
        band=_string(raw.get("band"), "band"),
        queue=_string(raw.get("queue"), "queue"),
        evidence_rank=_optional_integer(raw.get("evidence_rank"), "evidence_rank"),
        display_position=_optional_integer(raw.get("display_position"), "display_position"),
        rank_key=parsed_key,
    )


def _wait_for_source(process: subprocess.Popen[bytes], source_url: str) -> None:
    deadline = time.monotonic() + 8.0
    health_url = f"{source_url}/health"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise EvaluationError("source process exited during startup")
        try:
            with urllib.request.urlopen(health_url, timeout=0.2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise EvaluationError("source process did not become healthy")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _object(value: object, name: str) -> JsonObject:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise EvaluationError(f"{name} must be an object")
    return cast(JsonObject, value)


def _array(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise EvaluationError(f"{name} must be an array")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvaluationError(f"{name} must be a non-empty string")
    return value


def _optional_string(value: object, name: str) -> str | None:
    return None if value is None else _string(value, name)


def _string_array(value: object) -> list[str]:
    return [_string(item, "string array item") for item in _array(value, "string array")]


def _integer(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EvaluationError(f"{name} must be an integer")
    return value


def _optional_integer(value: object, name: str) -> int | None:
    return None if value is None else _integer(value, name)
